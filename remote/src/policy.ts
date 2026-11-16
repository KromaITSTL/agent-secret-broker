/**
 * Remote policy: which secrets may be sent where.
 *
 * The local broker binds secrets to a workspace directory and a command
 * allowlist. A cloud connector has neither, so the binding moves to the
 * destination: every handle used in a request must be covered by a rule that
 * names its tier, the secret, the exact host, the HTTP method and the path.
 * That is what stops an agent from sending a production key to a host it
 * picked itself. Everything fails closed.
 */

/** A vault slug: `personal`, `production`, or one per project (e.g. `acme-finance`). */
export type Tier = string;

/** Built-in vaults, always present. Production is strict. */
export const BUILTIN_VAULTS = ['personal', 'production'] as const;

export const VAULT_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;

export function isVaultSlug(s: unknown): s is Tier {
  return typeof s === 'string' && VAULT_RE.test(s);
}

/** Strict vaults require approvals and rules to name HTTP methods. */
export type StrictFn = (vault: Tier) => boolean;
export const defaultStrict: StrictFn = (v) => v === 'production';

export interface Rule {
  /** Free text, shown in secret_list so the agent knows what the rule is for. */
  description?: string;
  /**
   * `fetch` (default) sends the secret to hosts; `reveal` lets a human-approved caller read it and
   * takes no hosts, methods or paths; `run` hands it to the operator's local broker for the listed
   * commands only, and takes `commands` (and optionally `env`) instead of hosts.
   */
  action?: 'fetch' | 'reveal' | 'run';
  tier: Tier | Tier[];
  /** Secret names. `*` matches any run of characters. */
  secrets: string[];
  /** Exact hostnames, or `*.example.com` for any subdomain (not the apex). HTTPS only. */
  hosts?: string[];
  /** Allowed methods. Required for strict vaults (production, client projects); otherwise all methods. */
  methods?: string[];
  /** Path globs: `*` stays within one segment, `**` crosses segments. Default `/**`. */
  paths?: string[];
  /** Run rules: command lines the local broker may run with the secret. `*` stays out of `/`, `**` matches anything. */
  commands?: string[];
  /** Run rules: names of non-secret environment variables the run may set. `*` matches any characters. */
  env?: string[];
}

export interface Policy {
  rules: Rule[];
}

export const ALL_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

const HANDLE_RE = /^secret:\/\/([a-z0-9-]+)\/([^/\s{}]+)$/;

export function parseHandle(handle: string): { tier: Tier; name: string } | null {
  const m = HANDLE_RE.exec(handle);
  if (!m) return null;
  const tier = m[1] as Tier;
  if (!isVaultSlug(tier)) return null;
  return { tier, name: m[2]! };
}

export function handleOf(tier: Tier, name: string): string {
  return `secret://${tier}/${name}`;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** `*` = any characters. Used for secret names. */
export function nameMatches(pattern: string, name: string): boolean {
  return new RegExp('^' + pattern.split('*').map(escapeRe).join('.*') + '$').test(name);
}

export function hostMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p.startsWith('*.')) return h.endsWith(p.slice(1)) && h.length > p.length - 1;
  return p === h;
}

/** `**` = anything, `*` = anything except `/`. */
export function pathMatches(pattern: string, path: string): boolean {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    if (pattern.startsWith('**', i)) {
      re += '.*';
      i++;
    } else if (pattern[i] === '*') {
      re += '[^/]*';
    } else {
      re += escapeRe(pattern[i]!);
    }
  }
  return new RegExp('^' + re + '$').test(path);
}

function tiersOf(rule: Rule): Tier[] {
  return Array.isArray(rule.tier) ? rule.tier : [rule.tier];
}

/** Validate shape at startup. A bad policy refuses every request rather than half-applying. */
export function validatePolicy(input: unknown, isStrict: StrictFn = defaultStrict): Policy {
  const fail = (msg: string): never => {
    throw new Error(`invalid policy: ${msg}`);
  };
  const p = input as Policy;
  if (!p || typeof p !== 'object' || !Array.isArray(p.rules)) fail('expected { "rules": [...] }');
  const isStrArr = (v: unknown) => Array.isArray(v) && v.every((x) => typeof x === 'string' && x.length > 0);

  p.rules.forEach((r, i) => {
    const at = `rules[${i}]`;
    const tiers = Array.isArray(r.tier) ? r.tier : [r.tier];
    if (tiers.length === 0 || !tiers.every(isVaultSlug)) fail(`${at}.tier must be a vault name (lowercase letters, digits, dashes)`);
    if (!isStrArr(r.secrets) || r.secrets.length === 0) fail(`${at}.secrets must be a non-empty string array`);
    if (r.action !== undefined && r.action !== 'fetch' && r.action !== 'reveal' && r.action !== 'run') fail(`${at}.action must be "fetch", "reveal" or "run"`);
    if (r.action !== 'run' && (r.commands !== undefined || r.env !== undefined)) fail(`${at}: only run rules take commands or env`);
    if (r.action === 'reveal') {
      if (r.hosts !== undefined || r.methods !== undefined || r.paths !== undefined) fail(`${at}: reveal rules take no hosts, methods or paths`);
      return;
    }
    if (r.action === 'run') {
      if (r.hosts !== undefined || r.methods !== undefined || r.paths !== undefined) fail(`${at}: run rules take commands instead of hosts, methods or paths`);
      if (!isStrArr(r.commands) || (r.commands ?? []).length === 0) fail(`${at}.commands must list the command lines that may use the secret`);
      for (const c of r.commands ?? []) {
        if (/[\x00-\x1f]/.test(c) || c.trim() !== c || /^\*+$/.test(c)) fail(`${at}.commands entry ${JSON.stringify(c)}: use a command line, e.g. "supabase db push *"`);
      }
      if (r.env !== undefined && !isStrArr(r.env)) fail(`${at}.env must be a string array of variable names`);
      for (const e of r.env ?? []) {
        if (!/^[A-Za-z_][A-Za-z0-9_*]*$/.test(e)) fail(`${at}.env entry ${JSON.stringify(e)}: use variable names, e.g. "SUPABASE_DEBUG"`);
        if (envPatternUnsafe(e)) fail(`${at}.env entry ${JSON.stringify(e)} would let the agent set a variable that loads code (NODE_OPTIONS, PATH, HOME, GIT_SSH and similar)`);
      }
      if (tiers.includes('production') && isExfilCapable(r.commands ?? [])) {
        fail(`${at}: production secrets cannot go to a command that lets an interpreter run free arguments (${(r.commands ?? []).join(', ')})`);
      }
      return;
    }
    const hosts = r.hosts;
    if (!hosts || !isStrArr(hosts) || hosts.length === 0) fail(`${at}.hosts must be a non-empty string array`);
    for (const h of hosts ?? []) {
      if (h === '*' || h === '*.' || /[/:@\s]/.test(h) || h.slice(2).includes('*') || (h.includes('*') && !h.startsWith('*.'))) {
        fail(`${at}.hosts entry ${JSON.stringify(h)}: use an exact hostname or *.domain`);
      }
      if (h.startsWith('*.') && h.split('.').length < 3) fail(`${at}.hosts entry ${JSON.stringify(h)} is too broad`);
    }
    if (r.methods !== undefined) {
      if (!isStrArr(r.methods) || r.methods.length === 0) fail(`${at}.methods must be a non-empty string array`);
      for (const m of r.methods) if (!ALL_METHODS.includes(m.toUpperCase())) fail(`${at}.methods has unknown method ${m}`);
    } else if (tiers.some(isStrict)) {
      const strict = tiers.filter(isStrict).join(', ');
      fail(`${at}: ${strict} is a strict vault, so methods must be listed explicitly`);
    }
    if (r.paths !== undefined && (!isStrArr(r.paths) || !r.paths.every((x) => x.startsWith('/')))) {
      fail(`${at}.paths must be absolute path globs`);
    }
  });
  return p;
}

/**
 * Normalise a command line for matching. Only the program is folded: Windows finds `NODE.exe`
 * as `node`, so its case and extension are ignored. Arguments keep their case (`git -C` and
 * `git -c` differ), and `\` is read as `/` throughout so a path pattern cannot be escaped.
 */
function foldCommand(s: string): string {
  const t = s.trim().replace(/\\/g, '/');
  const sp = t.indexOf(' ');
  const program = (sp === -1 ? t : t.slice(0, sp)).toLowerCase().replace(/\.(exe|cmd|bat|com)$/, '');
  return sp === -1 ? program : program + t.slice(sp);
}

/** Glob over a command line: `**` matches anything, `*` stays within one argument and one path segment. */
function commandGlob(pattern: string, s: string): boolean {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    if (pattern.startsWith('**', i)) {
      re += '.*';
      i++;
    } else if (pattern[i] === '*') {
      re += '[^/\\s]*';
    } else {
      re += escapeRe(pattern[i]!);
    }
  }
  return new RegExp('^' + re + '$').test(s);
}

/**
 * Command patterns match the whole command line. Within the pattern `*` stays inside one
 * argument and one path segment, and `**` matches anything. A trailing ` *` (or ` **`) means
 * "any further arguments, or none", so `supabase db push *` allows `supabase db push` and
 * `supabase db push --db-url postgres://h/db`.
 */
export function commandMatches(pattern: string, invocation: string): boolean {
  const p = foldCommand(pattern);
  const inv = foldCommand(invocation);
  const tail = / \*{1,2}$/.exec(p);
  if (!tail) return commandGlob(p, inv);
  const head = p.slice(0, tail.index);
  if (commandGlob(head, inv)) return true;
  // Try every split point between the head and the free arguments.
  for (let i = inv.indexOf(' '); i !== -1; i = inv.indexOf(' ', i + 1)) {
    if (commandGlob(head, inv.slice(0, i))) return true;
  }
  return false;
}

/**
 * Invocations that run code of the agent's choosing, which is the same as letting it print the
 * secret. A pattern that matches any of them is flagged, and refused in production. Best
 * effort: no list can know every tool that runs code.
 */
export const EXFIL_CANARIES = [
  'x', 'node -p process.env.X', 'node -e 1', 'node --eval 1', 'node --require x', 'node --import x', 'node x.mjs',
  'npx -y x', 'npm exec x', 'npm run x', 'npm x', 'pnpm dlx x', 'pnpm exec x', 'yarn dlx x', 'bunx x', 'uvx x', 'pipx run x',
  'node c:/program files/nodejs/node_modules/npm/bin/npx-cli.js -y x', 'tsx -e 1', 'tsx x.ts', 'deno eval 1', 'deno run x', 'bun -e 1', 'bun x.ts',
  'sh -c 1', 'sh x', 'bash -c 1', 'bash -lc 1', 'bash x', 'zsh -c 1', 'powershell -c 1', 'powershell -command 1', 'pwsh -c 1',
  'pwsh -command 1', 'cmd /c x', 'python -c 1', 'python -m x', 'python3 -c 1', 'python3 -m x', 'py -c 1', 'perl -e 1',
  'ruby -e 1', 'php -r 1', 'env x', 'git -c core.pager=x log', 'docker run x', 'wsl x',
];

/** For the code-running check only: the program's file name, so `C:/nodejs/node.exe **` reads as `node **`. */
function programName(pattern: string): string {
  const t = pattern.trim().replace(/\\/g, '/');
  const sp = t.indexOf(' ');
  const program = sp === -1 ? t : t.slice(0, sp);
  const base = program.slice(program.lastIndexOf('/') + 1) || program;
  return sp === -1 ? base : base + t.slice(sp);
}

export function isExfilCapable(commands: string[]): boolean {
  return EXFIL_CANARIES.some((c) => commands.some((p) => commandMatches(p, c) || commandMatches(programName(p), c)));
}

/**
 * Environment names that tools read to load code, find their config, choose a helper program
 * or proxy traffic. A run approval may never let the agent set them, or it could run its own
 * code inside the process that holds the secret. Kept in step with the local broker.
 */
export const RESERVED_ENV_RE =
  /^(PATH.*|ENV|BASH_.*|SHELL.*|COMSPEC|IFS|PS\d|PROMPT_COMMAND|EDITOR|VISUAL|PAGER|BROWSER|HOME|USERPROFILE|APPDATA|LOCALAPPDATA|XDG_.*|TMP|TEMP|TMPDIR|LD_.*|DYLD_.*|.*_PROXY|NODE_(?!ENV$).*|NPM_.*|YARN_.*|PNPM_.*|PYTHON.*|PERL.*|RUBY.*|GEM_.*|BUNDLE_.*|JAVA_.*|_JAVA_.*|JDK_.*|CLASSPATH|DOTNET_.*|CORECLR_.*|COR_.*|GIT_.*|SSH_.*|DENO_.*|BUN_.*|.*_OPTIONS|.*_OPTS)$/i;

/** One concrete example per family above, so wildcard patterns that would reach one are caught. */
const RESERVED_EXAMPLES = [
  'PATH', 'PATHEXT', 'ENV', 'BASH_ENV', 'SHELL', 'COMSPEC', 'IFS', 'PS1', 'PROMPT_COMMAND', 'EDITOR', 'VISUAL', 'PAGER', 'BROWSER',
  'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'TMP', 'TEMP', 'TMPDIR', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES',
  'HTTPS_PROXY', 'NODE_OPTIONS', 'NODE_PATH', 'NPM_CONFIG_SCRIPT_SHELL', 'YARN_RC_FILENAME', 'PNPM_HOME', 'PYTHONPATH', 'PYTHONSTARTUP',
  'PERL5OPT', 'RUBYOPT', 'GEM_HOME', 'BUNDLE_GEMFILE', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH',
  'DOTNET_STARTUP_HOOKS', 'CORECLR_PROFILER', 'COR_PROFILER', 'GIT_ASKPASS', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_CONFIG_PARAMETERS',
  'SSH_ASKPASS', 'DENO_DIR', 'BUN_INSTALL', 'MAVEN_OPTS', 'GRADLE_OPTS',
];

export function isReservedEnvName(name: string): boolean {
  return RESERVED_ENV_RE.test(name);
}

/** Whether an env name pattern would let a reserved name through. */
export function envPatternUnsafe(pattern: string): boolean {
  return isReservedEnvName(pattern) || RESERVED_EXAMPLES.some((n) => nameMatches(pattern.toUpperCase(), n));
}

/** First run rule that covers the handle and allows the command line and every extra env var name. */
export function runRule<R extends Rule>(policy: { rules: R[] }, handle: string, invocation: string, envKeys: string[] = []): R | null {
  const parsed = parseHandle(handle);
  if (!parsed) return null;
  return (
    policy.rules.find(
      (r) =>
        r.action === 'run' &&
        ruleCovers(r, parsed.tier, parsed.name) &&
        (r.commands ?? []).some((c) => commandMatches(c, invocation)) &&
        envKeys.every((k) => !isReservedEnvName(k) && (r.env ?? []).some((p) => nameMatches(p, k))),
    ) ?? null
  );
}

export interface Destination {
  host: string;
  method: string;
  path: string;
}

export function ruleCovers(rule: Rule, tier: Tier, name: string): boolean {
  return tiersOf(rule).includes(tier) && rule.secrets.some((p) => nameMatches(p, name));
}

function ruleAllows(rule: Rule, dest: Destination): boolean {
  const methods = (rule.methods ?? ALL_METHODS).map((m) => m.toUpperCase());
  return (
    !!rule.hosts?.some((h) => hostMatches(h, dest.host)) &&
    methods.includes(dest.method.toUpperCase()) &&
    (rule.paths ?? ['/**']).some((p) => pathMatches(p, dest.path))
  );
}

/** First fetch rule that covers the handle and allows the destination. Reveal rules never match. */
export function matchRule<R extends Rule>(policy: { rules: R[] }, handle: string, dest: Destination): R | null {
  const parsed = parseHandle(handle);
  if (!parsed) return null;
  return (
    policy.rules.find(
      (r) => r.hosts && r.action !== 'reveal' && ruleCovers(r, parsed.tier, parsed.name) && ruleAllows(r, dest),
    ) ?? null
  );
}

/** First reveal rule that covers the handle. */
export function revealRule<R extends Rule>(policy: { rules: R[] }, handle: string): R | null {
  const parsed = parseHandle(handle);
  if (!parsed) return null;
  return policy.rules.find((r) => r.action === 'reveal' && ruleCovers(r, parsed.tier, parsed.name)) ?? null;
}

/** Null when allowed; otherwise the reason it is not. */
export function checkHandle(policy: Policy, handle: string, dest: Destination): string | null {
  const parsed = parseHandle(handle);
  if (!parsed) return `not a valid handle: ${handle}`;
  const covering = policy.rules.filter((r) => r.hosts && r.action !== 'reveal' && ruleCovers(r, parsed.tier, parsed.name));
  if (covering.length === 0) return `${handle} is not in the policy`;
  if (matchRule(policy, handle, dest)) return null;
  const hosts = [...new Set(covering.flatMap((r) => r.hosts ?? []))].join(', ');
  return `${handle} may not be sent to ${dest.method.toUpperCase()} ${dest.host}${dest.path} (allowed hosts: ${hosts})`;
}

export interface HandleGrant {
  handle: string;
  /** One entry per covering rule; a request must fit one of them entirely. */
  destinations: Array<{ hosts: string[]; methods: string[]; paths: string[]; description?: string }>;
}

/** Where a secret may be sent, per covering rule. Null if no rule covers it. */
export function grantFor(policy: Policy, tier: Tier, name: string): HandleGrant | null {
  const covering = policy.rules.flatMap((r) =>
    r.hosts && r.action !== 'reveal' && ruleCovers(r, tier, name) ? [{ ...r, hosts: r.hosts }] : [],
  );
  if (covering.length === 0) return null;
  return {
    handle: handleOf(tier, name),
    destinations: covering.map((r) => ({
      hosts: r.hosts,
      methods: (r.methods ?? ALL_METHODS).map((m) => m.toUpperCase()),
      paths: r.paths ?? ['/**'],
      ...(r.description ? { description: r.description } : {}),
    })),
  };
}
