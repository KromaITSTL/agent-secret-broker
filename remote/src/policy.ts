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
  /** `fetch` (default) sends the secret to hosts; `reveal` lets a human-approved caller read it and takes no hosts, methods or paths. */
  action?: 'fetch' | 'reveal';
  tier: Tier | Tier[];
  /** Secret names. `*` matches any run of characters. */
  secrets: string[];
  /** Exact hostnames, or `*.example.com` for any subdomain (not the apex). HTTPS only. */
  hosts?: string[];
  /** Allowed methods. Required for strict vaults (production, client projects); otherwise all methods. */
  methods?: string[];
  /** Path globs: `*` stays within one segment, `**` crosses segments. Default `/**`. */
  paths?: string[];
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
    if (r.action !== undefined && r.action !== 'fetch' && r.action !== 'reveal') fail(`${at}.action must be "fetch" or "reveal"`);
    if (r.action === 'reveal') {
      if (r.hosts !== undefined || r.methods !== undefined || r.paths !== undefined) fail(`${at}: reveal rules take no hosts, methods or paths`);
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
