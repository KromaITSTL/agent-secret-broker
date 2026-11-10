import { toB64 } from './crypto';
import { GrantError, isLive, normalizeRepo, validateRequestInput, type AccessItem, type GrantRule, type Grants, type VaultRules } from './grants';
import { checkHandle, grantFor, handleOf, matchRule, parseHandle, revealRule, ruleCovers, type HandleGrant, type Policy, type Rule, type Tier } from './policy';
import { makeRedactor } from './redact';
import type { LoginFields } from './store';

export interface VaultSummary {
  slug: Tier;
  name: string;
  strict: boolean;
  /** Linked repos; empty means any repo. */
  repos: string[];
}

export interface SecretSource {
  /** Every vault. */
  vaults(): Promise<VaultSummary[]>;
  /** Every name -> current value in the vault. */
  load(vault: Tier): Promise<Map<string, string>>;
  /** Login fields when the item is a website login; null for ordinary secrets and missing items. */
  loginInfo(vault: Tier, name: string): Promise<LoginFields | null>;
  /** One secret's value, or null when it does not exist. Throws when the vault is unreadable. */
  readSecret(vault: Tier, name: string): Promise<string | null>;
  /** File a request for a new project vault; the operator approves it on the web. */
  requestVault?(input: { slug: string; name: string; repo: string; reason: string; requestedBy: string }): Promise<{ id: string; slug: string }>;
}

function rulesFrom(vaults: VaultSummary[]): VaultRules {
  const by = new Map(vaults.map((v) => [v.slug, v]));
  return { isStrict: (t) => by.get(t)?.strict ?? true, reposFor: (t) => by.get(t)?.repos };
}

/** A vault linked to other repos is invisible and unusable from this repo. */
function visibleTo(v: VaultSummary, repo: string | null): boolean {
  return !repo || v.repos.length === 0 || v.repos.includes(repo);
}

export interface FetchRequest {
  /** owner/name of the repo whose approvals apply. */
  repo?: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  basic_auth?: { username: string; password: string };
}

export interface FetchResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
}

export interface AuditEvent {
  event: 'secret_fetch' | 'secret_list' | 'secret_reveal' | 'access_requested';
  repo?: string;
  user: string;
  outcome: 'allowed' | 'denied' | 'error';
  method?: string;
  host?: string;
  /** The path as the agent wrote it, before substitution, so no value is logged. */
  pathTemplate?: string;
  handles?: string[];
  status?: number;
  reason?: string;
  /** Approval rule that served a reveal. */
  ruleId?: string;
  usesLeft?: number;
}

/** A rule in force: static policy rules, or approved rules that are neither expired nor used up. */
export type ActiveRule = Rule & Partial<Pick<GrantRule, 'id' | 'expiresAt' | 'usesLeft'>>;

export interface ListedSecret extends HandleGrant {
  approved: boolean;
  kind?: 'login';
  username?: string;
  url?: string;
  revealApproved?: boolean;
  expiresAt?: number;
  usesLeft?: number;
}

export interface BrokerDeps {
  /** Static rules from policy.json; usually empty when using per-repo approvals. */
  policy: Policy;
  /** Per-repo approvals. Without it only the static policy applies. */
  grants?: Grants;
  /** Origin used to build approval links, e.g. https://secret-broker.x.workers.dev */
  publicUrl?: string;
  source: SecretSource;
  user: string;
  fetchFn?: typeof fetch;
  audit?: (e: AuditEvent) => void;
  maxBodyChars?: number;
  timeoutMs?: number;
  /** Clock for expiry checks; defaults to Date.now. */
  now?: () => number;
}

export class DeniedError extends Error {
  override name = 'DeniedError';
}

const PLACEHOLDER_RE = /\{\{\s*([^{}\s]+)\s*\}\}/g;
// Method-override headers are refused too: many frameworks honour them, which would turn a
// GET-only approval into a DELETE.
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'keep-alive', 'proxy-authorization', 'x-http-method-override', 'x-http-method', 'x-method-override']);
const TEXT_TYPE_RE = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded|graphql|[a-z.+-]*\+(json|xml)))/i;

function placeholders(s: string | undefined): string[] {
  if (!s) return [];
  return [...s.matchAll(PLACEHOLDER_RE)].map((m) => m[1]!);
}

type Encode = (v: string) => string;
const raw: Encode = (v) => v;
const jsonString: Encode = (v) => JSON.stringify(v).slice(1, -1);

function substitute(s: string, values: Map<string, string>, encode: Encode): string {
  return s.replace(PLACEHOLDER_RE, (_m, handle: string) => encode(values.get(handle)!));
}

/** `https://host[:443]` only, with nothing templated or hidden before the path. */
function parseDestination(urlTemplate: string): { host: string; pathTemplate: string } {
  // The URL parser strips tabs and newlines and treats backslash as a slash; refuse them up
  // front so the path the policy sees is the path that gets requested.
  if (/[\x00-\x1f\x7f\\]/.test(urlTemplate)) throw new DeniedError('control characters and backslashes are not allowed in the url');
  const m = /^https:\/\/([^/?#]*)(.*)$/i.exec(urlTemplate.trim());
  if (!m) throw new DeniedError('url must start with https://');
  const authority = m[1]!;
  if (authority.includes('{') || authority.includes('}')) throw new DeniedError('secrets may not be placed in the hostname');
  if (authority.includes('@')) throw new DeniedError('credentials in the url authority are not allowed; use basic_auth or a header');
  let u: URL;
  try {
    u = new URL(`https://${authority}/`);
  } catch {
    throw new DeniedError('invalid url');
  }
  if (u.port && u.port !== '443') throw new DeniedError('only the default HTTPS port is allowed');
  const rest = m[2] ?? '';
  const rawPath = (rest.split(/[?#]/)[0] || '/');
  if (rawPath.includes('{{')) throw new DeniedError('secrets may not be placed in the url path; use the query, a header, or the body');
  if (/(^|\/)\.\.?(\/|$)|%2e|%2f|\\/i.test(rawPath)) throw new DeniedError('dot segments and encoded separators are not allowed in the path');
  // Everything after the first '?' is the query the server sees, even if it contains more '?'.
  const beforeFragment = rest.split('#')[0]!;
  const query = beforeFragment.includes('?') ? beforeFragment.slice(beforeFragment.indexOf('?') + 1) : '';
  // Split on every separator some framework accepts, not only '&', so no parser sees a key we did not.
  const queryKeys = query.split(/[&;?]/).map((p) => { try { return decodeURIComponent(p.split('=')[0]!); } catch { return p; } });
  if (queryKeys.some((k) => k.toLowerCase() === '_method')) throw new DeniedError('_method overrides are not allowed');
  // Policy is checked against the path as the parser will send it, not as the agent wrote it.
  let full: URL;
  try {
    full = new URL(`https://${authority}${rawPath}`);
  } catch {
    throw new DeniedError('invalid url');
  }
  return { host: u.hostname.toLowerCase(), pathTemplate: full.pathname };
}

export function createBroker(deps: BrokerDeps) {
  const fetchFn = deps.fetchFn ?? fetch;
  const audit = deps.audit ?? (() => {});
  const maxBody = deps.maxBodyChars ?? 100_000;
  const now = deps.now ?? Date.now;

  async function policyFor(repo: string | undefined): Promise<{ rules: ActiveRule[] }> {
    if (!repo || !deps.grants) return deps.policy;
    const r = normalizeRepo(repo);
    const [grant, vaults] = await Promise.all([deps.grants.getGrant(r), deps.source.vaults()]);
    const by = new Map(vaults.map((v) => [v.slug, v]));
    // Re-check vault links at use time, so unlinking a repo cuts it off even if an approval exists.
    const live = (grant?.rules ?? []).filter((rule) => isLive(rule, now()) && [rule.tier].flat().every((t) => { const v = by.get(t); return !!v && visibleTo(v, r); }));
    return { rules: [...deps.policy.rules, ...live] };
  }

  async function status(repo?: string) {
    const r = repo ? normalizeRepo(repo) : null;
    const vaults = (await deps.source.vaults()).filter((v) => visibleTo(v, r));
    const out: Record<string, unknown> = {
      user: deps.user,
      vaults: vaults.map((v) => ({ vault: v.slug, name: v.name, strict: v.strict, linkedRepos: v.repos })),
      staticRules: deps.policy.rules.length,
    };
    if (repo && deps.grants) {
      const r = normalizeRepo(repo);
      out.repo = r;
      out.approvedForRepo = (await deps.grants.getGrant(r))?.rules.filter((rule) => isLive(rule, now())).length ?? 0;
    }
    return out;
  }

  /**
   * Every secret name the configured machine accounts can read, so the agent
   * knows what exists. Where a secret is already usable (static policy or this
   * repo's approvals) its destinations are attached. Never values.
   */
  async function list(repo?: string): Promise<{ repo: string | null; vaults: Array<{ vault: string; name: string; strict: boolean }>; secrets: ListedSecret[]; errors: string[] }> {
    const r = repo ? normalizeRepo(repo) : null;
    const policy = await policyFor(r ?? undefined);
    const vaults = (await deps.source.vaults()).filter((v) => visibleTo(v, r));
    const secrets: ListedSecret[] = [];
    const errors: string[] = [];
    for (const tier of vaults.map((v) => v.slug)) {
      try {
        for (const name of [...(await deps.source.load(tier)).keys()].sort()) {
          const g = grantFor(policy, tier, name);
          const handle = handleOf(tier, name);
          const entry: ListedSecret = g ? { ...g, approved: true } : { handle, destinations: [], approved: false };
          // Known limit: one loginInfo RPC per name; add a per-vault batch if lists get slow
          const info = await deps.source.loginInfo(tier, name);
          if (info) {
            const rr = revealRule(policy, handle);
            const limited = [rr, ...policy.rules.filter((r) => r.hosts && r.action !== 'reveal' && ruleCovers(r, tier, name))].find((r) => r && (r.expiresAt !== undefined || r.usesLeft !== undefined));
            Object.assign(entry, { kind: 'login', username: info.username, revealApproved: !!rr });
            if (info.url) entry.url = info.url;
            if (limited?.expiresAt !== undefined) entry.expiresAt = limited.expiresAt;
            if (limited?.usesLeft !== undefined) entry.usesLeft = limited.usesLeft;
          }
          secrets.push(entry);
        }
      } catch (err) {
        errors.push(`${tier}: ${(err as Error).message}`);
      }
    }
    audit({ event: 'secret_list', user: deps.user, repo: r ?? undefined, outcome: errors.length ? 'error' : 'allowed', reason: errors.join('; ') || undefined });
    return { repo: r, vaults: vaults.map((v) => ({ vault: v.slug, name: v.name, strict: v.strict })), secrets, errors };
  }

  async function requestAccess(input: { repo: string; reason: string; items: AccessItem[] }) {
    if (!deps.grants) throw new GrantError('per-repo approvals are not enabled on this server');
    const vaults = await deps.source.vaults();
    // Fail fast on typos: every handle must exist in a vault.
    const logins = new Set<string>();
    for (const item of input.items ?? []) {
      const parsed = parseHandle(item.handle);
      if (!parsed) throw new GrantError(`not a valid handle: ${item.handle}`);
      if (!vaults.some((v) => v.slug === parsed.tier)) throw new GrantError(`there is no vault named ${parsed.tier}`);
      if (!(await deps.source.load(parsed.tier)).has(parsed.name)) {
        throw new GrantError(`${item.handle} does not exist (call secret_list for exact names)`);
      }
      if (item.reveal === true && (await deps.source.loginInfo(parsed.tier, parsed.name))) logins.add(item.handle);
    }
    // Checked here for a clear message, and again by the vault itself.
    validateRequestInput(input, { ...rulesFrom(vaults), isLogin: (h) => logins.has(h) });
    const req = await deps.grants.createRequest({ ...input, requestedBy: deps.user });
    audit({ event: 'access_requested', user: deps.user, repo: req.repo, outcome: 'allowed', handles: req.items.map((i) => i.handle) });
    const base = (deps.publicUrl ?? '').replace(/\/+$/, '');
    return {
      approvalUrl: `${base}/approve/${req.id}`,
      repo: req.repo,
      requested: req.items,
      next: `Show the approval link to the user and wait for them to approve before calling ${input.items.some((i) => i.reveal === true) ? 'secret_fetch or secret_reveal' : 'secret_fetch'} with this repo.`,
    };
  }

  async function requestVault(input: { repo: string; name: string; slug: string; reason: string }) {
    if (!deps.source.requestVault) throw new GrantError('vault requests are not enabled on this server');
    const r = await deps.source.requestVault({ ...input, requestedBy: deps.user });
    audit({ event: 'access_requested', user: deps.user, repo: normalizeRepo(input.repo), outcome: 'allowed', reason: `new vault ${r.slug}` });
    const base = (deps.publicUrl ?? '').replace(/\/+$/, '');
    return {
      approvalUrl: `${base}/approve-vault/${r.id}`,
      vault: r.slug,
      next:
        'Show the link to the user. Once they approve, they add the values in the vault UI (or import an existing .env ' +
        'with npm run import-env). Then use secret_request_access for the secrets this repo needs.',
    };
  }

  async function doFetch(req: FetchRequest): Promise<FetchResult> {
    const method = (req.method ?? 'GET').toUpperCase();
    const base: AuditEvent = { event: 'secret_fetch', user: deps.user, outcome: 'denied', method };
    const deny = (reason: string): never => {
      audit({ ...base, reason });
      throw new DeniedError(reason);
    };

    let dest: { host: string; pathTemplate: string };
    try {
      dest = parseDestination(req.url);
    } catch (err) {
      return deny((err as Error).message);
    }
    Object.assign(base, { host: dest.host, pathTemplate: dest.pathTemplate });

    for (const name of Object.keys(req.headers ?? {})) {
      if (FORBIDDEN_HEADERS.has(name.toLowerCase())) deny(`header ${name} may not be set`);
      if (name.includes('{{')) deny('secrets may not be placed in header names');
    }

    const headerValues = Object.values(req.headers ?? {});
    const handles = [
      ...new Set([
        ...placeholders(req.url),
        ...headerValues.flatMap(placeholders),
        ...placeholders(req.body),
        ...placeholders(req.basic_auth?.username),
        ...placeholders(req.basic_auth?.password),
      ]),
    ];
    base.handles = handles;
    if (handles.length === 0) deny('no {{secret://tier/NAME}} placeholders found; this tool only makes requests that need a secret');

    let repo: string | undefined;
    try {
      repo = req.repo ? normalizeRepo(req.repo) : undefined;
    } catch (err) {
      return deny((err as Error).message);
    }
    base.repo = repo;
    const policy = await policyFor(repo);
    for (const handle of handles) {
      const why = checkHandle(policy, handle, { host: dest.host, method, path: dest.pathTemplate });
      if (why) {
        deny(
          why +
            (deps.grants
              ? repo
                ? `. To use it, call secret_request_access for repo ${repo} with this secret and host, and have the user approve.`
                : '. Pass the repo you are working on (owner/name); approvals are per repo.'
              : ''),
        );
      }
    }

    // One use per limited rule that authorizes this call, however many placeholders it covers.
    const consumed: string[] = [];
    let reached = false;
    if (deps.grants && repo) {
      const limited = new Map<string, ActiveRule>();
      for (const h of handles) {
        const r = matchRule(policy, h, { host: dest.host, method, path: dest.pathTemplate })!;
        if (r.id && r.usesLeft !== undefined) limited.set(r.id, r);
      }
      for (const id of limited.keys()) {
        let res;
        try {
          res = await deps.grants.consume(repo, id);
        } catch (err) {
          await refundAll(repo, consumed);
          throw err;
        }
        if (!res.ok) {
          await refundAll(repo, consumed);
          return deny(res.reason);
        }
        consumed.push(id);
      }
    }
    try {
      // Resolve. Every gate has passed.
      const tiers = [...new Set(handles.map((h) => parseHandle(h)!.tier))];
      const loaded = new Map<Tier, Map<string, string>>();
      for (const tier of tiers) {
        try {
          loaded.set(tier, await deps.source.load(tier));
        } catch (err) {
          audit({ ...base, outcome: 'error', reason: (err as Error).message });
          throw new Error(`could not load ${tier} secrets: ${(err as Error).message}`);
        }
      }
      const values = new Map<string, string>();
      for (const handle of handles) {
        const { tier, name } = parseHandle(handle)!;
        const v = loaded.get(tier)!.get(name);
        if (v === undefined) deny(`${handle} does not exist in the vault`);
        values.set(handle, v!);
      }

      // Build the request. Values are encoded for the context they land in.
      const url = substitute(req.url.trim(), values, encodeURIComponent);
      const finalUrl = new URL(url);
      if (finalUrl.hostname.toLowerCase() !== dest.host || finalUrl.protocol !== 'https:' || finalUrl.pathname !== dest.pathTemplate) deny('url changed after substitution');

      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers ?? {})) {
        try {
          headers.set(k, substitute(v, values, raw));
        } catch {
          deny(`header ${k} is invalid after substitution`);
        }
      }
      const extra = new Map<string, string>();
      if (req.basic_auth) {
        const pair = `${substitute(req.basic_auth.username, values, raw)}:${substitute(req.basic_auth.password, values, raw)}`;
        headers.set('Authorization', `Basic ${toB64(new TextEncoder().encode(pair))}`);
        extra.set('basic_auth', pair);
      }
      let body: string | undefined;
      if (req.body !== undefined) {
        const ct = headers.get('content-type') ?? '';
        const encodeBody = /json/i.test(ct) ? jsonString : /x-www-form-urlencoded/i.test(ct) ? encodeURIComponent : raw;
        body = substitute(req.body, values, encodeBody);
      }

      // Redact against every tier this repo may use, not only the ones in this request: a value
      // written through one grant and read back through another must still be scrubbed.
      const others = new Map<string, string>();
      const redactTiers = new Set<Tier>([...loaded.keys(), ...policy.rules.flatMap((r) => [r.tier].flat())]);
      for (const tier of redactTiers) {
        const secrets = loaded.get(tier) ?? (await deps.source.load(tier).catch(() => null));
        if (!secrets) continue;
        for (const [name, v] of secrets) others.set(handleOf(tier, name), v);
      }
      const redact = makeRedactor(values, others, extra);

      let res: Response;
      try {
        res = await fetchFn(finalUrl.toString(), {
          method,
          headers,
          body: method === 'GET' || method === 'HEAD' ? undefined : body,
          redirect: 'manual',
          signal: AbortSignal.timeout(deps.timeoutMs ?? 30_000),
        });
        reached = true;
      } catch (err) {
        const reason = redact(String((err as Error).message ?? err));
        audit({ ...base, outcome: 'error', reason });
        throw new Error(`request failed: ${reason}`);
      }

      const outHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        if (k.toLowerCase() !== 'set-cookie') outHeaders[k] = redact(v);
      });
      const ct = res.headers.get('content-type') ?? '';
      let text: string;
      let truncated = false;
      if (method === 'HEAD') {
        text = '';
      } else if (ct === '' || TEXT_TYPE_RE.test(ct)) {
        // Redact before truncating, so a cut can never leave half a secret behind.
        text = redact(await res.text());
        if (text.length > maxBody) {
          text = text.slice(0, maxBody);
          truncated = true;
        }
      } else {
        const bytes = (await res.arrayBuffer()).byteLength;
        text = `[binary response omitted: ${bytes} bytes, ${ct}]`;
      }

      audit({ ...base, outcome: 'allowed', status: res.status });
      return { status: res.status, statusText: res.statusText, headers: outHeaders, body: text, truncated };
    } finally {
      // Upstream status codes count as a use; only a call that never reached upstream is refunded.
      if (!reached && repo) await refundAll(repo, consumed);
    }
  }

  /** Give back uses taken for a call that never reached its target. A failed refund must not mask the real error. */
  async function refundAll(repo: string, ids: string[]): Promise<void> {
    for (const id of ids) {
      try {
        await deps.grants!.refund(repo, id);
      } catch (err) {
        audit({ event: 'secret_fetch', user: deps.user, repo, outcome: 'error', reason: `refund failed for ${id}: ${(err as Error).message}` });
      }
    }
  }

  async function reveal(input: { repo?: string; handle: string }): Promise<{ username: string; password: string; url?: string }> {
    const { handle } = input;
    const base: AuditEvent = { event: 'secret_reveal', user: deps.user, outcome: 'denied', handles: [handle] };
    const deny = (reason: string): never => {
      audit({ ...base, reason });
      throw new DeniedError(reason);
    };
    const parsed = parseHandle(handle);
    if (!parsed) return deny('not a valid handle');
    let repo: string | undefined;
    try {
      repo = input.repo ? normalizeRepo(input.repo) : undefined;
    } catch (err) {
      return deny((err as Error).message);
    }
    base.repo = repo;
    const rule = revealRule(await policyFor(repo), handle);
    if (!rule) {
      return deny(
        `${handle} is not approved for reveal` +
          (deps.grants
            ? repo
              ? `. To use it, call secret_request_access for repo ${repo} with this login and reveal: true, and have the user approve.`
              : '. Pass the repo you are working on (owner/name); approvals are per repo.'
            : ''),
      );
    }
    // Kind check first, so a non-login is refused before its value is ever decrypted or a use is spent.
    let info: LoginFields | null;
    try {
      info = await deps.source.loginInfo(parsed.tier, parsed.name);
    } catch (err) {
      audit({ ...base, outcome: 'error', reason: (err as Error).message });
      throw new Error(`could not read ${handle}: ${(err as Error).message}`);
    }
    if (!info) return deny(`${handle} is not a login; only logins can be revealed`);
    let remaining: number | null = null;
    let consumedId: string | undefined;
    if (rule.id && rule.usesLeft !== undefined && deps.grants && repo) {
      const res = await deps.grants.consume(repo, rule.id);
      if (!res.ok) return deny(res.reason);
      remaining = res.usesLeft;
      consumedId = rule.id;
    }
    let served = false;
    try {
      let password: string | null;
      try {
        password = await deps.source.readSecret(parsed.tier, parsed.name);
      } catch (err) {
        audit({ ...base, outcome: 'error', reason: (err as Error).message });
        throw new Error(`could not read ${handle}: ${(err as Error).message}`);
      }
      if (password === null) return deny(`${handle} does not exist in the vault`);
      served = true;
      audit({ ...base, outcome: 'allowed', ruleId: rule.id, usesLeft: remaining ?? undefined });
      return { username: info.username, password, ...(info.url ? { url: info.url } : {}) };
    } finally {
      if (!served && consumedId && repo) await refundAll(repo, [consumedId]);
    }
  }

  return { status, list, requestAccess, requestVault, fetch: doFetch, reveal };
}

export type Broker = ReturnType<typeof createBroker>;
