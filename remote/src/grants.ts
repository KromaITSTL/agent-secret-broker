/**
 * Per-repo approvals.
 *
 * An agent can see every secret name, but it can only use a secret after
 * the operator approves it for a repo, for specific hosts (and, for production,
 * specific methods). The agent files a request; only the approval page,
 * behind GitHub sign-in, turns a request into a grant. Grants last until
 * revoked.
 */
import { defaultStrict, parseHandle, validatePolicy, type Rule, type StrictFn } from './policy';

export interface AccessItem {
  handle: string;
  hosts?: string[];
  methods?: string[];
  paths?: string[];
  /** Show a website login's fields once instead of sending a secret to a host. */
  reveal?: true;
}

export interface AccessRequest {
  id: string;
  repo: string;
  reason: string;
  items: AccessItem[];
  requestedBy: string;
  createdAt: number;
}

export interface GrantRule extends Rule {
  approvedAt: number;
  approvedBy: string;
  /** Absent on legacy rules, which have no limits and are never consumed. */
  id?: string;
  expiresAt?: number;
  usesLeft?: number;
}

export interface ItemLimits {
  ttlMs?: number;
  uses?: number;
}
/** Limits keyed by index into request.items. */
export type ApprovalLimits = Record<number, ItemLimits>;
export const MAX_USES = 1000;

export type RuleState = 'live' | 'expired' | 'used_up';

export function ruleState(r: Pick<GrantRule, 'expiresAt' | 'usesLeft'>, now: number): RuleState {
  if (r.expiresAt !== undefined && r.expiresAt <= now) return 'expired';
  if (r.usesLeft !== undefined && r.usesLeft <= 0) return 'used_up';
  return 'live';
}

export function isLive(r: Pick<GrantRule, 'expiresAt' | 'usesLeft'>, now: number): boolean {
  return ruleState(r, now) === 'live';
}

export interface ListedRule extends GrantRule {
  state: RuleState;
}
export interface ListedGrant {
  repo: string;
  rules: ListedRule[];
}

export interface RepoGrant {
  repo: string;
  rules: GrantRule[];
}

/** The subset of Durable Object storage this needs; a Map-backed fake works in tests. */
export interface KvLike {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T>(options: { prefix: string }): Promise<Map<string, T>>;
}

export const PENDING_TTL_MS = 7 * 24 * 3600_000;
const MAX_PENDING = 50;
const REPO_RE = /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/;

/** What the grant logic needs to know about vaults. */
export interface VaultRules {
  isStrict?: StrictFn;
  /** Repos a vault is linked to; empty or undefined means any repo. */
  reposFor?: (vault: string) => string[] | undefined;
  /** Whether a handle names a website login; absent means none do (reveal items fail closed). */
  isLogin?: (handle: string) => boolean;
}

export type ConsumeResult = { ok: true; usesLeft: number | null } | { ok: false; reason: string };

export class GrantError extends Error {
  override name = 'GrantError';
}

export function normalizeRepo(repo: string): string {
  const r = repo
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\/github\.com\//, '')
    .replace(/\.git$/, '')
    .replace(/\/+$/, '');
  if (!REPO_RE.test(r)) throw new GrantError(`repo must look like owner/name (got ${JSON.stringify(repo)})`);
  return r;
}

export function itemToRule(item: AccessItem, reason: string): Rule {
  const parsed = parseHandle(item.handle);
  if (!parsed) throw new GrantError(`not a valid handle: ${item.handle}`);
  if (item.reveal === true) return { action: 'reveal', description: reason, tier: parsed.tier, secrets: [parsed.name] };
  return {
    description: reason,
    tier: parsed.tier,
    secrets: [parsed.name],
    hosts: (item.hosts ?? []).map((h) => h.trim().toLowerCase()),
    ...(item.methods ? { methods: item.methods.map((m) => m.toUpperCase()) } : {}),
    ...(item.paths ? { paths: item.paths } : {}),
  };
}

/** Shape and safety checks, reusing the static policy validator (host format, production needs methods). */
export function validateRequestInput(input: { repo: string; reason: string; items: AccessItem[] }, rules: VaultRules = {}): {
  repo: string;
  reason: string;
  items: AccessItem[];
} {
  const repo = normalizeRepo(input.repo);
  const reason = (input.reason ?? '').trim().slice(0, 500);
  if (!reason) throw new GrantError('reason is required: say what the secrets are for');
  if (!Array.isArray(input.items) || input.items.length === 0) throw new GrantError('items must list at least one secret');
  if (input.items.length > 25) throw new GrantError('at most 25 secrets per request');
  const seen = new Set<string>();
  for (const item of input.items) {
    if (seen.has(item.handle)) throw new GrantError(`${item.handle} is listed twice`);
    seen.add(item.handle);
  }
  for (const item of input.items) checkRepoLink(item.handle, repo, rules);
  for (const item of input.items) {
    if (item.reveal !== true) continue;
    if (item.hosts || item.methods || item.paths) throw new GrantError(`${item.handle}: reveal items take no hosts, methods or paths`);
    if (rules.isLogin?.(item.handle) !== true) throw new GrantError(`${item.handle} is not a login; reveal is only for website logins`);
  }
  try {
    validatePolicy({ rules: input.items.map((i) => itemToRule(i, reason)) }, rules.isStrict ?? defaultStrict);
  } catch (err) {
    throw new GrantError((err as Error).message.replace(/^invalid policy: /, '').replace(/rules\[(\d+)\]/g, (_m, i) => `items[${i}] (${input.items[Number(i)]?.handle})`));
  }
  return { repo, reason, items: input.items };
}

/** A project vault linked to specific repos can only be approved for those repos. */
export function checkRepoLink(handle: string, repo: string, rules: VaultRules): void {
  const vault = parseHandle(handle)?.tier;
  if (!vault) throw new GrantError(`not a valid handle: ${handle}`);
  const linked = rules.reposFor?.(vault);
  if (linked && linked.length > 0 && !linked.includes(repo)) {
    throw new GrantError(`vault ${vault} is linked to ${linked.join(', ')}; its secrets cannot be approved for ${repo}`);
  }
}

/** Identity of a rule for de-duplication; ignores description and approval metadata. */
export function ruleKey(r: Rule): string {
  return JSON.stringify([r.action ?? 'fetch', r.tier, r.secrets, r.hosts ?? null, r.methods ?? null, r.paths ?? null]);
}

export class GrantLogic {
  constructor(
    private readonly kv: KvLike,
    private readonly now: () => number = Date.now,
    private readonly newId: () => string = () => crypto.randomUUID(),
  ) {}

  async createRequest(input: { repo: string; reason: string; items: AccessItem[]; requestedBy: string }, rules: VaultRules = {}): Promise<AccessRequest> {
    const v = validateRequestInput(input, rules);
    const pending = await this.listRequests();
    if (pending.length >= MAX_PENDING) throw new GrantError('too many pending requests; approve or deny some first');
    const req: AccessRequest = { id: this.newId(), ...v, requestedBy: input.requestedBy, createdAt: this.now() };
    await this.kv.put(`req:${req.id}`, req);
    return req;
  }

  async getRequest(id: string): Promise<AccessRequest | null> {
    const req = await this.kv.get<AccessRequest>(`req:${id}`);
    if (!req) return null;
    if (this.now() - req.createdAt > PENDING_TTL_MS) {
      await this.kv.delete(`req:${id}`);
      return null;
    }
    return req;
  }

  async listRequests(): Promise<AccessRequest[]> {
    const all = [...(await this.kv.list<AccessRequest>({ prefix: 'req:' })).values()];
    const live: AccessRequest[] = [];
    for (const r of all) {
      if (this.now() - r.createdAt > PENDING_TTL_MS) await this.kv.delete(`req:${r.id}`);
      else live.push(r);
    }
    return live.sort((a, b) => b.createdAt - a.createdAt);
  }

  /** Approve the chosen items (indexes into request.items). Anything not chosen is dropped. */
  async approve(id: string, selected: number[], approvedBy: string, limits: ApprovalLimits = {}, rules: VaultRules = {}): Promise<RepoGrant> {
    const req = await this.getRequest(id);
    if (!req) throw new GrantError('request not found or expired');
    const chosen = [...new Set(selected)].filter((i) => Number.isInteger(i) && i >= 0 && i < req.items.length);
    if (chosen.length === 0) throw new GrantError('select at least one secret, or deny the request');
    // Vault links may have changed since the request was filed.
    for (const i of chosen) checkRepoLink(req.items[i]!.handle, req.repo, rules);
    for (const i of chosen) {
      const { ttlMs, uses } = limits[i] ?? {};
      if (uses !== undefined && !(Number.isInteger(uses) && uses >= 1 && uses <= MAX_USES)) throw new GrantError(`uses must be a whole number from 1 to ${MAX_USES}`);
      if (ttlMs !== undefined && !(Number.isInteger(ttlMs) && ttlMs > 0)) throw new GrantError('duration must be a positive number of milliseconds');
    }

    const grant = (await this.getGrant(req.repo)) ?? { repo: req.repo, rules: [] };
    for (const i of chosen) {
      const rule = itemToRule(req.items[i]!, req.reason);
      const { ttlMs, uses } = limits[i] ?? {};
      const now = this.now();
      const next: GrantRule = {
        ...rule,
        id: this.newId(),
        approvedAt: now,
        approvedBy,
        ...(ttlMs ? { expiresAt: now + ttlMs } : {}),
        ...(uses ? { usesLeft: uses } : {}),
      };
      // Re-approval replaces the same rule (new id, new limits) in place.
      const at = grant.rules.findIndex((r) => ruleKey(r) === ruleKey(rule));
      if (at >= 0) grant.rules[at] = next;
      else grant.rules.push(next);
    }
    await this.kv.put(`grant:${req.repo}`, grant);
    await this.kv.delete(`req:${id}`);
    return grant;
  }

  async deny(id: string): Promise<boolean> {
    return this.kv.delete(`req:${id}`);
  }

  async getGrant(repo: string): Promise<RepoGrant | null> {
    return (await this.kv.get<RepoGrant>(`grant:${normalizeRepo(repo)}`)) ?? null;
  }

  /** Rule state is computed here on every read and never written to KV. */
  async listGrants(): Promise<ListedGrant[]> {
    const now = this.now();
    return [...(await this.kv.list<RepoGrant>({ prefix: 'grant:' })).values()]
      .sort((a, b) => a.repo.localeCompare(b.repo))
      .map((g) => ({ ...g, rules: g.rules.map((r) => ({ ...r, state: ruleState(r, now) })) }));
  }

  /** Restore grants from a backup; existing repos are left as they are. */
  async importGrants(grants: RepoGrant[]): Promise<number> {
    let n = 0;
    for (const g of grants ?? []) {
      const key = `grant:${normalizeRepo(g.repo)}`;
      if (await this.kv.get(key)) continue;
      // `state` is computed by listGrants and travels into backups; never store it.
      const rules = (g.rules ?? []).map((r) => {
        const { state: _state, ...rest } = r as GrantRule & { state?: unknown };
        return rest;
      });
      await this.kv.put(key, { ...g, rules });
      n++;
    }
    return n;
  }

  /** Revoke one rule (by index), or the whole repo when index is omitted. */
  async revoke(repo: string, index?: number): Promise<void> {
    const key = `grant:${normalizeRepo(repo)}`;
    if (index === undefined) {
      await this.kv.delete(key);
      return;
    }
    const grant = await this.kv.get<RepoGrant>(key);
    if (!grant || !grant.rules[index]) throw new GrantError('no such approval');
    grant.rules.splice(index, 1);
    if (grant.rules.length === 0) await this.kv.delete(key);
    else await this.kv.put(key, grant);
  }

  /**
   * Spend one use of a rule. Refusals are returned, not thrown, because a thrown GrantError
   * loses its class across the Durable Object RPC boundary.
   */
  async consume(repo: string, ruleId: string): Promise<ConsumeResult> {
    const key = `grant:${normalizeRepo(repo)}`;
    const grant = await this.kv.get<RepoGrant>(key);
    const rule = grant?.rules.find((r) => r.id === ruleId);
    if (!grant || !rule) return { ok: false, reason: 'no such approval' };
    if (!isLive(rule, this.now())) return { ok: false, reason: 'this approval has expired or is used up; call secret_request_access again' };
    if (rule.usesLeft === undefined) return { ok: true, usesLeft: null };
    rule.usesLeft -= 1;
    await this.kv.put(key, grant);
    return { ok: true, usesLeft: rule.usesLeft };
  }

  /** Give back a use after a failed call. No-op for unknown rules or rules without a use limit. */
  async refund(repo: string, ruleId: string): Promise<void> {
    const key = `grant:${normalizeRepo(repo)}`;
    const grant = await this.kv.get<RepoGrant>(key);
    const rule = grant?.rules.find((r) => r.id === ruleId);
    if (!grant || !rule || rule.usesLeft === undefined) return;
    rule.usesLeft += 1;
    await this.kv.put(key, grant);
  }
}

/** The grant operations the broker and web pages use; tests pass a GrantLogic directly. */
export type Grants = Pick<
  GrantLogic,
  'createRequest' | 'getRequest' | 'listRequests' | 'approve' | 'deny' | 'getGrant' | 'listGrants' | 'revoke' | 'consume' | 'refund'
>;
