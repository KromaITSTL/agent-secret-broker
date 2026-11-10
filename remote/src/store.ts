/**
 * The vault itself: secrets with version history and a trash bin, machine
 * tokens for the local broker, an audit log, and a freeze switch. Runs inside
 * the Vault Durable Object; written against a small storage interface so it
 * is fully testable in Node.
 *
 * Values are only ever stored sealed (see crypto.ts). Nothing here returns a
 * value to the web UI; values leave only through loadTier(), which serves the
 * MCP broker and machine tokens, and through the public-key-encrypted backup.
 */
import { openToken, openValue, randomToken, rewrap, rewrapToken, sealToken, sealValue, sha256Hex, type MasterKey, type Sealed } from './crypto';
import type { KvLike } from './grants';
import { BUILTIN_VAULTS, isVaultSlug, parseHandle, type Tier } from './policy';

export const NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;
export const MAX_VALUE_BYTES = 32 * 1024;
export const MAX_VERSIONS = 20;
export const TRASH_DAYS = 30;
export const MAX_USERNAME = 256;
export const MAX_URL = 2048;
export const MAX_NOTES = 2000;
const AUDIT_KEEP_DAYS = 180;
const REGISTRATION_WINDOW_MS = 15 * 60_000;
const REGISTRATION_MAX = 5;

export class VaultError extends Error {
  override name = 'VaultError';
}

export interface VersionMeta {
  v: number;
  createdAt: number;
  by: string;
  note?: string;
}

export interface LoginFields {
  username: string;
  url?: string;
  notes?: string;
}

export function checkLogin(input: { username?: unknown; url?: unknown; notes?: unknown }): LoginFields {
  const str = (x: unknown) => (typeof x === 'string' ? x.trim() : '');
  const username = str(input?.username);
  if (!username || username.length > MAX_USERNAME) throw new VaultError(`username is required (up to ${MAX_USERNAME} characters)`);
  const url = str(input.url);
  if (url) {
    let ok = url.length <= MAX_URL;
    if (ok) {
      try {
        const p = new URL(url).protocol;
        ok = p === 'http:' || p === 'https:';
      } catch {
        ok = false;
      }
    }
    if (!ok) throw new VaultError(`url must be an http or https address up to ${MAX_URL} characters`);
  }
  const notes = str(input.notes);
  if (notes.length > MAX_NOTES) throw new VaultError(`notes are limited to ${MAX_NOTES} characters`);
  return { username, ...(url ? { url } : {}), ...(notes ? { notes } : {}) };
}

export type ItemKind = 'secret' | 'login' | 'config';

/** True when this version of a config item may be shown as text (legacy config items without the marker only show their current version). */
export function configReadable(m: Pick<SecretMeta, 'kind' | 'configSince' | 'current'>, v: number): boolean {
  return m.kind === 'config' && v >= (m.configSince ?? m.current);
}

export interface SecretMeta {
  kind?: ItemKind;
  /** First version that may be shown as text. Older versions were written while the item was a secret. */
  configSince?: number;
  login?: LoginFields;
  tier: Tier;
  name: string;
  current: number;
  versions: VersionMeta[];
  createdAt: number;
  updatedAt: number;
  deletedAt?: number;
  deletedBy?: string;
}

export interface Machine {
  id: string;
  name: string;
  tiers: Tier[];
  canImport: boolean;
  tokenHash: string;
  createdAt: number;
  createdBy: string;
  lastUsedAt?: number;
}

export type PublicMachine = Omit<Machine, 'tokenHash'>;

export interface AuditEntry {
  at: number;
  event: string;
  by: string;
  [k: string]: unknown;
}

export interface Snapshot {
  format: 'secret-broker-snapshot';
  version: 1;
  exportedAt: string;
  secrets: Array<{
    tier: Tier;
    name: string;
    kind?: ItemKind;
    configSince?: number;
    login?: LoginFields;
    deleted: boolean;
    versions: Array<VersionMeta & { value: string }>;
  }>;
  grants: unknown[];
  machines: Machine[];
  vaults?: VaultInfo[];
  connections?: Connection[];
  links?: TargetLink[];
  pushes?: PushRecord[];
}

export interface VaultInfo {
  slug: Tier;
  name: string;
  kind: 'personal' | 'production' | 'project';
  /** Approvals and rules for this vault must name HTTP methods. */
  strict: boolean;
  /** Project vaults: the only repos its secrets may be approved for (owner/name). Empty = any. */
  repos: string[];
  note?: string;
  createdAt: number;
  createdBy: string;
}

export interface VaultRequest {
  id: string;
  slug: string;
  name: string;
  repo: string;
  reason: string;
  requestedBy: string;
  createdAt: number;
}

export type Provider = 'vercel' | 'cloudflare';
export type VercelEnv = 'production' | 'preview' | 'development';
export const CONN_ID_RE = /^[0-9a-f-]{36}$/;
export const TARGET_ID_RE = /^[A-Za-z0-9_.-]{1,100}$/;
export const PUSH_ID_RE = /^\d{14}:[A-Za-z0-9_-]{1,32}$/;
export const VAR_RE = /^[A-Z_][A-Z0-9_]*$/;
export const MAX_VAR = 256;
export const PAGE_SIZE = 25;
export const VERCEL_ENVS: readonly VercelEnv[] = ['development', 'preview', 'production'];

export function defaultVarName(name: string): string {
  const v = name.toUpperCase().replace(/[.-]/g, '_');
  return /^[0-9]/.test(v) ? `_${v}` : v;
}
export function envGroup(envs?: readonly string[]): string {
  return envs ? [...envs].sort().join(',') : '';
}

export interface Connection {
  id: string;
  provider: Provider;
  name: string;
  accountId: string;
  /** Sealed with associated data `conn:<id>`; never leaves the store. */
  token: Sealed;
  createdAt: number;
  createdBy: string;
  lastCheckedAt?: number;
  lastCheckOk?: boolean;
  lastCheckError?: string;
}
export type PublicConnection = Omit<Connection, 'token'>;

export interface LinkItem {
  handle: string;
  varName: string;
  environments?: VercelEnv[];
}
export interface TargetLink {
  connectionId: string;
  targetId: string;
  targetName: string;
  items: LinkItem[];
  updatedAt: number;
  updatedBy: string;
}
export type PushAction = 'created' | 'updated' | 'replaced' | 'failed';
export interface PushRow {
  handle: string;
  version: number;
  kind: ItemKind;
  varName: string;
  environments?: VercelEnv[];
  action: PushAction;
  error?: string;
}
export interface PushRecord {
  id: string;
  at: number;
  by: string;
  connectionId: string;
  targetId: string;
  targetName: string;
  rows: PushRow[];
  redeploy?: { at: number; deploymentId?: string; ok: boolean; error?: string };
}

export interface ImportItem {
  tier: Tier;
  name: string;
  value: string;
  login?: LoginFields;
}

function checkTier(t: string): Tier {
  if (!isVaultSlug(t)) throw new VaultError('vault names use lowercase letters, digits and dashes (2-40 chars)');
  return t;
}

const REPO_RE = /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/;
function normRepos(repos: string[]): string[] {
  const out = [
    ...new Set(
      repos
        .map((r) => r.trim().toLowerCase().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/+$/, ''))
        .filter(Boolean),
    ),
  ];
  for (const r of out) if (!REPO_RE.test(r)) throw new VaultError(`repo must look like owner/name (got ${r})`);
  return out;
}

const VAULT_REQ_TTL_MS = 7 * 24 * 3600_000;

function checkName(n: string): string {
  if (!NAME_RE.test(n)) throw new VaultError('name may use letters, digits, _ . - (max 128)');
  return n;
}

const metaKey = (t: Tier, n: string) => `sec:${t}:${n}`;
const verKey = (t: Tier, n: string, v: number) => `ver:${t}:${n}:${v}`;

function publicConn(c: Connection): PublicConnection {
  const { token: _t, ...pub } = c;
  return pub;
}

function cleanConnToken(t: string): string {
  const token = (t ?? '').trim();
  if (token.length < 1 || token.length > 4096) throw new VaultError('token is required (up to 4096 characters)');
  return token;
}

export class VaultLogic {
  constructor(
    private readonly kv: KvLike,
    /** [current, ...previous]. Current may be null if VAULT_MASTER_KEY is not set yet. */
    private readonly keys: { current: MasterKey | null; all: MasterKey[] },
    private readonly now: () => number = Date.now,
  ) {}

  private master(): MasterKey {
    if (!this.keys.current) throw new VaultError('VAULT_MASTER_KEY is not configured; run npm run setup-keys');
    return this.keys.current;
  }

  // ---------- audit ----------

  async log(entry: Omit<AuditEntry, 'at'>): Promise<void> {
    const at = this.now();
    await this.kv.put(`audit:${String(at).padStart(14, '0')}:${randomToken(4)}`, { at, ...entry });
  }

  async listAudit(limit = 200): Promise<AuditEntry[]> {
    const all = [...(await this.kv.list<AuditEntry>({ prefix: 'audit:' })).entries()];
    const cutoff = this.now() - AUDIT_KEEP_DAYS * 86400_000;
    const keep: AuditEntry[] = [];
    for (const [k, e] of all) {
      if (e.at < cutoff) await this.kv.delete(k);
      else keep.push(e);
    }
    return keep.sort((a, b) => b.at - a.at).slice(0, limit);
  }

  // ---------- freeze ----------

  async isFrozen(): Promise<boolean> {
    return (await this.kv.get<{ frozen: boolean }>('setting:frozen'))?.frozen === true;
  }

  async setFrozen(frozen: boolean, by: string): Promise<void> {
    await this.kv.put('setting:frozen', { frozen, by, at: this.now() });
    await this.log({ event: frozen ? 'vault_frozen' : 'vault_unfrozen', by });
  }

  // ---------- client registration ----------

  /** Dynamic client registration is closed unless the operator opens a short, counted window. */
  async registrationStatus(): Promise<{ until: number; left: number }> {
    const r = await this.kv.get<{ until: number; left: number }>('setting:registration');
    return r && r.until > this.now() && r.left > 0 ? { until: r.until, left: r.left } : { until: 0, left: 0 };
  }

  async openRegistration(by: string): Promise<void> {
    await this.kv.put('setting:registration', { until: this.now() + REGISTRATION_WINDOW_MS, left: REGISTRATION_MAX, by, at: this.now() });
    await this.log({ event: 'registration_opened', by });
  }

  async closeRegistration(by: string): Promise<void> {
    await this.kv.put('setting:registration', { until: 0, left: 0, by, at: this.now() });
    await this.log({ event: 'registration_closed', by });
  }

  /**
   * Spends one registration slot. One call, so the check and the count cannot race: it is atomic
   * because the Durable Object's input gate holds other calls while storage operations are pending.
   * Do not add network I/O (or anything else that yields) before the read.
   */
  async takeRegistration(info: { name: string; hosts: string[] }): Promise<boolean> {
    const r = await this.kv.get<{ until: number; left: number; by: string; at: number }>('setting:registration');
    if (!r || r.until <= this.now() || r.left <= 0) return false;
    await this.kv.put('setting:registration', { ...r, left: r.left - 1 });
    await this.log({ event: 'client_registered', by: 'unauthenticated', name: info.name.slice(0, 100), hosts: info.hosts.slice(0, 10) });
    return true;
  }

  // ---------- vaults ----------

  private async ensureBuiltins(): Promise<void> {
    for (const slug of BUILTIN_VAULTS) {
      if (await this.kv.get(`vault:${slug}`)) continue;
      const info: VaultInfo = {
        slug,
        name: slug === 'personal' ? 'Personal' : 'Production',
        kind: slug,
        strict: slug === 'production',
        repos: [],
        createdAt: this.now(),
        createdBy: 'system',
      };
      await this.kv.put(`vault:${slug}`, info);
    }
  }

  async listVaults(): Promise<VaultInfo[]> {
    await this.ensureBuiltins();
    const order = (v: VaultInfo) => (v.kind === 'personal' ? 0 : v.kind === 'production' ? 1 : 2);
    return [...(await this.kv.list<VaultInfo>({ prefix: 'vault:' })).values()].sort(
      (a, b) => order(a) - order(b) || a.slug.localeCompare(b.slug),
    );
  }

  async getVault(slug: string): Promise<VaultInfo | null> {
    if (!isVaultSlug(slug)) return null;
    if ((BUILTIN_VAULTS as readonly string[]).includes(slug)) await this.ensureBuiltins();
    return (await this.kv.get<VaultInfo>(`vault:${slug}`)) ?? null;
  }

  private async requireVault(slug: string): Promise<VaultInfo> {
    const v = await this.getVault(checkTier(slug));
    if (!v) throw new VaultError(`no vault named ${slug}`);
    return v;
  }

  async createVault(input: { slug: string; name: string; strict?: boolean; repos?: string[]; note?: string; by: string }): Promise<VaultInfo> {
    const slug = checkTier(input.slug.trim().toLowerCase());
    if (await this.getVault(slug)) throw new VaultError(`a vault named ${slug} already exists`);
    const info: VaultInfo = {
      slug,
      name: (input.name.trim() || slug).slice(0, 80),
      kind: 'project',
      strict: input.strict ?? true,
      repos: normRepos(input.repos ?? []),
      ...(input.note ? { note: input.note.slice(0, 300) } : {}),
      createdAt: this.now(),
      createdBy: input.by,
    };
    await this.kv.put(`vault:${slug}`, info);
    await this.log({ event: 'vault_created', by: input.by, vault: slug, strict: info.strict, repos: info.repos });
    return info;
  }

  async updateVault(slug: string, patch: { name?: string; strict?: boolean; repos?: string[] }, by: string): Promise<VaultInfo> {
    const v = await this.requireVault(slug);
    if (v.kind !== 'project' && patch.strict !== undefined && patch.strict !== v.strict) {
      throw new VaultError(`${v.slug} is built in; its strictness cannot change`);
    }
    const next: VaultInfo = {
      ...v,
      ...(patch.name !== undefined ? { name: patch.name.trim().slice(0, 80) || v.name } : {}),
      ...(patch.strict !== undefined ? { strict: patch.strict } : {}),
      ...(patch.repos !== undefined ? { repos: normRepos(patch.repos) } : {}),
    };
    await this.kv.put(`vault:${v.slug}`, next);
    await this.log({ event: 'vault_updated', by, vault: v.slug, strict: next.strict, repos: next.repos });
    return next;
  }

  /** Only empty project vaults (nothing live or in the trash). */
  async deleteVault(slug: string, by: string): Promise<void> {
    const v = await this.requireVault(slug);
    if (v.kind !== 'project') throw new VaultError(`${v.slug} is built in and cannot be deleted`);
    const any = [...(await this.kv.list<SecretMeta>({ prefix: `sec:${v.slug}:` })).values()];
    if (any.length) throw new VaultError(`${v.slug} still holds ${any.length} secret(s), including any in the trash; remove them first`);
    await this.kv.delete(`vault:${v.slug}`);
    await this.log({ event: 'vault_deleted', by, vault: v.slug });
  }

  // ---------- vault requests (an agent asks for a new project vault) ----------

  async requestVault(input: { slug: string; name: string; repo: string; reason: string; requestedBy: string }, newId: () => string = () => crypto.randomUUID()): Promise<VaultRequest> {
    const slug = checkTier(input.slug.trim().toLowerCase());
    if (await this.getVault(slug)) throw new VaultError(`a vault named ${slug} already exists`);
    const [repo] = normRepos([input.repo]);
    if (!repo) throw new VaultError('repo is required');
    const reason = input.reason.trim().slice(0, 500);
    if (!reason) throw new VaultError('reason is required');
    const pending = await this.listVaultRequests();
    if (pending.length >= 20) throw new VaultError('too many pending vault requests');
    if (pending.some((p) => p.slug === slug)) throw new VaultError(`a request for ${slug} is already waiting for approval`);
    const req: VaultRequest = { id: newId(), slug, name: (input.name.trim() || slug).slice(0, 80), repo, reason, requestedBy: input.requestedBy, createdAt: this.now() };
    await this.kv.put(`vreq:${req.id}`, req);
    await this.log({ event: 'vault_requested', by: input.requestedBy, vault: slug, repo });
    return req;
  }

  async getVaultRequest(id: string): Promise<VaultRequest | null> {
    const r = await this.kv.get<VaultRequest>(`vreq:${id}`);
    if (!r) return null;
    if (this.now() - r.createdAt > VAULT_REQ_TTL_MS) {
      await this.kv.delete(`vreq:${id}`);
      return null;
    }
    return r;
  }

  async listVaultRequests(): Promise<VaultRequest[]> {
    const out: VaultRequest[] = [];
    for (const r of (await this.kv.list<VaultRequest>({ prefix: 'vreq:' })).values()) {
      if (this.now() - r.createdAt > VAULT_REQ_TTL_MS) await this.kv.delete(`vreq:${r.id}`);
      else out.push(r);
    }
    return out.sort((a, b) => b.createdAt - a.createdAt);
  }

  async approveVaultRequest(id: string, by: string, opts: { strict: boolean; slug?: string; name?: string }): Promise<VaultInfo> {
    const r = await this.getVaultRequest(id);
    if (!r) throw new VaultError('request not found or expired');
    const info = await this.createVault({ slug: opts.slug || r.slug, name: opts.name || r.name, strict: opts.strict, repos: [r.repo], note: r.reason, by });
    await this.kv.delete(`vreq:${id}`);
    return info;
  }

  async denyVaultRequest(id: string, by: string): Promise<void> {
    const r = await this.getVaultRequest(id);
    await this.kv.delete(`vreq:${id}`);
    if (r) await this.log({ event: 'vault_request_denied', by, vault: r.slug, repo: r.repo });
  }

  // ---------- secrets ----------

  async listSecrets(opts: { trash?: boolean } = {}): Promise<SecretMeta[]> {
    const metas = [...(await this.kv.list<SecretMeta>({ prefix: 'sec:' })).values()];
    const out: SecretMeta[] = [];
    for (const m of metas) {
      if (m.deletedAt && this.now() - m.deletedAt > TRASH_DAYS * 86400_000) {
        await this.purge(m.tier, m.name, 'system');
        continue;
      }
      if (!!m.deletedAt === !!opts.trash) out.push(m);
    }
    return out.sort((a, b) => a.tier.localeCompare(b.tier) || a.name.localeCompare(b.name));
  }

  async getMeta(tier: string, name: string): Promise<SecretMeta | null> {
    return (await this.kv.get<SecretMeta>(metaKey(checkTier(tier), checkName(name)))) ?? null;
  }

  async putSecret(tierIn: string, nameIn: string, value: string, by: string, note?: string, login?: LoginFields, kind?: 'config'): Promise<SecretMeta> {
    const tier = (await this.requireVault(tierIn)).slug;
    const name = checkName(nameIn);
    if (typeof value !== 'string' || value.length === 0) throw new VaultError('value is empty');
    if (new TextEncoder().encode(value).length > MAX_VALUE_BYTES) throw new VaultError(`value is larger than ${MAX_VALUE_BYTES / 1024} KB`);

    const checked = login ? checkLogin(login) : undefined;
    if (kind === 'config' && login) throw new VaultError('a login cannot be config');

    const now = this.now();
    const existing = await this.kv.get<SecretMeta>(metaKey(tier, name));
    if (kind === 'config' && existing && !existing.deletedAt && existing.kind !== 'config') {
      throw new VaultError(`${tier}/${name} is a ${existing.kind ?? 'secret'}; use Convert to config`);
    }
    if (checked && existing && !existing.deletedAt && existing.kind === 'config') throw new VaultError('a config item cannot become a login');
    const meta: SecretMeta = existing ?? {
      tier, name, current: 0, versions: [], createdAt: now, updatedAt: now,
    };
    // A trashed config item revived without asking for config becomes an ordinary secret, so a
    // value entered as write-only is never shown; revived as config, only the new version is readable.
    const revivedConfig = !!existing?.deletedAt && existing.kind === 'config';
    if (revivedConfig && kind !== 'config') {
      delete meta.kind;
      delete meta.configSince;
    }
    if (checked) {
      meta.kind = 'login';
      meta.login = checked;
    }
    if (kind === 'config') {
      meta.kind = 'config';
      delete meta.login;
    }
    const v = (meta.versions.at(-1)?.v ?? 0) + 1;
    if (kind === 'config' && (meta.configSince === undefined || revivedConfig)) meta.configSince = v;
    const sealed = await sealValue(this.master(), tier, name, v, value);
    await this.kv.put(verKey(tier, name, v), sealed);
    meta.versions.push({ v, createdAt: now, by, ...(note ? { note: note.slice(0, 200) } : {}) });
    meta.current = v;
    meta.updatedAt = now;
    delete meta.deletedAt;
    delete meta.deletedBy;
    while (meta.versions.length > MAX_VERSIONS) {
      const old = meta.versions.shift()!;
      await this.kv.delete(verKey(tier, name, old.v));
    }
    await this.kv.put(metaKey(tier, name), meta);
    await this.log({ event: v === 1 ? 'secret_created' : 'secret_updated', by, handle: `secret://${tier}/${name}`, version: v });
    return meta;
  }

  /** Edit a login's clear fields. The password is untouched, so no new version. */
  async updateLogin(tier: string, name: string, login: LoginFields, by: string): Promise<SecretMeta> {
    const meta = await this.getMeta(tier, name);
    if (!meta || meta.deletedAt) throw new VaultError('no such login');
    if (meta.kind !== 'login') throw new VaultError(`${meta.tier}/${meta.name} is not a login`);
    meta.login = checkLogin(login);
    meta.updatedAt = this.now();
    await this.kv.put(metaKey(meta.tier, meta.name), meta);
    await this.log({ event: 'login_updated', by, handle: `secret://${meta.tier}/${meta.name}` });
    return meta;
  }

  /** One-way: mark a live secret as config. The value and versions are untouched. */
  async convertToConfig(tier: string, name: string, by: string): Promise<SecretMeta> {
    const meta = await this.getMeta(tier, name);
    if (!meta || meta.deletedAt) throw new VaultError('no such secret');
    if (meta.kind === 'login') throw new VaultError('logins cannot be converted to config');
    if (meta.kind === 'config') throw new VaultError(`${meta.tier}/${meta.name} is already config`);
    meta.kind = 'config';
    meta.configSince = meta.current;
    meta.updatedAt = this.now();
    await this.kv.put(metaKey(meta.tier, meta.name), meta);
    await this.log({ event: 'secret_converted_to_config', by, handle: `secret://${meta.tier}/${meta.name}` });
    return meta;
  }

  /** Current values of all live config items, keyed `tier/name`. For the dashboard only; ignores freeze. */
  async configValues(): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const m of await this.listSecrets()) {
      if (m.deletedAt || !configReadable(m, m.current)) continue;
      const sealed = await this.kv.get<Sealed>(verKey(m.tier, m.name, m.current));
      if (sealed) out.set(`${m.tier}/${m.name}`, await openValue(this.keys.all, m.tier, m.name, m.current, sealed));
    }
    return out;
  }

  /** Apply incoming login fields to a live secret whose value is unchanged. Returns true when the stored meta changed; no new version. */
  private async applyLoginIfChanged(meta: SecretMeta, login: LoginFields | undefined, by: string): Promise<boolean> {
    if (!login || meta.kind === 'config') return false;
    const checked = checkLogin(login);
    if (meta.kind === 'login' && JSON.stringify(meta.login) === JSON.stringify(checked)) return false;
    meta.kind = 'login';
    meta.login = checked;
    meta.updatedAt = this.now();
    await this.kv.put(metaKey(meta.tier, meta.name), meta);
    await this.log({ event: 'login_updated', by, handle: `secret://${meta.tier}/${meta.name}` });
    return true;
  }

  /** Current value of one secret, or null when missing or trashed. */
  async readSecret(tierIn: string, name: string): Promise<string | null> {
    const tier = (await this.requireVault(tierIn)).slug;
    if (await this.isFrozen()) throw new VaultError('the vault is frozen; unfreeze it in Settings');
    const meta = await this.getMeta(tier, name);
    if (!meta || meta.deletedAt) return null;
    const sealed = await this.kv.get<Sealed>(verKey(tier, meta.name, meta.current));
    return sealed ? openValue(this.keys.all, tier, meta.name, meta.current, sealed) : null;
  }

  /** A kept version's value; refuses while frozen. */
  async readVersion(tierIn: string, name: string, v: number): Promise<string> {
    const tier = (await this.requireVault(tierIn)).slug;
    if (await this.isFrozen()) throw new VaultError('the vault is frozen; unfreeze it in Settings');
    const meta = await this.getMeta(tier, name);
    if (!meta || meta.deletedAt || !meta.versions.some((x) => x.v === v)) throw new VaultError('no such version');
    const sealed = await this.kv.get<Sealed>(verKey(tier, meta.name, v));
    if (!sealed) throw new VaultError('no such version');
    return openValue(this.keys.all, tier, meta.name, v, sealed);
  }

  async loginInfo(tier: string, name: string): Promise<LoginFields | null> {
    const meta = await this.getMeta(tier, name);
    return meta && !meta.deletedAt && meta.kind === 'login' ? (meta.login ?? null) : null;
  }

  /** Make an old version current again (as a new version, so history is preserved). */
  async restoreVersion(tier: string, name: string, v: number, by: string): Promise<SecretMeta> {
    const meta = await this.getMeta(tier, name);
    if (!meta || !meta.versions.some((x) => x.v === v)) throw new VaultError('no such version');
    if (meta.kind === 'config' && !configReadable(meta, v)) throw new VaultError('versions from before this item became config cannot be restored');
    const sealed = await this.kv.get<Sealed>(verKey(meta.tier, meta.name, v));
    if (!sealed) throw new VaultError('version data missing');
    const value = await openValue(this.keys.all, meta.tier, meta.name, v, sealed);
    return this.putSecret(meta.tier, meta.name, value, by, `restored from v${v}`);
  }

  async deleteSecret(tier: string, name: string, by: string): Promise<void> {
    const meta = await this.getMeta(tier, name);
    if (!meta || meta.deletedAt) throw new VaultError('no such secret');
    meta.deletedAt = this.now();
    meta.deletedBy = by;
    await this.kv.put(metaKey(meta.tier, meta.name), meta);
    await this.log({ event: 'secret_trashed', by, handle: `secret://${meta.tier}/${meta.name}` });
  }

  /**
   * Move a secret, with its whole version history, to another vault.
   * Each version is decrypted and re-sealed, because ciphertexts are bound to
   * their vault. Approvals for the old handle no longer apply.
   */
  async moveSecret(tier: string, name: string, toVault: string, by: string): Promise<SecretMeta> {
    const meta = await this.getMeta(tier, name);
    if (!meta || meta.deletedAt) throw new VaultError('no such secret');
    const to = (await this.requireVault(toVault)).slug;
    if (to === meta.tier) throw new VaultError('it is already in that vault');
    const clash = await this.getMeta(to, meta.name);
    if (clash) throw new VaultError(`${to} already has a secret named ${meta.name}${clash.deletedAt ? ' (in the trash: restore or purge it first)' : ''}`);

    const master = this.master();
    const moved: SecretMeta = { ...meta, tier: to };
    for (const ver of meta.versions) {
      const sealed = await this.kv.get<Sealed>(verKey(meta.tier, meta.name, ver.v));
      if (!sealed) throw new VaultError(`version ${ver.v} is missing`);
      const value = await openValue(this.keys.all, meta.tier, meta.name, ver.v, sealed);
      await this.kv.put(verKey(to, meta.name, ver.v), await sealValue(master, to, meta.name, ver.v, value));
    }
    moved.updatedAt = this.now();
    await this.kv.put(metaKey(to, meta.name), moved);
    // Only after the copy is complete, remove the original.
    for (const ver of meta.versions) await this.kv.delete(verKey(meta.tier, meta.name, ver.v));
    await this.kv.delete(metaKey(meta.tier, meta.name));
    await this.log({ event: 'secret_moved', by, from: `secret://${meta.tier}/${meta.name}`, to: `secret://${to}/${meta.name}`, versions: meta.versions.length });
    return moved;
  }

  async undeleteSecret(tier: string, name: string, by: string): Promise<void> {
    const meta = await this.getMeta(tier, name);
    if (!meta?.deletedAt) throw new VaultError('not in trash');
    delete meta.deletedAt;
    delete meta.deletedBy;
    await this.kv.put(metaKey(meta.tier, meta.name), meta);
    await this.log({ event: 'secret_restored', by, handle: `secret://${meta.tier}/${meta.name}` });
  }

  /** Permanent. Only from the trash. */
  async purge(tier: string, name: string, by: string): Promise<void> {
    const meta = await this.getMeta(tier, name);
    if (!meta?.deletedAt) throw new VaultError('only secrets in the trash can be purged');
    for (const ver of meta.versions) await this.kv.delete(verKey(meta.tier, meta.name, ver.v));
    await this.kv.delete(metaKey(meta.tier, meta.name));
    await this.log({ event: 'secret_purged', by, handle: `secret://${meta.tier}/${meta.name}` });
  }

  /** Current values for a tier. The only path values take to callers (broker / machines). */
  async loadTier(tierIn: string): Promise<Map<string, string>> {
    const tier = (await this.requireVault(tierIn)).slug;
    if (await this.isFrozen()) throw new VaultError('the vault is frozen; unfreeze it in Settings');
    const out = new Map<string, string>();
    for (const m of await this.listSecrets()) {
      if (m.tier !== tier) continue;
      const sealed = await this.kv.get<Sealed>(verKey(tier, m.name, m.current));
      if (sealed) out.set(m.name, await openValue(this.keys.all, tier, m.name, m.current, sealed));
    }
    return out;
  }

  /** Re-wrap every stored data key under the current master key (after rotation). */
  async rotate(by: string): Promise<{ rewrapped: number; tokensSkipped: number }> {
    const next = this.master();
    let n = 0;
    let tokensSkipped = 0;
    for (const [k, s] of await this.kv.list<Sealed>({ prefix: 'ver:' })) {
      if (s.kid === next.id) continue;
      const [, tier, name, v] = k.split(':') as [string, string, string, string];
      await this.kv.put(k, await rewrap(this.keys.all, next, tier, name, Number(v), s));
      n++;
    }
    for (const [k, c] of await this.kv.list<Connection>({ prefix: 'conn:' })) {
      if (c.token?.kid === next.id) continue;
      // one token sealed under an unloaded key must not block rotation of everything; it needs re-adding
      if (typeof c.token?.kid !== 'string' || !this.keys.all.some((key) => key.id === c.token.kid)) {
        tokensSkipped++;
        continue;
      }
      await this.kv.put(k, { ...c, token: await rewrapToken(this.keys.all, next, c.id, c.token) });
      n++;
    }
    await this.log({ event: 'master_key_rotated', by, rewrapped: n, tokensSkipped, keyId: next.id });
    return { rewrapped: n, tokensSkipped };
  }

  /** Count of stored versions per master key id; non-current ids mean rotation is unfinished. */
  async keyUsage(): Promise<Record<string, number>> {
    const out: Record<string, number> = {};
    for (const s of (await this.kv.list<Sealed>({ prefix: 'ver:' })).values()) out[s.kid] = (out[s.kid] ?? 0) + 1;
    for (const c of (await this.kv.list<Connection>({ prefix: 'conn:' })).values()) out[c.token.kid] = (out[c.token.kid] ?? 0) + 1;
    return out;
  }

  // ---------- import ----------

  async importSecrets(items: ImportItem[], by: string, overwrite: boolean): Promise<{ created: number; updated: number; skipped: number }> {
    let created = 0, updated = 0, skipped = 0;
    for (const it of items) {
      const existing = await this.getMeta(it.tier, it.name);
      if (existing && !existing.deletedAt && !overwrite) {
        skipped++;
        continue;
      }
      if (existing && !existing.deletedAt) {
        const sealed = await this.kv.get<Sealed>(verKey(existing.tier, existing.name, existing.current));
        if (sealed && (await openValue(this.keys.all, existing.tier, existing.name, existing.current, sealed)) === it.value) {
          if (await this.applyLoginIfChanged(existing, it.login, by)) updated++;
          else skipped++;
          continue;
        }
      }
      await this.putSecret(it.tier, it.name, it.value, by, 'imported', it.login);
      if (existing) updated++;
      else created++;
    }
    await this.log({ event: 'secrets_imported', by, created, updated, skipped });
    return { created, updated, skipped };
  }

  // ---------- machines (local broker tokens) ----------

  /** Token format sbv.<base64url origin>.<id>.<secret>: self-contained, so the local broker needs no config. */
  async createMachine(input: { name: string; tiers: string[]; canImport: boolean; by: string; origin: string }): Promise<{ token: string; machine: PublicMachine }> {
    const name = input.name.trim().slice(0, 60);
    if (!name) throw new VaultError('give the machine a name');
    const tiers = [...new Set(input.tiers.map(checkTier))];
    for (const t of tiers) await this.requireVault(t);
    if (tiers.length === 0 && !input.canImport) throw new VaultError('pick at least one vault or allow import');
    const id = randomToken(9);
    const secret = randomToken(32);
    const machine: Machine = { id, name, tiers, canImport: input.canImport, tokenHash: await sha256Hex(secret), createdAt: this.now(), createdBy: input.by };
    await this.kv.put(`mach:${id}`, machine);
    await this.log({ event: 'machine_created', by: input.by, machine: name, tiers, canImport: input.canImport });
    const originB64 = btoa(input.origin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const { tokenHash: _h, ...pub } = machine;
    return { token: `sbv.${originB64}.${id}.${secret}`, machine: pub };
  }

  async listMachines(): Promise<PublicMachine[]> {
    return [...(await this.kv.list<Machine>({ prefix: 'mach:' })).values()]
      .map(({ tokenHash: _h, ...m }) => m)
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async revokeMachine(id: string, by: string): Promise<void> {
    const m = await this.kv.get<Machine>(`mach:${id}`);
    if (!m) throw new VaultError('no such machine');
    await this.kv.delete(`mach:${id}`);
    await this.log({ event: 'machine_revoked', by, machine: m.name });
  }

  async authMachine(token: string): Promise<PublicMachine | null> {
    const parts = token.split('.');
    if (parts.length !== 4 || parts[0] !== 'sbv') return null;
    const m = await this.kv.get<Machine>(`mach:${parts[2]}`);
    if (!m) return null;
    const h = await sha256Hex(parts[3]!);
    if (h.length !== m.tokenHash.length) return null;
    let d = 0;
    for (let i = 0; i < h.length; i++) d |= h.charCodeAt(i) ^ m.tokenHash.charCodeAt(i);
    if (d !== 0) return null;
    m.lastUsedAt = this.now();
    await this.kv.put(`mach:${m.id}`, m);
    const { tokenHash: _h, ...pub } = m;
    return pub;
  }

  // ---------- connections (deploy targets) ----------

  private async connRecord(id: string): Promise<Connection> {
    const c = await this.kv.get<Connection>(`conn:${id}`);
    if (!c) throw new VaultError('no such connection');
    return c;
  }

  async addConnection(input: { provider: Provider; name: string; accountId: string; token: string; by: string }): Promise<PublicConnection> {
    if (input.provider !== 'vercel' && input.provider !== 'cloudflare') throw new VaultError('provider must be vercel or cloudflare');
    const name = (input.name ?? '').trim();
    if (name.length < 1 || name.length > 60) throw new VaultError('connection name must be 1 to 60 characters');
    const accountId = (input.accountId ?? '').trim();
    if (input.provider === 'vercel' && accountId !== '' && !/^team_[A-Za-z0-9]{1,64}$/.test(accountId)) {
      throw new VaultError('Vercel team id looks like team_... (leave it empty for a personal account)');
    }
    if (input.provider === 'cloudflare' && !/^[a-f0-9]{32}$/.test(accountId)) throw new VaultError('Cloudflare account id is 32 hex characters');
    const token = cleanConnToken(input.token);
    const id = crypto.randomUUID();
    const conn: Connection = {
      id, provider: input.provider, name, accountId, token: await sealToken(this.master(), id, token),
      createdAt: this.now(), createdBy: input.by,
    };
    await this.kv.put(`conn:${id}`, conn);
    await this.log({ event: 'connection_added', by: input.by, connection: name, provider: input.provider });
    return publicConn(conn);
  }

  async replaceConnectionToken(id: string, token: string, by: string): Promise<PublicConnection> {
    const conn = await this.connRecord(id);
    const clean = cleanConnToken(token);
    const next: Connection = { ...conn, token: await sealToken(this.master(), id, clean) };
    delete next.lastCheckedAt;
    delete next.lastCheckOk;
    delete next.lastCheckError;
    await this.kv.put(`conn:${id}`, next);
    await this.log({ event: 'connection_token_replaced', by, connection: conn.name });
    return publicConn(next);
  }

  async recordConnectionCheck(id: string, ok: boolean, error?: string): Promise<void> {
    const conn = await this.connRecord(id);
    conn.lastCheckedAt = this.now();
    conn.lastCheckOk = ok;
    if (ok) delete conn.lastCheckError;
    else conn.lastCheckError = error?.slice(0, 300);
    await this.kv.put(`conn:${id}`, conn);
  }

  /** Removes the connection and its links; push history is kept as the audit trail. */
  async removeConnection(id: string, by: string): Promise<void> {
    const conn = await this.connRecord(id);
    await this.kv.delete(`conn:${id}`);
    for (const k of (await this.kv.list<unknown>({ prefix: `link:${id}:` })).keys()) await this.kv.delete(k);
    await this.log({ event: 'connection_removed', by, connection: conn.name });
  }

  async getConnection(id: string): Promise<PublicConnection | null> {
    const c = await this.kv.get<Connection>(`conn:${id}`);
    return c ? publicConn(c) : null;
  }

  async listConnections(): Promise<PublicConnection[]> {
    return [...(await this.kv.list<Connection>({ prefix: 'conn:' })).values()]
      .map(publicConn)
      .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  }

  /** Server-side only: no Durable Object wrapper exposes this. */
  async connectionToken(id: string): Promise<string> {
    const conn = await this.connRecord(id);
    return openToken(this.keys.all, id, conn.token);
  }

  // ---------- deploy links and push history ----------

  async saveLink(input: { connectionId: string; targetId: string; targetName: string; items: LinkItem[]; by: string }): Promise<TargetLink> {
    const conn = await this.kv.get<Connection>(`conn:${input.connectionId}`);
    if (!conn) throw new VaultError('no such connection');
    if (!TARGET_ID_RE.test(input.targetId ?? '')) throw new VaultError('target id may use letters, digits, _ . - (max 100)');
    const targetName = (input.targetName ?? '').trim();
    if (targetName.length < 1 || targetName.length > 200) throw new VaultError('target name must be 1 to 200 characters');
    if (!Array.isArray(input.items) || input.items.length > 100) throw new VaultError('a link holds at most 100 items');
    const items: LinkItem[] = [];
    const seen = new Set<string>();
    for (const it of input.items) {
      const parsed = parseHandle(it.handle);
      const meta = parsed ? await this.getMeta(parsed.tier, parsed.name) : null;
      if (!parsed || !meta || meta.deletedAt) throw new VaultError(`no such item: ${it.handle}`);
      const varName = it.varName;
      if (typeof varName !== 'string' || !VAR_RE.test(varName)) throw new VaultError(`${varName}: variable names use A-Z, 0-9 and _ and do not start with a digit`);
      if (varName.length > MAX_VAR) throw new VaultError(`${varName.slice(0, 20)}...: variable names are at most 256 characters`);
      const out: LinkItem = { handle: it.handle, varName };
      if (conn.provider === 'vercel') {
        const envs: readonly string[] | undefined = it.environments === undefined ? ['preview', 'production'] : it.environments;
        if (!Array.isArray(envs)) throw new VaultError(`${varName}: unknown environment`);
        for (const e of envs) if (!VERCEL_ENVS.includes(e as VercelEnv)) throw new VaultError(`${varName}: unknown environment`);
        const picked = VERCEL_ENVS.filter((e) => envs.includes(e));
        if (picked.length === 0) throw new VaultError(`${varName}: pick at least one environment`);
        out.environments = picked;
      }
      if (seen.has(varName)) throw new VaultError(`${varName} is used twice in this link`);
      seen.add(varName);
      items.push(out);
    }
    // Same provider, account and target id is one real target, whichever connection reaches it.
    const overlaps = (a?: readonly string[], b?: readonly string[]) => !a || !b || a.some((e) => b.includes(e));
    for (const other of await this.listLinks()) {
      if (other.targetId !== input.targetId || other.connectionId === input.connectionId) continue;
      const oc = await this.kv.get<Connection>(`conn:${other.connectionId}`);
      if (!oc || oc.provider !== conn.provider || oc.accountId !== conn.accountId) continue;
      for (const mine of items) {
        const clash = other.items.find((o) => o.varName === mine.varName && o.handle !== mine.handle && overlaps(o.environments, mine.environments));
        if (clash) throw new VaultError(`${mine.varName} on this target already comes from ${clash.handle} (link via ${oc.name})`);
      }
    }
    const link: TargetLink = { connectionId: input.connectionId, targetId: input.targetId, targetName, items, updatedAt: this.now(), updatedBy: input.by };
    await this.kv.put(`link:${input.connectionId}:${input.targetId}`, link);
    return link;
  }

  async getLink(connectionId: string, targetId: string): Promise<TargetLink | null> {
    return (await this.kv.get<TargetLink>(`link:${connectionId}:${targetId}`)) ?? null;
  }

  async listLinks(): Promise<TargetLink[]> {
    return [...(await this.kv.list<TargetLink>({ prefix: 'link:' })).values()]
      .sort((a, b) => a.targetName.localeCompare(b.targetName) || a.targetId.localeCompare(b.targetId));
  }

  async addPushRecord(rec: Omit<PushRecord, 'id'>): Promise<PushRecord> {
    const full: PushRecord = { ...rec, id: `${String(rec.at).padStart(14, '0')}:${randomToken(4)}` };
    await this.kv.put(`push:${rec.connectionId}:${rec.targetId}:${full.id}`, full);
    return full;
  }

  async setPushRedeploy(connectionId: string, targetId: string, pushId: string, redeploy: NonNullable<PushRecord['redeploy']>): Promise<void> {
    const key = `push:${connectionId}:${targetId}:${pushId}`;
    const rec = await this.kv.get<PushRecord>(key);
    if (rec) await this.kv.put(key, { ...rec, redeploy });
  }

  async listPushes(page: number, filter?: { connectionId: string; targetId: string }): Promise<{ records: PushRecord[]; page: number; pages: number; total: number }> {
    const prefix = filter ? `push:${filter.connectionId}:${filter.targetId}:` : 'push:';
    // Known limit: loads every push record; add a time-sorted index if history grows past a few thousand
    const all = [...(await this.kv.list<PushRecord>({ prefix })).values()].sort((a, b) => b.at - a.at || b.id.localeCompare(a.id));
    const pages = Math.max(1, Math.ceil(all.length / PAGE_SIZE));
    const p = Number.isInteger(page) ? Math.min(Math.max(page, 1), pages) : 1;
    return { records: all.slice((p - 1) * PAGE_SIZE, p * PAGE_SIZE), page: p, pages, total: all.length };
  }

  private async pushesFor(connectionId: string, targetId: string): Promise<PushRecord[]> {
    return [...(await this.kv.list<PushRecord>({ prefix: `push:${connectionId}:${targetId}:` })).values()]
      .sort((a, b) => a.at - b.at || a.id.localeCompare(b.id));
  }

  async lastPushed(connectionId: string, targetId: string): Promise<Map<string, { handle: string; version: number; at: number }>> {
    const out = new Map<string, { handle: string; version: number; at: number }>();
    for (const rec of await this.pushesFor(connectionId, targetId)) {
      for (const row of rec.rows) {
        if (row.action === 'failed') continue;
        out.set(`${row.varName}|${envGroup(row.environments)}`, { handle: row.handle, version: row.version, at: rec.at });
      }
    }
    return out;
  }

  async linkSummaries(): Promise<Array<{ link: TargetLink; connection: PublicConnection | null; changed: number; missing: number; lastPushAt?: number }>> {
    const out = [];
    for (const link of await this.listLinks()) {
      const recs = await this.pushesFor(link.connectionId, link.targetId);
      let changed = 0;
      let missing = 0;
      for (const item of link.items) {
        const parsed = parseHandle(item.handle);
        const meta = parsed ? await this.getMeta(parsed.tier, parsed.name) : null;
        if (!meta || meta.deletedAt) { missing++; continue; }
        let pushed: number | undefined;
        for (const rec of recs) for (const row of rec.rows) if (row.handle === item.handle && row.varName === item.varName && row.action !== 'failed') pushed = row.version;
        if (pushed !== meta.current) changed++;
      }
      const last = recs[recs.length - 1];
      out.push({ link, connection: await this.getConnection(link.connectionId), changed, missing, ...(last ? { lastPushAt: last.at } : {}) });
    }
    return out;
  }

  // ---------- snapshots (backup / restore) ----------

  async exportSnapshot(grants: unknown[]): Promise<Snapshot> {
    const metas = [...(await this.kv.list<SecretMeta>({ prefix: 'sec:' })).values()];
    const secrets: Snapshot['secrets'] = [];
    for (const m of metas) {
      const versions: Array<VersionMeta & { value: string }> = [];
      for (const ver of m.versions) {
        const sealed = await this.kv.get<Sealed>(verKey(m.tier, m.name, ver.v));
        if (sealed) versions.push({ ...ver, value: await openValue(this.keys.all, m.tier, m.name, ver.v, sealed) });
      }
      secrets.push({ tier: m.tier, name: m.name, ...(m.kind === 'login' ? { kind: 'login' as const, login: m.login } : m.kind === 'config' ? { kind: 'config' as const, configSince: m.configSince ?? m.current } : {}), deleted: !!m.deletedAt, versions });
    }
    const machines = [...(await this.kv.list<Machine>({ prefix: 'mach:' })).values()];
    const vaults = await this.listVaults();
    const connections = [...(await this.kv.list<Connection>({ prefix: 'conn:' })).values()];
    const links = [...(await this.kv.list<TargetLink>({ prefix: 'link:' })).values()];
    const pushes = [...(await this.kv.list<PushRecord>({ prefix: 'push:' })).values()];
    return { format: 'secret-broker-snapshot', version: 1, exportedAt: new Date(this.now()).toISOString(), secrets, grants, machines, vaults, connections, links, pushes };
  }

  /**
   * Restore secrets (current value of each, as a new version) and machines from a decrypted
   * snapshot. When `overwriteTiers` is given, an existing live value is only replaced in those
   * tiers; elsewhere the snapshot may fill gaps but not substitute values.
   */
  async restoreSnapshot(snap: Snapshot, by: string, overwriteTiers?: Tier[]): Promise<{ secrets: number; machines: number; connections: number; connectionsUnreadable: number; links: number; pushes: number }> {
    if (snap?.format !== 'secret-broker-snapshot') throw new VaultError('not a secret-broker snapshot');
    await this.ensureBuiltins();
    for (const v of snap.vaults ?? []) {
      if (!(await this.kv.get(`vault:${v.slug}`))) await this.kv.put(`vault:${v.slug}`, v);
    }
    // Older snapshots without vault records: recreate any vault their secrets need.
    for (const s of snap.secrets) {
      if (!(await this.kv.get(`vault:${s.tier}`))) {
        await this.kv.put(`vault:${s.tier}`, { slug: s.tier, name: s.tier, kind: 'project', strict: true, repos: [], createdAt: this.now(), createdBy: by } satisfies VaultInfo);
      }
    }
    let secrets = 0;
    for (const s of snap.secrets) {
      if (s.deleted || s.versions.length === 0) continue;
      const latest = s.versions[s.versions.length - 1]!;
      const existing = await this.getMeta(s.tier, s.name);
      if (existing && !existing.deletedAt) {
        const sealed = await this.kv.get<Sealed>(verKey(existing.tier, existing.name, existing.current));
        if (sealed && (await openValue(this.keys.all, existing.tier, existing.name, existing.current, sealed)) === latest.value) {
          if ((!overwriteTiers || overwriteTiers.includes(s.tier)) && (await this.applyLoginIfChanged(existing, s.kind === 'login' ? s.login : undefined, by))) secrets++;
          continue;
        }
        if (overwriteTiers && !overwriteTiers.includes(s.tier)) continue;
        // a backup value of unknown provenance must not become readable text on a live config item
        if (existing.kind === 'config') continue;
      }
      const createKind = (!existing || existing.deletedAt) && s.kind === 'config' ? 'config' : undefined;
      await this.putSecret(s.tier, s.name, latest.value, by, `restored from backup ${snap.exportedAt}`, s.kind === 'login' ? s.login : undefined, createKind);
      secrets++;
    }
    let machines = 0;
    for (const m of snap.machines ?? []) {
      if (!(await this.kv.get(`mach:${m.id}`))) {
        await this.kv.put(`mach:${m.id}`, m);
        machines++;
      }
    }
    // Connections, links and push records are only ever added, never overwritten, and ids are
    // checked because they become KV key segments.
    let connections = 0;
    let connectionsUnreadable = 0;
    for (const c of snap.connections ?? []) {
      if (!CONN_ID_RE.test(c?.id) || (c.provider !== 'vercel' && c.provider !== 'cloudflare')) continue;
      // A token that no loaded master key can open would break rotate() and keyUsage() for good.
      if (typeof c.token?.kid !== 'string' || !this.keys.all.some((k) => k.id === c.token.kid)) {
        connectionsUnreadable++;
        continue;
      }
      if (!(await this.kv.get(`conn:${c.id}`))) {
        await this.kv.put(`conn:${c.id}`, c);
        connections++;
      }
    }
    let links = 0;
    for (const l of snap.links ?? []) {
      if (!CONN_ID_RE.test(l?.connectionId) || !TARGET_ID_RE.test(l.targetId)) continue;
      if (!(await this.kv.get(`conn:${l.connectionId}`))) continue; // orphan links could not be removed later
      const key = `link:${l.connectionId}:${l.targetId}`;
      if (!(await this.kv.get(key))) {
        await this.kv.put(key, l);
        links++;
      }
    }
    let pushes = 0;
    for (const r of snap.pushes ?? []) {
      if (!CONN_ID_RE.test(r?.connectionId) || !TARGET_ID_RE.test(r.targetId) || !PUSH_ID_RE.test(r.id)) continue;
      const key = `push:${r.connectionId}:${r.targetId}:${r.id}`;
      if (!(await this.kv.get(key))) {
        await this.kv.put(key, r);
        pushes++;
      }
    }
    await this.log({ event: 'snapshot_restored', by, secrets, machines, connections, connectionsUnreadable, links, pushes, from: snap.exportedAt });
    return { secrets, machines, connections, connectionsUnreadable, links, pushes };
  }
}
