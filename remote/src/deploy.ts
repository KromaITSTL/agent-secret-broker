import { assertSessionKey } from './env';
import { PlatformError, cloudflareClient, vercelClient, type ExistingVar, type FetchFn, type PlatformTarget, type VercelType } from './platforms';
import { parseHandle } from './policy';
import {
  VaultError, configReadable, envGroup,
  type ItemKind, type LinkItem, type Provider, type PublicConnection, type PushAction, type PushRecord, type PushRow, type VaultLogic, type VercelEnv,
} from './store';

export type RowClass = 'new' | 'uptodate' | 'update' | 'replace' | 'missing';
export interface PlanRow {
  key: string; // `${varName}|${group}`
  handle: string; kind: ItemKind | null; version: number; versions: number[];
  varName: string; group: string; environments?: VercelEnv[];
  type?: VercelType | 'secret_text';
  cls: RowClass; ticked: boolean; recreate: boolean;
  existingIds: string[]; // Vercel ids of matched records
  existingEnvs?: string[]; // environments those records cover, Vercel only (shown so a recreate's losses are visible)
  oldValue?: string; newValue?: string; // Vercel config rows only
  branchScoped?: boolean; // a branch-scoped or custom-environment record with this name exists and is left alone
}
export interface Plan {
  connection: PublicConnection; targetId: string; targetName: string;
  rows: PlanRow[]; sig: string; cloudflareNote: boolean;
  summary: { new: number; update: number; replace: number; uptodate: number; missing: number };
}
export interface PushInput { connectionId: string; targetId: string; versions: Record<string, number>; ticked: string[]; sig: string; by: string }

const FROZEN = 'vault is frozen; unfreeze to push';
const STALE = 'the target changed since you reviewed it, review again';
const enc = new TextEncoder();

/** The matched record ids are signed, so a push deletes only records that were on the reviewed page. */
export function planCanonical(connectionId: string, targetId: string, rows: Pick<PlanRow, 'varName' | 'group' | 'cls' | 'handle' | 'version' | 'recreate' | 'type' | 'existingIds'>[]): string {
  const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  const tuples = [...rows]
    .sort((a, b) => cmp(a.varName, b.varName) || cmp(a.group, b.group))
    .map((r) => [r.varName, r.group, r.cls, r.handle, r.version, r.recreate ? 1 : 0, r.type ?? '', [...r.existingIds].sort(cmp)]);
  return 'deploy-plan|v2|' + JSON.stringify([connectionId, targetId, tuples]);
}

const hmacKey = (key: string, usage: 'sign' | 'verify') => crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);

export async function signPlan(key: string, canonical: string): Promise<string> {
  const mac = await crypto.subtle.sign('HMAC', await hmacKey(key, 'sign'), enc.encode(canonical));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Constant-time check through subtle.verify over the hex-decoded signature. */
async function verifyPlan(key: string, canonical: string, sig: string): Promise<boolean> {
  if (typeof sig !== 'string' || !/^[0-9a-f]{64}$/.test(sig)) return false;
  const bytes = new Uint8Array((sig.match(/../g) ?? []).map((h) => parseInt(h, 16)));
  return crypto.subtle.verify('HMAC', await hmacKey(key, 'verify'), bytes, enc.encode(canonical));
}

const sameSet = (a: readonly string[], b: readonly string[]) => {
  const x = [...a].sort();
  const y = [...b].sort();
  return x.length === y.length && x.every((v, i) => v === y[i]);
};
// Only a PlatformError message is already redacted; anything else could echo a URL or value.
const failText = (err: unknown) => (err instanceof PlatformError ? err.message : 'request failed');
const redact = (text: string, value: string) => (value ? text.split(value).join('[value hidden]') : text).slice(0, 300);

type Clients = { vercel: ReturnType<typeof vercelClient>; cf?: undefined } | { vercel?: undefined; cf: ReturnType<typeof cloudflareClient> };

export class DeployLogic {
  private readonly now: () => number;
  constructor(private readonly vault: VaultLogic, private readonly deps: { fetchFn: FetchFn; planKey: string; now?: () => number }) {
    assertSessionKey(deps.planKey);
    this.now = deps.now ?? Date.now;
  }

  private async client(conn: PublicConnection): Promise<Clients> {
    const token = await this.vault.connectionToken(conn.id);
    return conn.provider === 'vercel'
      ? { vercel: vercelClient(this.deps.fetchFn, token, conn.accountId) }
      : { cf: cloudflareClient(this.deps.fetchFn, token, conn.accountId) };
  }

  private async checked(conn: PublicConnection): Promise<{ connection: PublicConnection; error?: string }> {
    let error: string | undefined;
    try {
      const c = await this.client(conn);
      await (c.vercel ?? c.cf).check();
    } catch (err) {
      error = failText(err);
    }
    await this.vault.recordConnectionCheck(conn.id, error === undefined, error);
    const connection = (await this.vault.getConnection(conn.id)) ?? conn;
    return error === undefined ? { connection } : { connection, error };
  }

  async addConnection(input: { provider: Provider; name: string; accountId: string; token: string; by: string }) {
    return this.checked(await this.vault.addConnection(input));
  }

  async replaceConnectionToken(id: string, token: string, by: string) {
    return this.checked(await this.vault.replaceConnectionToken(id, token, by));
  }

  private async conn(id: string): Promise<PublicConnection> {
    const conn = await this.vault.getConnection(id);
    if (!conn) throw new VaultError('no such connection');
    return conn;
  }

  async listTargets(connectionId: string): Promise<PlatformTarget[]> {
    const c = await this.client(await this.conn(connectionId));
    return (c.vercel ?? c.cf).listTargets();
  }

  private groups(provider: Provider, kind: ItemKind, item: LinkItem): Array<{ envs?: VercelEnv[]; type: VercelType | 'secret_text' }> {
    if (provider === 'cloudflare') return [{ type: 'secret_text' }];
    const e = [...(item.environments ?? [])].sort();
    if (kind === 'config') return [{ envs: e, type: 'plain' }];
    const s = e.filter((x) => x === 'preview' || x === 'production');
    const d = e.filter((x) => x === 'development');
    return [...(s.length ? [{ envs: s, type: 'sensitive' as const }] : []), ...(d.length ? [{ envs: d, type: 'encrypted' as const }] : [])];
  }

  async reviewPush(connectionId: string, targetId: string, versions: Record<string, number> = {}): Promise<Plan> {
    if (await this.vault.isFrozen()) throw new VaultError(FROZEN);
    const connection = await this.conn(connectionId);
    const link = await this.vault.getLink(connectionId, targetId);
    if (!link) throw new VaultError('link this target first');
    const c = await this.client(connection);
    const listed: ExistingVar[] = await (c.vercel ?? c.cf).listVars(targetId);
    // branch-scoped and custom-environment records are a non-goal: never matched, so never deleted
    const scoped = (x: ExistingVar) => x.gitBranch !== undefined || (x.customEnvironmentIds?.length ?? 0) > 0;
    const existing = listed.filter((x) => !scoped(x));
    const last = await this.vault.lastPushed(connectionId, targetId);
    const rows: PlanRow[] = [];

    for (const item of link.items) {
      const parsed = parseHandle(item.handle);
      const meta = parsed ? await this.vault.getMeta(parsed.tier, parsed.name) : null;
      if (!parsed || !meta || meta.deletedAt) {
        const group = envGroup(item.environments);
        rows.push({
          key: `${item.varName}|${group}`, handle: item.handle, kind: null, version: 0, versions: [], varName: item.varName, group,
          ...(item.environments ? { environments: [...item.environments].sort() } : {}),
          cls: 'missing', ticked: false, recreate: false, existingIds: [],
        });
        continue;
      }
      const version = versions[item.handle] ?? meta.current;
      if (!meta.versions.some((x) => x.v === version)) throw new VaultError(`${item.handle} has no version ${version}`);
      const kind: ItemKind = meta.kind ?? 'secret';
      // versions written while a config item was still a secret stay secret forever, so they never go out as plain
      if (kind === 'config' && !configReadable(meta, version)) throw new VaultError(`${item.handle} version ${version} is from before it became config and cannot be pushed`);
      const offered = meta.versions.map((x) => x.v).filter((n) => kind !== 'config' || configReadable(meta, n)).sort((a, b) => b - a);
      for (const g of this.groups(connection.provider, kind, item)) {
        const group = envGroup(g.envs);
        // platform target entries are unchecked strings, so compare as plain strings
        const envs: readonly string[] = g.envs ?? [];
        const matches = c.vercel
          ? existing.filter((x) => x.key === item.varName && (x.target ?? []).some((t) => envs.includes(t)))
          : existing.filter((x) => x.key === item.varName);
        const exists = matches.length > 0;
        const only = matches.length === 1 ? matches[0] : undefined;
        const recreate = c.vercel !== undefined && exists && !(only !== undefined && only.type === g.type && sameSet(only.target ?? [], envs));
        const prev = last.get(`${item.varName}|${group}`);
        const cls: RowClass = !exists ? 'new'
          : prev && prev.handle === item.handle && prev.version === version ? 'uptodate'
          : prev && prev.handle === item.handle ? 'update'
          : 'replace';
        const row: PlanRow = {
          key: `${item.varName}|${group}`, handle: item.handle, kind, version, versions: offered,
          varName: item.varName, group, type: g.type, cls, ticked: cls === 'new' || cls === 'update', recreate,
          existingIds: c.vercel ? matches.map((m) => m.id).filter((id): id is string => Boolean(id)) : [],
        };
        if (g.envs) row.environments = g.envs;
        if (c.vercel && exists) row.existingEnvs = [...new Set(matches.flatMap((m) => m.target ?? []))].sort();
        if (listed.some((x) => scoped(x) && x.key === item.varName && (x.customEnvironmentIds !== undefined || (x.target ?? []).some((t) => envs.includes(t))))) row.branchScoped = true;
        if (c.vercel && kind === 'config') {
          // versions written while the item was still a secret are never shown as text
          if (configReadable(meta, version)) {
            row.newValue = await this.vault.readVersion(parsed.tier, parsed.name, version);
            if (only?.type === 'plain') row.oldValue = only.value;
          }
        }
        rows.push(row);
      }
    }
    const summary = { new: 0, update: 0, replace: 0, uptodate: 0, missing: 0 };
    for (const r of rows) summary[r.cls]++;
    const sig = await signPlan(this.deps.planKey, planCanonical(connectionId, targetId, rows));
    return { connection, targetId, targetName: link.targetName, rows, sig, cloudflareNote: connection.provider === 'cloudflare', summary };
  }

  async pushTarget(input: PushInput): Promise<PushRecord> {
    if (await this.vault.isFrozen()) throw new VaultError(FROZEN);
    if (!input.ticked.length) throw new VaultError('tick at least one row to push');
    const plan = await this.reviewPush(input.connectionId, input.targetId, input.versions);
    if (!(await verifyPlan(this.deps.planKey, planCanonical(input.connectionId, input.targetId, plan.rows), input.sig))) throw new VaultError(STALE);

    const tickedKeys = new Set(input.ticked);
    const byKey = new Map(plan.rows.map((r) => [r.key, r]));
    for (const k of tickedKeys) {
      const r = byKey.get(k);
      if (!r || r.cls === 'missing') throw new VaultError('a ticked row is not on the page you reviewed, review again');
    }
    const ticked = plan.rows.filter((r) => tickedKeys.has(r.key));
    const keptIds = new Set(plan.rows.filter((r) => !tickedKeys.has(r.key) && r.cls !== 'missing').flatMap((r) => r.existingIds));
    for (const r of ticked) {
      if (r.recreate && r.existingIds.some((id) => keptIds.has(id))) {
        throw new VaultError(`${r.varName}: tick every environment row for it, they share one Vercel variable`);
      }
    }

    const c = await this.client(plan.connection);
    const failed = new Map<string, string>();
    const done = new Map<string, PushAction>();
    const deleted = new Set<string>();
    if (c.vercel) {
      const ids = [...new Set(ticked.filter((r) => r.recreate).flatMap((r) => r.existingIds))];
      for (const id of ids) {
        try {
          await c.vercel.deleteEnv(input.targetId, id);
          deleted.add(id);
        } catch (err) {
          const msg = failText(err);
          for (const r of ticked) if (r.recreate && r.existingIds.includes(id) && !failed.has(r.key)) failed.set(r.key, msg);
        }
      }
      // after the whole loop, since a later delete can make a failed row partial
      for (const r of ticked) {
        const msg = failed.get(r.key);
        if (msg !== undefined && r.existingIds.some((id) => deleted.has(id))) failed.set(r.key, `some environments were already removed: ${msg}`);
      }
    }
    for (const r of ticked) {
      if (failed.has(r.key)) continue;
      const parsed = parseHandle(r.handle);
      let value = '';
      try {
        if (!parsed) throw new Error('bad handle');
        value = await this.vault.readVersion(parsed.tier, parsed.name, r.version);
        if (c.vercel) {
          await c.vercel.createEnv(input.targetId, { key: r.varName, value, type: r.type as VercelType, target: r.environments ?? [] }, r.existingIds.length > 0 && !r.recreate);
        } else {
          await c.cf.putSecret(input.targetId, r.varName, value);
        }
        done.set(r.key, r.cls === 'new' ? 'created' : r.cls === 'replace' ? 'replaced' : 'updated');
      } catch (err) {
        const msg = redact(failText(err), value);
        // a recreate row only reaches create after all its records were deleted
        const gone = r.recreate ? (r.existingEnvs ?? []).filter((e) => (r.environments ?? []).some((x) => x === e)) : [];
        failed.set(r.key, gone.length ? `removed from ${gone.join(', ')}, not recreated: ${msg}` : msg);
      }
    }

    // each row is built field by field; nothing that could carry a value is spread in
    const rows: PushRow[] = ticked.map((r) => {
      const error = failed.get(r.key);
      const row: PushRow = { handle: r.handle, version: r.version, kind: r.kind ?? 'secret', varName: r.varName, action: error === undefined ? (done.get(r.key) ?? 'failed') : 'failed' };
      if (r.environments) row.environments = r.environments;
      if (error !== undefined) row.error = error;
      return row;
    });
    const record = await this.vault.addPushRecord({ at: this.now(), by: input.by, connectionId: input.connectionId, targetId: input.targetId, targetName: plan.targetName, rows });
    const n = (a: PushAction) => rows.filter((r) => r.action === a).length;
    await this.vault.log({
      event: 'push', by: input.by, connection: plan.connection.name, connectionId: input.connectionId, target: plan.targetName, targetId: input.targetId,
      pushId: record.id, created: n('created'), updated: n('updated'), replaced: n('replaced'), failed: n('failed'), handles: [...new Set(rows.map((r) => r.handle))],
    });
    return record;
  }

  async redeployTarget(connectionId: string, targetId: string, pushId: string | undefined, by: string): Promise<NonNullable<PushRecord['redeploy']>> {
    const connection = await this.conn(connectionId);
    if (connection.provider !== 'vercel') throw new VaultError('redeploy is for Vercel projects; each Worker secret change already deployed a new version');
    const link = await this.vault.getLink(connectionId, targetId);
    if (!link) throw new VaultError('link this target first');
    const at = this.now();
    let result: NonNullable<PushRecord['redeploy']>;
    try {
      const c = await this.client(connection);
      const { deploymentId } = await c.vercel!.redeploy(targetId, link.targetName);
      result = { at, ok: true, deploymentId };
    } catch (err) {
      result = { at, ok: false, error: failText(err) };
    }
    if (pushId) await this.vault.setPushRedeploy(connectionId, targetId, pushId, result);
    await this.vault.log({
      event: 'redeploy', by, connection: connection.name, target: link.targetName, targetId, ok: result.ok,
      ...(result.deploymentId ? { deploymentId: result.deploymentId } : {}), ...(result.error ? { error: result.error } : {}),
    });
    return result;
  }
}
