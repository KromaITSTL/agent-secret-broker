import type { FetchFn } from '../src/platforms';
import { generateMasterKey, loadMasterKey } from '../src/crypto';
import { GrantLogic, type ApprovalLimits, type KvLike } from '../src/grants';
import { DeployLogic } from '../src/deploy';
import { VaultLogic } from '../src/store';
import type { VaultApi } from '../src/vault-do';

/** In-memory stand-in for Durable Object storage (structured-clone semantics, sorted list). */
export class MapKv implements KvLike {
  readonly m = new Map<string, unknown>();
  async get<T>(k: string) {
    return this.m.has(k) ? (structuredClone(this.m.get(k)) as T) : undefined;
  }
  async put<T>(k: string, v: T) {
    this.m.set(k, structuredClone(v));
  }
  async delete(k: string) {
    return this.m.delete(k);
  }
  async list<T>({ prefix }: { prefix: string }) {
    return new Map(
      [...this.m.entries()]
        .filter(([k]) => k.startsWith(prefix))
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([k, v]) => [k, structuredClone(v) as T]),
    );
  }
}

/** Mirrors the Durable Object: these VaultLogic members are never reachable over RPC. */
const DENIED = new Set(['connectionToken', 'readVersion', 'recordConnectionCheck', 'addPushRecord', 'setPushRedeploy', 'lastPushed']);

/** Vault API backed by in-memory storage, mirroring the Vault Durable Object RPC surface. */
export async function makeVault(opts: { fetchFn?: FetchFn; planKey?: string } = {}) {
  const kv = new MapKv();
  const mk = (await loadMasterKey(generateMasterKey()))!;
  const v = new VaultLogic(kv, { current: mk, all: [mk] });
  const d = new DeployLogic(v, {
    fetchFn: opts.fetchFn ?? (async (u) => { throw new Error(`no network in tests: ${String(u)}`); }),
    planKey: opts.planKey ?? 'test-cookie-key-0123456789abcdef',
  });
  let n = 0;
  const g = new GrantLogic(kv, Date.now, () => `req${++n}`);
  const rules = async () => {
    const by = new Map((await v.listVaults()).map((x) => [x.slug, x]));
    const logins = new Set((await v.listSecrets()).filter((m) => m.kind === 'login').map((m) => `secret://${m.tier}/${m.name}`));
    return { isStrict: (t: string) => by.get(t)?.strict ?? true, reposFor: (t: string) => by.get(t)?.repos, isLogin: (h: string) => logins.has(h) };
  };
  // Mirrors the Vault Durable Object's RPC surface.
  const overrides: Record<string, unknown> = {
    listSecrets: (trash = false) => v.listSecrets({ trash }),
    currentKeyId: async () => mk.id,
    createRequest: async (input: never) => g.createRequest(input, await rules()),
    approve: async (id: string, sel: number[], by: string, limits?: ApprovalLimits) => g.approve(id, sel, by, limits, await rules()),
    createBackup: async () => ({ createdAt: '2026-10-07T08:13:00.000Z', body: '{"format":"secret-broker-backup"}' }),
    addConnection: d.addConnection.bind(d),
    replaceConnectionToken: d.replaceConnectionToken.bind(d),
    listTargets: d.listTargets.bind(d),
    reviewPush: d.reviewPush.bind(d),
    pushTarget: d.pushTarget.bind(d),
    redeployTarget: d.redeployTarget.bind(d),
    restoreSnapshot: (snap: never, by: string, tiers?: string[]) => v.restoreSnapshot(snap, by, tiers),
  };
  const api = new Proxy(
    {},
    {
      get: (_t, k: string) => {
        if (DENIED.has(k)) return undefined;
        if (k in overrides) return overrides[k];
        const fromV = (v as unknown as Record<string, unknown>)[k];
        if (typeof fromV === 'function') return fromV.bind(v);
        const fromG = (g as unknown as Record<string, unknown>)[k];
        if (typeof fromG === 'function') return fromG.bind(g);
        return undefined;
      },
      has: (_t, k: string) => !DENIED.has(k) && (k in overrides || typeof (v as never)[k] === 'function' || typeof (g as never)[k] === 'function'),
    },
  );
  await v.createVault({ slug: 'client-work', name: 'Client work', strict: false, by: 'test' });
  return { kv, api: api as unknown as VaultApi, logic: v, deploy: d };
}

export function fakeR2() {
  const objs = new Map<string, { body: string; uploaded: Date }>();
  return {
    objs,
    async put(key: string, body: string) {
      objs.set(key, { body, uploaded: new Date() });
    },
    async get(key: string) {
      const o = objs.get(key);
      return o ? { body: o.body } : null;
    },
    async delete(key: string) {
      objs.delete(key);
    },
    async list({ prefix }: { prefix: string }) {
      return { objects: [...objs].filter(([k]) => k.startsWith(prefix)).map(([key, o]) => ({ key, size: o.body.length, uploaded: o.uploaded })) };
    },
  };
}

export function fakeKv() {
  const m = new Map<string, string>();
  /** Every put or delete, so tests can assert that a request wrote nothing. */
  const writes: string[] = [];
  return {
    writes,
    get: async (k: string) => m.get(k) ?? null,
    put: async (k: string, v: string) => void (writes.push(k), m.set(k, v)),
    delete: async (k: string) => void (writes.push(k), m.delete(k)),
  };
}

export function fakePlatform() {
  const calls: Array<{ method: string; url: string; auth: string | null; body?: unknown }> = [];
  const routes = new Map<string, (body: unknown) => { status: number; json: unknown }>();
  const key = (method: string, url: string) => `${method} ${url}`;
  return {
    calls,
    on(method: string, url: string, json: unknown, status = 200) {
      routes.set(key(method, url), () => ({ status, json }));
    },
    reply(method: string, url: string, fn: (body: unknown) => { status: number; json: unknown }) {
      routes.set(key(method, url), fn);
    },
    fetchFn: (async (url: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body = typeof init.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
      const auth = new Headers(init.headers).get('Authorization');
      calls.push({ method, url, auth, ...(body !== undefined ? { body } : {}) });
      const route = routes.get(key(method, url));
      if (!route) throw new Error(`unexpected ${method} ${url}`);
      const { status, json } = route(body);
      return new Response(JSON.stringify(json), { status, headers: { 'Content-Type': 'application/json' } });
    }) as FetchFn,
  };
}
