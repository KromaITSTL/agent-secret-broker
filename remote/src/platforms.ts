import type { VercelEnv } from './store';

export type FetchFn = (url: string, init: RequestInit) => Promise<Response>;
export const ALLOWED_HOSTS: readonly string[] = ['api.vercel.com', 'api.cloudflare.com'];

/** Message is built from the platform's error fields and HTTP status only; never the request. */
export class PlatformError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'PlatformError';
  }
}

export type VercelType = 'plain' | 'encrypted' | 'sensitive';
export interface PlatformTarget { id: string; name: string }
/** gitBranch and customEnvironmentIds mark Vercel records scoped past the three standard environments. */
export interface ExistingVar { key: string; id?: string; type?: string; target?: VercelEnv[]; value?: string; gitBranch?: string; customEnvironmentIds?: string[] }

const VERCEL = 'https://api.vercel.com';
const CLOUDFLARE = 'https://api.cloudflare.com/client/v4';
const MAX_ERROR = 300;

type Json = Record<string, unknown>;
const obj = (v: unknown): Json | null => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : null);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export function assertAllowedUrl(url: string): void {
  let host: string;
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' || u.username || u.password) throw new Error('bad url');
    host = u.hostname;
  } catch {
    throw new Error('host not allowed');
  }
  if (!ALLOWED_HOSTS.includes(host)) throw new Error('host not allowed');
}

export async function call(fetchFn: FetchFn, token: string, method: string, url: string, body?: unknown): Promise<{ status: number; ok: boolean; body: unknown }> {
  assertAllowedUrl(url);
  const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
  // manual: a 3xx surfaces as a non-ok response instead of being followed off the allowlist
  const init: RequestInit = { method, headers, redirect: 'manual' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetchFn(url, init);
  const parsed: unknown = await res.json().catch(() => null);
  return { status: res.status, ok: res.ok, body: parsed };
}

function platformError(prefix: string, status: number, err: Json | null, secrets: string[]): PlatformError {
  const message = err ? str(err.message) : '';
  const code = err?.code === undefined || err.code === null || err.code === '' ? '' : ` (${String(err.code)})`;
  let text = message ? `${prefix} ${status}: ${message}${code}` : `${prefix} ${status}: HTTP ${status}`;
  // backstop: the platform may echo what we sent
  // Known limit: values under 4 chars are not redacted (they would shred the message); real tokens are long
  for (const s of secrets) if (s.length >= 4) text = text.split(s).join('[redacted]');
  return new PlatformError(status, text.slice(0, MAX_ERROR));
}
const vercelError = (status: number, body: unknown, secrets: string[]) => platformError('Vercel', status, obj(obj(body)?.error), secrets);
const cfError = (status: number, body: unknown, secrets: string[]) => platformError('Cloudflare', status, obj(arr(obj(body)?.errors)[0]), secrets);

const enc = encodeURIComponent;
/** Path segment from data: '.' and '..' survive encodeURIComponent and URL parsing would retarget the request, so ids are charset-checked first. */
function seg(id: string): string {
  if (id === '.' || id === '..' || !/^[A-Za-z0-9_.-]+$/.test(id)) throw new PlatformError(0, `bad path segment: ${id.slice(0, 40)}`);
  return enc(id);
}

export function vercelClient(fetchFn: FetchFn, token: string, teamId: string) {
  const team = teamId === '' ? '' : `teamId=${enc(teamId)}`;
  const q = (...parts: string[]) => {
    const all = [...parts, team].filter(Boolean);
    return all.length ? `?${all.join('&')}` : '';
  };
  const req = async (method: string, path: string, query: string, body?: unknown, value = '') => {
    const r = await call(fetchFn, token, method, `${VERCEL}${path}${query}`, body);
    if (!r.ok) throw vercelError(r.status, r.body, [token, value]);
    return r;
  };
  const create = async (projectId: string, v: { key: string; value: string; type: VercelType; target: VercelEnv[] }, upsert: boolean) => {
    const r = await req('POST', `/v10/projects/${seg(projectId)}/env`, q(...(upsert ? ['upsert=true'] : [])), { key: v.key, value: v.value, type: v.type, target: v.target }, v.value);
    const failed = arr(obj(r.body)?.failed);
    if (failed.length) throw vercelError(r.status, { error: obj(failed[0])?.error }, [token, v.value]);
  };
  return {
    async check(): Promise<void> {
      await req('GET', '/v10/projects', q('limit=1'));
    },
    async listTargets(): Promise<PlatformTarget[]> {
      const out: PlatformTarget[] = [];
      let from = '';
      // Known limit: 10 x 100 projects; raise the cap or add search= if an account outgrows it
      for (let i = 0; i < 10; i++) {
        const b = obj((await req('GET', '/v10/projects', q('limit=100', ...(from ? [`from=${from}`] : [])))).body);
        for (const p of arr(b?.projects)) {
          const o = obj(p);
          if (o) out.push({ id: str(o.id), name: str(o.name) });
        }
        const next = obj(b?.pagination)?.next;
        if (next === null || next === undefined || next === '') break;
        from = enc(String(next));
      }
      return out;
    },
    async listVars(projectId: string): Promise<ExistingVar[]> {
      const b = obj((await req('GET', `/v10/projects/${seg(projectId)}/env`, q())).body);
      const out: ExistingVar[] = [];
      for (const e of arr(b?.envs)) {
        const o = obj(e);
        if (!o) continue;
        const target = (Array.isArray(o.target) ? o.target : o.target ? [o.target] : []) as VercelEnv[];
        const v: ExistingVar = { id: str(o.id), key: str(o.key), type: str(o.type), target };
        if (o.type === 'plain' && typeof o.value === 'string') v.value = o.value;
        if (typeof o.gitBranch === 'string' && o.gitBranch) v.gitBranch = o.gitBranch;
        const custom = arr(o.customEnvironmentIds).filter((x): x is string => typeof x === 'string' && x !== '');
        if (custom.length) v.customEnvironmentIds = custom;
        out.push(v);
      }
      return out;
    },
    createEnv: create,
    async deleteEnv(projectId: string, envId: string): Promise<void> {
      await req('DELETE', `/v9/projects/${seg(projectId)}/env/${seg(envId)}`, q());
    },
    async redeploy(projectId: string, projectName: string): Promise<{ deploymentId: string }> {
      const list = obj((await req('GET', '/v7/deployments', q(`projectId=${enc(projectId)}`, 'target=production', 'state=READY', 'limit=1'))).body);
      const uid = str(obj(arr(list?.deployments)[0])?.uid);
      if (!uid) throw new PlatformError(404, 'no ready production deployment to redeploy');
      const r = await req('POST', '/v13/deployments', q('forceNew=1'), { name: projectName, project: projectId, deploymentId: uid, target: 'production' });
      const deploymentId = str(obj(r.body)?.id);
      if (!deploymentId) throw new PlatformError(r.status, `Vercel ${r.status}: redeploy returned no deployment id`);
      return { deploymentId };
    },
  };
}

export function cloudflareClient(fetchFn: FetchFn, token: string, accountId: string) {
  const scripts = `${CLOUDFLARE}/accounts/${seg(accountId)}/workers/scripts`;
  const req = async (method: string, url: string, body?: unknown, value = '') => {
    const r = await call(fetchFn, token, method, url, body);
    if (!r.ok || obj(r.body)?.success === false) throw cfError(r.status, r.body, [token, value]);
    return obj(r.body);
  };
  return {
    async check(): Promise<void> {
      await req('GET', scripts);
    },
    async listTargets(): Promise<PlatformTarget[]> {
      const b = await req('GET', scripts);
      return arr(b?.result).flatMap((r) => {
        const id = str(obj(r)?.id);
        return id ? [{ id, name: id }] : [];
      });
    },
    async listVars(script: string): Promise<ExistingVar[]> {
      const b = await req('GET', `${scripts}/${seg(script)}/secrets`);
      return arr(b?.result).map((r) => ({ key: str(obj(r)?.name), type: str(obj(r)?.type) }));
    },
    async putSecret(script: string, name: string, text: string): Promise<void> {
      await req('PUT', `${scripts}/${seg(script)}/secrets`, { name, text, type: 'secret_text' }, text);
    },
  };
}
