import { describe, expect, it } from 'vitest';
import { ALLOWED_HOSTS, PlatformError, assertAllowedUrl, call, cloudflareClient, vercelClient } from '../src/platforms';
import { generateMasterKey, loadMasterKey } from '../src/crypto';
import { DeployLogic, planCanonical } from '../src/deploy';
import { VaultLogic, type LinkItem, type VercelEnv } from '../src/store';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { VaultApi } from '../src/vault-do';
import { MapKv, fakePlatform, makeVault } from './helpers';

const V = 'https://api.vercel.com';
const CF = 'https://api.cloudflare.com/client/v4';
const ACCT = 'a'.repeat(32);

describe('vercel client', () => {
  it('pages the project list with from, omits teamId for a personal account, and sends the bearer token', async () => {
    const p = fakePlatform();
    p.on('GET', `${V}/v10/projects?limit=100`, { projects: [{ id: 'prj_1', name: 'one' }], pagination: { count: 1, next: 'tok2' } });
    p.on('GET', `${V}/v10/projects?limit=100&from=tok2`, { projects: [{ id: 'prj_2', name: 'two' }], pagination: { count: 1, next: null } });
    expect(await vercelClient(p.fetchFn, 'vtok', '').listTargets()).toEqual([{ id: 'prj_1', name: 'one' }, { id: 'prj_2', name: 'two' }]);
    expect(p.calls.every((c) => c.auth === 'Bearer vtok')).toBe(true);
  });

  it('stops paging after 10 calls', async () => {
    const p = fakePlatform();
    p.on('GET', `${V}/v10/projects?limit=100&teamId=team_a`, { projects: [], pagination: { next: 1 } });
    p.on('GET', `${V}/v10/projects?limit=100&from=1&teamId=team_a`, { projects: [{ id: 'p', name: 'p' }], pagination: { next: 1 } });
    await vercelClient(p.fetchFn, 't', 'team_a').listTargets();
    expect(p.calls).toHaveLength(10);
  });

  it('checks with one project and lists env vars with types, targets and plain values only', async () => {
    const p = fakePlatform();
    p.on('GET', `${V}/v10/projects?limit=1&teamId=team_a`, { projects: [] });
    p.on('GET', `${V}/v10/projects/prj_1/env?teamId=team_a`, { envs: [
      { id: 'e1', key: 'CLIENT_ID', type: 'plain', target: ['production', 'preview'], value: 'cid' },
      { id: 'e2', key: 'SECRET', type: 'sensitive', target: 'production', value: 'should-not-surface' },
    ] });
    const c = vercelClient(p.fetchFn, 't', 'team_a');
    await c.check();
    expect(await c.listVars('prj_1')).toEqual([
      { id: 'e1', key: 'CLIENT_ID', type: 'plain', target: ['production', 'preview'], value: 'cid' },
      { id: 'e2', key: 'SECRET', type: 'sensitive', target: ['production'] },
    ]);
  });

  it('keeps the git branch and custom environment ids on listed vars, ignoring empty ones', async () => {
    const p = fakePlatform();
    p.on('GET', `${V}/v10/projects/prj_1/env`, { envs: [
      { id: 'b1', key: 'S', type: 'sensitive', target: ['preview'], gitBranch: 'feature-x' },
      { id: 'c1', key: 'S', type: 'sensitive', target: [], customEnvironmentIds: ['env_1'] },
      { id: 'n1', key: 'S', type: 'sensitive', target: ['production'], gitBranch: null, customEnvironmentIds: [] },
    ] });
    expect(await vercelClient(p.fetchFn, 't', '').listVars('prj_1')).toEqual([
      { id: 'b1', key: 'S', type: 'sensitive', target: ['preview'], gitBranch: 'feature-x' },
      { id: 'c1', key: 'S', type: 'sensitive', target: [], customEnvironmentIds: ['env_1'] },
      { id: 'n1', key: 'S', type: 'sensitive', target: ['production'] },
    ]);
  });

  it('creates with exact body, upserts only when asked, and deletes on v9', async () => {
    const p = fakePlatform();
    p.on('POST', `${V}/v10/projects/prj_1/env?teamId=team_a`, { created: {}, failed: [] }, 201);
    p.on('POST', `${V}/v10/projects/prj_1/env?upsert=true&teamId=team_a`, { created: {}, failed: [] }, 201);
    p.on('DELETE', `${V}/v9/projects/prj_1/env/e1?teamId=team_a`, {});
    const c = vercelClient(p.fetchFn, 't', 'team_a');
    await c.createEnv('prj_1', { key: 'K', value: 'v', type: 'sensitive', target: ['preview', 'production'] }, false);
    await c.createEnv('prj_1', { key: 'K', value: 'v', type: 'plain', target: ['development'] }, true);
    await c.deleteEnv('prj_1', 'e1');
    expect(p.calls.map((x) => [x.method, x.url, x.body])).toEqual([
      ['POST', `${V}/v10/projects/prj_1/env?teamId=team_a`, { key: 'K', value: 'v', type: 'sensitive', target: ['preview', 'production'] }],
      ['POST', `${V}/v10/projects/prj_1/env?upsert=true&teamId=team_a`, { key: 'K', value: 'v', type: 'plain', target: ['development'] }],
      ['DELETE', `${V}/v9/projects/prj_1/env/e1?teamId=team_a`, undefined],
    ]);
  });

  it('treats a 201 with failed items as a failure', async () => {
    const p = fakePlatform();
    p.on('POST', `${V}/v10/projects/prj_1/env`, { created: [], failed: [{ error: { code: 'ENV_CONFLICT', message: 'conflicts with an existing variable', value: 'the-value' } }] }, 201);
    const err = await vercelClient(p.fetchFn, 't', '').createEnv('prj_1', { key: 'K', value: 'the-value', type: 'plain', target: ['production'] }, false).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PlatformError);
    expect((err as Error).message).toBe('Vercel 201: conflicts with an existing variable (ENV_CONFLICT)');
  });

  it('redeploys from the latest ready production deployment with forceNew', async () => {
    const p = fakePlatform();
    p.on('GET', `${V}/v7/deployments?projectId=prj_1&target=production&state=READY&limit=1&teamId=team_a`, { deployments: [{ uid: 'dpl_9', name: 'acme' }] });
    p.on('POST', `${V}/v13/deployments?forceNew=1&teamId=team_a`, { id: 'dpl_10' });
    expect(await vercelClient(p.fetchFn, 't', 'team_a').redeploy('prj_1', 'acme-portal')).toEqual({ deploymentId: 'dpl_10' });
    expect(p.calls[1]!.body).toEqual({ name: 'acme-portal', project: 'prj_1', deploymentId: 'dpl_9', target: 'production' });
  });

  it('refuses to redeploy with no ready production deployment', async () => {
    const p = fakePlatform();
    p.on('GET', `${V}/v7/deployments?projectId=prj_1&target=production&state=READY&limit=1`, { deployments: [] });
    await expect(vercelClient(p.fetchFn, 't', '').redeploy('prj_1', 'x')).rejects.toThrow('no ready production deployment to redeploy');
  });
});

describe('cloudflare client', () => {
  it('lists Workers and secret names with no query string and puts secret_text', async () => {
    const p = fakePlatform();
    p.on('GET', `${CF}/accounts/${ACCT}/workers/scripts`, { success: true, errors: [], result: [{ id: 'worker-1' }, { id: 'worker-2' }] });
    p.on('GET', `${CF}/accounts/${ACCT}/workers/scripts/worker-1/secrets`, { success: true, errors: [], result: [{ name: 'API_KEY', type: 'secret_text' }] });
    p.on('PUT', `${CF}/accounts/${ACCT}/workers/scripts/worker-1/secrets`, { success: true, errors: [], result: { name: 'API_KEY', type: 'secret_text' } });
    const c = cloudflareClient(p.fetchFn, 'cftok', ACCT);
    expect(await c.listTargets()).toEqual([{ id: 'worker-1', name: 'worker-1' }, { id: 'worker-2', name: 'worker-2' }]);
    expect(await c.listVars('worker-1')).toEqual([{ key: 'API_KEY', type: 'secret_text' }]);
    await c.putSecret('worker-1', 'API_KEY', 'v');
    expect(p.calls[2]).toMatchObject({ method: 'PUT', auth: 'Bearer cftok', body: { name: 'API_KEY', text: 'v', type: 'secret_text' } });
  });

  it('surfaces success:false on a 200 as an error', async () => {
    const p = fakePlatform();
    p.on('PUT', `${CF}/accounts/${ACCT}/workers/scripts/w/secrets`, { success: false, errors: [{ code: 10007, message: 'script not found' }], result: null });
    await expect(cloudflareClient(p.fetchFn, 't', ACCT).putSecret('w', 'K', 'v')).rejects.toThrow('Cloudflare 200: script not found (10007)');
  });
});

describe('platform safety', () => {
  it('rejects unsafe path segments with no fetch, and still accepts real id formats', async () => {
    const p = fakePlatform();
    const v = vercelClient(p.fetchFn, 't', 'team_a1B2');
    const cf = cloudflareClient(p.fetchFn, 't', ACCT);
    for (const bad of ['..', '.', '', 'a/b', 'evil.com/../x@y', 'a%2Fb']) {
      await expect(v.listVars(bad), bad).rejects.toThrow('bad path segment');
      await expect(v.deleteEnv('prj_1', bad), bad).rejects.toThrow('bad path segment');
      await expect(cf.putSecret(bad, 'K', 'v'), bad).rejects.toThrow('bad path segment');
    }
    expect(() => cloudflareClient(p.fetchFn, 't', '..').check()).toThrow('bad path segment');
    expect(p.calls).toHaveLength(0);
    p.on('GET', `${V}/v10/projects/prj_AbC123xyz/env?teamId=team_a1B2`, { envs: [] });
    p.on('DELETE', `${V}/v9/projects/prj_1/env/2ZyXwV9abcDEF?teamId=team_a1B2`, {});
    p.on('PUT', `${CF}/accounts/${ACCT}/workers/scripts/my-worker_2/secrets`, { success: true });
    await v.listVars('prj_AbC123xyz');
    await v.deleteEnv('prj_1', '2ZyXwV9abcDEF');
    await cf.putSecret('my-worker_2', 'K', 'v');
    expect(p.calls).toHaveLength(3);
  });

  it('rejects any host outside the allowlist', () => {
    expect(ALLOWED_HOSTS).toEqual(['api.vercel.com', 'api.cloudflare.com']);
    expect(() => assertAllowedUrl('https://api.vercel.com/v10/projects')).not.toThrow();
    for (const bad of ['https://evil.com/x', 'https://api.vercel.com.evil.com/x', 'https://user@evil.com/x', 'http://localhost/x', 'not a url']) {
      expect(() => assertAllowedUrl(bad), bad).toThrow();
    }
  });

  it('does not follow a redirect off the allowlist', async () => {
    const seen: RequestInit[] = [];
    const fetchFn = async (_url: string, init: RequestInit) => {
      seen.push(init);
      return new Response(null, { status: 302, headers: { Location: 'https://evil.com/steal' } });
    };
    await expect(vercelClient(fetchFn, 't', '').listTargets()).rejects.toThrow('Vercel 302: HTTP 302');
    expect(seen).toHaveLength(1);
    expect(seen[0]!.redirect).toBe('manual');
  });

  it('call() itself enforces the allowlist before fetching', async () => {
    let calls = 0;
    const fetchFn = async () => { calls++; return new Response('{}'); };
    await expect(call(fetchFn, 't', 'GET', 'https://evil.com/x')).rejects.toThrow('host not allowed');
    expect(calls).toBe(0);
  });

  it('refuses a redeploy response with no deployment id and treats an empty next token as the end', async () => {
    const p = fakePlatform();
    p.on('GET', `${V}/v7/deployments?projectId=p&target=production&state=READY&limit=1`, { deployments: [{ uid: 'd' }] });
    p.on('POST', `${V}/v13/deployments?forceNew=1`, {});
    await expect(vercelClient(p.fetchFn, 't', '').redeploy('p', 'n')).rejects.toBeInstanceOf(PlatformError);
    const q = fakePlatform();
    q.on('GET', `${V}/v10/projects?limit=100`, { projects: [{ id: 'a', name: 'a' }], pagination: { next: '' } });
    expect(await vercelClient(q.fetchFn, 't', '').listTargets()).toHaveLength(1);
    expect(q.calls).toHaveLength(1);
  });

  it('redacts an echoed token or value and omits empty code parens', async () => {
    const p = fakePlatform();
    p.on('POST', `${V}/v10/projects/p/env`, { error: { code: 'X', message: 'bad tok-secret and leaky-value' } }, 400);
    p.on('PUT', `${CF}/accounts/${ACCT}/workers/scripts/w/secrets`, { success: false, errors: [{ message: 'echo leaky-value tok-secret' }] }, 400);
    const e1 = await vercelClient(p.fetchFn, 'tok-secret', '').createEnv('p', { key: 'K', value: 'leaky-value', type: 'plain', target: ['production'] }, false).catch((e: Error) => e.message);
    const e2 = await cloudflareClient(p.fetchFn, 'tok-secret', ACCT).putSecret('w', 'K', 'leaky-value').catch((e: Error) => e.message);
    expect(e1).toBe('Vercel 400: bad [redacted] and [redacted] (X)');
    expect(e2).toBe('Cloudflare 400: echo [redacted] [redacted]');
  });

  it('error text never carries the value or the token', async () => {
    const p = fakePlatform();
    p.on('PUT', `${CF}/accounts/${ACCT}/workers/scripts/w/secrets`, { success: false, errors: [{ code: 1, message: 'bad' }], result: { name: 'K', text: 'leaky-value' } }, 400);
    p.on('POST', `${V}/v10/projects/p/env`, 'not json at all', 500);
    const e1 = await cloudflareClient(p.fetchFn, 'tok-secret', ACCT).putSecret('w', 'K', 'leaky-value').catch((e: Error) => e.message);
    const e2 = await vercelClient(p.fetchFn, 'tok-secret', '').createEnv('p', { key: 'K', value: 'leaky-value', type: 'plain', target: ['production'] }, false).catch((e: Error) => e.message);
    expect(e1).toBe('Cloudflare 400: bad (1)');
    expect(e2).toBe('Vercel 500: HTTP 500');
    for (const m of [e1, e2]) expect(m).not.toMatch(/leaky-value|tok-secret/);
  });
});

const KEY = 'test-plan-key-0123456789abcdefghij';
async function world(provider: 'vercel' | 'cloudflare' = 'vercel') {
  const kv = new MapKv();
  const mk = (await loadMasterKey(generateMasterKey()))!;
  let t = 1_000_000;
  const v = new VaultLogic(kv, { current: mk, all: [mk] }, () => t);
  const p = fakePlatform();
  const d = new DeployLogic(v, { fetchFn: p.fetchFn, planKey: KEY, now: () => t });
  const acct = provider === 'vercel' ? 'team_a' : ACCT;
  if (provider === 'vercel') p.on('GET', `${V}/v10/projects?limit=1&teamId=team_a`, { projects: [] });
  else p.on('GET', `${CF}/accounts/${ACCT}/workers/scripts`, { success: true, errors: [], result: [] });
  const { connection: c } = await d.addConnection({ provider, name: 'Acme Vercel', accountId: acct, token: 'tok', by: 'b' });
  await v.putSecret('personal', 'CLIENT_ID', 'cid-1', 'b', undefined, undefined, 'config');
  await v.putSecret('personal', 'CLIENT_SECRET', 'cs-1', 'b');
  const tick = () => (t += 1000);
  return { kv, v, d, p, c, tick, envUrl: `${V}/v10/projects/prj_1/env?teamId=team_a` };
}
const ok201 = { created: {}, failed: [] };
const writes = (p: ReturnType<typeof fakePlatform>) => p.calls.filter((x) => x.method !== 'GET').map((x) => [x.method, x.url, x.body]);
const link = (v: VaultLogic, connectionId: string, items: LinkItem[], targetName = 'acme-portal') =>
  v.saveLink({ connectionId, targetId: 'prj_1', targetName, by: 'b', items });

describe('planner', () => {
  it('builds the canonical form exactly', () => {
    expect(planCanonical('c', 't', [
      { varName: 'B', group: 'development', cls: 'new', handle: 'secret://p/B', version: 2, recreate: false, type: 'encrypted', existingIds: [] },
      { varName: 'A', group: 'preview,production', cls: 'replace', handle: 'secret://p/A', version: 1, recreate: true, type: 'sensitive', existingIds: ['e2', 'e1'] },
      { varName: 'M', group: '', cls: 'missing', handle: 'secret://p/M', version: 0, recreate: false, existingIds: [] },
    ])).toBe('deploy-plan|v2|["c","t",[["A","preview,production","replace","secret://p/A",1,1,"sensitive",["e1","e2"]],["B","development","new","secret://p/B",2,0,"encrypted",[]],["M","","missing","secret://p/M",0,0,"",[]]]]');
  });

  it('splits a Vercel secret into sensitive and encrypted groups and keeps config as one plain group', async () => {
    const { v, d, p, c, envUrl } = await world();
    await v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'b', items: [
      { handle: 'secret://personal/CLIENT_ID', varName: 'AZURE_CLIENT_ID', environments: ['production', 'preview', 'development'] },
      { handle: 'secret://personal/CLIENT_SECRET', varName: 'AZURE_CLIENT_SECRET', environments: ['production', 'preview', 'development'] },
    ] });
    p.on('GET', envUrl, { envs: [] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows.map((r) => [r.key, r.type, r.cls, r.ticked])).toEqual([
      ['AZURE_CLIENT_ID|development,preview,production', 'plain', 'new', true],
      ['AZURE_CLIENT_SECRET|preview,production', 'sensitive', 'new', true],
      ['AZURE_CLIENT_SECRET|development', 'encrypted', 'new', true],
    ]);
    expect(plan.rows[0]!.newValue).toBe('cid-1');
    expect(plan.rows[1]!.newValue).toBeUndefined();
    expect(plan.sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it('classifies by key plus target overlap and flags recreate', async () => {
    const { v, d, p, c, envUrl } = await world();
    await v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme', by: 'b', items: [
      { handle: 'secret://personal/CLIENT_SECRET', varName: 'S', environments: ['production', 'preview'] },
      { handle: 'secret://personal/CLIENT_ID', varName: 'C', environments: ['production'] },
    ] });
    p.on('GET', envUrl, { envs: [
      { id: 'e-dev', key: 'S', type: 'encrypted', target: ['development'] }, // no overlap: ignored
      { id: 'e-prod', key: 'S', type: 'plain', target: ['production', 'preview'], value: 'old' }, // overlap, wrong type
      { id: 'e-c', key: 'C', type: 'plain', target: ['production'], value: 'cid-0' }, // exact match
    ] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    const s = plan.rows.find((r) => r.varName === 'S')!;
    const cfg = plan.rows.find((r) => r.varName === 'C')!;
    expect(s).toMatchObject({ cls: 'replace', ticked: false, recreate: true, existingIds: ['e-prod'] });
    expect(s.oldValue).toBeUndefined();
    expect(cfg).toMatchObject({ cls: 'replace', ticked: false, recreate: false, existingIds: ['e-c'], oldValue: 'cid-0', newValue: 'cid-1' });
  });

  it('recreates when the target set differs even if the type matches, and tolerates unknown target strings', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: 'secret://personal/CLIENT_SECRET', varName: 'S', environments: ['production', 'preview'] }]);
    p.on('GET', envUrl, { envs: [{ id: 'e1', key: 'S', type: 'sensitive', target: ['production', 'preview', 'custom-env'] }] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]).toMatchObject({ recreate: true, existingIds: ['e1'], type: 'sensitive' });
  });

  it('marks up to date, update after a new version, and update on rollback to an older version', async () => {
    const { v, d, p, c, envUrl } = await world();
    const H = 'secret://personal/CLIENT_SECRET';
    await link(v, c.id, [{ handle: H, varName: 'S', environments: ['production', 'preview'] }]);
    p.on('GET', envUrl, { envs: [{ id: 'e1', key: 'S', type: 'sensitive', target: ['preview', 'production'] }] });
    const pushed = (version: number, at: number) => v.addPushRecord({ at, by: 'b', connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal',
      rows: [{ handle: H, version, kind: 'secret', varName: 'S', environments: ['preview', 'production'], action: version === 1 ? 'created' : 'updated' }] });
    const sRow = async (versions?: Record<string, number>) => (await d.reviewPush(c.id, 'prj_1', versions)).rows.find((r) => r.varName === 'S')!;
    await pushed(1, 1);
    expect(await sRow()).toMatchObject({ cls: 'uptodate', ticked: false, version: 1 });
    await v.putSecret('personal', 'CLIENT_SECRET', 'cs-2', 'b');
    expect(await sRow()).toMatchObject({ cls: 'update', ticked: true, version: 2, versions: [2, 1] });
    await pushed(2, 2);
    expect(await sRow({ [H]: 1 })).toMatchObject({ cls: 'update', ticked: true, version: 1 });
    await expect(d.reviewPush(c.id, 'prj_1', { [H]: 7 })).rejects.toThrow('secret://personal/CLIENT_SECRET has no version 7');
  });

  it('shows missing items without blocking the others', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: 'secret://personal/CLIENT_ID', varName: 'C' }, { handle: 'secret://personal/CLIENT_SECRET', varName: 'S' }]);
    await v.deleteSecret('personal', 'CLIENT_ID', 'b');
    p.on('GET', envUrl, { envs: [] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows.map((r) => [r.key, r.cls, r.ticked, r.kind])).toEqual([
      ['C|preview,production', 'missing', false, null],
      ['S|preview,production', 'new', true, 'secret'],
    ]);
    expect(plan.summary).toEqual({ new: 1, update: 0, replace: 0, uptodate: 0, missing: 1 });
  });

  it('uses one secret_text group on Cloudflare and sets the note', async () => {
    const { v, d, p, c } = await world('cloudflare');
    await v.saveLink({ connectionId: c.id, targetId: 'worker-1', targetName: 'worker-1', by: 'b', items: [{ handle: 'secret://personal/CLIENT_ID', varName: 'CLIENT_ID' }] });
    p.on('GET', `${CF}/accounts/${ACCT}/workers/scripts/worker-1/secrets`, { success: true, errors: [], result: [{ name: 'CLIENT_ID', type: 'secret_text' }] });
    const plan = await d.reviewPush(c.id, 'worker-1');
    expect(plan.rows).toHaveLength(1);
    expect(plan.rows[0]).toMatchObject({ key: 'CLIENT_ID|', group: '', type: 'secret_text', cls: 'replace', ticked: false, recreate: false, existingIds: [] });
    expect(plan.rows[0]!.newValue).toBeUndefined();
    expect(plan.cloudflareNote).toBe(true);
  });

  it('refuses to review while frozen', async () => {
    const { v, d, c } = await world();
    await link(v, c.id, [{ handle: 'secret://personal/CLIENT_ID', varName: 'C' }]);
    await v.setFrozen(true, 'b');
    await expect(d.reviewPush(c.id, 'prj_1')).rejects.toThrow('vault is frozen; unfreeze to push');
  });
});

describe('push', () => {
  const S = 'secret://personal/CLIENT_SECRET';
  const C = 'secret://personal/CLIENT_ID';
  const push = (d: DeployLogic, connectionId: string, ticked: string[], sig: string, versions: Record<string, number> = {}) =>
    d.pushTarget({ connectionId, targetId: 'prj_1', versions, ticked, sig, by: 'alice' });

  it('pushes ticked rows, records one row per variable and group, and audits without values', async () => {
    const { v, d, p, c, envUrl } = await world();
    const all: VercelEnv[] = ['production', 'preview', 'development'];
    await link(v, c.id, [{ handle: C, varName: 'AZURE_CLIENT_ID', environments: all }, { handle: S, varName: 'AZURE_CLIENT_SECRET', environments: all }]);
    p.on('GET', envUrl, { envs: [] });
    p.on('POST', envUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    const record = await push(d, c.id, plan.rows.map((r) => r.key), plan.sig);
    expect(writes(p)).toEqual([
      ['POST', envUrl, { key: 'AZURE_CLIENT_ID', value: 'cid-1', type: 'plain', target: ['development', 'preview', 'production'] }],
      ['POST', envUrl, { key: 'AZURE_CLIENT_SECRET', value: 'cs-1', type: 'sensitive', target: ['preview', 'production'] }],
      ['POST', envUrl, { key: 'AZURE_CLIENT_SECRET', value: 'cs-1', type: 'encrypted', target: ['development'] }],
    ]);
    expect(record.rows.map((r) => [r.handle, r.varName, r.environments, r.version, r.kind, r.action])).toEqual([
      [C, 'AZURE_CLIENT_ID', ['development', 'preview', 'production'], 1, 'config', 'created'],
      [S, 'AZURE_CLIENT_SECRET', ['preview', 'production'], 1, 'secret', 'created'],
      [S, 'AZURE_CLIENT_SECRET', ['development'], 1, 'secret', 'created'],
    ]);
    const audit = await v.listAudit();
    expect(audit.find((e) => e.event === 'push')).toMatchObject({ by: 'alice', connection: 'Acme Vercel', target: 'acme-portal', targetId: 'prj_1', pushId: record.id, created: 3, updated: 0, replaced: 0, failed: 0, handles: [C, S] });
    for (const s of [JSON.stringify(record), JSON.stringify(audit)]) {
      expect(s).not.toContain('cs-1');
      expect(s).not.toContain('cid-1'); // config values appear on the review page only
      expect(s).not.toContain('"tok"');
    }
    p.on('GET', envUrl, { envs: [
      { id: 'n1', key: 'AZURE_CLIENT_ID', type: 'plain', target: ['development', 'preview', 'production'], value: 'cid-1' },
      { id: 'n2', key: 'AZURE_CLIENT_SECRET', type: 'sensitive', target: ['preview', 'production'] },
      { id: 'n3', key: 'AZURE_CLIENT_SECRET', type: 'encrypted', target: ['development'] },
    ] });
    expect((await d.reviewPush(c.id, 'prj_1')).rows.map((r) => [r.cls, r.recreate])).toEqual([['uptodate', false], ['uptodate', false], ['uptodate', false]]);
  });

  it('pushes an item added as a secret over a trashed config item as sensitive, with no value on the review', async () => {
    const { v, d, p, c, envUrl } = await world();
    await v.deleteSecret('personal', 'CLIENT_ID', 'b');
    await v.putSecret('personal', 'CLIENT_ID', 'now-secret', 'b');
    await link(v, c.id, [{ handle: C, varName: 'C', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    p.on('POST', envUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]).toMatchObject({ kind: 'secret', type: 'sensitive' });
    expect(plan.rows[0]!.newValue).toBeUndefined();
    await push(d, c.id, ['C|production'], plan.sig);
    expect(writes(p)).toEqual([['POST', envUrl, { key: 'C', value: 'now-secret', type: 'sensitive', target: ['production'] }]]);
  });

  it('offers and pushes only config versions from the conversion on, refusing older ones without the value', async () => {
    const { v, d, p, c, envUrl } = await world();
    await v.putSecret('personal', 'FLAG', 'secret-era-value', 'b');
    await v.putSecret('personal', 'FLAG', 'converted-value', 'b');
    await v.convertToConfig('personal', 'FLAG', 'b');
    await v.putSecret('personal', 'FLAG', 'config-value', 'b');
    await link(v, c.id, [{ handle: 'secret://personal/FLAG', varName: 'FLAG', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]!.versions).toEqual([3, 2]);
    const err = await d.reviewPush(c.id, 'prj_1', { 'secret://personal/FLAG': 1 }).catch((e: unknown) => e);
    expect((err as Error).message).toBe('secret://personal/FLAG version 1 is from before it became config and cannot be pushed');
    await expect(push(d, c.id, ['FLAG|production'], plan.sig, { 'secret://personal/FLAG': 1 })).rejects.toThrow('cannot be pushed');
    expect(writes(p)).toEqual([]);
  });

  it('refuses a push when a matching record appears on the platform after review, and deletes nothing', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [{ id: 'e1', key: 'S', type: 'plain', target: ['production'], value: 'old' }] });
    p.on('DELETE', `${V}/v9/projects/prj_1/env/e1?teamId=team_a`, {});
    p.on('DELETE', `${V}/v9/projects/prj_1/env/e2?teamId=team_a`, {});
    p.on('POST', envUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]).toMatchObject({ cls: 'replace', recreate: true, type: 'sensitive', existingIds: ['e1'] });
    p.on('GET', envUrl, { envs: [
      { id: 'e1', key: 'S', type: 'plain', target: ['production'], value: 'old' },
      { id: 'e2', key: 'S', type: 'sensitive', target: ['production', 'preview'] },
    ] });
    await expect(push(d, c.id, ['S|production'], plan.sig)).rejects.toThrow('the target changed since you reviewed it, review again');
    expect(writes(p)).toEqual([]);
  });

  it('leaves branch-scoped and custom-environment records alone and notes them', async () => {
    const { v, d, p, c, envUrl } = await world();
    const upsertUrl = `${V}/v10/projects/prj_1/env?upsert=true&teamId=team_a`;
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['preview', 'production'] }]);
    p.on('GET', envUrl, { envs: [
      { id: 'e1', key: 'S', type: 'sensitive', target: ['preview', 'production'] },
      { id: 'eb', key: 'S', type: 'sensitive', target: ['preview'], gitBranch: 'feature-x' },
      { id: 'ec', key: 'S', type: 'sensitive', target: ['preview'], customEnvironmentIds: ['env_1'] },
    ] });
    p.on('POST', upsertUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]).toMatchObject({ cls: 'replace', recreate: false, existingIds: ['e1'], existingEnvs: ['preview', 'production'], branchScoped: true });
    await push(d, c.id, ['S|preview,production'], plan.sig);
    expect(writes(p)).toEqual([['POST', upsertUrl, { key: 'S', value: 'cs-1', type: 'sensitive', target: ['preview', 'production'] }]]);
  });

  it('refuses a push whose versions differ from the reviewed ones', async () => {
    const { v, d, p, c, envUrl } = await world();
    await v.putSecret('personal', 'CLIENT_SECRET', 'cs-2', 'b');
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    p.on('POST', envUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]).toMatchObject({ version: 2, versions: [2, 1] });
    await expect(push(d, c.id, ['S|production'], plan.sig, { [S]: 1 })).rejects.toThrow('the target changed since you reviewed it, review again');
    expect(writes(p)).toEqual([]);
  });

  it('refuses a stale review and writes nothing', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]).toMatchObject({ cls: 'new', ticked: true });
    p.on('GET', envUrl, { envs: [{ id: 'x', key: 'S', type: 'sensitive', target: ['production'] }] });
    await expect(push(d, c.id, ['S|production'], plan.sig)).rejects.toThrow('the target changed since you reviewed it, review again');
    expect(writes(p)).toEqual([]);
    expect((await v.listPushes(1)).total).toBe(0);
  });

  it('refuses a forged tick, a bad signature, and an empty tick list', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }, { handle: C, varName: 'C', environments: ['production'] }]);
    await v.deleteSecret('personal', 'CLIENT_ID', 'b');
    p.on('GET', envUrl, { envs: [] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    await expect(push(d, c.id, ['NOPE|production'], plan.sig)).rejects.toThrow('a ticked row is not on the page you reviewed, review again');
    await expect(push(d, c.id, ['C|production'], plan.sig)).rejects.toThrow('a ticked row is not on the page you reviewed, review again');
    await expect(push(d, c.id, ['S|production'], 'f'.repeat(64))).rejects.toThrow('the target changed since you reviewed it, review again');
    await expect(push(d, c.id, ['S|production'], 'zz')).rejects.toThrow('the target changed since you reviewed it, review again');
    await expect(push(d, c.id, [], plan.sig)).rejects.toThrow('tick at least one row to push');
    expect(writes(p)).toEqual([]);
  });

  it('pushes a replace row only when ticked from the signed page', async () => {
    const { v, d, p, c, envUrl } = await world();
    const upsertUrl = `${V}/v10/projects/prj_1/env?upsert=true&teamId=team_a`;
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['preview', 'production'] }, { handle: C, varName: 'C', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [{ id: 'e1', key: 'S', type: 'sensitive', target: ['preview', 'production'] }] });
    p.on('POST', envUrl, ok201, 201);
    p.on('POST', upsertUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows.find((r) => r.varName === 'S')).toMatchObject({ cls: 'replace', ticked: false, recreate: false, existingIds: ['e1'] });
    await push(d, c.id, ['C|production'], plan.sig);
    expect(writes(p).map((w) => (w[2] as { key: string }).key)).toEqual(['C']);
    const again = await d.reviewPush(c.id, 'prj_1');
    const rec = await push(d, c.id, ['S|preview,production'], again.sig);
    expect(writes(p).at(-1)).toEqual(['POST', upsertUrl, { key: 'S', value: 'cs-1', type: 'sensitive', target: ['preview', 'production'] }]);
    expect(rec.rows.map((r) => [r.varName, r.action])).toEqual([['S', 'replaced']]);
  });

  it('deletes shared records once, before any create, and refuses a half-ticked shared record', async () => {
    const { v, d, p, c, envUrl } = await world();
    const del = `${V}/v9/projects/prj_1/env/e-all?teamId=team_a`;
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production', 'preview', 'development'] }]);
    p.on('GET', envUrl, { envs: [{ id: 'e-all', key: 'S', type: 'plain', target: ['production', 'preview', 'development'], value: 'old' }] });
    p.on('DELETE', del, {});
    p.on('POST', envUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows.map((r) => [r.key, r.cls, r.recreate, r.existingIds])).toEqual([
      ['S|preview,production', 'replace', true, ['e-all']],
      ['S|development', 'replace', true, ['e-all']],
    ]);
    await expect(push(d, c.id, ['S|preview,production'], plan.sig)).rejects.toThrow('S: tick every environment row for it, they share one Vercel variable');
    expect(writes(p)).toEqual([]);
    const rec = await push(d, c.id, ['S|preview,production', 'S|development'], plan.sig);
    expect(writes(p)).toEqual([
      ['DELETE', del, undefined],
      ['POST', envUrl, { key: 'S', value: 'cs-1', type: 'sensitive', target: ['preview', 'production'] }],
      ['POST', envUrl, { key: 'S', value: 'cs-1', type: 'encrypted', target: ['development'] }],
    ]);
    expect(rec.rows.map((r) => r.action)).toEqual(['replaced', 'replaced']);
  });

  it('skips create for rows whose delete failed and records the redacted error', async () => {
    const { v, d, p, c, envUrl } = await world();
    const del = `${V}/v9/projects/prj_1/env/e1?teamId=team_a`;
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }, { handle: C, varName: 'C', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [{ id: 'e1', key: 'S', type: 'plain', target: ['production'], value: 'old' }] });
    p.on('DELETE', del, { error: { code: 'forbidden', message: 'nope' } }, 403);
    p.on('POST', envUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    const rec = await push(d, c.id, ['S|production', 'C|production'], plan.sig);
    expect(writes(p).map((w) => w[0])).toEqual(['DELETE', 'POST']);
    expect(rec.rows.map((r) => [r.varName, r.action, r.error])).toEqual([
      ['S', 'failed', 'Vercel 403: nope (forbidden)'],
      ['C', 'created', undefined],
    ]);
  });

  it('says the variable is gone when a recreate deleted it and the create then failed', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [{ id: 'e1', key: 'S', type: 'plain', target: ['production'], value: 'old' }] });
    p.on('DELETE', `${V}/v9/projects/prj_1/env/e1?teamId=team_a`, {});
    p.on('POST', envUrl, { error: { code: 'bad_request', message: 'nope' } }, 400);
    const plan = await d.reviewPush(c.id, 'prj_1');
    const rec = await push(d, c.id, ['S|production'], plan.sig);
    expect(writes(p).map((w) => w[0])).toEqual(['DELETE', 'POST']);
    expect(rec.rows[0]).toMatchObject({ action: 'failed', error: 'removed from production, not recreated: Vercel 400: nope (bad_request)' });
  });

  it('says some environments were already removed when only some deletes of a recreate failed', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['preview', 'production'] }]);
    p.on('GET', envUrl, { envs: [
      { id: 'e1', key: 'S', type: 'sensitive', target: ['production'] },
      { id: 'e2', key: 'S', type: 'sensitive', target: ['preview'] },
    ] });
    p.on('DELETE', `${V}/v9/projects/prj_1/env/e1?teamId=team_a`, {});
    p.on('DELETE', `${V}/v9/projects/prj_1/env/e2?teamId=team_a`, { error: { code: 'forbidden', message: 'nope' } }, 403);
    const plan = await d.reviewPush(c.id, 'prj_1');
    expect(plan.rows[0]).toMatchObject({ recreate: true, existingIds: ['e1', 'e2'] });
    const rec = await push(d, c.id, ['S|preview,production'], plan.sig);
    expect(writes(p).map((w) => w[0])).toEqual(['DELETE', 'DELETE']);
    expect(rec.rows[0]).toMatchObject({ action: 'failed', error: 'some environments were already removed: Vercel 403: nope (forbidden)' });
  });

  it('redacts the value from a failed row and keeps going', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }, { handle: C, varName: 'C', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    p.reply('POST', envUrl, (body) => ((body as { key: string }).key === 'S'
      ? { status: 400, json: { error: { code: 'bad_request', message: 'value cs-1 is invalid' } } }
      : { status: 201, json: ok201 }));
    const plan = await d.reviewPush(c.id, 'prj_1');
    const rec = await push(d, c.id, ['S|production', 'C|production'], plan.sig);
    // the platform client already redacts the echoed value as [redacted]; deploy.ts redacts again as a backstop
    expect(rec.rows.map((r) => [r.varName, r.action, r.error])).toEqual([
      ['S', 'failed', 'Vercel 400: value [redacted] is invalid (bad_request)'],
      ['C', 'created', undefined],
    ]);
    const audit = await v.listAudit();
    expect(audit.find((e) => e.event === 'push')).toMatchObject({ created: 1, failed: 1 });
    for (const s of [JSON.stringify(rec), JSON.stringify(audit)]) expect(s).not.toContain('cs-1');
  });

  it('records a fixed string for a non-platform failure', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    // no POST route: the fake fetch throws an Error that echoes the URL, which must not be recorded
    const rec = await push(d, c.id, ['S|production'], plan.sig);
    expect(rec.rows[0]).toMatchObject({ action: 'failed', error: 'request failed' });
  });

  it('refuses while frozen', async () => {
    const { v, d, p, c, envUrl } = await world();
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    const plan = await d.reviewPush(c.id, 'prj_1');
    await v.setFrozen(true, 'b');
    await expect(push(d, c.id, ['S|production'], plan.sig)).rejects.toThrow('vault is frozen; unfreeze to push');
    expect(writes(p)).toEqual([]);
  });

  it('records a failing connection check but still saves the connection', async () => {
    const mk = (await loadMasterKey(generateMasterKey()))!;
    const v = new VaultLogic(new MapKv(), { current: mk, all: [mk] });
    const p = fakePlatform();
    const d = new DeployLogic(v, { fetchFn: p.fetchFn, planKey: KEY });
    p.on('GET', `${V}/v10/projects?limit=1`, { error: { code: 'forbidden', message: 'Not authorized' } }, 403);
    const r = await d.addConnection({ provider: 'vercel', name: 'Bad', accountId: '', token: 'bad-tok', by: 'b' });
    expect(r.error).toBe('Vercel 403: Not authorized (forbidden)');
    expect(await v.getConnection(r.connection.id)).toMatchObject({ lastCheckOk: false, lastCheckError: 'Vercel 403: Not authorized (forbidden)' });
    expect(p.calls[0]!.auth).toBe('Bearer bad-tok');
  });

  it('redeploys Vercel targets onto the push record and refuses Cloudflare', async () => {
    const { v, d, p, c, envUrl } = await world();
    const v8 = `${V}/v13/deployments?forceNew=1&teamId=team_a`;
    await link(v, c.id, [{ handle: S, varName: 'S', environments: ['production'] }]);
    p.on('GET', envUrl, { envs: [] });
    p.on('POST', envUrl, ok201, 201);
    const plan = await d.reviewPush(c.id, 'prj_1');
    const rec = await push(d, c.id, ['S|production'], plan.sig);
    p.on('GET', `${V}/v7/deployments?projectId=prj_1&target=production&state=READY&limit=1&teamId=team_a`, { deployments: [{ uid: 'dpl_9', name: 'acme-portal' }] });
    p.on('POST', v8, { id: 'dpl_10' });
    expect(await d.redeployTarget(c.id, 'prj_1', rec.id, 'alice')).toMatchObject({ ok: true, deploymentId: 'dpl_10' });
    expect(p.calls.at(-1)!.body).toEqual({ name: 'acme-portal', project: 'prj_1', deploymentId: 'dpl_9', target: 'production' });
    expect((await v.listPushes(1)).records[0]!.redeploy).toMatchObject({ ok: true, deploymentId: 'dpl_10' });
    expect((await v.listAudit()).some((e) => e.event === 'redeploy' && e.ok === true && e.deploymentId === 'dpl_10')).toBe(true);
    p.on('POST', v8, { error: { code: 'internal_server_error', message: 'boom' } }, 500);
    expect(await d.redeployTarget(c.id, 'prj_1', undefined, 'alice')).toMatchObject({ ok: false, error: 'Vercel 500: boom (internal_server_error)' });
    const cf = await world('cloudflare');
    await cf.v.saveLink({ connectionId: cf.c.id, targetId: 'worker-1', targetName: 'worker-1', by: 'b', items: [] });
    await expect(cf.d.redeployTarget(cf.c.id, 'worker-1', undefined, 'alice')).rejects.toThrow('redeploy is for Vercel projects; each Worker secret change already deployed a new version');
  });
});

describe('durable object surface', () => {
  it('never exposes the token or raw version reads over RPC', async () => {
    const src = readFileSync(join(__dirname, '..', 'src', 'vault-do.ts'), 'utf8');
    for (const name of ['connectionToken', 'readVersion', 'recordConnectionCheck', 'addPushRecord', 'setPushRedeploy', 'lastPushed']) expect(src).not.toMatch(new RegExp(`\\b${name}\\s*\\(`));
    for (const name of ['reviewPush', 'pushTarget', 'redeployTarget', 'addConnection', 'listConnections', 'saveLink', 'linkSummaries', 'listPushes', 'convertToConfig', 'configValues']) expect(src).toMatch(new RegExp(`async ${name}\\(`));
    // type-level: these keys must not exist on VaultApi
    const noToken: 'connectionToken' extends keyof VaultApi ? never : true = true;
    const noRead: 'readVersion' extends keyof VaultApi ? never : true = true;
    expect([noToken, noRead]).toEqual([true, true]);
    const { api } = await makeVault();
    for (const name of ['connectionToken', 'readVersion', 'recordConnectionCheck', 'addPushRecord', 'setPushRedeploy', 'lastPushed']) {
      expect((api as unknown as Record<string, unknown>)[name]).toBeUndefined();
      expect(name in api).toBe(false);
    }
  });

  it('the test mirror routes deploy calls through DeployLogic with the injected fetch', async () => {
    const p = fakePlatform();
    p.on('GET', 'https://api.vercel.com/v10/projects?limit=1', { projects: [] });
    const { api } = await makeVault({ fetchFn: p.fetchFn });
    const r = await api.addConnection({ provider: 'vercel', name: 'Mine', accountId: '', token: 't', by: 'b' });
    expect(r.error).toBeUndefined();
    expect(r.connection.name).toBe('Mine');
    expect(p.calls).toHaveLength(1);
  });

  it('refuses to build DeployLogic without a plan key', async () => {
    const kv = new MapKv();
    const mk = (await loadMasterKey(generateMasterKey()))!;
    const v = new VaultLogic(kv, { current: mk, all: [mk] });
    expect(() => new DeployLogic(v, { fetchFn: async () => new Response('{}'), planKey: 'x'.repeat(31) })).toThrow(/COOKIE_ENCRYPTION_KEY/);
  });
});
