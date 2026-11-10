import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import { registerAdminRoutes, type OAuthApi } from '../src/admin';
import { registerApiRoutes } from '../src/api';
import { sha256Hex } from '../src/crypto';
import { AuthHandler } from '../src/auth-handler';
import { addApprovedClient } from '../src/workers-oauth-utils';
import { redirectAllowed, registrationDecision, sessionKeyProblem, type Env } from '../src/env';
import type { Grants } from '../src/grants';
import { csrfToken, hmacHex, limitText, registerWebRoutes, signSession, type Session } from '../src/web';
import { fakeKv, fakePlatform, fakeR2, makeVault } from './helpers';

const KEY = 'test-cookie-key-0123456789abcdef';

let vault: Awaited<ReturnType<typeof makeVault>>;
let platform: ReturnType<typeof fakePlatform>;
let r2: ReturnType<typeof fakeR2>;
let app: Hono<{ Bindings: Env }>;
let env: Env;
const me: Session = { githubId: '42', login: 'alice', exp: Math.floor(Date.now() / 1000) + 3600 };
let cookie: string;

beforeEach(async () => {
  platform = fakePlatform();
  vault = await makeVault({ fetchFn: platform.fetchFn, planKey: KEY });
  r2 = fakeR2();
  env = { COOKIE_ENCRYPTION_KEY: KEY, ALLOWED_GITHUB_IDS: '42', OAUTH_KV: fakeKv(), BACKUPS: r2 } as unknown as Env;
  app = new Hono<{ Bindings: Env }>();
  registerWebRoutes(app, { grants: () => vault.api as unknown as Grants });
  registerAdminRoutes(app, { vault: () => vault.api });
  registerApiRoutes(app, { vault: () => vault.api });
  cookie = `__Host-sb_session=${await signSession(KEY, me)}`;
});

const csrf = (purpose = 'admin') => csrfToken(KEY, me, purpose);
const form = (o: Record<string, string | string[]>) => {
  const f = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) for (const x of [v].flat()) f.append(k, x);
  return f;
};
const postForm = async (path: string, o: Record<string, string | string[]>, c = cookie) =>
  app.request(path, { method: 'POST', headers: { Cookie: c, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form(o) }, env);
const getPage = (path: string, c = cookie) => app.request(path, { headers: { Cookie: c } }, env);

describe('sign-in and session', () => {
  it('redirects to GitHub sign-in without a session, or with a forged or non-allowlisted one', async () => {
    for (const c of ['', '__Host-sb_session=abc.def', `__Host-sb_session=${await signSession(KEY, { ...me, githubId: '7' })}`, `__Host-sb_session=${await signSession('other-key-0123456789abcdef0123456789', me)}`]) {
      const r = await getPage('/vault', c);
      expect(r.status).toBe(302);
      expect(r.headers.get('location')).toContain('/login?next=%2Fvault');
    }
  });

  it('expired sessions are rejected', async () => {
    const old = `__Host-sb_session=${await signSession(KEY, { ...me, exp: 1 })}`;
    expect((await getPage('/vault', old)).status).toBe(302);
  });

  it('pages send anti-framing and CSP headers', async () => {
    const r = await getPage('/vault');
    expect(r.status).toBe(200);
    expect(r.headers.get('x-frame-options')).toBe('DENY');
    expect(r.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
  });

  it('login only redirects back to local paths, and writes nothing to KV', async () => {
    const r = await app.request('/login?next=https://evil.io', {}, env);
    expect(r.headers.get('location')).toContain('github.com/login/oauth/authorize');
    expect(((env.OAUTH_KV as unknown) as ReturnType<typeof fakeKv>).writes).toEqual([]);
    const { cb } = await signIn(r);
    expect((await cb()).headers.get('location')).toBe('/approvals');
  });

  /** Follows /login's redirect: the state GitHub would echo back, and the callback with a chosen cookie. */
  const signIn = async (login: Response) => {
    const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!;
    const gh = { github: async () => ({ id: 42, login: 'alice' }) };
    const a = new Hono<{ Bindings: Env }>();
    registerWebRoutes(a, { grants: () => vault.api as unknown as Grants, ...gh });
    const cb = (c = cookie, s = state) => a.request(`/callback/web?code=abc&state=${s}`, { headers: { Cookie: c } }, env);
    return { state, cookie, cb };
  };

  it('rejects a tampered, expired or mismatched sign-in cookie', async () => {
    const { cookie, cb } = await signIn(await app.request('/login', {}, env));
    const [payload = '', sig = ''] = cookie.split('=')[1]!.split('.');
    const forged = btoa(JSON.stringify({ ...JSON.parse(atob(payload)), next: '/settings' })).replace(/=+$/, '');
    expect((await cb(`__Host-sb_login=${forged}.${sig}`)).status).toBe(400);
    const old = btoa(JSON.stringify({ state: 's1', next: '/vault', exp: 1 })).replace(/=+$/, '');
    expect((await cb(`__Host-sb_login=${old}.${await hmacHex(KEY, `weblogin:${old}`)}`, 's1')).status).toBe(400);
    expect((await cb(cookie, 'other-state')).status).toBe(400);
    expect((await cb(cookie)).status).toBe(302);
  });
});

describe('vault pages', () => {
  it('adds, replaces, and never shows values', async () => {
    expect((await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'GITHUB_TOKEN', value: 'ghp_first_value' })).status).toBe(303);
    expect((await postForm('/vault/s/personal/GITHUB_TOKEN/replace', { csrf: await csrf(), value: 'ghp_second_value' })).status).toBe(303);
    for (const p of ['/vault', '/vault/s/personal/GITHUB_TOKEN', '/audit', '/settings']) {
      const html = await (await getPage(p)).text();
      expect(html).not.toContain('ghp_first_value');
      expect(html).not.toContain('ghp_second_value');
    }
    expect((await vault.api.loadTier('personal')).get('GITHUB_TOKEN')).toBe('ghp_second_value');
    const detail = await (await getPage('/vault/s/personal/GITHUB_TOKEN')).text();
    expect(detail).toContain('v2');
    expect(detail).toContain('Make current');
  });

  it('creates a login, edits it, reveals it once with an audit entry, and never shows the password elsewhere', async () => {
    const add = (o: Record<string, string>) => postForm('/vault/add-login', { tier: 'personal', name: 'PORTAL', username: 'agent@example.com', password: 'pw-first-123', url: 'https://portal.example.com/login', notes: 'MFA off', ...o });
    expect((await add({ csrf: await csrf() })).status).toBe(303);
    expect(await vault.api.getMeta('personal', 'PORTAL')).toMatchObject({ kind: 'login', login: { username: 'agent@example.com', url: 'https://portal.example.com/login', notes: 'MFA off' } });
    expect(await (await getPage('/vault')).text()).toContain('<span class="tag">login</span>');
    const detail = await (await getPage('/vault/s/personal/PORTAL')).text();
    expect(detail).toContain('agent@example.com');
    expect(detail).toContain('href="https://portal.example.com/login"');
    expect(detail).toContain('Agents approved to reveal this login can see the password too.');
    for (const p of ['/vault', '/vault/s/personal/PORTAL', '/audit']) expect(await (await getPage(p)).text()).not.toContain('pw-first-123');

    expect((await postForm('/vault/s/personal/PORTAL/reveal', { csrf: 'nope' })).status).toBe(403);
    const shown = await postForm('/vault/s/personal/PORTAL/reveal', { csrf: await csrf() });
    expect(shown.status).toBe(200);
    const shownHtml = await shown.text();
    expect(shownHtml).toContain('<a href="/vault/s/personal/PORTAL">Hide password</a>');
    expect(shownHtml).not.toContain('Leave or reload');
    expect(shownHtml).toContain('<pre class="reveal" aria-label="Revealed password">pw-first-123</pre>');
    expect(await (await getPage('/vault/s/personal/PORTAL')).text()).not.toContain('pw-first-123');
    const audit = await vault.api.listAudit();
    expect(audit.some((e) => e.event === 'admin_reveal' && e.handle === 'secret://personal/PORTAL' && e.by === 'alice')).toBe(true);
    expect(JSON.stringify(audit)).not.toContain('pw-first-123');
    expect(await (await getPage('/audit')).text()).toContain('<code>admin_reveal</code> <span class="tag warn">reveal</span>');

    expect((await postForm('/vault/s/personal/PORTAL/login', { csrf: await csrf(), username: 'agent2@example.com', url: '', notes: '' })).status).toBe(303);
    expect((await vault.api.getMeta('personal', 'PORTAL'))).toMatchObject({ current: 1, login: { username: 'agent2@example.com' } });
    await postForm('/vault/s/personal/PORTAL/replace', { csrf: await csrf(), value: 'pw-second-456' });
    expect((await vault.api.getMeta('personal', 'PORTAL'))).toMatchObject({ current: 2, login: { username: 'agent2@example.com' } });

    expect((await add({ csrf: await csrf(), name: 'LONG', username: 'u'.repeat(257) })).status).toBe(400);
    expect((await add({ csrf: await csrf(), name: 'JS', url: 'javascript:alert(1)' })).status).toBe(400);
    expect((await add({ csrf: await csrf() })).status).toBe(400);
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'KEY', value: 'api-key-value' });
    const refused = await postForm('/vault/s/personal/KEY/reveal', { csrf: await csrf() });
    expect(refused.status).toBe(400);
    expect(await refused.text()).not.toContain('api-key-value');
  });

  it('detail page and move warning list only repos with a live approval', async () => {
    await vault.api.putSecret('personal', 'PORTAL', 'pw-9', 'alice', undefined, { username: 'agent@example.com' });
    const r1 = await vault.api.createRequest({ repo: 'acme/spent', reason: 'sign in', items: [{ handle: 'secret://personal/PORTAL', reveal: true }], requestedBy: 'alice' });
    const spent = await vault.api.approve(r1.id, [0], 'alice', { 0: { uses: 1 } });
    await vault.api.consume('acme/spent', spent.rules[0]!.id!);
    const r2 = await vault.api.createRequest({ repo: 'acme/active', reason: 'sign in', items: [{ handle: 'secret://personal/PORTAL', reveal: true }], requestedBy: 'alice' });
    await vault.api.approve(r2.id, [0], 'alice', { 0: { uses: 5 } });
    const html = await (await getPage('/vault/s/personal/PORTAL')).text();
    expect(html).toContain('acme/active');
    expect(html).not.toContain('acme/spent');
  });

  it('refuses to silently overwrite via Add', async () => {
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'A', value: 'one' });
    const r = await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'A', value: 'two' });
    expect(r.status).toBe(400);
    expect(await r.text()).toContain('already exists');
  });

  it('requires CSRF on every POST', async () => {
    for (const p of ['/vault/add', '/settings/freeze', '/machines/create', '/backups/run']) {
      const r = await postForm(p, { csrf: 'nope', tier: 'personal', name: 'A', value: 'x', frozen: '1', name2: 'm' });
      expect(r.status, p).toBe(403);
    }
    expect(await vault.api.isFrozen()).toBe(false);
  });

  it('trash, restore, purge', async () => {
    await postForm('/vault/add', { csrf: await csrf(), tier: 'client-work', name: 'X', value: 'v' });
    await postForm('/vault/s/client-work/X/delete', { csrf: await csrf() });
    expect(await (await getPage('/vault/trash')).text()).toContain('X');
    await postForm('/vault/s/client-work/X/undelete', { csrf: await csrf() });
    expect((await vault.api.loadTier('client-work')).get('X')).toBe('v');
    await postForm('/vault/s/client-work/X/delete', { csrf: await csrf() });
    await postForm('/vault/s/client-work/X/purge', { csrf: await csrf() });
    expect(await vault.api.getMeta('client-work', 'X')).toBeNull();
  });
});

describe('approval pages', () => {
  it('formats remaining time and uses', () => {
    const now = 1_000_000;
    expect(limitText({ expiresAt: now + 3 * 86_400_000 + 5 }, now)).toBe('expires in 3 d');
    expect(limitText({ expiresAt: now + 5 * 3_600_000, usesLeft: 2 }, now)).toBe('expires in 5 h · 2 uses left');
    expect(limitText({ expiresAt: now + 90_000 }, now)).toBe('expires in 2 min');
    expect(limitText({ usesLeft: 1 }, now)).toBe('1 use left');
    expect(limitText({}, now)).toBe('');
    expect(limitText({ expiresAt: now - 1, usesLeft: 2 }, now)).toBe('');
  });

  it('applies expiry and uses from the form, with defaults per kind', async () => {
    await vault.api.putSecret('personal', 'PORTAL', 'pw-9', 'alice', undefined, { username: 'agent@example.com' });
    await vault.api.putSecret('production', 'BANK', 'pw-bank', 'alice', undefined, { username: 'ops@example.com' });
    await vault.api.putSecret('production', 'KEY', 'k-1', 'alice');
    await vault.api.createRequest({ repo: 'acme/app', reason: 'sign in', items: [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }, { handle: 'secret://personal/B', hosts: ['api.example.com'] }, { handle: 'secret://personal/PORTAL', reveal: true }, { handle: 'secret://production/BANK', reveal: true }, { handle: 'secret://production/KEY', hosts: ['api.example.com'], methods: ['GET'] }], requestedBy: 'alice' });
    const html = await (await getPage('/approve/req1')).text();
    expect(html).toMatch(/name="expiry_0">(?:(?!<select)[\s\S])*?<option value="never" selected>/);
    expect(html).toMatch(/name="expiry_2">(?:(?!<select)[\s\S])*?<option value="7d" selected>/);
    // Production items (fetch or reveal) default to 7 days; a production fetch keeps no use limit.
    expect(html).toMatch(/name="expiry_3">(?:(?!<select)[\s\S])*?<option value="7d" selected>/);
    expect(html).toMatch(/name="expiry_4">(?:(?!<select)[\s\S])*?<option value="7d" selected>/);
    expect(html).not.toMatch(/name="uses_4"[^>]*value=/);
    expect(html).toContain('name="uses_2"');
    expect(html).toContain('<span class="tag warn">reveal</span>');
    // Production reveals start at one use and say the risk once; other items have no use limit by default.
    expect(html).toMatch(/name="uses_3"[^>]*value="1"/);
    expect(html).not.toMatch(/name="uses_2"[^>]*value=/);
    expect(html).toMatch(/name="item" value="3">/);
    expect(html).toContain('Ticked when this page opened: 3 of 5.</strong> 1 reveal, 0 production.');
    expect(html).not.toContain('hosts, any path');
    expect(html).toContain('The agent will see this password once approved.');
    expect(html).toMatch(/name="item" value="2" checked/);
    expect(html).not.toContain('pw-9');
    expect(html).not.toContain('pw-bank');
    const before = Date.now();
    const ok = await postForm('/approve/req1', { csrf: await csrf('approve:req1'), action: 'approve', item: ['0', '1', '2', '4'], expiry_0: '1h', uses_0: '3', uses_1: '' });
    expect(ok.status).toBe(200);
    const rules = (await vault.api.getGrant('acme/app'))!.rules;
    expect(rules[0]!.usesLeft).toBe(3);
    expect(rules[0]!.expiresAt).toBeGreaterThanOrEqual(before + 3_600_000);
    expect(rules[0]!.expiresAt).toBeLessThanOrEqual(Date.now() + 3_600_000);
    expect(rules[1]!.expiresAt).toBeUndefined();
    expect(rules[1]!.usesLeft).toBeUndefined();
    expect(rules[2]).toMatchObject({ action: 'reveal' });
    expect(rules[2]!.expiresAt).toBeGreaterThanOrEqual(before + 604_800_000);
    // An absent expiry_4 on a production fetch falls back to 7 days, matching the form default.
    expect(rules[3]!.expiresAt).toBeGreaterThanOrEqual(before + 604_800_000);
  });

  it('refuses tampered limits and grants nothing', async () => {
    await vault.api.createRequest({ repo: 'acme/app', reason: 'r', items: [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }], requestedBy: 'alice' });
    for (const bad of <Array<Record<string, string>>>[{ expiry_0: 'forever' }, { expiry_0: 'constructor' }, { uses_0: '0' }, { uses_0: '-1' }, { uses_0: '1.5' }, { uses_0: 'abc' }, { uses_0: '1001' }]) {
      const r = await postForm('/approve/req1', { csrf: await csrf('approve:req1'), action: 'approve', item: '0', ...bad });
      expect(r.status, JSON.stringify(bad)).toBe(400);
    }
    expect(await vault.api.getGrant('acme/app')).toBeNull();
  });

  it('shows remaining uses and tags expired or used-up approvals, keeping revoke', async () => {
    await vault.api.createRequest({ repo: 'acme/app', reason: 'r', items: [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }, { handle: 'secret://personal/B', hosts: ['api.example.com'] }], requestedBy: 'alice' });
    const grant = await vault.api.approve('req1', [0, 1], 'alice', { 0: { uses: 2 }, 1: { ttlMs: 1 } });
    await new Promise((r) => setTimeout(r, 5));
    let html = await (await getPage('/approvals')).text();
    expect(html).toContain('2 uses left');
    expect(html).toContain('<span class="tag muted">expired</span>');
    expect(html).toContain('<span class="c-open">Revoke<span class="sr"> secret://personal/B for acme/app</span></span>');
    await vault.api.consume('acme/app', grant.rules[0]!.id!);
    await vault.api.consume('acme/app', grant.rules[0]!.id!);
    html = await (await getPage('/approvals')).text();
    expect(html).toContain('<span class="tag muted">used up</span>');
  });

  it('approves a reveal request for a login with limits through the vault surface', async () => {
    await vault.api.putSecret('personal', 'PORTAL', 'pw-9', 'alice', undefined, { username: 'agent@example.com' });
    await vault.api.putSecret('personal', 'KEY', 'k', 'alice');
    await expect(vault.api.createRequest({ repo: 'acme/app', reason: 'r', items: [{ handle: 'secret://personal/KEY', reveal: true }], requestedBy: 'alice' })).rejects.toThrow(/not a login/);
    await vault.api.createRequest({ repo: 'acme/app', reason: 'sign in', items: [{ handle: 'secret://personal/PORTAL', reveal: true }], requestedBy: 'alice' });
    const grant = await vault.api.approve('req1', [0], 'alice', { 0: { uses: 2 } });
    expect(grant.rules[0]).toMatchObject({ action: 'reveal', usesLeft: 2 });
    expect(await vault.api.consume('acme/app', grant.rules[0]!.id!)).toEqual({ ok: true, usesLeft: 1 });
    expect(await vault.api.loginInfo('personal', 'PORTAL')).toEqual({ username: 'agent@example.com' });
    expect(await vault.api.readSecret('personal', 'PORTAL')).toBe('pw-9');
  });

  it('escapes agent-written text and approves only ticked items', async () => {
    await vault.api.createRequest({
      repo: 'acme/app',
      reason: '<script>alert(1)</script> sync',
      items: [
        { handle: 'secret://personal/A', hosts: ['api.github.com'] },
        { handle: 'secret://production/B', hosts: ['x.supabase.co'], methods: ['GET'] },
      ],
      requestedBy: 'alice',
    });
    const html = await (await getPage('/approve/req1')).text();
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('production');

    const bad = await postForm('/approve/req1', { csrf: await csrf('approve:other'), action: 'approve', item: '0' });
    expect(bad.status).toBe(403);
    const ok = await postForm('/approve/req1', { csrf: await csrf('approve:req1'), action: 'approve', item: '0' });
    expect(ok.status).toBe(200);
    expect((await vault.api.getGrant('acme/app'))!.rules.map((r) => r.secrets[0])).toEqual(['A']);

    const list = await (await getPage('/approvals')).text();
    expect(list).toContain('acme/app');
    await postForm('/approvals/revoke', { csrf: await csrf('revoke'), repo: 'acme/app' });
    expect(await vault.api.getGrant('acme/app')).toBeNull();
  });
});

describe('machines and API', () => {
  async function newToken(tiers: string[], canImport = false) {
    const html = await (await postForm('/machines/create', { csrf: await csrf(), name: 'desktop', tier: tiers, ...(canImport ? { canImport: '1' } : {}) })).text();
    return /class="tok">([^<]+)</.exec(html)![1]!;
  }
  const api = (path: string, token: string, init: RequestInit = {}) =>
    app.request(path, { ...init, headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) } }, env);

  it('serves a tier only to a token scoped to it; freeze and revoke cut it off', async () => {
    await vault.api.putSecret('personal', 'A', 'value-a', 'b');
    await vault.api.putSecret('production', 'P', 'value-p', 'b');
    const token = await newToken(['personal']);
    expect(await (await getPage('/machines')).text()).not.toContain(token.split('.')[3]);

    const ok = await api('/api/v1/secrets?tier=personal', token);
    expect(await ok.json()).toEqual({ tier: 'personal', secrets: { A: 'value-a' } });
    expect((await api('/api/v1/secrets?tier=production', token)).status).toBe(403);
    expect((await api('/api/v1/secrets?tier=personal', 'sbv.x.y.z')).status).toBe(401);

    await vault.api.setFrozen(true, 'b');
    expect((await api('/api/v1/secrets?tier=personal', token)).status).toBe(423);
    await vault.api.setFrozen(false, 'b');

    const id = token.split('.')[2]!;
    await postForm(`/machines/${id}/revoke`, { csrf: await csrf() });
    expect((await api('/api/v1/secrets?tier=personal', token)).status).toBe(401);

    const log = JSON.stringify(await vault.api.listAudit());
    expect(log).toContain('machine_read');
    expect(log).not.toContain('value-a');
  });

  it('import requires an import-capable token', async () => {
    const plain = await newToken(['personal']);
    const body = JSON.stringify({ items: [{ tier: 'personal', name: 'N', value: 'v' }] });
    expect((await api('/api/v1/import', plain, { method: 'POST', body, headers: { 'Content-Type': 'application/json' } })).status).toBe(403);
    const imp = await newToken([], true);
    const r = await api('/api/v1/import', imp, { method: 'POST', body, headers: { 'Content-Type': 'application/json' } });
    expect(await r.json()).toEqual({ created: 1, updated: 0, skipped: 0 });
  });
});

describe('snapshot import by machine token', () => {
  it('restores secrets but skips machines, grants and vaults', async () => {
    const html = await (await postForm('/machines/create', { csrf: await csrf(), name: 'importer', canImport: '1' })).text();
    const imp = /class="tok">([^<]+)</.exec(html)![1]!;
    const planted = 'sbv.x.planted.plant-secret';
    const snapshot = {
      format: 'secret-broker-snapshot',
      version: 1,
      exportedAt: '2026-10-21T00:00:00.000Z',
      secrets: [{ tier: 'client-work', name: 'RESTORED', deleted: false, versions: [{ value: 'restored-value' }] }],
      grants: [{ repo: 'evil/repo', rules: [] }],
      machines: [{ id: 'planted', name: 'planted', tiers: ['client-work'], canImport: true, tokenHash: await sha256Hex('plant-secret'), createdAt: 'x', createdBy: 'x' }],
      vaults: [{ slug: 'planted-vault', name: 'p', kind: 'project', strict: true, repos: [], createdAt: 'x', createdBy: 'x' }],
    };
    const call = (token: string, path: string, init: RequestInit = {}) =>
      app.request(path, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }, env);
    const r = await call(imp, '/api/v1/import', { method: 'POST', body: JSON.stringify({ snapshot }) });
    const out = (await r.json()) as { secrets: number; skipped: unknown };
    expect(out.secrets).toBe(1);
    expect(out.skipped).toEqual({ machines: 1, grants: 1, vaults: 1, connections: 0, links: 0, pushes: 0 });
    expect((await call(planted, '/api/v1/secrets?tier=client-work')).status).toBe(401);
    expect((await vault.api.listMachines()).map((m) => m.name)).toEqual(['importer']);
    expect((await vault.api.listVaults()).some((x) => x.slug === 'planted-vault')).toBe(false);
  });

  it('machine snapshot import skips connections, links and push records', async () => {
    const html = await (await postForm('/machines/create', { csrf: await csrf(), name: 'importer', canImport: '1' })).text();
    const imp = /class="tok">([^<]+)</.exec(html)![1]!;
    const connId = '11111111-2222-3333-4444-555555555555';
    const snapshot = {
      format: 'secret-broker-snapshot', version: 1, exportedAt: '2026-10-23T00:00:00.000Z', secrets: [], grants: [], machines: [], vaults: [],
      connections: [{ id: connId, provider: 'vercel', name: 'Planted', accountId: '', token: { f: 1, kid: 'x', iv: 'x', ct: 'x', wiv: 'x', wk: 'x' }, createdAt: 1, createdBy: 'x' }],
      links: [{ connectionId: connId, targetId: 'prj_x', targetName: 'x', items: [{ handle: 'secret://production/STRIPE', varName: 'STRIPE' }], updatedAt: 1, updatedBy: 'x' }],
      pushes: [{ id: '00000000000001:aa', at: 1, by: 'x', connectionId: connId, targetId: 'prj_x', targetName: 'x', rows: [] }],
    };
    const r = await app.request('/api/v1/import', { method: 'POST', headers: { Authorization: `Bearer ${imp}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ snapshot }) }, env);
    expect(((await r.json()) as { skipped: unknown }).skipped).toEqual({ machines: 0, grants: 0, vaults: 0, connections: 1, links: 1, pushes: 1 });
    expect(await vault.logic.listConnections()).toEqual([]);
    expect(await vault.kv.get(`link:${connId}:prj_x`)).toBeUndefined();
  });
});

describe('backups page', () => {
  it('backs up to R2 and downloads only backup keys', async () => {
    expect((await postForm('/backups/run', { csrf: await csrf() })).status).toBe(303);
    expect([...r2.objs.keys()]).toEqual(['backups/2026-10-07T08:13:00.000Z.json']);
    const d = await getPage('/backups/download?key=' + encodeURIComponent('backups/2026-10-07T08:13:00.000Z.json'));
    expect(d.headers.get('content-disposition')).toContain('attachment');
    expect((await getPage('/backups/download?key=../oauth')).status).toBe(400);
  });
});

describe('vault management pages', () => {
  it('creates a linked strict project vault and shows it', async () => {
    const r = await postForm('/vaults/create', { csrf: await csrf(), name: 'Acme finance', slug: 'acme-finance', repos: 'acme/acme-dash\nhttps://github.com/acme/acme-api', strict: '1' });
    expect(r.status).toBe(303);
    expect(await vault.api.getVault('acme-finance')).toMatchObject({ strict: true, repos: ['acme/acme-dash', 'acme/acme-api'] });
    const html = await (await getPage('/vaults')).text();
    expect(html).toContain('acme-finance');
    expect(html).toContain('acme/acme-dash');
    expect((await postForm('/vault/add', { csrf: await csrf(), tier: 'acme-finance', name: 'DB_URL', value: 'pg://x' })).headers.get('location')).toBe('/vault?v=acme-finance&done=added');
    expect(await (await getPage('/vault?v=acme-finance')).text()).toContain('DB_URL');
  });

  it('approves a vault request from Claude, linked to the repo', async () => {
    await vault.api.requestVault({ slug: 'acme', name: 'Acme <b>', repo: 'acme/acme-site', reason: '<img src=x onerror=alert(1)>', requestedBy: 'alice' });
    const [req] = await vault.api.listVaultRequests();
    expect(await (await getPage('/approvals')).text()).toContain(`/approve-vault/${req!.id}`);
    const html = await (await getPage(`/approve-vault/${req!.id}`)).text();
    expect(html).not.toContain('<img src=x');
    const r = await postForm(`/approve-vault/${req!.id}`, { csrf: await csrf(), action: 'approve', name: 'Acme', slug: 'acme', strict: '1' });
    expect(await r.text()).toContain('npm run import-env -- acme');
    expect(await vault.api.getVault('acme')).toMatchObject({ repos: ['acme/acme-site'], strict: true });
  });

  it('refuses an approval that would break a vault link', async () => {
    await vault.api.createVault({ slug: 'acme', name: 'Acme', repos: ['acme/acme-site'], strict: false, by: 'b' });
    await vault.api.putSecret('acme', 'KEY', 'v', 'b');
    await expect(
      vault.api.createRequest({ repo: 'acme/other', reason: 'r', items: [{ handle: 'secret://acme/KEY', hosts: ['api.acme.com'] }], requestedBy: 'b' }),
    ).rejects.toThrow(/linked to acme\/acme-site/);
  });
});

describe('move page', () => {
  it('moves from the secret page and approvals for the old handle stop applying', async () => {
    await vault.api.createVault({ slug: 'initech', name: 'Initech', repos: [], strict: false, by: 'b' });
    await postForm('/vault/add', { csrf: await csrf(), tier: 'client-work', name: 'DO_INITECH', value: 'tok' });
    expect(await (await getPage('/vault/s/client-work/DO_INITECH')).text()).toContain('Move to another vault');
    const r = await postForm('/vault/s/client-work/DO_INITECH/move', { csrf: await csrf(), to: 'initech' });
    expect(r.status).toBe(303);
    expect(r.headers.get('location')).toBe('/vault/s/initech/DO_INITECH?done=moved');
    expect((await vault.api.loadTier('initech')).get('DO_INITECH')).toBe('tok');
    expect((await postForm('/vault/s/client-work/DO_INITECH/move', { csrf: 'bad', to: 'initech' })).status).toBe(403);
  });
});

describe('client registration redirect allowlist', () => {
  it('accepts Claude callbacks and loopback, refuses everything else', () => {
    expect(redirectAllowed('https://claude.ai/api/mcp/auth_callback')).toBe(true);
    expect(redirectAllowed('https://claude.com/api/mcp/auth_callback')).toBe(true);
    expect(redirectAllowed('http://localhost:6274/oauth/callback')).toBe(true);
    expect(redirectAllowed('http://127.0.0.1:8080/cb')).toBe(true);
    expect(redirectAllowed('https://attacker.example/cb')).toBe(false);
    expect(redirectAllowed('https://claude.ai.attacker.example/cb')).toBe(false);
    expect(redirectAllowed('http://claude.ai/api/mcp/auth_callback')).toBe(false);
    expect(redirectAllowed('not a url')).toBe(false);
    expect(redirectAllowed(undefined)).toBe(false);
  });
});
describe('deploy pages', () => {
  const V = 'https://api.vercel.com';
  async function vercelConn(name = 'Acme Vercel') {
    platform.on('GET', `${V}/v10/projects?limit=1&teamId=team_a`, { projects: [] });
    expect((await postForm('/deploy/connections/add', { csrf: await csrf(), provider: 'vercel', name, accountId: 'team_a', token: 'vercel-token-xyz' })).status).toBe(303);
    return (await vault.api.listConnections()).find((c) => c.name === name)!;
  }

  it('adds Deploy to the nav and shows the three tabs', async () => {
    const html = await (await getPage('/deploy')).text();
    expect(html).toContain('<a href="/deploy" class="on" aria-current="page">Deploy</a>');
    for (const t of ['/deploy/history', '/deploy/connections']) expect(html).toContain(`href="${t}"`);
  });

  it('adds, checks, replaces and removes a connection without ever echoing the token', async () => {
    const c = await vercelConn();
    platform.on('GET', `${V}/v10/projects?limit=1&teamId=team_a`, { error: { code: 'forbidden', message: 'Not authorized' } }, 403);
    expect((await postForm(`/deploy/connections/${c.id}/token`, { csrf: await csrf(), token: 'vercel-token-new' })).status).toBe(303);
    const html = await (await getPage('/deploy/connections')).text();
    expect(html).toContain('Acme Vercel');
    expect(html).toContain('Vercel 403: Not authorized (forbidden)');
    expect(html).toContain('<details class="confirm');
    expect(html).not.toMatch(/vercel-token-(xyz|new)/);
    expect((await postForm(`/deploy/connections/${c.id}/remove`, { csrf: await csrf() })).status).toBe(303);
    expect(await vault.api.listConnections()).toEqual([]);
    for (const p of ['/deploy', '/deploy/history', '/audit']) expect(await (await getPage(p)).text()).not.toMatch(/vercel-token/);
  });

  it('requires csrf on every deploy POST', async () => {
    const c = await vercelConn();
    for (const path of ['/deploy/connections/add', `/deploy/connections/${c.id}/token`, `/deploy/connections/${c.id}/remove`, `/deploy/t/${c.id}/prj_1/link`, `/deploy/t/${c.id}/prj_1/push`, `/deploy/t/${c.id}/prj_1/redeploy`])
      expect((await postForm(path, { csrf: 'nope' })).status, path).toBe(403);
  });

  it('pages the target picker at 25 and filters by name', async () => {
    const c = await vercelConn();
    const projects = Array.from({ length: 30 }, (_, i) => ({ id: `prj_${i}`, name: `site-${String(i).padStart(2, '0')}` }));
    platform.on('GET', `${V}/v10/projects?limit=100&teamId=team_a`, { projects, pagination: { next: null } });
    const p1 = await (await getPage(`/deploy/pick?conn=${c.id}`)).text();
    expect(p1.match(/href="\/deploy\/t\//g)).toHaveLength(25);
    expect(p1).toContain('site-00');
    expect(p1).not.toContain('site-25');
    const p2 = await (await getPage(`/deploy/pick?conn=${c.id}&page=2`)).text();
    expect(p2.match(/href="\/deploy\/t\//g)).toHaveLength(5);
    const f = await (await getPage(`/deploy/pick?conn=${c.id}&q=SITE-1`)).text();
    expect(f.match(/href="\/deploy\/t\//g)).toHaveLength(10);
  });

  it('saves a link and refuses a name used by two items', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'CLIENT_ID', 'cid-1', 'alice', undefined, undefined, 'config');
    await vault.api.putSecret('personal', 'CLIENT_SECRET', 'super-secret-value', 'alice');
    const ok = await postForm(`/deploy/t/${c.id}/prj_1/link`, { csrf: await csrf(), targetName: 'acme-portal',
      item: ['secret://personal/CLIENT_ID', 'secret://personal/CLIENT_SECRET'],
      'var:secret://personal/CLIENT_ID': 'AZURE_CLIENT_ID', 'env:secret://personal/CLIENT_ID': ['production', 'preview'],
      'var:secret://personal/CLIENT_SECRET': 'AZURE_CLIENT_SECRET', 'env:secret://personal/CLIENT_SECRET': ['production'] });
    expect(ok.status).toBe(303);
    expect((await vault.api.getLink(c.id, 'prj_1'))?.items.map((i) => i.varName)).toEqual(['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET']);
    const bad = await postForm(`/deploy/t/${c.id}/prj_1/link`, { csrf: await csrf(), targetName: 'acme-portal',
      item: ['secret://personal/CLIENT_ID', 'secret://personal/CLIENT_SECRET'],
      'var:secret://personal/CLIENT_ID': 'SAME', 'var:secret://personal/CLIENT_SECRET': 'SAME' });
    expect(bad.status).toBe(400);
    expect(await bad.text()).toContain('SAME is used twice in this link');
  });

  const envUrl = `${V}/v10/projects/prj_1/env?teamId=team_a`;
  const sigOf = (html: string) => /name="sig" value="([0-9a-f]{64})"/.exec(html)![1]!;
  const versOf = (html: string) => [...html.matchAll(/<input type="hidden" name="ver" value="([^"]+)">/g)].map((m) => m[1]!);

  it('reviews with replace rows unticked and the summary line, pushes, and never shows a secret value', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'CLIENT_ID', 'cid-1', 'alice', undefined, undefined, 'config');
    await vault.api.putSecret('personal', 'CLIENT_SECRET', 'super-secret-value', 'alice');
    await vault.api.putSecret('personal', 'NEW_KEY', 'new-key-value', 'alice');
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [
      { handle: 'secret://personal/CLIENT_ID', varName: 'AZURE_CLIENT_ID', environments: ['production', 'preview'] },
      { handle: 'secret://personal/CLIENT_SECRET', varName: 'AZURE_CLIENT_SECRET', environments: ['production'] },
      { handle: 'secret://personal/NEW_KEY', varName: 'NEW_KEY', environments: ['production'] },
    ] });
    platform.on('GET', envUrl, { envs: [
      { id: 'e1', key: 'AZURE_CLIENT_ID', type: 'plain', target: ['preview', 'production'], value: 'cid-0' },
      { id: 'e2', key: 'AZURE_CLIENT_SECRET', type: 'sensitive', target: ['production'] },
    ] });
    platform.on('POST', envUrl, { created: {}, failed: [] }, 201);
    platform.on('POST', `${V}/v10/projects/prj_1/env?upsert=true&teamId=team_a`, { created: {}, failed: [] }, 201);
    const review = await (await getPage(`/deploy/t/${c.id}/prj_1/review`)).text();
    expect(review).toContain('Acme Vercel / acme-portal. Ticked when this page opened: 1 of 3 (1 new).');
    expect(review).toContain('Replace rows go only if you tick them; re-check any you change.');
    expect(review).toContain('<input type="checkbox" name="tick" value="NEW_KEY|production" checked>');
    expect(review).toContain('<input type="checkbox" name="tick" value="AZURE_CLIENT_SECRET|production">');
    expect(review).toContain('<input type="checkbox" name="tick" value="AZURE_CLIENT_ID|preview,production">');
    expect(review).toContain('Now: <code>cid-0</code>');
    expect(review).toContain('After push: <code>cid-1</code>');
    expect(review).toContain('exists, will be overwritten, value cannot be compared');
    expect(review).not.toContain('super-secret-value');
    expect(review).not.toContain('new-key-value');
    const before = platform.calls.length;
    const res = await postForm(`/deploy/t/${c.id}/prj_1/push`, { csrf: await csrf(), sig: sigOf(review), ver: versOf(review), tick: ['NEW_KEY|production', 'AZURE_CLIENT_SECRET|production'] });
    expect(res.status).toBe(200);
    const result = await res.text();
    expect(result).toContain('Push result');
    expect(result).toContain('<span class="tag ok">replaced</span>');
    expect(result).toContain('<span class="tag ok">created</span>');
    expect(result).not.toContain('super-secret-value');
    const posted = platform.calls.slice(before).filter((x) => x.method === 'POST').map((x) => (x.body as { key: string }).key);
    expect(posted).toEqual(['AZURE_CLIENT_SECRET', 'NEW_KEY']);
    const hist = await (await getPage('/deploy/history')).text();
    expect(hist).toContain('secret://personal/CLIENT_SECRET');
    expect(hist).toContain('v1');
    expect(hist).not.toContain('super-secret-value');
  });

  it('refuses a push whose target changed after review', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'NEW_KEY', 'new-key-value', 'alice');
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [{ handle: 'secret://personal/NEW_KEY', varName: 'NEW_KEY', environments: ['production'] }] });
    platform.on('GET', envUrl, { envs: [] });
    const review = await (await getPage(`/deploy/t/${c.id}/prj_1/review`)).text();
    platform.on('GET', envUrl, { envs: [{ id: 'x', key: 'NEW_KEY', type: 'sensitive', target: ['production'] }] });
    const res = await postForm(`/deploy/t/${c.id}/prj_1/push`, { csrf: await csrf(), sig: sigOf(review), ver: versOf(review), tick: 'NEW_KEY|production' });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('the target changed since you reviewed it, review again');
    expect(platform.calls.some((x) => x.method === 'POST')).toBe(false);
  });

  it('re-reviews an older version through the version select', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'CLIENT_SECRET', 'one', 'alice');
    await vault.api.putSecret('personal', 'CLIENT_SECRET', 'two', 'alice');
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [{ handle: 'secret://personal/CLIENT_SECRET', varName: 'S', environments: ['production'] }] });
    platform.on('GET', envUrl, { envs: [] });
    const html = await (await getPage(`/deploy/t/${c.id}/prj_1/review?ver=${encodeURIComponent('secret://personal/CLIENT_SECRET@1')}`)).text();
    expect(html).toContain('<option value="secret://personal/CLIENT_SECRET@1" selected>v1</option>');
    expect(html).toContain('<option value="secret://personal/CLIENT_SECRET@2">v2 (current)</option>');
    expect(versOf(html)).toEqual(['secret://personal/CLIENT_SECRET@1']);
  });

  it('offers Redeploy only for Vercel and records it', async () => {
    const c = await vercelConn();
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [] });
    const vercelPage = await (await getPage(`/deploy/t/${c.id}/prj_1`)).text();
    expect(vercelPage).toContain(`action="/deploy/t/${c.id}/prj_1/redeploy"`);
    platform.on('GET', `${V}/v7/deployments?projectId=prj_1&target=production&state=READY&limit=1&teamId=team_a`, { deployments: [{ uid: 'dpl_9', name: 'acme-portal' }] });
    platform.on('POST', `${V}/v13/deployments?forceNew=1&teamId=team_a`, { id: 'dpl_10' });
    const r = await postForm(`/deploy/t/${c.id}/prj_1/redeploy`, { csrf: await csrf() });
    expect(r.status).toBe(303);
    expect(r.headers.get('location')).toContain('done=redeployed');
    expect((await vault.api.listAudit()).some((e) => e.event === 'redeploy' && e.deploymentId === 'dpl_10')).toBe(true);
    const ACCT = 'a'.repeat(32);
    platform.on('GET', `https://api.cloudflare.com/client/v4/accounts/${ACCT}/workers/scripts`, { success: true, errors: [], result: [] });
    await postForm('/deploy/connections/add', { csrf: await csrf(), provider: 'cloudflare', name: 'CF', accountId: ACCT, token: 'cf-tok' });
    const cf = (await vault.api.listConnections()).find((x) => x.name === 'CF')!;
    await vault.api.saveLink({ connectionId: cf.id, targetId: 'worker-1', targetName: 'worker-1', by: 'alice', items: [] });
    const cfPage = await (await getPage(`/deploy/t/${cf.id}/worker-1`)).text();
    expect(cfPage).not.toContain('/redeploy"');
    expect(cfPage).toContain('Each secret change already deployed a new Worker version.');
  });

  it('pages history at 25', async () => {
    const c = await vercelConn();
    for (let i = 1; i <= 26; i++) await vault.logic.addPushRecord({ at: 1_000 + i, by: 'alice', connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', rows: [] });
    const p1 = await (await getPage('/deploy/history')).text();
    expect(p1.match(/<div class="srow push">/g)).toHaveLength(25);
    expect(p1).toContain('href="/deploy/history?page=2"');
    const p2 = await (await getPage('/deploy/history?page=2')).text();
    expect(p2.match(/<div class="srow push">/g)).toHaveLength(1);
  });

  it('tells the operator which existing environments a recreate removes', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'NEW_KEY', 'new-key-value', 'alice');
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [{ handle: 'secret://personal/NEW_KEY', varName: 'NEW_KEY', environments: ['production'] }] });
    platform.on('GET', envUrl, { envs: [{ id: 'e1', key: 'NEW_KEY', type: 'sensitive', target: ['preview', 'production'] }] });
    const html = await (await getPage(`/deploy/t/${c.id}/prj_1/review`)).text();
    expect(html).toContain('will be recreated (type or environments differ); removed from preview');
  });

  it('notes a branch-scoped variable with the same name and leaves it out of the recreate', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'NEW_KEY', 'new-key-value', 'alice');
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [{ handle: 'secret://personal/NEW_KEY', varName: 'NEW_KEY', environments: ['preview', 'production'] }] });
    platform.on('GET', envUrl, { envs: [{ id: 'eb', key: 'NEW_KEY', type: 'sensitive', target: ['preview'], gitBranch: 'feature-x' }] });
    const html = await (await getPage(`/deploy/t/${c.id}/prj_1/review`)).text();
    expect(html).toContain('a branch-scoped variable with this name exists and is left alone');
    expect(html).not.toContain('will be recreated');
  });

  it('refuses a malformed link post with 400 and a clear all-unticked check', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'CLIENT_ID', 'cid-1', 'alice');
    const h = 'secret://personal/CLIENT_ID';
    const base = { csrf: await csrf(), targetName: 'acme-portal' };
    const cases: Array<Record<string, string | string[]>> = [
      { item: 'not-a-handle', 'var:not-a-handle': 'OK_NAME' },
      { item: h, [`var:${h}`]: 'lower_case' },
      { item: h, [`var:${h}`]: 'OK_NAME', [`env:${h}`]: 'staging' },
      { item: h, [`var:${h}`]: 'OK_NAME', [`envs:${h}`]: '1' },
    ];
    for (const extra of cases) expect((await postForm(`/deploy/t/${c.id}/prj_1/link`, { ...base, ...extra })).status, JSON.stringify(extra)).toBe(400);
    const none = await postForm(`/deploy/t/${c.id}/prj_1/link`, { ...base, item: h, [`var:${h}`]: 'OK_NAME', [`envs:${h}`]: '1' });
    expect(await none.text()).toContain('pick at least one environment');
    expect((await postForm(`/deploy/t/${c.id}/prj_1/link`, { ...base, item: h, [`var:${h}`]: 'OK_NAME' })).status).toBe(303);
    expect((await vault.api.getLink(c.id, 'prj_1'))?.items[0]?.environments).toEqual(['preview', 'production']);
  });

  it('does not echo the submitted token when adding a connection fails', async () => {
    const res = await postForm('/deploy/connections/add', { csrf: await csrf(), provider: 'bogus', name: 'X', accountId: '', token: 'tok-should-not-echo-123' });
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain('tok-should-not-echo-123');
  });

  it('rejects a malformed push id on redeploy', async () => {
    const c = await vercelConn();
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [] });
    expect((await postForm(`/deploy/t/${c.id}/prj_1/redeploy`, { csrf: await csrf(), push: '<b>x'.repeat(30) })).status).toBe(400);
  });

  it('never shows a config value written while the item was still a secret', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'FLAG', 'old-secret-one', 'alice');
    await vault.api.putSecret('personal', 'FLAG', 'second-value', 'alice');
    await vault.logic.convertToConfig('personal', 'FLAG', 'alice');
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [{ handle: 'secret://personal/FLAG', varName: 'FLAG', environments: ['production'] }] });
    platform.on('GET', envUrl, { envs: [{ id: 'e1', key: 'FLAG', type: 'plain', target: ['production'], value: 'platform-now' }] });
    const h = encodeURIComponent('secret://personal/FLAG@1');
    const old = await (await getPage(`/deploy/t/${c.id}/prj_1/review?ver=${h}`)).text();
    expect(old).not.toContain('old-secret-one');
    expect(old).toContain('secret://personal/FLAG version 1 is from before it became config and cannot be pushed');
    await expect(vault.api.reviewPush(c.id, 'prj_1', { 'secret://personal/FLAG': 1 })).rejects.toThrow('cannot be pushed');
    const cur = await (await getPage(`/deploy/t/${c.id}/prj_1/review?ver=${encodeURIComponent('secret://personal/FLAG@2')}`)).text();
    expect(cur).toContain('second-value');
    expect(cur).not.toContain('old-secret-one');
    expect(cur).toContain('value="secret://personal/FLAG@2"');
    expect(cur).not.toContain('value="secret://personal/FLAG@1"');
  });

  it('cannot restore a pre-config version into readable text', async () => {
    const c = await vercelConn();
    await vault.api.putSecret('personal', 'FLAG', 'old-secret-one', 'alice');
    await vault.api.putSecret('personal', 'FLAG', 'second-value', 'alice');
    await vault.logic.convertToConfig('personal', 'FLAG', 'alice');
    await expect(vault.api.restoreVersion('personal', 'FLAG', 1, 'alice')).rejects.toThrow('cannot be restored');
    const snap = await vault.logic.exportSnapshot([]);
    snap.secrets.find((x) => x.name === 'FLAG')!.versions.at(-1)!.value = 'backup-unknown-value';
    await vault.api.restoreSnapshot(snap, 'alice');
    await vault.api.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'alice', items: [{ handle: 'secret://personal/FLAG', varName: 'FLAG', environments: ['production'] }] });
    platform.on('GET', envUrl, { envs: [] });
    const html = await (await getPage(`/deploy/t/${c.id}/prj_1/review`)).text();
    expect((await vault.api.reviewPush(c.id, 'prj_1')).rows[0]?.newValue).toBe('second-value');
    expect(html).not.toContain('old-secret-one');
    expect(html).not.toContain('backup-unknown-value');
  });

  it('refuses deploy routes to a machine bearer token with no session', async () => {
    const c = await vercelConn();
    const m = await vault.api.createMachine({ name: 'ci', tiers: ['personal'], canImport: false, by: 'alice', origin: 'https://x.test' });
    const bearer = { Authorization: `Bearer ${(m as { token: string }).token}` };
    for (const path of ['/deploy', '/deploy/history', '/deploy/connections', `/deploy/pick?conn=${c.id}`, `/deploy/t/${c.id}/prj_1`, `/deploy/t/${c.id}/prj_1/review`]) {
      const r = await app.request(path, { headers: bearer }, env);
      expect(r.status, path).toBe(302);
      expect(r.headers.get('location')).toContain('/login');
    }
    for (const path of [`/deploy/t/${c.id}/prj_1/push`, `/deploy/t/${c.id}/prj_1/redeploy`, '/deploy/connections/add']) {
      const r = await app.request(path, { method: 'POST', headers: { ...bearer, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ csrf: await csrf() }) }, env);
      expect(r.status, path).toBe(302);
    }
  });

  it('keeps deploy methods out of api.ts and mcp.ts', () => {
    for (const f of ['api.ts', 'mcp.ts']) {
      const src = readFileSync(join(__dirname, '..', 'src', f), 'utf8');
      for (const name of ['configValues', 'pushTarget', 'reviewPush', 'redeployTarget', 'addConnection']) expect(src, `${f} ${name}`).not.toContain(name);
    }
  });
});

describe('config items', () => {
  it('adds config, shows it truncated in the list and in full on its page, and edits it as a new version', async () => {
    const long = 'https://login.microsoftonline.com/tenant-0123456789/v2.0';
    expect((await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'AZURE_AUTHORITY', value: long, kind: 'config' })).status).toBe(303);
    const list = await (await getPage('/vault')).text();
    expect(list).toContain('<span class="tag">config</span>');
    expect(list).toContain(`${long.slice(0, 40)}…`);
    expect(list).not.toContain(long);
    const detail = await (await getPage('/vault/s/personal/AZURE_AUTHORITY')).text();
    expect(detail).toContain(long);
    expect((await postForm('/vault/s/personal/AZURE_AUTHORITY/edit', { csrf: await csrf(), value: 'v2-value' })).status).toBe(303);
    expect(await vault.api.getMeta('personal', 'AZURE_AUTHORITY')).toMatchObject({ kind: 'config', current: 2 });
    expect(await (await getPage('/vault/s/personal/AZURE_AUTHORITY')).text()).toContain('v2-value');
  });

  it('escapes config values', async () => {
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'HTML_CFG', value: '<script>x</script>', kind: 'config' });
    for (const p of ['/vault', '/vault/s/personal/HTML_CFG']) {
      const html = await (await getPage(p)).text();
      expect(html).not.toContain('<script>x');
      expect(html).toContain('&lt;script&gt;x');
    }
  });

  it('converts a secret to config in two steps and refuses logins', async () => {
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'CLIENT_SECRET', value: 'cs-hidden-value' });
    const before = await (await getPage('/vault/s/personal/CLIENT_SECRET')).text();
    expect(before).toContain('Convert to config');
    expect(before).toContain('<details class="confirm quiet">');
    expect(before).not.toContain('cs-hidden-value');
    expect((await postForm('/vault/s/personal/CLIENT_SECRET/convert', { csrf: await csrf() })).status).toBe(303);
    const after = await (await getPage('/vault/s/personal/CLIENT_SECRET')).text();
    expect(after).toContain('cs-hidden-value');
    expect(after).not.toContain('Convert to config');
    await postForm('/vault/add-login', { csrf: await csrf(), tier: 'personal', name: 'PORTAL', username: 'u', password: 'pw-123456' });
    expect(await (await getPage('/vault/s/personal/PORTAL')).text()).not.toContain('Convert to config');
    const r = await postForm('/vault/s/personal/PORTAL/convert', { csrf: await csrf() });
    expect(r.status).toBe(400);
    expect(await r.text()).toContain('logins cannot be converted to config');
  });

  it('keeps secrets write-only and serves config to machines exactly as before', async () => {
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'API_KEY', value: 'sk-never-shown' });
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'CLIENT_ID', value: 'cid-shown', kind: 'config' });
    for (const p of ['/vault', '/vault/s/personal/API_KEY', '/audit']) expect(await (await getPage(p)).text()).not.toContain('sk-never-shown');
    expect((await vault.api.loadTier('personal')).get('CLIENT_ID')).toBe('cid-shown');
  });

  it('keeps a value added as a secret over a trashed config item write-only', async () => {
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'REUSED', value: 'was-config', kind: 'config' });
    expect((await postForm('/vault/s/personal/REUSED/delete', { csrf: await csrf() })).status).toBe(303);
    expect((await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'REUSED', value: 'now-a-secret-value' })).status).toBe(303);
    for (const p of ['/vault', '/vault/s/personal/REUSED']) {
      const html = await (await getPage(p)).text();
      expect(html, p).not.toContain('now-a-secret-value');
      expect(html, p).not.toContain('was-config');
    }
    expect((await vault.api.getMeta('personal', 'REUSED'))?.kind).toBeUndefined();
  });

  it('does not offer Make current for versions from before the conversion', async () => {
    await postForm('/vault/add', { csrf: await csrf(), tier: 'personal', name: 'OLDSEC', value: 'first-secret' });
    await vault.api.putSecret('personal', 'OLDSEC', 'second-secret', 'alice');
    await vault.logic.convertToConfig('personal', 'OLDSEC', 'alice');
    await vault.api.putSecret('personal', 'OLDSEC', 'third-config', 'alice');
    const html = await (await getPage('/vault/s/personal/OLDSEC')).text();
    expect(html).not.toContain('first-secret');
    expect(html).not.toContain('second-secret');
    expect(html).not.toContain('name="v" value="1"');
    expect(html).toContain('name="v" value="2"'); // v2 is the converted value, at configSince
    expect(html).toContain('third-config');
  });
});

describe('security gates', () => {
  it('refuses a session key shorter than 32 characters in the helper, hmacHex and the approved-clients cookie', async () => {
    expect(sessionKeyProblem('x'.repeat(31))).toMatch(/COOKIE_ENCRYPTION_KEY.*32/);
    expect(sessionKeyProblem(undefined)).not.toBeNull();
    expect(sessionKeyProblem('x'.repeat(32))).toBeNull();
    await expect(hmacHex('x'.repeat(31), 'data')).rejects.toThrow(/COOKIE_ENCRYPTION_KEY/);
    await expect(addApprovedClient(new Request('https://x.example.com/'), 'c1', 'x'.repeat(31))).rejects.toThrow(/COOKIE_ENCRYPTION_KEY/);
  });

  const register = (uri = 'https://claude.ai/api/mcp/auth_callback') => ({ client_name: 'Claude', redirect_uris: [uri] });

  it('registration is closed by default, opens for 5 clients, and a refusal writes nothing', async () => {
    const take = (info: { name: string; hosts: string[] }) => vault.api.takeRegistration(info);
    const before = JSON.stringify([...vault.kv.m]);
    const closed = await registrationDecision(register(), take);
    expect(closed).toMatchObject({ code: 'access_denied', status: 403 });
    expect(JSON.stringify([...vault.kv.m])).toBe(before);
    expect((await registrationDecision(register('https://evil.example.com/cb'), take))?.status).toBe(400);

    await vault.api.openRegistration('alice');
    for (let i = 0; i < 5; i++) expect(await registrationDecision(register(), take)).toBeUndefined();
    expect((await registrationDecision(register(), take))?.status).toBe(403);
    expect(await vault.api.registrationStatus()).toEqual({ until: 0, left: 0 });
    expect((await vault.api.listAudit()).filter((e) => e.event === 'client_registered')).toHaveLength(5);

    await vault.api.openRegistration('alice');
    await vault.api.closeRegistration('alice');
    expect(await vault.api.takeRegistration({ name: 'Claude', hosts: ['claude.ai'] })).toBe(false);
  });

  it('POST /authorize writes nothing for an unknown client', async () => {
    const known = { clientId: 'c1', redirectUris: ['https://claude.ai/cb'] };
    const OAUTH_PROVIDER = { lookupClient: async (id: string) => (id === 'c1' ? known : null) };
    const kv = fakeKv();
    const e = { ...env, OAUTH_KV: kv, OAUTH_PROVIDER } as unknown as Env;
    const send = (clientId: string, redirectUri: string) => {
      const state = btoa(JSON.stringify({ oauthReqInfo: { clientId, redirectUri } }));
      return AuthHandler.request('/authorize', { method: 'POST', headers: { Cookie: '__Host-CSRF_TOKEN=t', 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ csrf_token: 't', state }) }, e);
    };
    expect((await send('nobody', 'https://claude.ai/cb')).status).toBe(400);
    expect(kv.writes).toEqual([]);
    expect((await send('c1', 'https://claude.ai/cb')).status).toBe(302);
    expect(kv.writes).toHaveLength(1);
  });
});

describe('connectors page', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const deleted: string[] = [];
  const oauth = {
    listClients: async () => ({ items: [{ clientId: 'id/1', clientName: hostile, redirectUris: ['https://claude.ai/cb'], registrationDate: 1_700_000_000 }, { clientId: 'id2', redirectUris: ['http://localhost:9/cb'] }] }),
    listUserGrants: async () => ({ items: [{ id: 'g', clientId: 'id/1', userId: '42', scope: [], metadata: { label: 'alice' }, createdAt: 1_700_000_000 }] }),
    lookupClient: async (id: string) => ({ clientId: id, clientName: hostile, redirectUris: [] }),
    deleteClient: async (id: string) => void deleted.push(id),
  } as unknown as OAuthApi;
  beforeEach(() => {
    deleted.length = 0;
    app = new Hono<{ Bindings: Env }>();
    registerAdminRoutes(app, { vault: () => vault.api, oauth: () => oauth });
  });

  it('escapes client-supplied strings and shows sign-in state', async () => {
    const html = await (await getPage('/connectors')).text();
    expect(html).not.toContain(hostile);
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('/connectors/id%2F1/remove');
    expect(html).toContain('Unnamed app');
    expect(html).toContain('alice, ');
    expect(html).toContain('No active sign-in');
    expect(html).toContain('Closed. No new app can register.');
  });

  it('Remove deletes the client and records it; open and close need CSRF and are audited', async () => {
    expect((await postForm('/connectors/open', {})).status).toBe(403);
    expect((await postForm('/connectors/open', { csrf: await csrf() })).status).toBe(303);
    expect(await (await getPage('/connectors')).text()).toContain('registrations left');
    expect((await postForm('/connectors/id%2F1/remove', { csrf: await csrf() })).status).toBe(303);
    expect(deleted).toEqual(['id/1']);
    expect((await postForm('/connectors/close', { csrf: await csrf() })).status).toBe(303);
    const events = (await vault.api.listAudit()).map((x) => x.event);
    expect(events).toEqual(expect.arrayContaining(['registration_opened', 'connector_removed', 'registration_closed']));
  });
});
