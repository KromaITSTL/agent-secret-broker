// Renders the dashboard pages against seeded fake data so they can be opened in a browser
// for design review (no GitHub login, no Worker runtime). Skipped unless RENDER_FIXTURES is set.
//
// PowerShell: $env:RENDER_FIXTURES='C:\path\to\out'; npx vitest run tests/render-fixtures.test.ts
// bash:       RENDER_FIXTURES=/c/path/to/out npx vitest run tests/render-fixtures.test.ts
import { copyFileSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { registerAdminRoutes, type OAuthApi } from '../src/admin';
import { registerApiRoutes } from '../src/api';
import type { Env } from '../src/env';
import type { Grants } from '../src/grants';
import { csrfToken, registerWebRoutes, signSession, type Session } from '../src/web';
import { fakeKv, fakePlatform, fakeR2, makeVault } from './helpers';

const OUT = process.env.RENDER_FIXTURES ?? '';
const KEY = 'test-cookie-key-0123456789abcdef';
const REPO = 'acme/acme-web';

describe.skipIf(!OUT)('render fixtures', () => {
  it('writes each page as static HTML', async () => {
    const platform = fakePlatform();
    const vault = await makeVault({ fetchFn: platform.fetchFn, planKey: KEY });
    const env = { COOKIE_ENCRYPTION_KEY: KEY, ALLOWED_GITHUB_IDS: '42', OAUTH_KV: fakeKv(), BACKUPS: fakeR2() } as unknown as Env;
    const app = new Hono<{ Bindings: Env }>();
    registerWebRoutes(app, { grants: () => vault.api as unknown as Grants });
    // Connected apps for the Connectors page; empty until the open-window fixture below.
    let apps: Array<{ clientId: string; clientName?: string; redirectUris: string[]; registrationDate?: number }> = [];
    const oauth = {
      listClients: async () => ({ items: apps }),
      listUserGrants: async () => ({ items: [{ id: 'g1', clientId: 'app-1', userId: '42', scope: [], metadata: { label: 'alice' }, createdAt: Math.floor(Date.now() / 1000) - 3600 }] }),
    } as unknown as OAuthApi;
    registerAdminRoutes(app, { vault: () => vault.api, oauth: () => oauth });
    registerApiRoutes(app, { vault: () => vault.api });
    const me: Session = { githubId: '42', login: 'alice', exp: Math.floor(Date.now() / 1000) + 3600 };
    const cookie = `__Host-sb_session=${await signSession(KEY, me)}`;
    const get = (p: string) => app.request(p, { headers: { Cookie: cookie } }, env);
    const post = async (p: string, o: Record<string, string | string[]> = {}) => {
      const f = new URLSearchParams({ csrf: await csrfToken(KEY, me, 'admin') });
      for (const [k, v] of Object.entries(o)) for (const x of [v].flat()) f.append(k, x);
      return app.request(p, { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' }, body: f }, env);
    };
    const api = vault.api;

    // ---- seed (all values fake) ----
    await api.createVault({ slug: 'acme-web', name: 'Acme web', strict: false, repos: [REPO], by: 'alice' });
    const put = (t: string, n: string, note?: string) => api.putSecret(t, n, `fake-${n.toLowerCase()}`, 'alice', note);
    await put('personal', 'GITHUB_TOKEN', 'Personal access token for scripts');
    await put('personal', 'OPENAI_KEY');
    await put('production', 'STRIPE_LIVE_KEY', 'Live Stripe secret key');
    await put('production', 'SUPABASE_SERVICE_ROLE');
    await put('acme-web', 'DATABASE_URL', 'Staging database');
    await put('acme-web', 'STRIPE_KEY', 'Stripe test key');
    await put('acme-web', 'SENDGRID_KEY');
    await put('acme-web', 'CI_TOKEN');
    await put('acme-web', 'OLD_TOKEN');
    await put('acme-web', 'ANALYTICS_KEY');
    await put('acme-web', 'TRASHED_KEY');
    await api.deleteSecret('acme-web', 'TRASHED_KEY', 'alice');
    await api.putSecret('personal', 'VENDOR_PORTAL', 'fake-portal-password', 'alice', undefined, { username: 'agent@example.com', url: 'https://portal.example.com/login', notes: 'MFA is off for this account. Use the Billing tab only.' });
    await api.putSecret('production', 'BANK_PORTAL', 'fake-bank-password', 'alice', undefined, { username: 'ops@example.com', url: 'https://bank.example.com/signin', notes: 'Read-only operator account.' });

    // Grants: one request per rule so each can carry its own limit.
    const approve = async (handle: string, limit?: { uses?: number; ttlMs?: number }) => {
      const r = await api.createRequest({ repo: REPO, reason: 'Fixture rule', items: [{ handle, hosts: ['api.example.com'], methods: ['GET'] }], requestedBy: 'claude' });
      return api.approve(r.id, [0], 'alice', limit ? { 0: limit } : undefined);
    };
    await approve('secret://acme-web/DATABASE_URL', { ttlMs: 3 * 86_400_000 });
    await approve('secret://acme-web/SENDGRID_KEY', { uses: 5 });
    await approve('secret://acme-web/OLD_TOKEN', { ttlMs: 1 });
    const spent = await approve('secret://acme-web/CI_TOKEN', { uses: 1 });
    await api.consume(REPO, spent.rules.at(-1)!.id!);
    await approve('secret://acme-web/ANALYTICS_KEY');
    await new Promise((r) => setTimeout(r, 5));

    const pending = await api.createRequest({
      repo: REPO,
      reason: 'Ship the checkout fix: read the release, charge a test card in production, and sign in to both vendor portals.',
      requestedBy: 'claude',
      items: [
        { handle: 'secret://personal/GITHUB_TOKEN', hosts: ['api.github.com'], methods: ['GET', 'POST'] },
        { handle: 'secret://production/STRIPE_LIVE_KEY', hosts: ['*.stripe.com'], methods: ['GET'] },
        { handle: 'secret://personal/VENDOR_PORTAL', reveal: true },
        { handle: 'secret://production/BANK_PORTAL', reveal: true },
      ],
    });

    const log = (e: Record<string, unknown>) => api.log(e as never);
    await log({ event: 'secret_fetch', by: 'claude', repo: REPO, handle: 'secret://acme-web/DATABASE_URL', host: 'db.acme.example', method: 'GET', status: 200 });
    await log({ event: 'secret_reveal', by: 'claude', repo: REPO, handle: 'secret://acme-web/ANALYTICS_KEY' });
    await log({ event: 'secret_fetch', by: 'claude', repo: REPO, handle: 'secret://production/STRIPE_LIVE_KEY', host: 'api.stripe.com', outcome: 'denied', reason: 'no approval' });
    await log({ event: 'access_approved', by: 'alice', repo: REPO, handles: ['secret://acme-web/DATABASE_URL'] });

    // ---- deploy seed (fake platform, fake tokens and values) ----
    const V = 'https://api.vercel.com';
    const CF = 'https://api.cloudflare.com/client/v4';
    const ACCT = '0'.repeat(32);
    await api.putSecret('acme-web', 'AZURE_CLIENT_ID', 'fake-client-id-0001', 'alice', 'Azure app registration client id', undefined, 'config');
    await api.putSecret('acme-web', 'AZURE_CLIENT_ID', 'fake-client-id-0002', 'alice', undefined, undefined, 'config');
    await api.putSecret('acme-web', 'AZURE_TENANT_ID', 'fake-tenant-id-0001', 'alice', 'Azure directory (tenant) id', undefined, 'config');
    await api.putSecret('acme-web', 'AZURE_CLIENT_SECRET', 'fake-azure-secret-v1', 'alice', 'Azure client secret');

    platform.on('GET', `${V}/v10/projects?limit=1&teamId=team_acme`, { projects: [] });
    platform.on('GET', `${CF}/accounts/${ACCT}/workers/scripts`, { success: true, errors: [], result: [{ id: 'acme-worker' }, { id: 'acme-cron' }] });
    const vercel = (await api.addConnection({ provider: 'vercel', name: 'Acme Vercel', accountId: 'team_acme', token: 'fake-vercel-token-0001', by: 'alice' })).connection;
    const cf = (await api.addConnection({ provider: 'cloudflare', name: 'Acme Cloudflare', accountId: ACCT, token: 'fake-cloudflare-token-0001', by: 'alice' })).connection;

    const projects = [
      { id: 'prj_portal', name: 'acme-portal' },
      { id: 'prj_marketing', name: 'acme-marketing' },
      ...Array.from({ length: 28 }, (_, i) => ({ id: `prj_site${String(i + 1).padStart(2, '0')}`, name: `acme-site-${String(i + 1).padStart(2, '0')}` })),
    ];
    platform.on('GET', `${V}/v10/projects?limit=100&teamId=team_acme`, { projects, pagination: { count: projects.length, next: null } });
    platform.on('GET', `${V}/v10/projects/prj_portal/env?teamId=team_acme`, { envs: [
      { id: 'env_cid', key: 'AZURE_CLIENT_ID', type: 'plain', value: 'old-client-id', target: ['production', 'preview'] },
      { id: 'env_sec', key: 'AZURE_CLIENT_SECRET', type: 'sensitive', target: ['production', 'preview', 'development'] },
    ] });
    platform.on('GET', `${V}/v10/projects/prj_marketing/env?teamId=team_acme`, { envs: [] });
    platform.on('POST', `${V}/v10/projects/prj_marketing/env?teamId=team_acme`, { created: {}, failed: [] }, 201);
    platform.on('GET', `${CF}/accounts/${ACCT}/workers/scripts/acme-worker/secrets`, { success: true, errors: [], result: [{ name: 'AZURE_CLIENT_SECRET', type: 'secret_text' }] });
    platform.on('GET', `${CF}/accounts/${ACCT}/workers/scripts/acme-cron/secrets`, { success: true, errors: [], result: [] });
    platform.on('PUT', `${CF}/accounts/${ACCT}/workers/scripts/acme-worker/secrets`, { success: true, errors: [], result: { name: 'AZURE_CLIENT_SECRET', type: 'secret_text' } });

    const H = (n: string) => `secret://acme-web/${n}`;
    const prod = ['production' as const, 'preview' as const];
    const push = async (connId: string, target: string) => {
      const plan = await api.reviewPush(connId, target);
      return post(`/deploy/t/${connId}/${target}/push`, { sig: plan.sig, tick: plan.rows.filter((r) => r.cls !== 'missing').map((r) => r.key), ver: plan.rows.map((r) => `${r.handle}@${r.version}`) });
    };

    // marketing: a first push of one config item, kept as the push result page
    await api.saveLink({ connectionId: vercel.id, targetId: 'prj_marketing', targetName: 'acme-marketing', items: [{ handle: H('AZURE_TENANT_ID'), varName: 'AZURE_TENANT_ID', environments: prod }], by: 'alice' });
    const pushed = await push(vercel.id, 'prj_marketing');

    // worker: pushed once at v1 so the next review shows an update after v2
    await api.saveLink({ connectionId: cf.id, targetId: 'acme-worker', targetName: 'acme-worker', items: [{ handle: H('AZURE_CLIENT_SECRET'), varName: 'AZURE_CLIENT_SECRET' }], by: 'alice' });
    await push(cf.id, 'acme-worker');
    await api.putSecret('acme-web', 'AZURE_CLIENT_SECRET', 'fake-azure-secret-v2', 'alice');
    await api.putSecret('acme-web', 'RETIRED_API_KEY', 'fake-retired-key', 'alice');
    await api.saveLink({ connectionId: cf.id, targetId: 'acme-worker', targetName: 'acme-worker', items: [
      { handle: H('AZURE_CLIENT_SECRET'), varName: 'AZURE_CLIENT_SECRET' },
      { handle: H('AZURE_TENANT_ID'), varName: 'AZURE_TENANT_ID' },
      { handle: H('RETIRED_API_KEY'), varName: 'RETIRED_API_KEY' },
    ], by: 'alice' });

    await api.deleteSecret('acme-web', 'RETIRED_API_KEY', 'alice'); // trashed after linking, so the row reads missing

    // portal: replace (unticked), recreate naming development as lost, new
    await api.saveLink({ connectionId: vercel.id, targetId: 'prj_portal', targetName: 'acme-portal', items: [
      { handle: H('AZURE_CLIENT_ID'), varName: 'AZURE_CLIENT_ID', environments: prod },
      { handle: H('AZURE_CLIENT_SECRET'), varName: 'AZURE_CLIENT_SECRET', environments: prod },
      { handle: H('AZURE_TENANT_ID'), varName: 'AZURE_TENANT_ID', environments: prod },
    ], by: 'alice' });

    // a failed push with a redeploy outcome, written straight to history
    await vault.logic.addPushRecord({
      at: Date.now() - 86_400_000, by: 'alice', connectionId: vercel.id, targetId: 'prj_site01', targetName: 'acme-site-01',
      rows: [
        { handle: H('AZURE_CLIENT_ID'), version: 1, kind: 'config', varName: 'AZURE_CLIENT_ID', environments: prod, action: 'replaced' },
        { handle: H('AZURE_CLIENT_SECRET'), version: 1, kind: 'secret', varName: 'AZURE_CLIENT_SECRET', environments: prod, action: 'failed', error: 'Vercel 403: forbidden' },
      ],
      redeploy: { at: Date.now() - 86_000_000, ok: false, error: 'Vercel 404: no ready production deployment to redeploy' },
    });

    // Machine and backup so those pages are not empty.
    await post('/machines/create', { name: 'dev-laptop', tier: ['personal', 'acme-web'] });
    await post('/backups/run');

    // ---- render ----
    const fixtures: Array<{ file: string; route: string }> = [];
    const write = async (file: string, route: string, res: Response) => {
      expect(res.status, route).toBe(200);
      const html = (await res.text()).replace(/(href|src)="\/fonts\//g, '$1="fonts/');
      mkdirSync(OUT, { recursive: true });
      writeFileSync(join(OUT, file), html);
      fixtures.push({ file, route });
    };
    const page = async (file: string, route: string) => write(file, route, await get(route));

    await page('vault.html', '/vault');
    await page('vault-production.html', '/vault?v=production');
    await page('login-detail.html', '/vault/s/personal/VENDOR_PORTAL');
    await write('login-reveal.html', 'POST /vault/s/personal/VENDOR_PORTAL/reveal', await post('/vault/s/personal/VENDOR_PORTAL/reveal'));
    await page('secret-detail.html', '/vault/s/acme-web/DATABASE_URL');
    await page('trash.html', '/vault/trash');
    await page('approve.html', `/approve/${pending.id}`);
    await page('approvals.html', '/approvals');
    await page('audit.html', '/audit');
    await page('vaults.html', '/vaults');
    await page('machines.html', '/machines');
    await page('connectors-closed.html', '/connectors');
    await post('/connectors/open');
    apps = [
      { clientId: 'app-1', clientName: 'Claude', redirectUris: ['https://claude.ai/api/mcp/auth_callback'], registrationDate: Math.floor(Date.now() / 1000) - 86_400 },
      { clientId: 'app-2', redirectUris: ['http://localhost:6274/oauth/callback'] },
    ];
    await page('connectors.html', '/connectors');
    await page('settings.html', '/settings');
    await page('backups.html', '/backups');
    await page('config-detail.html', '/vault/s/acme-web/AZURE_TENANT_ID');
    await page('deploy-targets.html', '/deploy');
    await page('deploy-connections.html', '/deploy/connections');
    await page('deploy-pick.html', `/deploy/pick?conn=${vercel.id}`);
    await page('deploy-target.html', `/deploy/t/${vercel.id}/prj_portal`);
    await page('deploy-target-cloudflare.html', `/deploy/t/${cf.id}/acme-worker`);
    await page('deploy-review.html', `/deploy/t/${vercel.id}/prj_portal/review`);
    await page('deploy-review-cloudflare.html', `/deploy/t/${cf.id}/acme-worker/review`);
    await write('deploy-result.html', `POST /deploy/t/${vercel.id}/prj_marketing/push`, pushed);
    await page('deploy-history.html', '/deploy/history');

    const fonts = join(__dirname, '..', 'public', 'fonts');
    mkdirSync(join(OUT, 'fonts'), { recursive: true });
    for (const f of readdirSync(fonts)) copyFileSync(join(fonts, f), join(OUT, 'fonts', f));

    const links = fixtures.map((f) => `<li><a href="${f.file}">${f.route}</a></li>`).join('\n');
    writeFileSync(join(OUT, 'index.html'), `<!doctype html><meta charset="utf-8"><title>Dashboard fixtures</title><body style="font:16px sans-serif;margin:2rem"><h1>Dashboard fixtures</h1><ul>\n${links}\n</ul></body>`);
  });
});
