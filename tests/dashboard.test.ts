import { describe, expect, it } from 'vitest';
import { createDashboardBroker, DashboardClient, repoFromRemote } from '../src/dashboard.js';

describe('repoFromRemote', () => {
  it('reads owner/name from https and ssh remotes, lowercased', () => {
    expect(repoFromRemote('https://github.com/Acme/Site.git')).toBe('acme/site');
    expect(repoFromRemote('https://user@github.com/acme/site')).toBe('acme/site');
    expect(repoFromRemote('git@github.com:acme/site.git')).toBe('acme/site');
    expect(repoFromRemote('ssh://git@github.com/acme/site.git')).toBe('acme/site');
  });

  it('refuses anything that is not owner/name', () => {
    expect(repoFromRemote('C:/work/site')).toBeNull();
    expect(repoFromRemote('https://github.com/acme')).toBeNull();
    expect(repoFromRemote('')).toBeNull();
  });
});

type Call = { tool: string; body: Record<string, unknown> };

function setup(opts: { repo?: string | null; answer?: (c: Call) => unknown } = {}) {
  const calls: Call[] = [];
  const spawned: Array<{ cmd: string; args: string[]; env: Record<string, string> }> = [];
  const client = {
    call: async (tool: string, body: unknown) => {
      const c = { tool, body: body as Record<string, unknown> };
      calls.push(c);
      const a = opts.answer?.(c);
      if (a instanceof Error) throw a;
      return a ?? {};
    },
  } as Pick<DashboardClient, 'call'>;
  const broker = createDashboardBroker({
    cwd: 'C:/work/site',
    repo: opts.repo === undefined ? 'acme/site' : opts.repo,
    client,
    auditPath: null,
    spawn: async (cmd, args, env) => {
      spawned.push({ cmd, args, env });
      return { stdout: `url=${env.DB_URL ?? ''}`, stderr: '', code: 0 };
    },
  });
  return { broker, calls, spawned };
}

describe('dashboard broker', () => {
  it('runs with the values the vault returns and redacts them', async () => {
    const t = setup({ answer: (c) => (c.tool === 'run' ? { values: { 'secret://acme/DB_URL': 'postgres://secret-value' } } : {}) });
    const r = await t.broker.secretRun({ command: 'supabase', args: ['db', 'push'], env: { DB_URL: 'secret://acme/DB_URL', SUPABASE_DEBUG: '1' } });
    expect(t.calls[0]).toEqual({ tool: 'run', body: { repo: 'acme/site', command: 'supabase', args: ['db', 'push'], handles: ['secret://acme/DB_URL'], env: ['SUPABASE_DEBUG'] } });
    expect(t.spawned[0]!.env).toEqual({ DB_URL: 'postgres://secret-value', SUPABASE_DEBUG: '1' });
    expect(r.stdout).toBe('url=[redacted:secret://acme/DB_URL]');
  });

  it('does not run when the vault refuses', async () => {
    const t = setup({ answer: () => new Error('secret://acme/DB_URL is not approved for supabase db reset in acme/site') });
    await expect(t.broker.secretRun({ command: 'supabase', args: ['db', 'reset'], env: { DB_URL: 'secret://acme/DB_URL' } })).rejects.toThrow(/not approved/);
    expect(t.spawned).toHaveLength(0);
  });

  it('refuses a secret in a variable the runtime reads, before asking the vault', async () => {
    const t = setup();
    await expect(t.broker.secretRun({ command: 'node', args: ['x.mjs'], env: { NODE_OPTIONS: 'secret://acme/DB_URL' } })).rejects.toThrow(/NODE_OPTIONS/);
    expect(t.calls).toHaveLength(0);
  });

  it('refuses when the vault omits a requested value', async () => {
    const t = setup({ answer: () => ({ values: {} }) });
    await expect(t.broker.secretRun({ command: 'x', args: [], env: { A: 'secret://acme/DB_URL' } })).rejects.toThrow(/did not return/);
    expect(t.spawned).toHaveLength(0);
  });

  it('sends the git repo with every tool call, never one the agent picks', async () => {
    const t = setup();
    await t.broker.secretList();
    await t.broker.secretRequestAccess({ reason: 'migrations', items: [{ handle: 'secret://acme/DB_URL', commands: ['supabase db push *'] }], repo: 'evil/other' } as never);
    expect(t.calls.map((c) => c.body.repo)).toEqual(['acme/site', 'acme/site']);
  });

  it('explains when the folder has no git remote, and asks the vault nothing', async () => {
    const t = setup({ repo: null });
    expect(await t.broker.secretStatus()).toMatchObject({ repo: null, reason: expect.stringMatching(/git repository/) });
    await expect(t.broker.secretList()).rejects.toThrow(/git repository/);
    await expect(t.broker.secretRun({ command: 'x', args: [], env: { A: 'secret://acme/DB_URL' } })).rejects.toThrow(/git repository/);
    expect(t.calls).toHaveLength(0);
  });
});

describe('DashboardClient', () => {
  const token = `sbv.${Buffer.from('https://vault.example.com').toString('base64url')}.id.secret`;

  it('posts to the machine API on the origin inside the token', async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const c = new DashboardClient(token, (async (url: string, init: RequestInit) => {
      seen = { url, init };
      return Response.json({ ok: true });
    }) as unknown as typeof fetch);
    expect(await c.call('list', { repo: 'acme/site' })).toEqual({ ok: true });
    expect(seen!.url).toBe('https://vault.example.com/api/v1/broker/list');
    expect((seen!.init.headers as Record<string, string>).Authorization).toBe(`Bearer ${token}`);
  });

  it('turns refusals into errors with the vault message and a hint', async () => {
    const c = new DashboardClient(token, (async () => Response.json({ error: 'invalid or revoked machine token' }, { status: 401 })) as unknown as typeof fetch);
    await expect(c.call('run', {})).rejects.toThrow(/revoked.*store-token runner/);
  });
});

describe('review fixes (local)', () => {
  it('accepts only github.com remotes', () => {
    expect(repoFromRemote('https://gitlab.com/acme/site.git')).toBeNull();
    expect(repoFromRemote('https://evil.example/acme/site')).toBeNull();
    expect(repoFromRemote('/tmp/a@b:acme/site')).toBeNull();
    expect(repoFromRemote('git@github.com:acme/site.git')).toBe('acme/site');
  });

  it('refuses a variable that loads code even when it holds no secret', async () => {
    const t = setup();
    await expect(t.broker.secretRun({ command: 'node', args: ['x.mjs'], env: { NODE_OPTIONS: '--require ./x.js', DB_URL: 'secret://acme/DB_URL' } })).rejects.toThrow(/NODE_OPTIONS/);
    expect(t.calls).toHaveLength(0);
  });
});
