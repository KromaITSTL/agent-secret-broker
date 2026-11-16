// Run approvals: the local broker asks the dashboard, and the Worker hands out values only for approved runs.
import { describe, expect, it } from 'vitest';
import { createBroker, DeniedError, type AuditEvent, type SecretSource } from '../src/broker';
import { GrantError, GrantLogic } from '../src/grants';
import { isExfilCapable, runRule, validatePolicy, type Tier } from '../src/policy';
import { MapKv } from './helpers';

const VAULT: Record<Tier, Record<string, string>> = {
  acme: { DB_URL: 'postgres://acme-db-value', SERVICE_KEY: 'acme-service-key-value' },
  production: { PROD_KEY: 'prod-key-value' },
};

function source(): SecretSource {
  return {
    vaults: async () => Object.keys(VAULT).map((slug) => ({ slug, name: slug, strict: true, repos: [] })),
    load: async (t) => new Map(Object.entries(VAULT[t] ?? {})),
    loginInfo: async () => null,
    readSecret: async (t, n) => VAULT[t]?.[n] ?? null,
  };
}

function world(now = () => Date.now()) {
  let n = 0;
  const grants = new GrantLogic(new MapKv(), now, () => `id${++n}`);
  const events: AuditEvent[] = [];
  const broker = createBroker({ policy: { rules: [] }, grants, source: source(), user: 'machine:alice-pc', audit: (e) => events.push(e), publicUrl: 'https://vault.example.com', now });
  return { grants, broker, events };
}

const REPO = 'acme/site';

describe('run rules', () => {
  it('validates run rules: commands required, no hosts, free interpreters refused in production', () => {
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['supabase db push *'] }] })).not.toThrow();
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: [] }] })).toThrow(/commands/);
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['x'], hosts: ['a.example.com'] }] })).toThrow(/instead of hosts/);
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['**'] }] })).toThrow(/command line/);
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'production', secrets: ['PROD_KEY'], commands: ['node **'] }] })).toThrow(/free arguments/);
    expect(() => validatePolicy({ rules: [{ tier: 'acme', secrets: ['DB_URL'], hosts: ['a.example.com'], methods: ['GET'], commands: ['x'] }] })).toThrow(/only run rules/);
  });

  it('flags commands that let an interpreter run free arguments', () => {
    expect(isExfilCapable(['node **'])).toBe(true);
    expect(isExfilCapable(['bash *'])).toBe(true);
    expect(isExfilCapable(['supabase db push *', 'node scripts/migrate.mjs'])).toBe(false);
  });

  it('matches the command line and requires every env name to be allowed', () => {
    const p = validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['supabase db push *'], env: ['SUPABASE_*'] }] });
    expect(runRule(p, 'secret://acme/DB_URL', 'supabase db push --dry-run')).not.toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'supabase db reset')).toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'supabase db push x', ['SUPABASE_DEBUG'])).not.toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'supabase db push x', ['NODE_OPTIONS'])).toBeNull();
    expect(runRule(p, 'secret://acme/SERVICE_KEY', 'supabase db push x')).toBeNull();
  });
});

describe('broker.run', () => {
  it('refuses before approval, then returns only the approved values once approved', async () => {
    const w = world();
    const run = { repo: 'Acme/Site', command: 'supabase', args: ['db', 'push'], handles: ['secret://acme/DB_URL'] };
    await expect(w.broker.run(run)).rejects.toThrow(/not approved for supabase db push in acme\/site/);
    const req = await w.broker.requestAccess({ repo: REPO, reason: 'migrations', items: [{ handle: 'secret://acme/DB_URL', commands: ['supabase db push *'] }] });
    expect(req.approvalUrl).toBe('https://vault.example.com/approve/id1');
    expect(req.next).toMatch(/secret_run/);
    await w.grants.approve('id1', [0], 'alice');
    expect(await w.broker.run(run)).toEqual({ values: { 'secret://acme/DB_URL': 'postgres://acme-db-value' } });
    expect(w.events.at(-1)).toMatchObject({ event: 'secret_run', outcome: 'allowed', repo: REPO, command: 'supabase db push', handles: ['secret://acme/DB_URL'] });
    expect(JSON.stringify(w.events)).not.toContain('acme-db-value');
  });

  it('refuses another command, another repo, and an unapproved handle in the same run', async () => {
    const w = world();
    await w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: ['supabase db push *'] }] });
    await w.grants.approve('id1', [0], 'alice');
    const base = { repo: REPO, command: 'supabase', args: ['db', 'push'], handles: ['secret://acme/DB_URL'] };
    await expect(w.broker.run({ ...base, args: ['db', 'reset'] })).rejects.toBeInstanceOf(DeniedError);
    await expect(w.broker.run({ ...base, repo: 'acme/other' })).rejects.toBeInstanceOf(DeniedError);
    await expect(w.broker.run({ ...base, handles: ['secret://acme/DB_URL', 'secret://acme/SERVICE_KEY'] })).rejects.toThrow(/SERVICE_KEY is not approved/);
    await expect(w.broker.run({ ...base, env: ['NODE_OPTIONS'] })).rejects.toBeInstanceOf(DeniedError);
  });

  it('counts uses and stops when they run out; an expired approval refuses', async () => {
    let clock = 1_000_000;
    const w = world(() => clock);
    await w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: ['node scripts/migrate.mjs'] }, { handle: 'secret://acme/SERVICE_KEY', commands: ['node scripts/seed.mjs'] }] });
    await w.grants.approve('id1', [0, 1], 'alice', { 0: { uses: 1 }, 1: { ttlMs: 60_000 } });
    const migrate = { repo: REPO, command: 'node', args: ['scripts/migrate.mjs'], handles: ['secret://acme/DB_URL'] };
    await expect(w.broker.run(migrate)).resolves.toBeTruthy();
    await expect(w.broker.run(migrate)).rejects.toBeInstanceOf(DeniedError);
    const seed = { repo: REPO, command: 'node', args: ['scripts/seed.mjs'], handles: ['secret://acme/SERVICE_KEY'] };
    await expect(w.broker.run(seed)).resolves.toBeTruthy();
    clock += 60_000;
    await expect(w.broker.run(seed)).rejects.toBeInstanceOf(DeniedError);
  });

  it('refuses malformed input without throwing a TypeError', async () => {
    const w = world();
    await expect(w.broker.run({ repo: REPO, command: 'x', args: 'nope', handles: [] } as never)).rejects.toBeInstanceOf(DeniedError);
    await expect(w.broker.run({ repo: REPO, command: 'x', args: [], handles: [] })).rejects.toThrow(/no secret/);
    await expect(w.broker.run({ repo: 'not a repo', command: 'x', args: [], handles: ['secret://acme/DB_URL'] })).rejects.toBeInstanceOf(DeniedError);
  });

  it('lists run approvals for the local broker, and refuses mixed or free-interpreter production requests', async () => {
    const w = world();
    await w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: ['supabase db push *'] }] });
    await w.grants.approve('id1', [0], 'alice');
    const listed = await w.broker.list(REPO);
    expect(listed.secrets.find((s) => s.handle === 'secret://acme/DB_URL')).toMatchObject({ approved: false, runCommands: ['supabase db push *'] });
    expect(listed.secrets.find((s) => s.handle === 'secret://acme/SERVICE_KEY')).toMatchObject({ approved: false });
    await expect(w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: ['x'], hosts: ['a.example.com'] }] })).rejects.toBeInstanceOf(GrantError);
    await expect(w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://production/PROD_KEY', commands: ['node **'] }] })).rejects.toThrow(/free arguments/);
  });
});

describe('review fixes', () => {
  it('matches case-insensitively, folds .exe and backslashes, and lets a trailing * take arguments with slashes', () => {
    const p = validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['supabase db push *', 'node scripts/*.mjs'] }] });
    expect(runRule(p, 'secret://acme/DB_URL', 'supabase db push --db-url postgres://u@h/db')).not.toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'SUPABASE.exe db push')).not.toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'node scripts/seed.mjs')).not.toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', String.raw`node scripts\..\..\tmp\x.mjs`)).toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'supabase db pushx')).toBeNull();
  });

  it('recognises more ways to run free code, whatever the case', () => {
    for (const c of ['NODE **', 'node.exe **', 'perl *', 'env **', 'git *', 'ruby *', 'npm exec *', 'docker *']) {
      expect(isExfilCapable([c]), c).toBe(true);
    }
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'production', secrets: ['PROD_KEY'], commands: ['NODE **'] }] })).toThrow(/free arguments/);
  });

  it('refuses env names that load code, including wildcards that cover them', () => {
    for (const e of ['*', 'NODE_OPTIONS', 'NODE_*', 'LD_PRELOAD', 'HTTPS_PROXY', 'PATH', 'node_options']) {
      expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['x'], env: [e] }] }), e).toThrow();
    }
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['x'], env: ['SUPABASE_DEBUG'] }] })).not.toThrow();
  });

  it('stores a clean copy of each item: unknown keys dropped, strings trimmed, bad shapes refused', async () => {
    const w = world();
    await w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: [' node scripts/a.mjs '], action: 'run' } as never] });
    const req = await w.grants.getRequest('id1');
    expect(req!.items).toEqual([{ handle: 'secret://acme/DB_URL', commands: ['node scripts/a.mjs'] }]);
    await expect(w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: ['x'], env: 'NODE_OPTIONS' } as never] })).rejects.toBeInstanceOf(GrantError);
    await expect(w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: [' node ** '] }] })).resolves.toBeTruthy();
    const wide = await w.grants.getRequest('id2');
    expect(wide!.items[0]!.commands).toEqual(['node **']);
  });

  it('refuses a program name with spaces in it', async () => {
    const w = world();
    await w.broker.requestAccess({ repo: REPO, reason: 'x', items: [{ handle: 'secret://acme/DB_URL', commands: ['tool other'] }] });
    await w.grants.approve('id1', [0], 'alice');
    await expect(w.broker.run({ repo: REPO, command: 'tool other', args: [], handles: ['secret://acme/DB_URL'] })).rejects.toBeInstanceOf(DeniedError);
  });
});

describe('second-round fixes', () => {
  it('keeps argument case and stops * at spaces', () => {
    const p = validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['git -C * push'] }] });
    expect(runRule(p, 'secret://acme/DB_URL', 'git -C repo push')).not.toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'git -c core.hooksPath=. push')).toBeNull();
    expect(runRule(p, 'secret://acme/DB_URL', 'git -C x -c core.hooksPath=. push')).toBeNull();
  });

  it('flags full program paths and more launchers', () => {
    for (const c of ['C:/nodejs/node.exe **', '**/node *', 'node --eval *', 'python -m *', 'bash -lc *', 'pwsh -command *', 'uvx *', 'bunx *', 'pnpm exec *', 'npm run *']) {
      expect(isExfilCapable([c]), c).toBe(true);
    }
  });

  it('refuses env names tools read for helpers, homes and options, but allows NODE_ENV', () => {
    for (const e of ['GIT_ASKPASS', 'GIT_SSH', 'HOME', 'JDK_JAVA_OPTIONS', 'DOTNET_STARTUP_HOOKS', 'SSH_ASKPASS', 'USERPROFILE', 'MAVEN_OPTS', '*_OPTIONS', 'NODE_OPT*']) {
      expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['x'], env: [e] }] }), e).toThrow();
    }
    expect(() => validatePolicy({ rules: [{ action: 'run', tier: 'acme', secrets: ['DB_URL'], commands: ['x'], env: ['NODE_ENV', 'SUPABASE_DEBUG'] }] })).not.toThrow();
  });
});
