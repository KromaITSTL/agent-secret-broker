import { describe, it, expect } from 'vitest';
import { createBroker, parseRunRequest } from '../src/server.js';
import { FakeResolver } from '../src/resolver.js';
import type { Policy } from '../src/types.js';

const policy: Policy = {
  workspaces: [
    { match: 'c:/work/globex*', tier: 'client-work', allow: ['globex-*'], commands: ['npm run deploy'], env: ['NODE_ENV'] },
  ],
};

function makeBroker(cwd = 'C:/work/Globex') {
  const resolver = new FakeResolver({ 'client-work/globex-db-url': 'postgres://real' });
  const spawned: Array<{ cmd: string; env: Record<string, string> }> = [];
  const broker = createBroker({
    cwd,
    policy,
    resolver,
    auditPath: null,
    spawn: async (cmd, args, env) => {
      spawned.push({ cmd, env });
      return { stdout: `ran with ${env.DATABASE_URL}`, stderr: '', code: 0 };
    },
  });
  return { broker, resolver, spawned };
}

describe('secret_list', () => {
  it('returns real handles, never values', async () => {
    const { broker } = makeBroker();
    const res = await broker.secretList();
    expect(res.tier).toBe('client-work');
    expect(res.handles).toEqual(['secret://client-work/globex-db-url']);
    expect(JSON.stringify(res)).not.toContain('postgres://real');
  });

  it('filters out handles the allow patterns exclude', async () => {
    const resolver = new FakeResolver({
      'client-work/globex-db-url': 'postgres://real',
      'client-work/initech-key': 'nope',
    });
    const broker = createBroker({
      cwd: 'C:/work/Globex',
      policy,
      resolver,
      auditPath: null,
      spawn: async () => ({ stdout: '', stderr: '', code: 0 }),
    });
    const res = await broker.secretList();
    expect(res.handles).toEqual(['secret://client-work/globex-db-url']);
  });

  it('returns an empty list for an unmatched workspace', async () => {
    const { broker } = makeBroker('C:/Windows/System32');
    const res = await broker.secretList();
    expect(res.tier).toBeNull();
    expect(res.handles).toEqual([]);
  });
});

describe('secret_status', () => {
  it('reports deny for an unmatched workspace', async () => {
    const { broker } = makeBroker('C:/Windows/System32');
    const res = await broker.secretStatus();
    expect(res.tier).toBeNull();
    expect(res.authorized).toBe(false);
  });
});

describe('secret_run', () => {
  it('injects the resolved value and redacts it from output', async () => {
    const { broker, spawned } = makeBroker();
    const res = await broker.secretRun({
      command: 'npm',
      args: ['run', 'deploy'],
      env: { DATABASE_URL: 'secret://client-work/globex-db-url' },
    });
    expect(spawned[0].env.DATABASE_URL).toBe('postgres://real');
    expect(res.stdout).toBe('ran with [redacted:secret://client-work/globex-db-url]');
    expect(res.exitCode).toBe(0);
  });

  it('denies a command that is not allowlisted, and does not resolve anything', async () => {
    const { broker, resolver, spawned } = makeBroker();
    await expect(broker.secretRun({
      command: 'node',
      args: ['-e', 'console.log(process.env)'],
      env: { X: 'secret://client-work/globex-db-url' },
    })).rejects.toThrow(/not allowed/i);
    expect(resolver.calls).toEqual([]);
    expect(spawned).toEqual([]);
  });

  it('denies the whole request when one handle is out of tier', async () => {
    const { broker, resolver, spawned } = makeBroker();
    await expect(broker.secretRun({
      command: 'npm',
      args: ['run', 'deploy'],
      env: {
        A: 'secret://client-work/globex-db-url',
        B: 'secret://production/anything',
      },
    })).rejects.toThrow(/secret:\/\/production\/anything/);
    expect(resolver.calls).toEqual([]);
    expect(spawned).toEqual([]);
  });

  it('passes an allowlisted non-handle env value through untouched', async () => {
    const { broker, spawned } = makeBroker();
    await broker.secretRun({
      command: 'npm',
      args: ['run', 'deploy'],
      env: { NODE_ENV: 'production', DATABASE_URL: 'secret://client-work/globex-db-url' },
    });
    expect(spawned[0].env.NODE_ENV).toBe('production');
  });

  it('denies a non-handle env var that is not on the env allowlist, without resolving or spawning', async () => {
    // NODE_OPTIONS=--require x.js would run agent-chosen code inside the
    // child that holds the secret, bypassing the command allowlist.
    const { broker, resolver, spawned } = makeBroker();
    await expect(broker.secretRun({
      command: 'npm',
      args: ['run', 'deploy'],
      env: { NODE_OPTIONS: '--require C:/tmp/steal.js', DATABASE_URL: 'secret://client-work/globex-db-url' },
    })).rejects.toThrow(/NODE_OPTIONS/);
    expect(resolver.calls).toEqual([]);
    expect(spawned).toEqual([]);
  });

  it.each(['NODE_OPTIONS', 'PATH'])('denies a secret handle mapped to reserved env var %s, without spawning', async (key) => {
    const { broker, spawned } = makeBroker();
    await expect(broker.secretRun({
      command: 'npm',
      args: ['run', 'deploy'],
      env: { [key]: 'secret://client-work/globex-db-url' },
    })).rejects.toThrow(new RegExp(key));
    expect(spawned).toEqual([]);
  });

  it('denies all non-handle env vars when the rule has no env allowlist', async () => {
    const bare: Policy = {
      workspaces: [
        { match: 'c:/work/globex*', tier: 'client-work', allow: ['globex-*'], commands: ['npm run deploy'] },
      ],
    };
    const broker = createBroker({
      cwd: 'C:/work/Globex',
      policy: bare,
      resolver: new FakeResolver({ 'client-work/globex-db-url': 'postgres://real' }),
      auditPath: null,
      spawn: async () => ({ stdout: '', stderr: '', code: 0 }),
    });
    await expect(broker.secretRun({
      command: 'npm',
      args: ['run', 'deploy'],
      env: { NODE_ENV: 'production' },
    })).rejects.toThrow(/NODE_ENV/);
  });
});

describe('parseRunRequest', () => {
  it('accepts a well-formed request', () => {
    expect(parseRunRequest({ command: 'npm', args: ['run'], env: { A: 'b' } }))
      .toEqual({ command: 'npm', args: ['run'], env: { A: 'b' } });
  });

  it.each([
    [null],
    [{ command: 42, args: [], env: {} }],
    [{ command: 'npm', args: 'run', env: {} }],
    [{ command: 'npm', args: [1], env: {} }],
    [{ command: 'npm', args: [], env: { A: 1 } }],
    [{ command: 'npm', args: [], env: null }],
  ])('rejects malformed input %#', (input) => {
    expect(() => parseRunRequest(input)).toThrow(/invalid secret_run arguments/);
  });
});
