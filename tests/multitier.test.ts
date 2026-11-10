import { describe, it, expect } from 'vitest';
import { createBroker } from '../src/server.js';
import { matchWorkspace, isHandleAllowed } from '../src/policy.js';
import { FakeResolver, TierRouter, ResolutionError } from '../src/resolver.js';
import type { Grant, Policy } from '../src/types.js';

// A home folder spanning every tier, restricted to itself, above a normal
// per-project rule and a broad catch-all.
const policy: Policy = {
  workspaces: [
    { match: 'c:/work', exact: true, tier: ['personal', 'client-work', 'production'], allow: ['*'], commands: ['node **'] },
    { match: 'c:/work/initechfull', tier: 'client-work', allow: ['DO_TOKEN'], commands: ['doctl **'] },
  ],
};

describe('multi-tier exact rules', () => {
  it('grants every listed tier to the exact directory', () => {
    expect(matchWorkspace(policy, 'C:\\work')?.tiers).toEqual(['personal', 'client-work', 'production']);
  });

  it('does not leak the home grant into an unruled subfolder', () => {
    expect(matchWorkspace(policy, 'C:/work/some-other-project')).toBeNull();
  });

  it('lets a project under the home folder keep its own narrower rule', () => {
    expect(matchWorkspace(policy, 'C:/work/InitechFull/api')?.tiers).toEqual(['client-work']);
  });

  it('without exact, a parent rule still covers its subtree', () => {
    const broad: Policy = { workspaces: [{ match: 'c:/work', tier: ['personal'], allow: ['*'], commands: [] }] };
    expect(matchWorkspace(broad, 'C:/work/anything')?.tiers).toEqual(['personal']);
  });

  it('allows handles from any granted tier and denies the rest', () => {
    const g: Grant = { tiers: ['personal', 'production'], allow: ['*'], commands: [] };
    expect(isHandleAllowed(g, 'secret://personal/a')).toBe(true);
    expect(isHandleAllowed(g, 'secret://production/b')).toBe(true);
    expect(isHandleAllowed(g, 'secret://client-work/c')).toBe(false);
  });

  it('lists handles across all granted tiers and labels the grant', async () => {
    const broker = createBroker({
      cwd: 'C:/work',
      policy,
      resolver: new FakeResolver({ 'personal/a': '1', 'client-work/b': '2', 'production/c': '3' }),
      auditPath: null,
      spawn: async () => ({ stdout: '', stderr: '', code: 0 }),
    });
    const status = await broker.secretStatus();
    expect(status.authorized).toBe(true);
    expect(status.tier).toBe('personal+client-work+production');
    expect(status.tiers).toEqual(['personal', 'client-work', 'production']);
    const list = await broker.secretList();
    expect(list.handles).toEqual(['secret://personal/a', 'secret://client-work/b', 'secret://production/c']);
  });
});

describe('TierRouter', () => {
  it('routes each tier to its own resolver', async () => {
    const personal = new FakeResolver({ 'personal/a': 'p' });
    const production = new FakeResolver({ 'production/a': 'q' });
    const router = new TierRouter({ personal, production });
    expect(await router.resolve('personal', 'a')).toBe('p');
    expect(await router.resolve('production', 'a')).toBe('q');
  });

  it('fails closed for a tier with no loaded token', () => {
    const router = new TierRouter({ personal: new FakeResolver({}) });
    expect(() => router.resolve('production', 'a')).toThrow(ResolutionError);
  });
});
