import { describe, it, expect } from 'vitest';
import { FakeResolver, ResolutionError } from '../src/resolver.js';

describe('FakeResolver', () => {
  it('returns a seeded value', async () => {
    const r = new FakeResolver({ 'client-work/globex-db-url': 'postgres://x' });
    await expect(r.resolve('client-work', 'globex-db-url')).resolves.toBe('postgres://x');
  });

  it('throws ResolutionError for an unknown secret', async () => {
    const r = new FakeResolver({});
    await expect(r.resolve('personal', 'nope')).rejects.toThrow(ResolutionError);
  });

  it('records what was asked for, so tests can assert no extra lookups', async () => {
    const r = new FakeResolver({ 'personal/a': '1' });
    await r.resolve('personal', 'a');
    expect(r.calls).toEqual([{ tier: 'personal', name: 'a' }]);
  });

  it('lists names for one tier only, never values', async () => {
    const r = new FakeResolver({
      'personal/a': 'secret-a',
      'personal/b': 'secret-b',
      'production/c': 'secret-c',
    });
    const names = await r.list('personal');
    expect(names.sort()).toEqual(['a', 'b']);
    expect(JSON.stringify(names)).not.toContain('secret-');
  });
});
