import { describe, it, expect } from 'vitest';
import { normalizePath, matchWorkspace, isExfilCapable, isReservedEnvKey } from '../src/policy.js';
import type { Policy } from '../src/types.js';

/**
 * These assertions are platform-independent by construction. The earlier
 * version passed only on Windows, because it relied on `path.resolve`
 * treating `C:/...` as absolute. It would have failed on the Mac mini,
 * which is a deployment target.
 */
describe('normalizePath', () => {
  it('converts backslashes to forward slashes', () => {
    expect(normalizePath('C:\\work\\Globex')).toBe('c:/work/globex');
  });

  it('lowercases so Windows matching is case-insensitive', () => {
    expect(normalizePath('C:/Work/GLOBEX')).toBe('c:/work/globex');
  });

  it('collapses .. so traversal cannot forge a prefix', () => {
    expect(normalizePath('C:/work/Globex/../Production')).toBe('c:/work/production');
  });

  it('collapses .. when the input uses backslashes', () => {
    // Regression: the original implementation converted separators AFTER
    // path.resolve, so on POSIX this returned a string still containing
    // '../' and would have matched the wrong policy glob.
    expect(normalizePath('C:\\work\\Globex\\..\\Production')).toBe('c:/work/production');
  });

  it('collapses .. in POSIX-style absolute paths', () => {
    expect(normalizePath('/Users/alice/dev/globex/../production')).toBe('/users/alice/dev/production');
  });

  it('collapses mixed separators in one path', () => {
    expect(normalizePath('C:\\work/Globex\\..\\Production')).toBe('c:/work/production');
  });

  it('collapses single-dot segments', () => {
    expect(normalizePath('C:/work/./Globex')).toBe('c:/work/globex');
  });

  it('strips trailing slashes', () => {
    expect(normalizePath('C:/work/Globex/')).toBe('c:/work/globex');
  });

  it('yields a relative path when traversal escapes the drive root, which matches no absolute glob', () => {
    // Deny is the correct failure direction: this can no longer match
    // a policy rule like 'c:/work/*'.
    const result = normalizePath('C:/work/../../Windows/System32');
    expect(result).not.toBeNull();
    expect(result?.startsWith('c:/')).toBe(false);
  });

  it('returns null for empty input rather than a matchable value', () => {
    expect(normalizePath('')).toBeNull();
  });

  it('returns null for whitespace-only input', () => {
    expect(normalizePath('   ')).toBeNull();
  });
});

const policy: Policy = {
  workspaces: [
    { match: 'c:/work/globex*', tier: 'client-work', allow: ['globex-*'], commands: ['npx prisma *'] },
    { match: 'c:/work/*', tier: 'personal', allow: ['*'], commands: ['npm run *'] },
  ],
};

describe('matchWorkspace', () => {
  it('returns the first matching rule, not the most specific', () => {
    const grant = matchWorkspace(policy, 'C:/work/Globex/api');
    expect(grant?.tiers).toEqual(['client-work']);
  });

  it('falls through to a later rule when earlier ones miss', () => {
    const grant = matchWorkspace(policy, 'C:/work/Umbrella');
    expect(grant?.tiers).toEqual(['personal']);
  });

  it('denies an unmatched workspace instead of defaulting', () => {
    expect(matchWorkspace(policy, 'C:/Windows/System32')).toBeNull();
  });

  it('denies when the path cannot be normalized', () => {
    expect(matchWorkspace(policy, '')).toBeNull();
  });

  it('denies traversal that would otherwise forge a prefix', () => {
    expect(matchWorkspace(policy, 'C:/work/Globex/../../Windows')).toBeNull();
  });

  it('denies an empty policy', () => {
    expect(matchWorkspace({ workspaces: [] }, 'C:/work/Globex')).toBeNull();
  });
});

describe('matchWorkspace with name-prefix patterns', () => {
  // Regression: a trailing-* rewrite to /** turned 'c:/work/client-*' into
  // 'c:/work/client-/**', which matched nothing at all.
  const prefixPolicy: Policy = {
    workspaces: [
      { match: 'c:/work/client-*', tier: 'client-work', allow: ['*'], commands: [] },
    ],
  };

  it('matches the sibling directory itself', () => {
    expect(matchWorkspace(prefixPolicy, 'C:/work/client-acme')?.tiers).toEqual(['client-work']);
  });

  it('matches subdirectories of a prefix match', () => {
    expect(matchWorkspace(prefixPolicy, 'C:/work/client-acme/api/src')?.tiers).toEqual(['client-work']);
  });

  it('does not match an unprefixed sibling', () => {
    expect(matchWorkspace(prefixPolicy, 'C:/work/other')).toBeNull();
  });
});

describe('isExfilCapable', () => {
  it('flags allowlists that let an interpreter take free arguments', () => {
    for (const c of ['**', '*', 'node **', 'node *', 'powershell **']) expect(isExfilCapable([c]), c).toBe(true);
  });

  it('accepts empty and specific allowlists', () => {
    expect(isExfilCapable([])).toBe(false);
    expect(isExfilCapable(['node scripts/deploy.js'])).toBe(false);
    expect(isExfilCapable(['gh pr list'])).toBe(false);
  });
});

describe('isReservedEnvKey', () => {
  it('flags env vars the child runtime reads, case-insensitively', () => {
    for (const k of ['PATH', 'NODE_OPTIONS', 'LD_PRELOAD', 'HTTPS_PROXY', 'node_options']) expect(isReservedEnvKey(k), k).toBe(true);
  });

  it('allows ordinary credential names', () => {
    expect(isReservedEnvKey('DATABASE_URL')).toBe(false);
    expect(isReservedEnvKey('API_KEY')).toBe(false);
  });
});
