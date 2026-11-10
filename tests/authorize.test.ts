import { describe, it, expect } from 'vitest';
import { parseHandle, isHandleAllowed } from '../src/policy.js';
import type { Grant } from '../src/types.js';

const grant: Grant = { tiers: ['client-work'], allow: ['globex-*'], commands: [] };

describe('parseHandle', () => {
  it('parses a well-formed handle', () => {
    expect(parseHandle('secret://client-work/globex-db-url'))
      .toEqual({ tier: 'client-work', name: 'globex-db-url' });
  });

  it('rejects a non-secret scheme', () => {
    expect(parseHandle('https://client-work/x')).toBeNull();
  });

  it('accepts any well-formed vault name (authorization is the grant\'s job)', () => {
    expect(parseHandle('secret://acme-finance/DB_URL')).toEqual({ tier: 'acme-finance', name: 'DB_URL' });
  });

  it('rejects a malformed vault name', () => {
    expect(parseHandle('secret://Made_Up/x')).toBeNull();
  });

  it('rejects a missing name', () => {
    expect(parseHandle('secret://client-work/')).toBeNull();
  });

  it('rejects a name containing a slash', () => {
    expect(parseHandle('secret://client-work/a/b')).toBeNull();
  });
});

describe('isHandleAllowed', () => {
  it('allows a handle in tier that matches an allow pattern', () => {
    expect(isHandleAllowed(grant, 'secret://client-work/globex-db-url')).toBe(true);
  });

  it('denies a handle from another tier', () => {
    expect(isHandleAllowed(grant, 'secret://production/globex-db-url')).toBe(false);
  });

  it('denies a handle in tier that matches no allow pattern', () => {
    expect(isHandleAllowed(grant, 'secret://client-work/initech-key')).toBe(false);
  });

  it('denies when allow is empty', () => {
    expect(isHandleAllowed({ ...grant, allow: [] }, 'secret://client-work/globex-db-url')).toBe(false);
  });

  it('denies an unparseable handle', () => {
    expect(isHandleAllowed(grant, 'not-a-handle')).toBe(false);
  });

  it('honours a wildcard allow', () => {
    expect(isHandleAllowed({ ...grant, allow: ['*'] }, 'secret://client-work/anything')).toBe(true);
  });
});
