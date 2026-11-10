import { describe, it, expect } from 'vitest';
import { loadTierToken, storeTierToken, SERVICE_NAME } from '../src/keychain.js';

const VALID_TOKEN = `sbv.${Buffer.from('https://vault.example.dev').toString('base64url')}.abc123.s3cretPart_-x`;

describe('loadTierToken', () => {
  it('reads the token for the tier from the keychain', () => {
    const read = (service: string, account: string) =>
      service === SERVICE_NAME && account === 'client-work' ? VALID_TOKEN : null;
    expect(loadTierToken('client-work', read)).toBe(VALID_TOKEN);
  });

  it('returns null for a stored value that is not a vault machine token', () => {
    expect(loadTierToken('client-work', () => 'not-a-vault-token')).toBeNull();
  });

  it('returns null when the tier has no stored token', () => {
    expect(loadTierToken('production', () => null)).toBeNull();
  });

  it('returns null rather than throwing when the keychain errors', () => {
    const read = () => { throw new Error('keychain locked'); };
    expect(loadTierToken('personal', read)).toBeNull();
  });

  it('never reads a tier other than the one requested', () => {
    const seen: string[] = [];
    const read = (_s: string, account: string) => { seen.push(account); return VALID_TOKEN; };
    loadTierToken('personal', read);
    expect(seen).toEqual(['personal']);
  });
});

describe('storeTierToken', () => {
  it('writes under the service name and tier account', () => {
    const calls: Array<{ service: string; account: string; token: string }> = [];
    storeTierToken('client-work', VALID_TOKEN, (service, account, token) => {
      calls.push({ service, account, token });
    });
    expect(calls).toEqual([{ service: SERVICE_NAME, account: 'client-work', token: VALID_TOKEN }]);
  });

  it('rejects an empty token rather than storing a useless entry', () => {
    expect(() => storeTierToken('personal', '   ', () => {})).toThrow(/empty/i);
  });

  it('strips surrounding whitespace from a pasted token', () => {
    let stored = '';
    storeTierToken('personal', `\n  ${VALID_TOKEN}\t`, (_s, _a, token) => { stored = token; });
    expect(stored).toBe(VALID_TOKEN);
  });

  it('rejects a token mangled by a bad paste instead of storing it', () => {
    expect(() => storeTierToken('client-work', `-${VALID_TOKEN}`, () => {})).toThrow(/malformed/i);
    expect(() => storeTierToken('client-work', `"${VALID_TOKEN}"`, () => {})).toThrow(/malformed/i);
    expect(() => storeTierToken('client-work', 'not-a-vault-token', () => {})).toThrow(/malformed/i);
  });
});
