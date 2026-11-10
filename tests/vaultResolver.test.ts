import { describe, expect, it } from 'vitest';
import { storeTierToken } from '../src/keychain.js';
import { isVaultToken, VaultResolver, vaultOrigin } from '../src/vaultResolver.js';

const origin = (o: string) => Buffer.from(o).toString('base64url');
const TOKEN = `sbv.${origin('https://vault.example.dev')}.abc123.s3cretPart_-x`;

function fakeFetch(status: number, body: unknown, seen: string[] = []) {
  return (async (url: string, init?: RequestInit) => {
    seen.push(`${url} ${new Headers(init?.headers).get('authorization')}`);
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
}

describe('vault tokens', () => {
  it('recognises vault tokens and reads the origin from them', () => {
    expect(isVaultToken(TOKEN)).toBe(true);
    expect(isVaultToken('not-a-vault-token')).toBe(false);
    expect(isVaultToken(null)).toBe(false);
    expect(vaultOrigin(TOKEN)).toBe('https://vault.example.dev');
  });

  it('refuses a non-https origin except localhost', () => {
    expect(() => vaultOrigin(`sbv.${origin('http://evil.example')}.a.b`)).toThrow(/https/);
    expect(vaultOrigin(`sbv.${origin('http://localhost:8788')}.a.b`)).toBe('http://localhost:8788');
  });

  it('can be stored in the keychain', () => {
    const written: string[] = [];
    storeTierToken('personal', `  ${TOKEN}\n`, (_s, _a, t) => written.push(t));
    expect(written).toEqual([TOKEN]);
    expect(() => storeTierToken('personal', 'sbv.only.three', () => {})).toThrow(/malformed/);
  });
});

describe('VaultResolver', () => {
  it('loads the tier once with the bearer token, then resolves and lists from cache', async () => {
    const seen: string[] = [];
    const r = new VaultResolver(TOKEN, 'personal', fakeFetch(200, { tier: 'personal', secrets: { A: 'one', B: 'two' } }, seen));
    expect(await r.resolve('personal', 'A')).toBe('one');
    expect((await r.list('personal')).sort()).toEqual(['A', 'B']);
    expect(seen).toEqual([`https://vault.example.dev/api/v1/secrets?tier=personal Bearer ${TOKEN}`]);
    await expect(r.resolve('personal', 'NOPE')).rejects.toThrow(/no secret named NOPE/);
  });

  it('explains vault refusals', async () => {
    await expect(new VaultResolver(TOKEN, 'personal', fakeFetch(401, {})).list('personal')).rejects.toThrow(/revoked/);
    await expect(new VaultResolver(TOKEN, 'production', fakeFetch(403, {})).list('production')).rejects.toThrow(/not allowed to read tier production/);
    await expect(new VaultResolver(TOKEN, 'personal', fakeFetch(423, {})).list('personal')).rejects.toThrow(/frozen/);
  });

  it('reports an unreachable vault', async () => {
    const failing = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    await expect(new VaultResolver(TOKEN, 'personal', failing).list('personal')).rejects.toThrow(/could not reach the vault/);
  });
});
