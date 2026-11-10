import { describe, expect, it } from 'vitest';
import {
  decryptBackup, encryptBackup, generateBackupKeyPair, generateMasterKey, loadMasterKey, openToken, openValue, rewrap, rewrapToken, sealToken, sealValue,
} from '../src/crypto';

describe('envelope encryption', () => {
  it('round-trips and binds ciphertext to tier, name and version', async () => {
    const m = (await loadMasterKey(generateMasterKey()))!;
    const s = await sealValue(m, 'personal', 'GITHUB_TOKEN', 3, 'ghp_value');
    expect(JSON.stringify(s)).not.toContain('ghp_value');
    expect(await openValue([m], 'personal', 'GITHUB_TOKEN', 3, s)).toBe('ghp_value');
    await expect(openValue([m], 'personal', 'OTHER', 3, s)).rejects.toThrow(/decryption failed/);
    await expect(openValue([m], 'production', 'GITHUB_TOKEN', 3, s)).rejects.toThrow(/decryption failed/);
    await expect(openValue([m], 'personal', 'GITHUB_TOKEN', 2, s)).rejects.toThrow(/decryption failed/);
  });

  it('fails with the wrong master key and supports rotation', async () => {
    const a = (await loadMasterKey(generateMasterKey()))!;
    const b = (await loadMasterKey(generateMasterKey()))!;
    const s = await sealValue(a, 'personal', 'X', 1, 'v');
    await expect(openValue([b], 'personal', 'X', 1, s)).rejects.toThrow(/no master key loaded/);
    const r = await rewrap([a, b], b, 'personal', 'X', 1, s);
    expect(r.kid).toBe(b.id);
    expect(r.ct).toBe(s.ct);
    expect(await openValue([b], 'personal', 'X', 1, r)).toBe('v');
  });

  it('rejects malformed master keys', async () => {
    await expect(loadMasterKey('AAAA')).rejects.toThrow(/32 bytes/);
    expect(await loadMasterKey('')).toBeNull();
  });

  it('seals connection tokens bound to conn:<id>, never openable as a secret value or another connection', async () => {
    const mk = (await loadMasterKey(generateMasterKey()))!;
    const s = await sealToken(mk, 'c1', 'vercel-token-abc');
    expect(await openToken([mk], 'c1', s)).toBe('vercel-token-abc');
    await expect(openToken([mk], 'c2', s)).rejects.toThrow('decryption failed');
    await expect(openValue([mk], 'conn', 'c1', 1, s)).rejects.toThrow('decryption failed');
    const next = (await loadMasterKey(generateMasterKey()))!;
    const r = await rewrapToken([mk, next], next, 'c1', s);
    expect(r.kid).toBe(next.id);
    expect(await openToken([next], 'c1', r)).toBe('vercel-token-abc');
  });
});

describe('backups', () => {
  it('encrypts to the public key; only the private key decrypts', async () => {
    const kp = await generateBackupKeyPair();
    const other = await generateBackupKeyPair();
    const env = await encryptBackup(kp.publicPem, '{"secrets":"s3cret"}');
    expect(JSON.stringify(env)).not.toContain('s3cret');
    expect(await decryptBackup(kp.privatePem, env)).toBe('{"secrets":"s3cret"}');
    await expect(decryptBackup(other.privatePem, env)).rejects.toThrow(/does not match/);
    await expect(decryptBackup(kp.privatePem, { ...env, createdAt: '2000-01-01T00:00:00.000Z' })).rejects.toThrow(/decryption failed/);
  }, 30000);
});
