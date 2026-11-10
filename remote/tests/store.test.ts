import { describe, expect, it } from 'vitest';
import { decryptBackup, encryptBackup, generateBackupKeyPair, generateMasterKey, loadMasterKey, type MasterKey } from '../src/crypto';
import { GrantLogic, isLive, itemToRule, validateRequestInput } from '../src/grants';
import { CONN_ID_RE, TRASH_DAYS, VaultLogic, defaultVarName, envGroup, type Snapshot } from '../src/store';
import { MapKv } from './helpers';

async function setup() {
  const kv = new MapKv();
  const key = (await loadMasterKey(generateMasterKey()))!;
  let now = 1_700_000_000_000;
  const v = new VaultLogic(kv, { current: key, all: [key] }, () => now);
  await v.createVault({ slug: 'client-work', name: 'Client work', strict: false, by: 'test' });
  return { kv, key, v, tick: (ms: number) => (now += ms) };
}

describe('secrets', () => {
  it('stores only ciphertext and returns values only via loadTier', async () => {
    const { kv, v } = await setup();
    await v.putSecret('personal', 'GITHUB_TOKEN', 'ghp_plaintext_value', 'alice');
    expect(JSON.stringify([...kv.m.values()])).not.toContain('ghp_plaintext_value');
    expect(JSON.stringify(await v.listSecrets())).not.toContain('ghp_plaintext_value');
    expect(await v.loadTier('personal')).toEqual(new Map([['GITHUB_TOKEN', 'ghp_plaintext_value']]));
    expect((await v.loadTier('production')).size).toBe(0);
  });

  it('keeps version history and restores an old version as a new one', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'K', 'one', 'alice');
    await v.putSecret('personal', 'K', 'two', 'alice');
    expect((await v.loadTier('personal')).get('K')).toBe('two');
    const m = await v.restoreVersion('personal', 'K', 1, 'alice');
    expect(m.current).toBe(3);
    expect(m.versions.map((x) => x.v)).toEqual([1, 2, 3]);
    expect(m.versions[2]!.note).toBe('restored from v1');
    expect((await v.loadTier('personal')).get('K')).toBe('one');
  });

  it('caps history at 20 versions', async () => {
    const { kv, v } = await setup();
    for (let i = 1; i <= 23; i++) await v.putSecret('personal', 'K', `v${i}`, 'b');
    const m = (await v.getMeta('personal', 'K'))!;
    expect(m.versions.length).toBe(20);
    expect(m.versions[0]!.v).toBe(4);
    expect([...kv.m.keys()].filter((k) => k.startsWith('ver:')).length).toBe(20);
  });

  it('trash hides from use, can be restored, and purges after 30 days', async () => {
    const { v, tick } = await setup();
    await v.putSecret('client-work', 'A', 'x', 'b');
    await v.deleteSecret('client-work', 'A', 'b');
    expect((await v.loadTier('client-work')).size).toBe(0);
    expect((await v.listSecrets({ trash: true })).map((m) => m.name)).toEqual(['A']);
    await v.undeleteSecret('client-work', 'A', 'b');
    expect((await v.loadTier('client-work')).get('A')).toBe('x');
    await v.deleteSecret('client-work', 'A', 'b');
    await expect(v.purge('personal', 'NOPE', 'b')).rejects.toThrow();
    tick(TRASH_DAYS * 86400_000 + 1);
    expect(await v.listSecrets({ trash: true })).toEqual([]);
    expect(await v.getMeta('client-work', 'A')).toBeNull();
  });

  it('validates names, tiers and size', async () => {
    const { v } = await setup();
    await expect(v.putSecret('staging', 'A', 'x', 'b')).rejects.toThrow(/no vault named staging/);
    await expect(v.putSecret('Bad_Vault', 'A', 'x', 'b')).rejects.toThrow(/vault names/);
    await expect(v.putSecret('personal', 'bad name', 'x', 'b')).rejects.toThrow(/name/);
    await expect(v.putSecret('personal', 'A', '', 'b')).rejects.toThrow(/empty/);
    await expect(v.putSecret('personal', 'A', 'x'.repeat(33 * 1024), 'b')).rejects.toThrow(/larger/);
  });

  it('freeze blocks every use', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'A', 'x', 'b');
    await v.setFrozen(true, 'alice');
    await expect(v.loadTier('personal')).rejects.toThrow(/frozen/);
    await v.setFrozen(false, 'alice');
    expect((await v.loadTier('personal')).get('A')).toBe('x');
  });

  it('fails clearly without a master key', async () => {
    const v = new VaultLogic(new MapKv(), { current: null, all: [] });
    await expect(v.putSecret('personal', 'A', 'x', 'b')).rejects.toThrow(/VAULT_MASTER_KEY/);
  });
});

describe('client registration window', () => {
  it('accepts a take just before 15 minutes and refuses at 15 minutes', async () => {
    const { v, tick } = await setup();
    await v.openRegistration('alice');
    tick(15 * 60_000 - 1);
    expect(await v.takeRegistration({ name: 'Claude', hosts: ['claude.ai'] })).toBe(true);
    tick(1);
    expect(await v.takeRegistration({ name: 'Claude', hosts: ['claude.ai'] })).toBe(false);
    expect(await v.registrationStatus()).toEqual({ until: 0, left: 0 });
  });
});

describe('logins', () => {
  const L = { username: 'agent@example.com', url: 'https://portal.example.com/login', notes: 'MFA off' };

  it('keeps login fields across replace and move, edits them without a new version, and reads one secret', async () => {
    const { kv, v } = await setup();
    await v.putSecret('personal', 'PORTAL', 'pw-1', 'b', undefined, L);
    expect(await v.getMeta('personal', 'PORTAL')).toMatchObject({ kind: 'login', login: L });
    expect(await v.loginInfo('personal', 'PORTAL')).toEqual(L);
    expect(JSON.stringify([...kv.m.values()])).not.toContain('pw-1');
    await v.putSecret('personal', 'PORTAL', 'pw-2', 'b');
    expect((await v.getMeta('personal', 'PORTAL'))!.login).toEqual(L);
    expect(await v.readSecret('personal', 'PORTAL')).toBe('pw-2');
    const m = await v.updateLogin('personal', 'PORTAL', { username: 'other@example.com' }, 'b');
    expect(m.login).toEqual({ username: 'other@example.com' });
    expect(m.current).toBe(2);
    await v.moveSecret('personal', 'PORTAL', 'client-work', 'b');
    expect(await v.loginInfo('client-work', 'PORTAL')).toEqual({ username: 'other@example.com' });
    expect(await v.readSecret('personal', 'PORTAL')).toBeNull();
    await v.deleteSecret('client-work', 'PORTAL', 'b');
    expect(await v.readSecret('client-work', 'PORTAL')).toBeNull();
    expect(await v.loginInfo('client-work', 'PORTAL')).toBeNull();
    await v.putSecret('personal', 'KEY', 'k', 'b');
    expect(await v.loginInfo('personal', 'KEY')).toBeNull();
    await expect(v.updateLogin('personal', 'KEY', { username: 'x' }, 'b')).rejects.toThrow(/not a login/);
    expect(JSON.stringify(await v.listAudit())).not.toMatch(/pw-1|pw-2/);
    await v.setFrozen(true, 'b');
    await expect(v.readSecret('personal', 'KEY')).rejects.toThrow(/frozen/);
  });

  it('enforces login field limits', async () => {
    const { v } = await setup();
    const put = (login: object) => v.putSecret('personal', 'P', 'pw', 'b', undefined, login as never);
    await expect(put({ username: '  ' })).rejects.toThrow(/username/);
    await expect(put({ username: 'u'.repeat(257) })).rejects.toThrow(/username/);
    await expect(put({ username: 'u', url: 'javascript:alert(1)' })).rejects.toThrow(/url/);
    await expect(put({ username: 'u', url: 'ftp://files.example.com' })).rejects.toThrow(/url/);
    await expect(put({ username: 'u', url: 'https://a.example.com/' + 'x'.repeat(2048) })).rejects.toThrow(/url/);
    await expect(put({ username: 'u', notes: 'n'.repeat(2001) })).rejects.toThrow(/notes/);
    expect((await put({ username: 'u'.repeat(256), url: '', notes: 'n'.repeat(2000) })).login).toEqual({ username: 'u'.repeat(256), notes: 'n'.repeat(2000) });
  });

  it('round-trips login fields through export, restore and import; old snapshots restore as secrets', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'PORTAL', 'pw-1', 'b', undefined, L);
    const snap = await v.exportSnapshot([]);
    expect(snap.secrets.find((s) => s.name === 'PORTAL')).toMatchObject({ kind: 'login', login: L });
    const fresh = async () => { const k = (await loadMasterKey(generateMasterKey()))!; return new VaultLogic(new MapKv(), { current: k, all: [k] }); };
    const a = await fresh();
    await a.restoreSnapshot(structuredClone(snap), 'r');
    expect(await a.loginInfo('personal', 'PORTAL')).toEqual(L);
    const old = structuredClone(snap);
    for (const s of old.secrets) { delete s.kind; delete s.login; }
    const b = await fresh();
    await b.restoreSnapshot(old, 'r');
    expect((await b.getMeta('personal', 'PORTAL'))!.kind).toBeUndefined();
    const c = await fresh();
    await c.importSecrets([{ tier: 'personal', name: 'PORTAL', value: 'pw-1', login: L }], 'b', false);
    expect(await c.loginInfo('personal', 'PORTAL')).toEqual(L);
  });

  it('applies login fields on a same-value re-import and restore without a new version', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'PORTAL', 'pw-1', 'b');
    expect(await v.importSecrets([{ tier: 'personal', name: 'PORTAL', value: 'pw-1', login: L }], 'b', true)).toEqual({ created: 0, updated: 1, skipped: 0 });
    const meta = (await v.getMeta('personal', 'PORTAL'))!;
    expect(meta).toMatchObject({ kind: 'login', login: L, current: 1 });
    expect(meta.versions).toHaveLength(1);
    expect(await v.importSecrets([{ tier: 'personal', name: 'PORTAL', value: 'pw-1', login: L }], 'b', true)).toEqual({ created: 0, updated: 0, skipped: 1 });
    const snap = await v.exportSnapshot([]);
    const k = (await loadMasterKey(generateMasterKey()))!;
    const other = new VaultLogic(new MapKv(), { current: k, all: [k] });
    await other.putSecret('personal', 'PORTAL', 'pw-1', 'b');
    await other.restoreSnapshot(structuredClone(snap), 'r');
    const restored = (await other.getMeta('personal', 'PORTAL'))!;
    expect(restored).toMatchObject({ kind: 'login', login: L });
    expect(restored.versions).toHaveLength(1);
  });
});

describe('config items', () => {
  it('creates config, keeps the kind across edits and restores, and shows values only through configValues', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'AZURE_TENANT_ID', 'tenant-1', 'alice', undefined, undefined, 'config');
    await v.putSecret('personal', 'AZURE_TENANT_ID', 'tenant-2', 'alice');
    await v.restoreVersion('personal', 'AZURE_TENANT_ID', 1, 'alice');
    const meta = await v.getMeta('personal', 'AZURE_TENANT_ID');
    expect(meta).toMatchObject({ kind: 'config', current: 3 });
    expect(await v.configValues()).toEqual(new Map([['personal/AZURE_TENANT_ID', 'tenant-1']]));
    expect(await v.loginInfo('personal', 'AZURE_TENANT_ID')).toBeNull();
    expect((await v.loadTier('personal')).get('AZURE_TENANT_ID')).toBe('tenant-1');
  });

  it('configValues skips secrets, logins and trashed config, and ignores freeze', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'API_KEY', 'sk-secret', 'alice');
    await v.putSecret('personal', 'PORTAL', 'pw', 'alice', undefined, { username: 'u' });
    await v.putSecret('personal', 'OLD_CFG', 'old', 'alice', undefined, undefined, 'config');
    await v.deleteSecret('personal', 'OLD_CFG', 'alice');
    await v.putSecret('personal', 'CLIENT_ID', 'cid', 'alice', undefined, undefined, 'config');
    await v.setFrozen(true, 'alice');
    expect([...(await v.configValues()).entries()]).toEqual([['personal/CLIENT_ID', 'cid']]);
  });

  it('refuses to create config over a live secret or login, and refuses config with login fields', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'API_KEY', 'sk', 'alice');
    await expect(v.putSecret('personal', 'API_KEY', 'x', 'alice', undefined, undefined, 'config')).rejects.toThrow('use Convert to config');
    await expect(v.putSecret('personal', 'NEW', 'x', 'alice', undefined, { username: 'u' }, 'config')).rejects.toThrow('a login cannot be config');
  });

  it('converts a secret to config one way, refuses logins, config and trashed items, and audits without the value', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'CLIENT_SECRET', 'cs-value-123', 'alice');
    await v.convertToConfig('personal', 'CLIENT_SECRET', 'alice');
    expect((await v.getMeta('personal', 'CLIENT_SECRET'))?.kind).toBe('config');
    await expect(v.convertToConfig('personal', 'CLIENT_SECRET', 'alice')).rejects.toThrow('already config');
    await v.putSecret('personal', 'PORTAL', 'pw', 'alice', undefined, { username: 'u' });
    await expect(v.convertToConfig('personal', 'PORTAL', 'alice')).rejects.toThrow('logins cannot be converted');
    await expect(v.convertToConfig('personal', 'NOPE', 'alice')).rejects.toThrow('no such secret');
    const audit = await v.listAudit();
    expect(audit.some((e) => e.event === 'secret_converted_to_config' && e.handle === 'secret://personal/CLIENT_SECRET')).toBe(true);
    expect(JSON.stringify(audit)).not.toContain('cs-value-123');
  });

  it('reads a kept version, refuses unknown versions, and refuses while frozen', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'K', 'one', 'alice');
    await v.putSecret('personal', 'K', 'two', 'alice');
    expect(await v.readVersion('personal', 'K', 1)).toBe('one');
    await expect(v.readVersion('personal', 'K', 9)).rejects.toThrow('no such version');
    await v.setFrozen(true, 'alice');
    await expect(v.readVersion('personal', 'K', 2)).rejects.toThrow('frozen');
  });

  it('round-trips the config kind through export and restore into an empty vault', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'CLIENT_ID', 'cid', 'alice', undefined, undefined, 'config');
    const snap = await v.exportSnapshot([]);
    expect(snap.secrets.find((s) => s.name === 'CLIENT_ID')?.kind).toBe('config');
    const { v: fresh } = await setup();
    await fresh.restoreSnapshot(structuredClone(snap), 'r');
    expect((await fresh.getMeta('personal', 'CLIENT_ID'))?.kind).toBe('config');
  });

  it('never turns config into a login, and drops a stale login when a trashed login is restored as config', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'CFG', 'same', 'alice', undefined, undefined, 'config');
    await expect(v.putSecret('personal', 'CFG', 'other', 'alice', undefined, { username: 'u' })).rejects.toThrow('a config item cannot become a login');
    expect(await v.importSecrets([{ tier: 'personal', name: 'CFG', value: 'same', login: { username: 'u' } }], 'b', true)).toEqual({ created: 0, updated: 0, skipped: 1 });
    expect(await v.getMeta('personal', 'CFG')).toMatchObject({ kind: 'config' });

    await v.putSecret('personal', 'PORTAL', 'pw', 'alice', undefined, { username: 'u' });
    await v.deleteSecret('personal', 'PORTAL', 'alice');
    const snap = await v.exportSnapshot([]);
    const entry = snap.secrets.find((x) => x.name === 'PORTAL')!;
    entry.deleted = false;
    delete entry.login;
    entry.kind = 'config';
    await v.restoreSnapshot(snap, 'r');
    const meta = (await v.getMeta('personal', 'PORTAL'))!;
    expect(meta.kind).toBe('config');
    expect(meta.login).toBeUndefined();
  });

  it('revives a trashed config item as an ordinary secret through add, import and restore', async () => {
    const { v } = await setup();
    const trashedConfig = async (name: string) => {
      await v.putSecret('personal', name, 'old-config', 'b', undefined, undefined, 'config');
      await v.deleteSecret('personal', name, 'b');
    };
    await trashedConfig('ADDED');
    await v.putSecret('personal', 'ADDED', 'added-secret', 'b');
    await trashedConfig('IMPORTED');
    await v.importSecrets([{ tier: 'personal', name: 'IMPORTED', value: 'imported-secret' }], 'b', false);
    await trashedConfig('RESTORED');
    const snap = await v.exportSnapshot([]);
    const entry = snap.secrets.find((x) => x.name === 'RESTORED')!;
    entry.deleted = false;
    delete entry.kind;
    delete entry.configSince;
    entry.versions.at(-1)!.value = 'restored-secret';
    await v.restoreSnapshot(snap, 'r');
    for (const name of ['ADDED', 'IMPORTED', 'RESTORED']) {
      const meta = (await v.getMeta('personal', name))!;
      expect(meta.kind, name).toBeUndefined();
      expect(meta.configSince, name).toBeUndefined();
      expect(meta.current, name).toBe(2);
    }
    expect(await v.configValues()).toEqual(new Map());
  });

  it('revives a trashed config item asked for as config with the boundary at the new version', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'CFG', 'old-config', 'b', undefined, undefined, 'config');
    await v.deleteSecret('personal', 'CFG', 'b');
    await v.putSecret('personal', 'CFG', 'new-config', 'b', undefined, undefined, 'config');
    expect(await v.getMeta('personal', 'CFG')).toMatchObject({ kind: 'config', configSince: 2, current: 2 });
    expect(await v.configValues()).toEqual(new Map([['personal/CFG', 'new-config']]));
  });
});

describe('master key rotation', () => {
  it('re-wraps everything under the new key; the old key is then unnecessary', async () => {
    const { kv, key: oldKey, v } = await setup();
    await v.putSecret('personal', 'A', 'alpha', 'b');
    await v.putSecret('production', 'B', 'beta', 'b');
    const newKey = (await loadMasterKey(generateMasterKey()))!;
    const during = new VaultLogic(kv, { current: newKey, all: [newKey, oldKey] });
    expect((await during.loadTier('personal')).get('A')).toBe('alpha');
    expect(await during.rotate('alice')).toEqual({ rewrapped: 2, tokensSkipped: 0 });
    expect(await during.keyUsage()).toEqual({ [newKey.id]: 2 });
    const after = new VaultLogic(kv, { current: newKey, all: [newKey] });
    expect((await after.loadTier('production')).get('B')).toBe('beta');
  });
});

describe('machines', () => {
  it('issues a self-contained token, stores only its hash, authenticates, and revokes', async () => {
    const { kv, v } = await setup();
    const { token, machine } = await v.createMachine({ name: 'desktop', tiers: ['personal'], canImport: false, by: 'alice', origin: 'https://sb.example.dev' });
    const [, origin, id, secret] = token.split('.');
    expect(atob(origin!.replace(/-/g, '+').replace(/_/g, '/'))).toBe('https://sb.example.dev');
    expect(id).toBe(machine.id);
    expect(JSON.stringify([...kv.m.values()])).not.toContain(secret!);
    expect((await v.authMachine(token))?.name).toBe('desktop');
    expect(await v.authMachine(token.slice(0, -2) + 'xx')).toBeNull();
    expect(await v.authMachine('garbage')).toBeNull();
    await v.revokeMachine(machine.id, 'alice');
    expect(await v.authMachine(token)).toBeNull();
  });
});

describe('audit', () => {
  it('records events without values and expires old ones', async () => {
    const { v, tick } = await setup();
    await v.putSecret('personal', 'A', 'secret-value-123', 'alice');
    const log = await v.listAudit();
    expect(log.find((e) => e.event === 'secret_created')).toMatchObject({ by: 'alice', handle: 'secret://personal/A' });
    expect(JSON.stringify(log)).not.toContain('secret-value-123');
    tick(181 * 86400_000);
    expect(await v.listAudit()).toEqual([]);
  });
});

describe('backup and restore', () => {
  it('round-trips the whole vault through an encrypted backup into an empty vault', async () => {
    const { kv, v } = await setup();
    await v.putSecret('personal', 'A', 'one', 'b');
    await v.putSecret('personal', 'A', 'two', 'b');
    await v.putSecret('client-work', 'C', 'see', 'b');
    await v.putSecret('production', 'GONE', 'x', 'b');
    await v.deleteSecret('production', 'GONE', 'b');
    await v.createMachine({ name: 'desktop', tiers: ['personal'], canImport: false, by: 'b', origin: 'https://x' });
    const grants = new GrantLogic(kv, () => 1, () => 'r1');
    await grants.createRequest({ repo: 'a/b', reason: 'r', items: [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }], requestedBy: 'b' });
    await grants.approve('r1', [0], 'b');

    const snap = await v.exportSnapshot(await grants.listGrants());
    const kp = await generateBackupKeyPair();
    const env = await encryptBackup(kp.publicPem, JSON.stringify(snap), snap.exportedAt);
    expect(JSON.stringify(env)).not.toContain('see');

    // Disaster: everything is gone, including the old master key.
    const freshKv = new MapKv();
    const freshKey: MasterKey = (await loadMasterKey(generateMasterKey()))!;
    const fresh = new VaultLogic(freshKv, { current: freshKey, all: [freshKey] });
    const restored = JSON.parse(await decryptBackup(kp.privatePem, env)) as Snapshot;
    expect(await fresh.restoreSnapshot(restored, 'restore')).toEqual({ secrets: 2, machines: 1, connections: 0, connectionsUnreadable: 0, links: 0, pushes: 0 });
    expect(await new GrantLogic(freshKv).importGrants(restored.grants as never)).toBe(1);
    expect((await fresh.loadTier('personal')).get('A')).toBe('two');
    expect((await fresh.loadTier('client-work')).get('C')).toBe('see');
    expect((await fresh.loadTier('production')).size).toBe(0);
    expect((await new GrantLogic(freshKv).getGrant('a/b'))?.rules).toHaveLength(1);
    // Restoring again changes nothing.
    expect(await fresh.restoreSnapshot(restored, 'restore')).toEqual({ secrets: 0, machines: 0, connections: 0, connectionsUnreadable: 0, links: 0, pushes: 0 });
  }, 30000);

  it('imports with skip or overwrite', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'A', 'old', 'b');
    expect(await v.importSecrets([{ tier: 'personal', name: 'A', value: 'new' }, { tier: 'personal', name: 'B', value: 'b' }], 'b', false)).toEqual({ created: 1, updated: 0, skipped: 1 });
    expect((await v.loadTier('personal')).get('A')).toBe('old');
    expect(await v.importSecrets([{ tier: 'personal', name: 'A', value: 'new' }], 'b', true)).toEqual({ created: 0, updated: 1, skipped: 0 });
    expect((await v.loadTier('personal')).get('A')).toBe('new');
  });
});

describe('grants', () => {
  it('approves only selected items, de-duplicates, revokes per rule and per repo, and expires requests', async () => {
    const kv = new MapKv();
    let now = 0;
    let n = 0;
    const g = new GrantLogic(kv, () => now, () => `r${++n}`);
    const items = [
      { handle: 'secret://personal/A', hosts: ['api.github.com'] },
      { handle: 'secret://personal/B', hosts: ['api.example.com'] },
    ];
    const req1 = await g.createRequest({ repo: 'o/r', reason: 'why', items, requestedBy: 'b' });
    const grant = await g.approve(req1.id, [1, 1, 7], 'alice');
    expect(grant.rules.map((r) => r.secrets[0])).toEqual(['B']);
    await expect(g.approve(req1.id, [0], 'alice')).rejects.toThrow(/not found/);
    const req2 = await g.createRequest({ repo: 'o/r', reason: 'again', items, requestedBy: 'b' });
    expect((await g.approve(req2.id, [0, 1], 'alice')).rules.map((r) => r.secrets[0])).toEqual(['B', 'A']);
    await g.revoke('o/r', 0);
    expect((await g.getGrant('o/r'))!.rules.map((r) => r.secrets[0])).toEqual(['A']);
    await g.revoke('o/r');
    expect(await g.getGrant('o/r')).toBeNull();
    const req3 = await g.createRequest({ repo: 'o/r', reason: 'x', items, requestedBy: 'b' });
    now += 8 * 86400_000;
    expect(await g.getRequest(req3.id)).toBeNull();
  });

  it('approves with per-item limits, consumes and refunds uses, and replaces on re-approval', async () => {
    const kv = new MapKv();
    let now = 1_000;
    let n = 0;
    const g = new GrantLogic(kv, () => now, () => `id${++n}`);
    const items = [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }, { handle: 'secret://personal/B', hosts: ['api.example.com'] }];
    await g.createRequest({ repo: 'o/r', reason: 'why', items, requestedBy: 'b' });
    const grant = await g.approve('id1', [0, 1], 'alice', { 0: { ttlMs: 3_600_000, uses: 2 } });
    expect(grant.rules[0]).toMatchObject({ id: 'id2', expiresAt: 3_601_000, usesLeft: 2 });
    expect(grant.rules[1]).toMatchObject({ id: 'id3' });
    expect(grant.rules[1]!.expiresAt).toBeUndefined();
    expect(grant.rules[1]!.usesLeft).toBeUndefined();
    expect(await g.consume('o/r', 'id2')).toEqual({ ok: true, usesLeft: 1 });
    expect(await g.consume('o/r', 'id3')).toEqual({ ok: true, usesLeft: null });
    expect((await g.listGrants())[0]!.rules.map((r) => r.state)).toEqual(['live', 'live']);
    expect(await g.consume('o/r', 'id2')).toEqual({ ok: true, usesLeft: 0 });
    expect(await g.consume('o/r', 'id2')).toMatchObject({ ok: false, reason: expect.stringMatching(/expired or is used up/) });
    expect((await g.listGrants())[0]!.rules[0]!.state).toBe('used_up');
    expect(JSON.stringify([...kv.m.values()])).not.toContain('"state"');
    await g.refund('o/r', 'id2');
    expect((await g.getGrant('o/r'))!.rules[0]!.usesLeft).toBe(1);
    await g.createRequest({ repo: 'o/r', reason: 'again', items: [items[0]!], requestedBy: 'b' });
    const re = await g.approve('id4', [0], 'alice', { 0: { uses: 5 } });
    expect(re.rules).toHaveLength(2);
    expect(re.rules[0]).toMatchObject({ id: 'id5', usesLeft: 5, description: 'again' });
    expect(re.rules[0]!.expiresAt).toBeUndefined();
  });

  it('expires rules by time and keeps them listed', async () => {
    const kv = new MapKv();
    let now = 1_000;
    let n = 0;
    const g = new GrantLogic(kv, () => now, () => `id${++n}`);
    await g.createRequest({ repo: 'o/r', reason: 'r', items: [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }], requestedBy: 'b' });
    const [rule] = (await g.approve('id1', [0], 'alice', { 0: { ttlMs: 3_600_000 } })).rules;
    expect(isLive(rule!, 3_600_999)).toBe(true);
    expect(isLive(rule!, 3_601_000)).toBe(false);
    now = 3_601_000;
    expect((await g.listGrants())[0]!.rules[0]!.state).toBe('expired');
    expect(await g.consume('o/r', 'id2')).toMatchObject({ ok: false, reason: expect.stringMatching(/expired or is used up/) });
    expect((await g.getGrant('o/r'))!.rules).toHaveLength(1);
  });

  it('rejects bad limits', async () => {
    const g = new GrantLogic(new MapKv(), () => 1, () => 'r1');
    await g.createRequest({ repo: 'o/r', reason: 'r', items: [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }], requestedBy: 'b' });
    for (const uses of [0, -1, 1.5, 1001]) await expect(g.approve('r1', [0], 'b', { 0: { uses } })).rejects.toThrow(/uses must be a whole number from 1 to 1000/);
    for (const ttlMs of [0, -5, 1.5]) await expect(g.approve('r1', [0], 'b', { 0: { ttlMs } })).rejects.toThrow(/duration/);
  });

  it('keeps legacy rules without an id working and replaces them in place', async () => {
    const kv = new MapKv();
    let n = 0;
    const g = new GrantLogic(kv, () => 1_000, () => `id${++n}`);
    const legacy = { tier: 'personal', secrets: ['A'], hosts: ['api.github.com'], approvedAt: 1, approvedBy: 'b' };
    await kv.put('grant:o/r', { repo: 'o/r', rules: [legacy, { ...legacy, secrets: ['B'] }] });
    expect((await g.listGrants())[0]!.rules.map((r) => r.state)).toEqual(['live', 'live']);
    expect(await g.consume('o/r', 'missing')).toEqual({ ok: false, reason: 'no such approval' });
    await g.refund('o/r', 'missing');
    expect((await g.getGrant('o/r'))!.rules).toEqual([legacy, { ...legacy, secrets: ['B'] }]);
    await g.createRequest({ repo: 'o/r', reason: 'r', items: [{ handle: 'secret://personal/A', hosts: ['api.github.com'] }], requestedBy: 'b' });
    const re = await g.approve('id1', [0], 'alice', { 0: { uses: 1 } });
    expect(re.rules.map((r) => [r.secrets[0], r.id])).toEqual([['A', 'id2'], ['B', undefined]]);
  });

  it('validates reveal items against the login check, failing closed', () => {
    const portal = { handle: 'secret://personal/PORTAL', reveal: true as const };
    const isLogin = (h: string) => h === portal.handle;
    expect(validateRequestInput({ repo: 'o/r', reason: 'r', items: [portal] }, { isLogin }).items).toEqual([portal]);
    expect(validateRequestInput({ repo: 'o/r', reason: 'r', items: [{ ...portal, handle: 'secret://production/PORTAL' }] }, { isLogin: () => true }).items).toHaveLength(1);
    expect(() => validateRequestInput({ repo: 'o/r', reason: 'r', items: [portal] })).toThrow(/not a login/);
    expect(() => validateRequestInput({ repo: 'o/r', reason: 'r', items: [{ handle: 'secret://personal/KEY', reveal: true }] }, { isLogin })).toThrow(/not a login/);
    expect(() => validateRequestInput({ repo: 'o/r', reason: 'r', items: [{ ...portal, hosts: ['a.example.com'] }] }, { isLogin })).toThrow(/reveal items take no hosts/);
    expect(() => validateRequestInput({ repo: 'o/r', reason: 'r', items: [{ handle: 'secret://personal/KEY' }] })).toThrow(/hosts/);
    expect(itemToRule(portal, 'sign in')).toEqual({ action: 'reveal', description: 'sign in', tier: 'personal', secrets: ['PORTAL'] });
  });

  it('importGrants strips the computed state field from every rule', async () => {
    const kv = new MapKv();
    const g = new GrantLogic(kv, () => 1_000);
    const rule = { tier: 'personal', secrets: ['A'], hosts: ['api.github.com'], approvedAt: 1, approvedBy: 'b', id: 'x', state: 'live' };
    expect(await g.importGrants([{ repo: 'o/r', rules: [rule] }] as never)).toBe(1);
    expect(JSON.stringify([...kv.m.values()])).not.toContain('"state"');
    expect((await g.getGrant('o/r'))!.rules[0]).toMatchObject({ id: 'x' });
  });
});

describe('vaults', () => {
  it('has personal and production built in; production is strict', async () => {
    const { v } = await setup();
    const list = await v.listVaults();
    expect(list.map((x) => [x.slug, x.kind, x.strict])).toEqual([
      ['personal', 'personal', false],
      ['production', 'production', true],
      ['client-work', 'project', false],
    ]);
  });

  it('creates project vaults (strict by default), edits links, and deletes only when empty', async () => {
    const { v } = await setup();
    const acme = await v.createVault({ slug: 'acme-finance', name: 'Acme', repos: ['https://github.com/acme/Acme-Dash.git'], by: 'b' });
    expect(acme).toMatchObject({ kind: 'project', strict: true, repos: ['acme/acme-dash'] });
    await expect(v.createVault({ slug: 'acme-finance', name: 'x', by: 'b' })).rejects.toThrow(/already exists/);
    await expect(v.createVault({ slug: 'x', name: 'x', by: 'b' })).rejects.toThrow(/vault names/);
    await expect(v.createVault({ slug: 'ok', name: 'x', repos: ['not a repo'], by: 'b' })).rejects.toThrow(/owner\/name/);
    expect((await v.updateVault('acme-finance', { repos: ['acme/a', 'acme/b'] }, 'b')).repos).toEqual(['acme/a', 'acme/b']);
    await expect(v.updateVault('production', { strict: false }, 'b')).rejects.toThrow(/built in/);
    await v.putSecret('acme-finance', 'DB_URL', 'postgres://x', 'b');
    await expect(v.deleteVault('acme-finance', 'b')).rejects.toThrow(/still holds 1/);
    await v.deleteSecret('acme-finance', 'DB_URL', 'b');
    await expect(v.deleteVault('acme-finance', 'b')).rejects.toThrow(/still holds 1/);
    await v.purge('acme-finance', 'DB_URL', 'b');
    await v.deleteVault('acme-finance', 'b');
    expect(await v.getVault('acme-finance')).toBeNull();
    await expect(v.deleteVault('personal', 'b')).rejects.toThrow(/built in/);
  });

  it('turns an approved vault request into a vault linked to the repo', async () => {
    const { v } = await setup();
    const r = await v.requestVault({ slug: 'acme-finance', name: 'Acme', repo: 'acme/acme-dash', reason: 'client creds', requestedBy: 'alice' }, () => 'vr1');
    await expect(v.requestVault({ slug: 'acme-finance', name: 'Acme', repo: 'acme/acme-dash', reason: 'again', requestedBy: 'alice' })).rejects.toThrow(/already waiting/);
    expect((await v.listVaultRequests()).map((x) => x.id)).toEqual(['vr1']);
    const info = await v.approveVaultRequest(r.id, 'alice', { strict: true, slug: 'acme' });
    expect(info).toMatchObject({ slug: 'acme', strict: true, repos: ['acme/acme-dash'], note: 'client creds' });
    expect(await v.listVaultRequests()).toEqual([]);
  });

  it('machines can only be scoped to vaults that exist', async () => {
    const { v } = await setup();
    await expect(v.createMachine({ name: 'm', tiers: ['nope'], canImport: false, by: 'b', origin: 'https://x' })).rejects.toThrow(/no vault named nope/);
  });

  it('grants honour strict vaults and repo links', async () => {
    const kv = new MapKv();
    const g = new GrantLogic(kv, () => 0, () => 'r1');
    const rules = { isStrict: (t: string) => t === 'acme', reposFor: (t: string) => (t === 'acme' ? ['acme/acme-dash'] : []) };
    const item = { handle: 'secret://acme/DB', hosts: ['db.example.com'] };
    await expect(g.createRequest({ repo: 'acme/acme-dash', reason: 'r', items: [item], requestedBy: 'b' }, rules)).rejects.toThrow(/acme is a strict vault/);
    await expect(g.createRequest({ repo: 'acme/other', reason: 'r', items: [{ ...item, methods: ['GET'] }], requestedBy: 'b' }, rules)).rejects.toThrow(/linked to acme\/acme-dash/);
    await g.createRequest({ repo: 'acme/acme-dash', reason: 'r', items: [{ ...item, methods: ['GET'] }], requestedBy: 'b' }, rules);
    // Link changed before approval: refused.
    await expect(g.approve('r1', [0], 'b', {}, { reposFor: () => ['acme/elsewhere'] })).rejects.toThrow(/linked to/);
  });
});

describe('moving secrets', () => {
  it('moves a secret with its history into another vault and removes the original', async () => {
    const { kv, v } = await setup();
    await v.createVault({ slug: 'initech', name: 'Initech', repos: ['acme/initech-sync'], by: 'b' });
    await v.putSecret('client-work', 'DO_INITECH', 'one', 'b');
    await v.putSecret('client-work', 'DO_INITECH', 'two', 'b');
    const moved = await v.moveSecret('client-work', 'DO_INITECH', 'initech', 'alice');
    expect(moved).toMatchObject({ tier: 'initech', name: 'DO_INITECH', current: 2 });
    expect(moved.versions.map((x) => x.v)).toEqual([1, 2]);
    expect((await v.loadTier('initech')).get('DO_INITECH')).toBe('two');
    expect((await v.loadTier('client-work')).has('DO_INITECH')).toBe(false);
    expect(await v.getMeta('client-work', 'DO_INITECH')).toBeNull();
    expect([...kv.m.keys()].some((k) => k.startsWith('ver:client-work:DO_INITECH'))).toBe(false);
    // History still works after the move.
    await v.restoreVersion('initech', 'DO_INITECH', 1, 'alice');
    expect((await v.loadTier('initech')).get('DO_INITECH')).toBe('one');
    expect(JSON.stringify(await v.listAudit())).toContain('secret_moved');
  });

  it('refuses clashes, same vault, missing vaults and trashed secrets', async () => {
    const { v } = await setup();
    await v.putSecret('personal', 'A', 'x', 'b');
    await v.putSecret('production', 'A', 'y', 'b');
    await expect(v.moveSecret('personal', 'A', 'production', 'b')).rejects.toThrow(/already has a secret named A/);
    await expect(v.moveSecret('personal', 'A', 'personal', 'b')).rejects.toThrow(/already in that vault/);
    await expect(v.moveSecret('personal', 'A', 'nope', 'b')).rejects.toThrow(/no vault named nope/);
    await v.deleteSecret('personal', 'A', 'b');
    await expect(v.moveSecret('personal', 'A', 'client-work', 'b')).rejects.toThrow(/no such secret/);
    expect((await v.loadTier('production')).get('A')).toBe('y');
  });
});

describe('connections', () => {
  it('adds, lists without tokens, replaces the token, records checks, and removes with links but keeps push history', async () => {
    const { v, kv } = await setup();
    const c = await v.addConnection({ provider: 'vercel', name: '  Acme Vercel  ', accountId: 'team_abc123', token: ' tok-1 ', by: 'alice' });
    expect(c).toMatchObject({ provider: 'vercel', name: 'Acme Vercel', accountId: 'team_abc123', createdBy: 'alice' });
    expect(c.id).toMatch(CONN_ID_RE);
    const listed = await v.listConnections();
    for (const k of ['token', 'ct', 'wk', 'iv', 'wiv']) expect(JSON.stringify(listed)).not.toContain(`"${k}"`);
    expect(JSON.stringify(listed)).not.toContain('tok-1');
    expect(await v.connectionToken(c.id)).toBe('tok-1');
    await v.replaceConnectionToken(c.id, 'tok-2', 'alice');
    expect(await v.connectionToken(c.id)).toBe('tok-2');
    await v.recordConnectionCheck(c.id, false, 'Vercel 403: forbidden (forbidden)');
    expect(await v.getConnection(c.id)).toMatchObject({ lastCheckOk: false, lastCheckError: 'Vercel 403: forbidden (forbidden)' });
    await kv.put(`link:${c.id}:prj_1`, { connectionId: c.id, targetId: 'prj_1', targetName: 'acme', items: [], updatedAt: 1, updatedBy: 'b' });
    await kv.put(`push:${c.id}:prj_1:00000000000001:abcd`, { id: '00000000000001:abcd', at: 1, by: 'b', connectionId: c.id, targetId: 'prj_1', targetName: 'acme', rows: [] });
    await v.removeConnection(c.id, 'alice');
    expect(await v.getConnection(c.id)).toBeNull();
    expect(await kv.get(`link:${c.id}:prj_1`)).toBeUndefined();
    expect(await kv.get(`push:${c.id}:prj_1:00000000000001:abcd`)).toBeDefined();
    const events = (await v.listAudit()).map((e) => e.event);
    expect(events).toEqual(expect.arrayContaining(['connection_added', 'connection_token_replaced', 'connection_removed']));
    expect(JSON.stringify(await v.listAudit())).not.toMatch(/tok-1|tok-2/);
  });

  it('validates name, provider, account id and token', async () => {
    const { v } = await setup();
    const add = (o: Partial<{ provider: string; name: string; accountId: string; token: string }>) =>
      v.addConnection({ provider: 'vercel', name: 'n', accountId: '', token: 't', by: 'b', ...o } as never);
    await expect(add({ name: ' ' })).rejects.toThrow('1 to 60 characters');
    await expect(add({ name: 'x'.repeat(61) })).rejects.toThrow('1 to 60 characters');
    await expect(add({ provider: 'netlify' })).rejects.toThrow('vercel or cloudflare');
    await expect(add({ accountId: 'acme' })).rejects.toThrow('team_');
    await expect(add({ provider: 'cloudflare', accountId: 'ABC' })).rejects.toThrow('32 hex');
    await expect(add({ token: '' })).rejects.toThrow('token');
    await expect(add({ token: 'x'.repeat(4097) })).rejects.toThrow('token');
    await expect(add({ provider: 'cloudflare', accountId: 'a'.repeat(32) })).resolves.toMatchObject({ provider: 'cloudflare' });
  });

  it('re-seals connection tokens on rotation and counts them in key usage', async () => {
    const { kv, key: oldKey, v } = await setup();
    await v.putSecret('personal', 'A', 'alpha', 'b');
    const c = await v.addConnection({ provider: 'vercel', name: 'Rot', accountId: '', token: 'tok-rot', by: 'b' });
    expect(await v.keyUsage()).toEqual({ [oldKey.id]: 2 });
    const newKey = (await loadMasterKey(generateMasterKey()))!;
    const during = new VaultLogic(kv, { current: newKey, all: [newKey, oldKey] });
    expect(await during.rotate('alice')).toEqual({ rewrapped: 2, tokensSkipped: 0 });
    expect(await during.keyUsage()).toEqual({ [newKey.id]: 2 });
    const after = new VaultLogic(kv, { current: newKey, all: [newKey] });
    expect(await after.connectionToken(c.id)).toBe('tok-rot');
  });

  it('skips and counts connection tokens sealed under an unloaded key instead of failing rotation', async () => {
    const { kv, v } = await setup();
    await v.addConnection({ provider: 'vercel', name: 'Dead', accountId: '', token: 'tok-dead', by: 'b' });
    const otherKey = (await loadMasterKey(generateMasterKey()))!;
    const newKey = (await loadMasterKey(generateMasterKey()))!;
    const during = new VaultLogic(kv, { current: newKey, all: [newKey, otherKey] });
    await during.putSecret('personal', 'A', 'alpha', 'b');
    expect(await during.rotate('alice')).toEqual({ rewrapped: 0, tokensSkipped: 1 });
    expect((await during.listAudit()).find((e) => e.event === 'master_key_rotated')).toMatchObject({ rewrapped: 0, tokensSkipped: 1 });
  });

  it('exports connections sealed, links and pushes; restore skips existing keys and bad ids', async () => {
    const { v, kv, key } = await setup();
    const c = await v.addConnection({ provider: 'cloudflare', name: 'CF', accountId: 'a'.repeat(32), token: 'cf-tok', by: 'b' });
    await kv.put(`link:${c.id}:worker-1`, { connectionId: c.id, targetId: 'worker-1', targetName: 'worker-1', items: [], updatedAt: 1, updatedBy: 'b' });
    await kv.put(`push:${c.id}:worker-1:00000000000005:zz`, { id: '00000000000005:zz', at: 5, by: 'b', connectionId: c.id, targetId: 'worker-1', targetName: 'worker-1', rows: [] });
    const snap = await v.exportSnapshot([]);
    expect(snap.connections).toHaveLength(1);
    expect(JSON.stringify(snap)).not.toContain('cf-tok');
    expect(snap.links).toHaveLength(1);
    expect(snap.pushes).toHaveLength(1);
    // same-master-key restore into an empty vault: everything comes back and the token opens
    const fresh = new VaultLogic(new MapKv(), { current: key, all: [key] });
    expect(await fresh.restoreSnapshot(structuredClone(snap), 'r')).toMatchObject({ connections: 1, links: 1, pushes: 1 });
    expect(await fresh.connectionToken(c.id)).toBe('cf-tok');
    // restore never overwrites: a replaced token survives a second restore
    await fresh.replaceConnectionToken(c.id, 'cf-new', 'b');
    expect(await fresh.restoreSnapshot(structuredClone(snap), 'r')).toMatchObject({ connections: 0, connectionsUnreadable: 0, links: 0, pushes: 0 });
    expect(await fresh.connectionToken(c.id)).toBe('cf-new');
    // bad ids are skipped
    const bad = { ...structuredClone(snap), connections: [{ ...snap.connections![0]!, id: '../x' }], links: [{ ...snap.links![0]!, targetId: 'a:b' }], pushes: [] };
    expect(await new VaultLogic(new MapKv(), { current: key, all: [key] }).restoreSnapshot(bad, 'r')).toMatchObject({ connections: 0, links: 0 });
    const bad2 = {
      ...structuredClone(snap),
      connections: [{ ...snap.connections![0]!, provider: 'netlify' as never }],
      links: [],
      pushes: [{ ...snap.pushes![0]!, id: 'nope' }],
    };
    expect(await new VaultLogic(new MapKv(), { current: key, all: [key] }).restoreSnapshot(bad2, 'r')).toMatchObject({ connections: 0, pushes: 0 });
  });

  it('skips connections sealed under an unloaded master key or with no token, and skips orphan links', async () => {
    const { v, kv } = await setup();
    const c = await v.addConnection({ provider: 'vercel', name: 'Old', accountId: '', token: 'tok', by: 'b' });
    await kv.put(`link:${c.id}:prj_1`, { connectionId: c.id, targetId: 'prj_1', targetName: 'a', items: [], updatedAt: 1, updatedBy: 'b' });
    const snap = await v.exportSnapshot([]);
    const freshKey = (await loadMasterKey(generateMasterKey()))!;
    const fresh = new VaultLogic(new MapKv(), { current: freshKey, all: [freshKey] });
    const noToken = { ...snap.connections![0]!, id: '99999999-2222-3333-4444-555555555555', token: undefined as never };
    snap.connections!.push(noToken);
    expect(await fresh.restoreSnapshot(snap, 'r')).toMatchObject({ connections: 0, connectionsUnreadable: 2, links: 0 });
    expect(await fresh.listConnections()).toEqual([]);
    expect(await fresh.rotate('b')).toEqual({ rewrapped: 0, tokensSkipped: 0 });
    expect(await fresh.keyUsage()).toEqual({});
  });
});

describe('deploy links and push history', () => {
  async function withConn(provider: 'vercel' | 'cloudflare' = 'vercel', accountId = 'team_a') {
    const s = await setup();
    const c = await s.v.addConnection({ provider, name: 'Acme', accountId: provider === 'vercel' ? accountId : 'a'.repeat(32), token: 't', by: 'b' });
    await s.v.putSecret('personal', 'CLIENT_ID', 'cid', 'b', undefined, undefined, 'config');
    await s.v.putSecret('personal', 'CLIENT_SECRET', 'cs', 'b');
    return { ...s, c };
  }

  it('derives default variable names and environment groups', () => {
    expect(defaultVarName('client.id-2')).toBe('CLIENT_ID_2');
    expect(defaultVarName('2fa_code')).toBe('_2FA_CODE');
    expect(envGroup(['production', 'preview'])).toBe('preview,production');
    expect(envGroup(undefined)).toBe('');
  });

  it('saves a link with validated names and environments, defaulting Vercel to production and preview', async () => {
    const { v, c } = await withConn();
    const link = await v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme-portal', by: 'b', items: [
      { handle: 'secret://personal/CLIENT_ID', varName: 'AZURE_CLIENT_ID' },
      { handle: 'secret://personal/CLIENT_SECRET', varName: 'AZURE_CLIENT_SECRET', environments: ['development', 'production', 'production'] },
    ] });
    expect(link.items[0]!.environments).toEqual(['preview', 'production']);
    expect(link.items[1]!.environments).toEqual(['development', 'production']);
    await expect(v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/CLIENT_ID', varName: 'lower' }] })).rejects.toThrow('A-Z');
    await expect(v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/CLIENT_ID', varName: 'A'.repeat(257) }] })).rejects.toThrow('256');
    await expect(v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/CLIENT_ID', varName: 'A', environments: [] as never }] })).rejects.toThrow('at least one environment');
    await expect(v.saveLink({ connectionId: c.id, targetId: 'bad/id', targetName: 'x', by: 'b', items: [] })).rejects.toThrow('target');
    await expect(v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/NOPE', varName: 'A' }] })).rejects.toThrow('no such item');
  });

  it('strips environments on Cloudflare links', async () => {
    const { v, c } = await withConn('cloudflare');
    const link = await v.saveLink({ connectionId: c.id, targetId: 'worker-1', targetName: 'worker-1', by: 'b', items: [{ handle: 'secret://personal/CLIENT_ID', varName: 'CLIENT_ID', environments: ['production'] }] });
    expect(link.items[0]!.environments).toBeUndefined();
  });

  it('refuses one variable name for two items, in one link or across links to the same target', async () => {
    const { v, c } = await withConn();
    await expect(v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [
      { handle: 'secret://personal/CLIENT_ID', varName: 'SAME' }, { handle: 'secret://personal/CLIENT_SECRET', varName: 'SAME' },
    ] })).rejects.toThrow('SAME is used twice');
    await v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/CLIENT_ID', varName: 'SAME' }] });
    const c2 = await v.addConnection({ provider: 'vercel', name: 'Acme 2', accountId: 'team_a', token: 't2', by: 'b' });
    await expect(v.saveLink({ connectionId: c2.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/CLIENT_SECRET', varName: 'SAME' }] }))
      .rejects.toThrow('SAME on this target already comes from secret://personal/CLIENT_ID (link via Acme)');
    // same handle, same name across links is allowed; a different account is a different target
    await expect(v.saveLink({ connectionId: c2.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/CLIENT_ID', varName: 'SAME' }] })).resolves.toBeDefined();
    const c3 = await v.addConnection({ provider: 'vercel', name: 'Other', accountId: 'team_b', token: 't3', by: 'b' });
    await expect(v.saveLink({ connectionId: c3.id, targetId: 'prj_1', targetName: 'x', by: 'b', items: [{ handle: 'secret://personal/CLIENT_SECRET', varName: 'SAME' }] })).resolves.toBeDefined();
  });

  it('pages push history at 25, newest first, and finds the last successful push per name and environment group', async () => {
    const { v, c } = await withConn();
    for (let i = 1; i <= 30; i++) {
      await v.addPushRecord({ at: 1_000 + i, by: 'b', connectionId: c.id, targetId: 'prj_1', targetName: 'acme', rows: [
        { handle: 'secret://personal/CLIENT_SECRET', version: i, kind: 'secret', varName: 'S', environments: ['production', 'preview'], action: i === 30 ? 'failed' : i % 2 ? 'created' : 'updated' },
      ] });
    }
    const p1 = await v.listPushes(1);
    expect(p1).toMatchObject({ page: 1, pages: 2, total: 30 });
    expect(p1.records).toHaveLength(25);
    expect(p1.records[0]!.rows[0]!.version).toBe(30);
    expect((await v.listPushes(2)).records).toHaveLength(5);
    expect((await v.listPushes(99)).page).toBe(2);
    const last = await v.lastPushed(c.id, 'prj_1');
    expect(last.get('S|preview,production')).toMatchObject({ handle: 'secret://personal/CLIENT_SECRET', version: 29 });
  });

  it('summarises links: changed since last push, missing items, last push time', async () => {
    const { v, c } = await withConn();
    await v.saveLink({ connectionId: c.id, targetId: 'prj_1', targetName: 'acme', by: 'b', items: [
      { handle: 'secret://personal/CLIENT_ID', varName: 'CLIENT_ID' }, { handle: 'secret://personal/CLIENT_SECRET', varName: 'CLIENT_SECRET' },
    ] });
    await v.addPushRecord({ at: 50, by: 'b', connectionId: c.id, targetId: 'prj_1', targetName: 'acme', rows: [
      { handle: 'secret://personal/CLIENT_ID', version: 1, kind: 'config', varName: 'CLIENT_ID', environments: ['preview', 'production'], action: 'created' },
      { handle: 'secret://personal/CLIENT_SECRET', version: 1, kind: 'secret', varName: 'CLIENT_SECRET', environments: ['preview', 'production'], action: 'created' },
    ] });
    await v.putSecret('personal', 'CLIENT_SECRET', 'cs2', 'b');
    let [s] = await v.linkSummaries();
    expect(s).toMatchObject({ changed: 1, missing: 0, lastPushAt: 50, connection: { name: 'Acme' } });
    await v.deleteSecret('personal', 'CLIENT_ID', 'b');
    [s] = await v.linkSummaries();
    expect(s).toMatchObject({ changed: 1, missing: 1 });
  });
});
