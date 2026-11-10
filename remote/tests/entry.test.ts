// Drives the real Worker entry (src/index.ts) and the real OAuth provider library with in-memory storage.
import { describe, expect, it } from 'vitest';
import worker from '../src/index';
import { makeVault } from './helpers';

const ORIGIN = 'https://vault.example.com';
const CLAUDE = { client_name: 'Claude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'], token_endpoint_auth_method: 'none' };

function kvNamespace() {
  const m = new Map<string, string>();
  const writes: string[] = [];
  return {
    writes,
    async get(k: string, o?: unknown) {
      const v = m.get(k);
      if (v === undefined) return null;
      return (typeof o === 'string' ? o : (o as { type?: string } | undefined)?.type) === 'json' ? JSON.parse(v) : v;
    },
    async put(k: string, v: string) { writes.push(`put ${k}`); m.set(k, v); },
    async delete(k: string) { writes.push(`delete ${k}`); m.delete(k); },
    async list(o: { prefix?: string } = {}) {
      return { keys: [...m.keys()].filter((k) => k.startsWith(o.prefix ?? '')).sort().map((name) => ({ name })), list_complete: true, cursor: undefined };
    },
  };
}

async function world(key = 'k'.repeat(40)) {
  const vault = await makeVault();
  const kv = kvNamespace();
  const env = { COOKIE_ENCRYPTION_KEY: key, ALLOWED_GITHUB_IDS: '42', GITHUB_CLIENT_ID: 'gh', GITHUB_CLIENT_SECRET: 'ghs', OAUTH_KV: kv, VAULT: { idFromName: () => 'id', get: () => vault.api }, PUBLIC_URL: '' } as never;
  const ctx = { waitUntil() {}, passThroughOnException() {}, props: undefined } as never;
  const register = (body: unknown) => worker.fetch(new Request(`${ORIGIN}/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), env, ctx);
  const registered = async () => (await vault.api.listAudit()).filter((e) => e.event === 'client_registered').length;
  return { vault, kv, env, ctx, register, registered };
}

describe('Worker entry', () => {
  it('answers 500 for a 31 character session key', async () => {
    const w = await world('k'.repeat(31));
    const r = await worker.fetch(new Request(`${ORIGIN}/login`), w.env, w.ctx);
    expect(r.status).toBe(500);
    expect(await r.text()).toContain('COOKIE_ENCRYPTION_KEY');
  });

  it('refuses registration while closed without writing anything', async () => {
    const w = await world();
    const before = JSON.stringify([...w.vault.kv.m]);
    const r = await w.register(CLAUDE);
    expect(r.status).toBe(403);
    expect(await r.json()).toMatchObject({ error: 'access_denied' });
    expect(w.kv.writes).toEqual([]);
    expect(JSON.stringify([...w.vault.kv.m])).toBe(before);
  });

  it('spends one slot for a registration the provider stores', async () => {
    const w = await world();
    await w.vault.api.openRegistration('alice');
    const r = await w.register(CLAUDE);
    expect(r.status).toBe(201);
    expect(await w.vault.api.registrationStatus()).toMatchObject({ left: 4 });
    expect(await w.registered()).toBe(1);
  });

  it('spends no slot and logs nothing for a registration the provider rejects', async () => {
    const w = await world();
    await w.vault.api.openRegistration('alice');
    const r = await w.register({ ...CLAUDE, token_endpoint_auth_method: 'bogus' });
    expect(r.status).toBe(400);
    expect(await w.vault.api.registrationStatus()).toMatchObject({ left: 5 });
    expect(await w.registered()).toBe(0);
    expect(w.kv.writes).toEqual([]);
  });
});
