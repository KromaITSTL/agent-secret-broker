/**
 * Machine API for the local broker and the restore script. Bearer machine
 * token (created on the Machines page), never a browser session.
 */
import type { Hono } from 'hono';
import type { Env } from './env';
import { isVaultSlug, type Tier } from './policy';
import type { ImportItem, Snapshot } from './store';
import { vaultFor } from './vault-client';
import type { VaultApi } from './vault-do';

type App<B extends Env> = Hono<{ Bindings: B }>;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export function registerApiRoutes<B extends Env>(app: App<B>, deps: { vault?: (env: Env) => VaultApi } = {}): void {
  const vault = deps.vault ?? ((env: Env) => vaultFor(env));

  async function machine(req: Request, v: VaultApi) {
    const auth = req.headers.get('Authorization') ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    return token ? v.authMachine(token) : null;
  }

  app.get('/api/v1/whoami', async (c) => {
    const v = vault(c.env);
    const m = await machine(c.req.raw, v);
    if (!m) return json({ error: 'invalid or revoked machine token' }, 401);
    return json({ name: m.name, tiers: m.tiers, canImport: m.canImport });
  });

  app.get('/api/v1/secrets', async (c) => {
    const v = vault(c.env);
    const m = await machine(c.req.raw, v);
    if (!m) return json({ error: 'invalid or revoked machine token' }, 401);
    const tier = c.req.query('tier') as Tier;
    if (!isVaultSlug(tier)) return json({ error: 'pass ?tier=<vault name>' }, 400);
    if (!m.tiers.includes(tier)) {
      await v.log({ event: 'machine_read_denied', by: m.name, tier });
      return json({ error: `this machine token cannot read vault ${tier}` }, 403);
    }
    try {
      const secrets = await v.loadTier(tier);
      await v.log({ event: 'machine_read', by: m.name, tier, count: secrets.size });
      return json({ tier, secrets: Object.fromEntries(secrets) });
    } catch (err) {
      const msg = (err as Error).message;
      return json({ error: msg }, /frozen/.test(msg) ? 423 : 500);
    }
  });

  /** For import-env: which vaults exist, so the script can stop early on a typo. */
  app.get('/api/v1/vaults', async (c) => {
    const v = vault(c.env);
    const m = await machine(c.req.raw, v);
    if (!m) return json({ error: 'invalid or revoked machine token' }, 401);
    if (!m.canImport) return json({ error: 'this machine token cannot import' }, 403);
    return json({ vaults: (await v.listVaults()).map((x) => ({ slug: x.slug, name: x.name })) });
  });

  /** For import scripts: create a project vault so a project can land in its own vault. */
  app.post('/api/v1/vaults', async (c) => {
    const v = vault(c.env);
    const m = await machine(c.req.raw, v);
    if (!m) return json({ error: 'invalid or revoked machine token' }, 401);
    if (!m.canImport) return json({ error: 'this machine token cannot import' }, 403);
    const body = (await c.req.json().catch(() => null)) as { slug?: string; name?: string; repos?: string[]; strict?: boolean } | null;
    try {
      const info = await v.createVault({
        slug: String(body?.slug ?? ''),
        name: String(body?.name ?? body?.slug ?? ''),
        repos: Array.isArray(body?.repos) ? body!.repos.map(String) : [],
        strict: body?.strict ?? true,
        by: `machine:${m.name}`,
      });
      return json({ slug: info.slug, name: info.name, strict: info.strict, repos: info.repos }, 201);
    } catch (err) {
      return json({ error: (err as Error).message }, 400);
    }
  });

  app.post('/api/v1/import', async (c) => {
    const v = vault(c.env);
    const m = await machine(c.req.raw, v);
    if (!m) return json({ error: 'invalid or revoked machine token' }, 401);
    if (!m.canImport) return json({ error: 'this machine token cannot import' }, 403);
    const body = (await c.req.json().catch(() => null)) as { snapshot?: Snapshot; items?: ImportItem[]; overwrite?: boolean } | null;
    try {
      if (body?.snapshot) {
        // A machine token restores values only. Machine, grant, vault, connection, link and push records from the
        // snapshot would let an import-only token mint itself read access to every vault;
        // those are re-created in the admin UI instead. Existing values are replaced only in
        // vaults the token is scoped to, so a leaked import token cannot swap production values.
        const { machines, grants, vaults, connections, links, pushes, ...rest } = body.snapshot;
        const result = await v.restoreSnapshot({ ...rest, machines: [], grants: [], vaults: [], connections: [], links: [], pushes: [] } as Snapshot, `machine:${m.name}`, m.tiers);
        return json({
          ...result,
          skipped: {
            machines: machines?.length ?? 0, grants: grants?.length ?? 0, vaults: vaults?.length ?? 0,
            connections: connections?.length ?? 0, links: links?.length ?? 0, pushes: pushes?.length ?? 0,
          },
        });
      }
      if (Array.isArray(body?.items)) {
        const outside = [...new Set(body!.items.map((it) => it.tier))].filter((t) => !m.tiers.includes(t));
        if (body!.overwrite && outside.length) return json({ error: `overwrite needs a token scoped to: ${outside.join(', ')}` }, 403);
        return json(await v.importSecrets(body!.items, `machine:${m.name}`, !!body!.overwrite));
      }
      return json({ error: 'send { snapshot } or { items, overwrite }' }, 400);
    } catch (err) {
      return json({ error: (err as Error).message }, 400);
    }
  });
}
