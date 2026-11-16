/**
 * Machine API for the local broker and the restore script. Bearer machine
 * token (created on the Machines page), never a browser session.
 */
import type { Hono } from 'hono';
import { DeniedError, type Broker } from './broker';
import { brokerFor } from './broker-env';
import type { Env } from './env';
import { GrantError } from './grants';
import { isVaultSlug, type Tier } from './policy';
import type { ImportItem, Snapshot } from './store';
import { vaultFor } from './vault-client';
import type { VaultApi } from './vault-do';

type App<B extends Env> = Hono<{ Bindings: B }>;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export interface ApiDeps {
  vault?: (env: Env) => VaultApi;
  /** Overridable for tests: the broker that serves the local broker's tool calls. */
  broker?: (env: Env, user: string, publicUrl: string, waitUntil: (p: Promise<unknown>) => void) => Broker;
}

/** Tools the local broker forwards, mirroring the claude.ai connector's tools. */
const BROKER_TOOLS = ['status', 'list', 'request_access', 'request_vault', 'run'] as const;
type BrokerTool = (typeof BROKER_TOOLS)[number];

export function registerApiRoutes<B extends Env>(app: App<B>, deps: ApiDeps = {}): void {
  const vault = deps.vault ?? ((env: Env) => vaultFor(env));
  const broker = deps.broker ?? brokerFor;

  async function machine(req: Request, v: VaultApi) {
    const auth = req.headers.get('Authorization') ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    return token ? v.authMachine(token) : null;
  }

  /**
   * The local broker's tools, served with the same broker as the claude.ai connector, so a
   * request from Claude Code lands on the same Approvals page. The local broker reads the repo
   * from the project's git remote. `run` returns values only for an approved run.
   */
  app.post('/api/v1/broker/:tool', async (c) => {
    const tool = c.req.param('tool') as BrokerTool;
    if (!BROKER_TOOLS.includes(tool)) return json({ error: 'unknown tool' }, 404);
    const m = await machine(c.req.raw, vault(c.env));
    if (!m) return json({ error: 'invalid or revoked machine token' }, 401);
    // Only a runner token (no vaults, no import) may use these routes, so an import or
    // vault-scoped token cannot collect run-approved values from other repos.
    if (m.tiers.length > 0 || m.canImport) return json({ error: 'this route needs a runner token (create one on the Machines page with nothing ticked)' }, 403);
    const args = ((await c.req.json().catch(() => null)) ?? {}) as Record<string, unknown>;
    if (args.repo !== undefined && typeof args.repo !== 'string') return json({ error: 'repo must be a string (owner/name)' }, 400);
    if (tool === 'request_access') {
      const items = Array.isArray(args.items) ? (args.items as Array<Record<string, unknown>>) : [];
      // The local broker asks only for runs on the PC; hosts and reveals belong to the connector.
      if (items.some((i) => !i || !Array.isArray(i.commands) || i.hosts !== undefined || i.methods !== undefined || i.paths !== undefined || i.reveal !== undefined)) {
        return json({ error: 'each item needs commands (the command lines that will use it) and nothing else' }, 400);
      }
    }
    const waitUntil = (p: Promise<unknown>) => {
      try {
        c.executionCtx.waitUntil(p);
      } catch {
        // no execution context (unit tests); the promise still runs
      }
    };
    const b = broker(c.env, `machine:${m.name}`, c.env.PUBLIC_URL || new URL(c.req.url).origin, waitUntil);
    try {
      switch (tool) {
        case 'status': return json(await b.status(args.repo as string | undefined));
        case 'list': return json(await b.list(args.repo as string | undefined));
        case 'request_access': return json(await b.requestAccess(args as unknown as Parameters<Broker['requestAccess']>[0]));
        case 'request_vault': return json(await b.requestVault(args as unknown as Parameters<Broker['requestVault']>[0]));
        case 'run': return json(await b.run(args as unknown as Parameters<Broker['run']>[0]));
      }
    } catch (err) {
      const msg = (err as Error).message;
      if (err instanceof DeniedError) return json({ error: msg }, 403);
      if (err instanceof GrantError) return json({ error: msg }, 400);
      return json({ error: msg }, /frozen/.test(msg) ? 423 : 500);
    }
  });

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
