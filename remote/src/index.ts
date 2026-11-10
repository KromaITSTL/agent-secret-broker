import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { createMcpHandler } from 'agents/mcp/server';
import policyJson from '../policy.json';
import { runBackup } from './admin';
import { AuthHandler } from './auth-handler';
import { createBroker, type AuditEvent, type SecretSource } from './broker';
import { isAllowedUser, registrationDecision, sessionKeyProblem, type Env, type Props } from './env';
import type { Grants } from './grants';
import { buildServer } from './mcp';
import { validatePolicy, type Policy } from './policy';
import { vaultFor } from './vault-client';

export { Vault } from './vault-do';

// Optional static rules, bundled at deploy time. Normally empty: access is
// granted per repo on the approval page instead.
let policy: Policy | null = null;
let policyError: string | null = null;
try {
  policy = validatePolicy(policyJson);
} catch (err) {
  policyError = (err as Error).message;
}

/** The MCP endpoint for an already-authenticated, allowlisted user. */
export function serveMcp(request: Request, env: Env, ctx: ExecutionContext, props: Props): Promise<Response> {
  const vault = vaultFor(env);
  const source: SecretSource = {
    vaults: async () => (await vault.listVaults()).map(({ slug, name, strict, repos }) => ({ slug, name, strict, repos })),
    load: (tier) => vault.loadTier(tier),
    loginInfo: (t, n) => vault.loginInfo(t, n),
    readSecret: (t, n) => vault.readSecret(t, n),
    requestVault: (input) => vault.requestVault(input),
  };
  // Every MCP-side event lands in the vault's audit log (and Workers Logs). Never values.
  const audit = (e: AuditEvent) => {
    console.log(JSON.stringify(e));
    const { event, user, ...rest } = e;
    ctx.waitUntil(vault.log({ event, by: user, ...rest }).catch(() => {}));
  };
  const broker = createBroker({
    policy: policy!,
    grants: vault as unknown as Grants,
    source,
    user: props.login,
    audit,
    publicUrl: env.PUBLIC_URL || new URL(request.url).origin,
  });
  return createMcpHandler(() => buildServer(broker), { route: '/mcp' })(request, env, ctx);
}

const apiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const props = (ctx as ExecutionContext & { props?: Props }).props;
    // Re-checked on every request, so removing an id from ALLOWED_GITHUB_IDS
    // cuts off tokens that were already issued.
    if (!props?.githubId || !isAllowedUser(env, props.githubId)) {
      return new Response('forbidden', { status: 403 });
    }
    if (!policy) return new Response(`secret-broker misconfigured: ${policyError}`, { status: 500 });
    return serveMcp(request, env, ctx, props);
  },
};

// Built on first request because the RFC 9728 resource URL comes from env.
let provider: OAuthProvider<Env> | null = null;
// The registration hook has no env argument, and the provider is built once, so keep the latest env here.
let currentEnv: Env;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const keyProblem = sessionKeyProblem(env.COOKIE_ENCRYPTION_KEY);
    if (keyProblem) return new Response(`secret-broker misconfigured: ${keyProblem}`, { status: 500 });
    currentEnv = env;
    provider ??= new OAuthProvider<Env>({
      apiRoute: '/mcp',
      apiHandler,
      defaultHandler: AuthHandler as unknown as ExportedHandler<Env>,
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/token',
      clientRegistrationEndpoint: '/register',
      // Registration is closed unless the operator opened a short window on the Connectors page.
      // The provider calls this after validating the metadata and before storing the client, so a
      // slot is spent and logged only for a registration that is kept, and a refusal writes nothing.
      // Redirect hosts are checked too, so a registered client cannot send tokens to an unknown host.
      clientRegistrationCallback: ({ clientMetadata }) => registrationDecision(clientMetadata, (info) => vaultFor(currentEnv).takeRegistration(info)),
      resourceMetadata: {
        resource: env.PUBLIC_URL ? new URL('/mcp', env.PUBLIC_URL).href : new URL('/mcp', request.url).href,
        resource_name: 'secret-broker',
      },
      accessTokenTTL: 3600,
      refreshTokenTTL: 30 * 24 * 3600,
    });
    return provider.fetch(request, env, ctx);
  },

  // Nightly encrypted backup to R2 (schedule in wrangler.jsonc).
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      runBackup(env, 'nightly').catch((err) => {
        console.error(JSON.stringify({ event: 'backup_failed', error: (err as Error).message }));
        throw err;
      }),
    );
  },
} satisfies ExportedHandler<Env>;
