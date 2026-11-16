import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { createMcpHandler } from 'agents/mcp/server';
import { runBackup } from './admin';
import { AuthHandler } from './auth-handler';
import { brokerFor, staticPolicy, staticPolicyError } from './broker-env';
import { isAllowedUser, registrationDecision, sessionKeyProblem, type Env, type Props } from './env';
import { buildServer } from './mcp';
import { vaultFor } from './vault-client';

export { Vault } from './vault-do';

/** The MCP endpoint for an already-authenticated, allowlisted user. */
export function serveMcp(request: Request, env: Env, ctx: ExecutionContext, props: Props): Promise<Response> {
  const broker = brokerFor(env, props.login, env.PUBLIC_URL || new URL(request.url).origin, (p) => ctx.waitUntil(p));
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
    if (!staticPolicy()) return new Response(`secret-broker misconfigured: ${staticPolicyError()}`, { status: 500 });
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
