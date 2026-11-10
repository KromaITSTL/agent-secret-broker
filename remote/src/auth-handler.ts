/**
 * GitHub login in front of the connector, adapted from Cloudflare's
 * remote-mcp-github-oauth demo (MIT, Copyright (c) 2025 Cloudflare, Inc.). Two changes that matter:
 *   - Only GitHub accounts listed (by numeric id) in ALLOWED_GITHUB_IDS get a
 *     token. Everyone else is refused before an MCP token is ever issued.
 *   - The GitHub access token is not kept in the MCP token's props. The
 *     broker never needs it, so it is not stored anywhere.
 */
import { AuthorizationError, type AuthRequest, type OAuthHelpers } from '@cloudflare/workers-oauth-provider';
import { Hono, type Context } from 'hono';
import type { Env, Props } from './env';
import { isAllowedUser } from './env';
import { registerAdminRoutes } from './admin';
import { registerApiRoutes } from './api';
import { vaultFor } from './vault-client';
import { githubUser, page, registerWebRoutes } from './web';
import {
  addApprovedClient,
  bindStateToSession,
  createOAuthState,
  generateCSRFProtection,
  isClientApproved,
  OAuthError,
  renderApprovalDialog,
  validateCSRFToken,
  validateOAuthState,
} from './workers-oauth-utils';

/**
 * Both sign-ins (Claude connector and the vault pages) return from GitHub to
 * /callback/web. The connector's one-time state lives under oauth:state:* in
 * KV; the web sign-in keeps its state in a signed cookie instead, so the handler
 * below tells them apart by looking the state up in KV. /callback is kept for
 * any flow already in progress.
 */
const GITHUB_CALLBACK = '/callback/web';

/** Shown when the provider no longer knows the app that asked to connect (removed, or its registration lapsed). */
const unknownApp = () =>
  page(
    'Cannot connect this app',
    '<h1>Cannot connect this app</h1><p>This vault does not recognise the app that asked to connect. It may have been removed on the Connectors page, or its registration lapsed after a long time without use.</p><p>Open <a href="/connectors">Connectors</a>, allow a new connection, then add the connector in the app again.</p>',
    400,
  );

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

function githubAuthorizeUrl(request: Request, env: Env, state: string): string {
  const u = new URL('https://github.com/login/oauth/authorize');
  u.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  u.searchParams.set('redirect_uri', new URL(GITHUB_CALLBACK, request.url).href);
  u.searchParams.set('scope', 'read:user');
  u.searchParams.set('state', state);
  return u.href;
}

app.get('/authorize', async (c) => {
  let oauthReqInfo: AuthRequest;
  try {
    oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
  } catch (error) {
    if (error instanceof AuthorizationError) return unknownApp();
    throw error;
  }
  if (!oauthReqInfo.clientId) return c.text('Invalid request', 400);

  if (await isClientApproved(c.req.raw, oauthReqInfo.clientId, c.env.COOKIE_ENCRYPTION_KEY)) {
    const { stateToken } = await createOAuthState(oauthReqInfo, c.env.OAUTH_KV);
    const { setCookie } = await bindStateToSession(stateToken);
    return new Response(null, {
      status: 302,
      headers: { Location: githubAuthorizeUrl(c.req.raw, c.env, stateToken), 'Set-Cookie': setCookie },
    });
  }

  const { token: csrfToken, setCookie } = generateCSRFProtection();
  return renderApprovalDialog(c.req.raw, {
    client: await c.env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId),
    csrfToken,
    server: {
      name: 'secret-broker',
      description:
        'Lets this client list your secret names, ask you to approve secrets per repo, and make HTTPS ' +
        'requests with approved secrets injected. It never sees values. Only approve clients you started yourself.',
    },
    setCookie,
    state: { oauthReqInfo },
  });
});

app.post('/authorize', async (c) => {
  try {
    const formData = await c.req.raw.formData();
    validateCSRFToken(formData, c.req.raw);

    const encodedState = formData.get('state');
    if (!encodedState || typeof encodedState !== 'string') return c.text('Missing state', 400);
    let state: { oauthReqInfo?: AuthRequest };
    try {
      state = JSON.parse(atob(encodedState));
    } catch {
      return c.text('Invalid state', 400);
    }
    if (typeof state.oauthReqInfo?.clientId !== 'string' || !state.oauthReqInfo.clientId) return c.text('Invalid request', 400);
    // An unknown client would only fill KV with state nobody can use, so refuse before writing.
    // The redirect URI is not compared here: completeAuthorization validates it, with the
    // any-port rule for loopback clients that a plain string comparison would break.
    if (!(await c.env.OAUTH_PROVIDER.lookupClient(state.oauthReqInfo.clientId))) return c.text('Invalid request', 400);

    const approvedClientCookie = await addApprovedClient(c.req.raw, state.oauthReqInfo.clientId, c.env.COOKIE_ENCRYPTION_KEY);
    const { stateToken } = await createOAuthState(state.oauthReqInfo, c.env.OAUTH_KV);
    const { setCookie } = await bindStateToSession(stateToken);

    const headers = new Headers({ Location: githubAuthorizeUrl(c.req.raw, c.env, stateToken) });
    headers.append('Set-Cookie', approvedClientCookie);
    headers.append('Set-Cookie', setCookie);
    return new Response(null, { status: 302, headers });
  } catch (error) {
    if (error instanceof OAuthError) return error.toResponse();
    console.error('POST /authorize error', (error as Error).message);
    return c.text('Internal server error', 500);
  }
});

type Ctx = Context<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>;

/** Best-effort audit entry; a failure here never breaks sign-in. */
function audit(c: Ctx, entry: { event: string; by: string; [k: string]: unknown }): void {
  const done = vaultFor(c.env).log(entry).catch(() => {});
  try {
    c.executionCtx.waitUntil(done);
  } catch {
    // no execution context (unit tests); the promise still runs
  }
}

/** Client details for the audit log; the name is client-supplied, so it is length-capped. */
async function clientDetails(c: Ctx, req: AuthRequest) {
  const client = await c.env.OAUTH_PROVIDER.lookupClient(req.clientId).catch(() => null);
  return { clientId: req.clientId, clientName: (client?.clientName ?? '').slice(0, 100), redirectHost: URL.canParse(req.redirectUri) ? new URL(req.redirectUri).hostname : '' };
}

async function connectorCallback(c: Ctx, callbackPath: string): Promise<Response> {
  let oauthReqInfo: AuthRequest;
  let clearSessionCookie: string;
  try {
    const result = await validateOAuthState(c.req.raw, c.env.OAUTH_KV);
    oauthReqInfo = result.oauthReqInfo;
    clearSessionCookie = result.clearCookie;
  } catch (error) {
    if (error instanceof OAuthError) return error.toResponse();
    return c.text('Internal server error', 500);
  }
  if (!oauthReqInfo.clientId) return c.text('Invalid OAuth request data', 400);

  const code = c.req.query('code');
  if (!code) return c.text('Missing code', 400);

  const user = await githubUser(c.env, code, new URL(callbackPath, c.req.url).href);
  if ('error' in user) return c.text(`GitHub login failed: ${user.error}`, 502);

  if (!isAllowedUser(c.env, String(user.id))) {
    console.log(JSON.stringify({ event: 'login_refused', githubId: user.id, login: user.login, clientId: oauthReqInfo.clientId }));
    return c.text(`GitHub account ${user.login} (id ${user.id}) is not allowed to use this connector.`, 403);
  }

  const props: Props = { githubId: String(user.id), login: user.login };
  let redirectTo: string;
  try {
    ({ redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthReqInfo,
      userId: String(user.id),
      metadata: { label: user.login },
      scope: oauthReqInfo.scope,
      props,
    }));
  } catch (error) {
    console.error(JSON.stringify({ event: 'authorization_failed', clientId: oauthReqInfo.clientId, error: (error as Error).message }));
    return unknownApp();
  }
  console.log(JSON.stringify({ event: 'login', githubId: user.id, login: user.login, clientId: oauthReqInfo.clientId }));
  audit(c, { event: 'connector_login', by: user.login, ...(await clientDetails(c, oauthReqInfo)) });

  const headers = new Headers({ Location: redirectTo });
  if (clearSessionCookie) headers.set('Set-Cookie', clearSessionCookie);
  return new Response(null, { status: 302, headers });
}

app.get('/callback', (c) => connectorCallback(c, '/callback'));

// Runs before the web sign-in handler: a connector state goes here, anything else falls through.
app.get('/callback/web', async (c, next) => {
  const state = c.req.query('state');
  if (state && (await c.env.OAUTH_KV.get(`oauth:state:${state}`)) !== null) {
    return connectorCallback(c, GITHUB_CALLBACK);
  }
  await next();
});

registerWebRoutes(app);
registerAdminRoutes(app);
registerApiRoutes(app);

export { app as AuthHandler };
