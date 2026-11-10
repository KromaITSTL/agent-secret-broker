import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { DeniedError, type Broker } from './broker';
import { GrantError } from './grants';

const json = (value: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] });
const failure = (message: string) => ({ content: [{ type: 'text' as const, text: message }], isError: true });

const repoField = z
  .string()
  .describe('The GitHub repo you are working on, as owner/name. Approvals are granted per repo.');

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;

async function guarded<T>(fn: () => Promise<T>) {
  try {
    return json(await fn());
  } catch (err) {
    const msg = (err as Error).message;
    return failure(err instanceof DeniedError ? `Denied by secret-broker policy: ${msg}` : err instanceof GrantError ? `Request not accepted: ${msg}` : msg);
  }
}

export function buildServer(broker: Broker): McpServer {
  const server = new McpServer(
    { name: 'secret-broker', version: '1.3.0' },
    {
      instructions:
        'Credential broker. Secrets live in vaults (personal, production, and one per client project) and you see ' +
        'handles like secret://<vault>/NAME, never values. Client credentials belong in a project vault, never in .env ' +
        'files. Workflow: (1) secret_list with the repo you are working on (owner/name) to see the vaults and secrets ' +
        'available to it and which are already approved, and where. If the project needs its own vault and none ' +
        'exists, call secret_request_vault and give the user the link. (2) If you need a secret that is not approved, call ' +
        'secret_request_access with the repo, a clear reason, and for each secret the exact host(s) it must go to ' +
        '(and methods/paths when you know them; strict vaults require methods). Show the returned approval link to the user and wait for them to ' +
        'approve. (3) Call secret_fetch with the repo and {{secret://tier/NAME}} placeholders in a header, the query ' +
        'string, the body, or basic_auth. ' +
        'Website logins (kind: "login" in secret_list) can be requested with reveal: true instead of hosts; once approved, secret_reveal returns the username and password for signing in through a browser. Prefer secret_fetch over secret_reveal whenever the sign-in can be done as an HTTP request. Never ask the user to paste a secret, never reconstruct or echo an API key, never repeat a revealed password outside the sign-in form, and never work around a denial. Ask only for what the task needs: the narrowest hosts and methods.',
    },
  );

  server.registerTool(
    'secret_status',
    {
      title: 'Secret broker status',
      description: 'Who is signed in, which vaults this repo can use, and how many approvals it has. Never returns secret values.',
      inputSchema: z.object({ repo: repoField.optional() }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ repo }) => guarded(() => broker.status(repo)),
  );

  server.registerTool(
    'secret_list',
    {
      title: 'List secrets',
      description:
        'List the vaults and secret handles available to the repo (names only, never values). Vaults linked to other ' +
        'repos are hidden. Secrets already approved for the repo show approved: true and the hosts, methods and paths ' +
        'they may be sent to.' +
        ' Logins show kind: "login", username and url, and revealApproved when you may reveal them. Limited approvals show expiresAt and usesLeft.',
      inputSchema: z.object({ repo: repoField.optional() }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ repo }) => guarded(() => broker.list(repo)),
  );

  server.registerTool(
    'secret_request_access',
    {
      title: 'Request access to secrets for a repo',
      description:
        'Ask the user to approve secrets for a repo. Returns an approval link: show it to the user and wait. Each ' +
        'item names one secret and the exact hosts it will be sent to (exact hostnames, or *.example.com). ' +
        'Secrets in strict vaults (production, client projects) must also list methods. Nothing is usable until the user approves.' +
        ' For a website login you will type into a browser, set reveal: true instead of hosts; the password will be visible to you once approved.',
      inputSchema: z.object({
        repo: repoField,
        reason: z.string().describe('One or two sentences: what you are doing and why these secrets are needed. Shown to the user.'),
        items: z
          .array(
            z.object({
              handle: z.string().describe('secret://tier/NAME, exactly as secret_list shows it.'),
              hosts: z.array(z.string()).min(1).optional().describe('Hostnames this secret will be sent to, e.g. api.github.com.'),
              reveal: z.literal(true).optional().describe('Website logins only: ask to reveal the username and password to you instead of sending them to hosts. Omit hosts, methods and paths.'),
              methods: z.array(z.enum(METHODS)).optional().describe('Required for strict vaults. Omit for any method.'),
              paths: z.array(z.string()).optional().describe('Path globs, e.g. /rest/v1/**. Omit for any path.'),
            })
              .refine((i) => (i.hosts !== undefined) !== (i.reveal === true), { message: 'each item needs exactly one of hosts (non-empty) or reveal: true' })
              .refine((i) => !(i.reveal === true && (i.methods !== undefined || i.paths !== undefined)), { message: 'reveal items take no methods or paths' }),
          )
          .min(1),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async (args) => guarded(() => broker.requestAccess(args)),
  );

  server.registerTool(
    'secret_request_vault',
    {
      title: 'Request a new project vault',
      description:
        'Ask the user to create a vault for a client project, linked to a repo, so its credentials stay out of .env ' +
        'files. Returns an approval link: show it to the user. The vault starts empty; the user adds values (or imports ' +
        'the project .env with npm run import-env), then you request access to the secrets you need.',
      inputSchema: z.object({
        repo: repoField,
        name: z.string().describe('Display name, e.g. "Acme Corp - billing dashboard".'),
        slug: z.string().describe('Vault id: lowercase letters, digits and dashes, 2-40 chars, e.g. acme-finance.'),
        reason: z.string().describe('One sentence on why this project needs its own vault. Shown to the user.'),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async (args) => guarded(() => broker.requestVault(args)),
  );

  server.registerTool(
    'secret_fetch',
    {
      title: 'HTTPS request with secrets',
      description:
        'Make one HTTPS request with secrets injected. Put {{secret://tier/NAME}} placeholders in header values, the ' +
        'query string, the body, or basic_auth; the broker substitutes them (URL-encoded in the query, JSON-escaped in ' +
        'JSON bodies) only if that secret is approved for this repo, host, method and path. Placeholders are not ' +
        'allowed in the hostname or the URL path. Redirects are not followed. Known secret values are redacted from the ' +
        'response. Example: {"repo":"acme/app","url":"https://api.github.com/user","headers":{"Authorization":"Bearer {{secret://personal/GITHUB_TOKEN}}"}}',
      inputSchema: z.object({
        repo: repoField,
        url: z.string().describe('Full https:// URL. Query string may contain placeholders; host and path may not.'),
        method: z.enum(METHODS).optional().describe('Default GET.'),
        headers: z.record(z.string(), z.string()).optional().describe('Header values may contain placeholders.'),
        body: z.string().optional().describe('Request body as a string. Serialize JSON yourself and set Content-Type.'),
        basic_auth: z
          .object({ username: z.string(), password: z.string() })
          .optional()
          .describe('Sets Authorization: Basic. Either field may be or contain a placeholder.'),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    async (args) => guarded(() => broker.fetch(args)),
  );

  server.registerTool(
    'secret_reveal',
    {
      title: 'Reveal a website login',
      description:
        'Return the username and password of a website login approved for reveal for this repo, to sign in through a browser. Logins only; API keys are never revealed. Every reveal is audited and may use up a limited approval. Prefer secret_fetch when the sign-in is a plain HTTP request.',
      inputSchema: z.object({ repo: repoField, handle: z.string().describe('secret://tier/NAME of a login, exactly as secret_list shows it.') }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async (args) => guarded(() => broker.reveal(args)),
  );

  return server;
}
