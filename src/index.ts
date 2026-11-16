import { readFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createDashboardBroker, DashboardClient, gitOrigin, repoFromRemote } from './dashboard.js';
import { createBroker, parseRunRequest } from './server.js';
import { SessionState } from './session.js';
import { VaultResolver } from './vaultResolver.js';
import { loadTierToken } from './keychain.js';
import { isExfilCapable, matchWorkspace, tierLabel } from './policy.js';
import { preflight } from './preflight.js';
import { TierRouter } from './resolver.js';
import { realSpawn } from './spawn.js';
import type { Policy, Tier } from './types.js';

const RUN_SCHEMA = {
  type: 'object',
  properties: {
    command: { type: 'string' },
    args: { type: 'array', items: { type: 'string' } },
    env: { type: 'object', additionalProperties: { type: 'string' } },
  },
  required: ['command', 'args', 'env'],
};

const text = (v: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(v) }] });

/** Dashboard mode: approvals come from the vault's Approvals page, per repo. */
async function runDashboard(cwd: string, token: string): Promise<void> {
  const origin = await gitOrigin(cwd);
  const repo = origin ? repoFromRemote(origin) : null;
  process.stderr.write(`[secret-broker] dashboard mode, repo ${repo ?? '(none: no git origin remote)'}\n`);
  const session = new SessionState({ idleMinutes: 30 });
  session.touch();
  setInterval(() => {
    if (session.isIdle()) {
      process.stderr.write('[secret-broker] idle shutdown, dropping secrets from memory\n');
      process.exit(0);
    }
  }, 60_000);
  const broker = createDashboardBroker({
    cwd,
    repo,
    client: new DashboardClient(token),
    spawn: realSpawn,
    auditPath: path.join(os.homedir(), '.secret-broker', 'audit.jsonl'),
    session,
  });
  const server = new Server({ name: 'secret-broker', version: '0.2.0' }, { capabilities: { tools: {} } });
  const noArgs = { type: 'object', properties: {} };
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: 'secret_status', description: `Which vaults this project's repo (${repo ?? 'none found'}) can use and how many approvals it has. Never returns secret values.`, inputSchema: noArgs },
      {
        name: 'secret_list',
        description: 'List the vaults and secret handles available to this repo (names only, never values). Secrets approved for commands on this PC show runCommands.',
        inputSchema: noArgs,
      },
      {
        name: 'secret_request_access',
        description:
          'Ask the user to approve secrets for this repo. Returns an approval link: show it to the user and wait. Each item names one secret and ' +
          'the exact command lines that will use it on this PC (e.g. "supabase db push *", "node scripts/migrate.mjs"); add env for any extra ' +
          'non-secret variable names the run sets. Nothing is usable until the user approves.',
        inputSchema: {
          type: 'object',
          properties: {
            reason: { type: 'string', description: 'One or two sentences: what you are doing and why these secrets are needed. Shown to the user.' },
            items: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  handle: { type: 'string', description: 'secret://vault/NAME, exactly as secret_list shows it.' },
                  commands: { type: 'array', items: { type: 'string' }, description: 'Command lines that may use it. A trailing * covers any further arguments.' },
                  env: { type: 'array', items: { type: 'string' }, description: 'Names of non-secret environment variables the run also sets.' },
                },
                required: ['handle', 'commands'],
              },
            },
          },
          required: ['reason', 'items'],
        },
      },
      {
        name: 'secret_request_vault',
        description: 'Ask the user to create a vault for this project, linked to its repo. Returns an approval link: show it to the user.',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string' }, slug: { type: 'string' }, reason: { type: 'string' } },
          required: ['name', 'slug', 'reason'],
        },
      },
      {
        name: 'secret_run',
        description:
          'Run an approved command with secrets injected as environment variables (env values like secret://vault/NAME). Output is redacted. ' +
          'If the run is not approved, call secret_request_access with the secret and this command line.',
        inputSchema: RUN_SCHEMA,
      },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: a } = req.params;
    const args = (a ?? {}) as Record<string, unknown>;
    if (name === 'secret_status') return text(await broker.secretStatus());
    if (name === 'secret_list') return text(await broker.secretList());
    if (name === 'secret_request_access') return text(await broker.secretRequestAccess(args));
    if (name === 'secret_request_vault') return text(await broker.secretRequestVault(args));
    if (name === 'secret_run') return text(await broker.secretRun(parseRunRequest(a)));
    throw new Error(`unknown tool: ${name}`);
  });
  await server.connect(new StdioServerTransport());
}

async function main(): Promise<void> {
  const cwd = process.cwd();
  // A stored runner token switches the broker to dashboard approvals; without one it uses policy.json as before.
  const runner = loadTierToken('runner');
  if (runner) return runDashboard(cwd, runner);
  const policyPath = path.join(os.homedir(), '.secret-broker', 'policy.json');

  let policyExists = true;
  let policyParsed = true;
  let policy: Policy = { workspaces: [] };
  try {
    policy = JSON.parse(await readFile(policyPath, 'utf8')) as Policy;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') policyExists = false;
    else policyParsed = false;
  }

  const grant = matchWorkspace(policy, cwd);
  // One token, and one resolver, per granted tier.
  const tokens = new Map<Tier, string | null>((grant?.tiers ?? []).map((t) => [t, loadTierToken(t)]));
  const missingTier = [...tokens].find(([, token]) => token === null)?.[0];

  const issues = preflight({
    policyExists,
    policyParsed,
    grantTier: missingTier ?? tierLabel(grant),
    tokenPresent: missingTier === undefined,
    prodWildcardCommands: policy.workspaces.some(
      (r) => [r.tier].flat().includes('production') && isExfilCapable(r.commands ?? []),
    ),
  });

  const nonFatal = new Set(['WORKSPACE_UNMATCHED', 'PROD_WILDCARD_COMMANDS']);
  const fatal = issues.filter((i) => !nonFatal.has(i.code));
  for (const issue of issues) {
    process.stderr.write(`[secret-broker] ${issue.code}: ${issue.message} ${issue.remediation}\n`);
  }
  if (fatal.length > 0) {
    process.stderr.write('[secret-broker] refusing to start with the issues above\n');
    process.exit(1);
  }

  const session = new SessionState({ idleMinutes: 30 });
  session.touch();
  setInterval(() => {
    if (session.isIdle()) {
      process.stderr.write('[secret-broker] idle shutdown, dropping secrets from memory\n');
      process.exit(0);
    }
  }, 60_000);

  const broker = createBroker({
    cwd,
    policy,
    resolver: new TierRouter(
      Object.fromEntries(
        [...tokens].map(([t, token]) => [t, new VaultResolver(token!, t)]),
      ),
    ),
    auditPath: path.join(os.homedir(), '.secret-broker', 'audit.jsonl'),
    spawn: realSpawn,
    session,
  });

  const server = new Server(
    { name: 'secret-broker', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: 'secret_status', description: 'Report workspace tier and token health. Never returns secret values.', inputSchema: { type: 'object', properties: {} } },
      { name: 'secret_list', description: 'List handles available to this workspace. Names only.', inputSchema: { type: 'object', properties: {} } },
      {
        name: 'secret_run',
        description: 'Run an allowlisted command with secrets injected as environment variables. Output is redacted. Never returns secret values.',
        inputSchema: {
          type: 'object',
          properties: {
            command: { type: 'string' },
            args: { type: 'array', items: { type: 'string' } },
            env: { type: 'object', additionalProperties: { type: 'string' } },
          },
          required: ['command', 'args', 'env'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: a } = req.params;
    if (name === 'secret_status') {
      return { content: [{ type: 'text', text: JSON.stringify(await broker.secretStatus()) }] };
    }
    if (name === 'secret_list') {
      return { content: [{ type: 'text', text: JSON.stringify(await broker.secretList()) }] };
    }
    if (name === 'secret_run') {
      const result = await broker.secretRun(parseRunRequest(a));
      return { content: [{ type: 'text', text: JSON.stringify(result) }] };
    }
    throw new Error(`unknown tool: ${name}`);
  });

  await server.connect(new StdioServerTransport());
}

main().catch((err: unknown) => {
  process.stderr.write(`secret-broker failed to start: ${String(err)}\n`);
  process.exit(1);
});
