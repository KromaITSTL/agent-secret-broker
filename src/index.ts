import { readFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createBroker, parseRunRequest } from './server.js';
import { SessionState } from './session.js';
import { VaultResolver } from './vaultResolver.js';
import { loadTierToken } from './keychain.js';
import { isExfilCapable, matchWorkspace, tierLabel } from './policy.js';
import { preflight } from './preflight.js';
import { TierRouter } from './resolver.js';
import { realSpawn } from './spawn.js';
import type { Policy, Tier } from './types.js';

async function main(): Promise<void> {
  const cwd = process.cwd();
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
