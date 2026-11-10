import { matchWorkspace, isHandleAllowed, isCommandAllowed, isEnvKeyAllowed, isReservedEnvKey, parseHandle, normalizePath, tierLabel } from './policy.js';
import { redact } from './redact.js';
import { appendAudit } from './audit.js';
import { SessionState } from './session.js';
import type { SecretResolver } from './resolver.js';
import type { Policy, Tier } from './types.js';

export type SpawnFn = (
  cmd: string,
  args: string[],
  env: Record<string, string>,
) => Promise<{ stdout: string; stderr: string; code: number }>;

export interface BrokerDeps {
  cwd: string;
  policy: Policy;
  resolver: SecretResolver;
  auditPath: string | null;
  spawn: SpawnFn;
  session?: SessionState;
}

export interface RunRequest {
  command: string;
  args: string[];
  env: Record<string, string>;
}

/**
 * Shape-check untrusted tool arguments. The MCP SDK does not enforce
 * inputSchema server-side, and this is the trust boundary of a credential
 * broker: malformed input gets a clean denial, not a TypeError.
 */
export function parseRunRequest(input: unknown): RunRequest {
  const o = input as Partial<RunRequest> | null | undefined;
  if (
    !o || typeof o !== 'object' ||
    typeof o.command !== 'string' ||
    !Array.isArray(o.args) || !o.args.every((x) => typeof x === 'string') ||
    typeof o.env !== 'object' || o.env === null || Array.isArray(o.env) ||
    !Object.values(o.env).every((v) => typeof v === 'string')
  ) {
    throw new Error('invalid secret_run arguments: expected { command: string, args: string[], env: Record<string, string> }');
  }
  return { command: o.command, args: o.args, env: o.env };
}

export function createBroker(deps: BrokerDeps) {
  const session = deps.session ?? new SessionState({ idleMinutes: 30 });
  const workspace = normalizePath(deps.cwd);
  const grant = workspace === null ? null : matchWorkspace(deps.policy, deps.cwd);

  async function audit(
    outcome: 'allowed' | 'denied',
    handles: string[],
    command: string,
    exitCode: number | null,
    reason?: string,
  ): Promise<void> {
    if (!deps.auditPath) return;
    await appendAudit(deps.auditPath, {
      ts: new Date().toISOString(),
      brokerId: session.brokerId,
      workspace: workspace ?? '(unresolvable)',
      tier: tierLabel(grant),
      handles,
      command,
      outcome,
      exitCode,
      reason,
    });
  }

  return {
    async secretStatus() {
      // Deliberately no touch: status is unauthenticated and must not let
      // an agent keep the broker (and its cached secrets) alive for free.
      return {
        brokerId: session.brokerId,
        workspace,
        tier: tierLabel(grant),
        tiers: (grant?.tiers ?? []) as Tier[],
        authorized: grant !== null,
        allow: grant?.allow ?? [],
        commands: grant?.commands ?? [],
      };
    },

    async secretList() {
      const tier = tierLabel(grant);
      if (!grant || tier === null) return { tier: null, handles: [] };
      session.touch();

      // Real handle names, filtered through the allow patterns, per the
      // spec's stated return shape. Never values.
      const handles: string[] = [];
      for (const t of grant.tiers) {
        const names = await deps.resolver.list(t);
        handles.push(
          ...names
            .map((name) => `secret://${t}/${name}`)
            .filter((handle) => isHandleAllowed(grant, handle)),
        );
      }
      return { tier, handles };
    },

    async secretRun(req: RunRequest) {
      const invocation = [req.command, ...req.args].join(' ');
      const handles = Object.values(req.env).filter((v) => v.startsWith('secret://'));

      if (workspace === null || grant === null) {
        await audit('denied', handles, invocation, null, 'workspace not in policy');
        throw new Error('workspace is not authorized by policy');
      }
      if (!session.bindWorkspace(workspace)) {
        await audit('denied', handles, invocation, null, 'workspace rebind refused');
        throw new Error('this broker is bound to a different workspace');
      }
      if (!isCommandAllowed(grant, req.command, req.args)) {
        await audit('denied', handles, invocation, null, 'command not allowed');
        throw new Error(`command not allowed by policy: ${invocation}`);
      }
      for (const handle of handles) {
        if (!isHandleAllowed(grant, handle)) {
          await audit('denied', handles, invocation, null, `handle not allowed: ${handle}`);
          throw new Error(`handle not allowed by policy: ${handle}`);
        }
      }
      for (const [key, value] of Object.entries(req.env)) {
        if (value.startsWith('secret://')) {
          if (isReservedEnvKey(key)) {
            await audit('denied', handles, invocation, null, `reserved env var: ${key}`);
            throw new Error(`env var ${key} may not hold a secret: the child runtime reads it`);
          }
          continue;
        }
        if (!isEnvKeyAllowed(grant, key)) {
          await audit('denied', handles, invocation, null, `env var not allowed: ${key}`);
          throw new Error(`env var not allowed by policy: ${key} (add it to the workspace rule's env list)`);
        }
      }

      // Every gate passed: this is authorized activity.
      session.touch();

      const values = new Map<string, string>();
      const env: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.env)) {
        if (!value.startsWith('secret://')) {
          env[key] = value;
          continue;
        }
        const parsed = parseHandle(value);
        if (!parsed) throw new Error(`unparseable handle: ${value}`);
        const secret = await deps.resolver.resolve(parsed.tier, parsed.name);
        values.set(value, secret);
        env[key] = secret;
      }

      session.runStarted();
      let result;
      try {
        result = await deps.spawn(req.command, req.args, env);
      } finally {
        session.runFinished();
      }
      await audit('allowed', handles, invocation, result.code);

      return {
        exitCode: result.code,
        stdout: redact(result.stdout, values),
        stderr: redact(result.stderr, values),
      };
    },
  };
}

export type Broker = ReturnType<typeof createBroker>;
