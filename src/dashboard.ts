/**
 * Dashboard mode: with a runner token stored (`npm run store-token runner`), the local broker
 * keeps no policy of its own. It reads the repo from the project's git remote, forwards
 * secret_list, secret_status and the request tools to the vault, and asks the vault for the
 * values of each run, which the vault hands out only for runs approved on its Approvals page.
 */
import { execFile } from 'node:child_process';
import { appendAudit } from './audit.js';
import { isReservedEnvKey, normalizePath } from './policy.js';
import { redact } from './redact.js';
import type { RunRequest, SpawnFn } from './server.js';
import { SessionState } from './session.js';
import { vaultOrigin, type FetchFn } from './vaultResolver.js';

/** owner/name in lowercase from a github.com remote URL (https or ssh), or null for any other host. */
export function repoFromRemote(url: string): string | null {
  const m = /^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|ssh:\/\/(?:[^@/]+@)?github\.com\/|[^@\s/]+@github\.com:)([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i.exec(url.trim());
  if (!m) return null;
  const repo = `${m[1]}/${m[2]}`.toLowerCase();
  return /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(repo) ? repo : null;
}

export type GitRemoteFn = (cwd: string) => Promise<string | null>;

/** The `origin` URL of the git repository containing cwd, or null when there is none. */
export const gitOrigin: GitRemoteFn = (cwd) =>
  new Promise((resolve) => {
    execFile('git', ['-C', cwd, 'remote', 'get-url', 'origin'], { windowsHide: true, timeout: 10_000 }, (err, stdout) => {
      resolve(err ? null : String(stdout).trim() || null);
    });
  });

export class DashboardError extends Error {
  override name = 'DashboardError';
}

/** Calls the vault's machine API for the local broker's tools. */
export class DashboardClient {
  constructor(
    private readonly token: string,
    private readonly fetchFn: FetchFn = fetch,
  ) {}

  get origin(): string {
    return vaultOrigin(this.token);
  }

  async call(tool: 'status' | 'list' | 'request_access' | 'request_vault' | 'run', body: unknown): Promise<unknown> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.origin}/api/v1/broker/${tool}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${this.token.trim()}`, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(20_000),
      });
    } catch (err) {
      throw new DashboardError(`could not reach the vault at ${this.origin}: ${(err as Error).message}`);
    }
    const json = (await res.json().catch(() => ({}))) as { error?: string };
    if (!res.ok) {
      const hint =
        res.status === 401 ? ' (runner token revoked or wrong; create a new one on the Machines page and run npm run store-token runner)'
        : res.status === 423 ? ' (the vault is frozen; unfreeze it in Settings)'
        : '';
      throw new DashboardError(`${json.error ?? `vault answered HTTP ${res.status}`}${hint}`);
    }
    return json;
  }
}

export interface DashboardDeps {
  cwd: string;
  /** owner/name from the git remote, or null outside a git repository with an origin. */
  repo: string | null;
  client: Pick<DashboardClient, 'call'>;
  spawn: SpawnFn;
  auditPath: string | null;
  session?: SessionState;
}

const NO_REPO =
  'This folder is not in a git repository with an origin remote, so the vault cannot approve anything for it: approvals are per repo. Open the project folder instead.';

export function createDashboardBroker(deps: DashboardDeps) {
  const session = deps.session ?? new SessionState({ idleMinutes: 30 });
  const workspace = normalizePath(deps.cwd);
  const needRepo = (): string => {
    if (!deps.repo) throw new DashboardError(NO_REPO);
    return deps.repo;
  };

  async function audit(outcome: 'allowed' | 'denied', handles: string[], command: string, exitCode: number | null, reason?: string): Promise<void> {
    if (!deps.auditPath) return;
    await appendAudit(deps.auditPath, {
      ts: new Date().toISOString(),
      brokerId: session.brokerId,
      workspace: workspace ?? '(unresolvable)',
      tier: deps.repo ? `repo:${deps.repo}` : null,
      handles,
      command,
      outcome,
      exitCode,
      reason,
    });
  }

  return {
    async secretStatus() {
      if (!deps.repo) return { mode: 'dashboard', repo: null, workspace, reason: NO_REPO };
      return { mode: 'dashboard', workspace, ...((await deps.client.call('status', { repo: deps.repo })) as Record<string, unknown>) };
    },

    async secretList() {
      session.touch();
      return deps.client.call('list', { repo: needRepo() });
    },

    async secretRequestAccess(args: { reason?: unknown; items?: unknown }) {
      return deps.client.call('request_access', { reason: args.reason, items: args.items, repo: needRepo() });
    },

    async secretRequestVault(args: { name?: unknown; slug?: unknown; reason?: unknown }) {
      return deps.client.call('request_vault', { name: args.name, slug: args.slug, reason: args.reason, repo: needRepo() });
    },

    async secretRun(req: RunRequest) {
      const invocation = [req.command, ...req.args].join(' ');
      const handles = [...new Set(Object.values(req.env).filter((v) => v.startsWith('secret://')))];
      const deny = async (reason: string): Promise<never> => {
        await audit('denied', handles, invocation, null, reason);
        throw new DashboardError(reason);
      };
      if (!deps.repo || workspace === null) return deny(NO_REPO);
      if (!session.bindWorkspace(workspace)) return deny('this broker is bound to a different workspace');
      for (const key of Object.keys(req.env)) {
        // These load code or change the search path, whether or not they hold a secret.
        if (isReservedEnvKey(key)) return deny(`env var ${key} may not be set: the child runtime reads it to load code`);
      }
      const extraEnv = Object.entries(req.env).filter(([, v]) => !v.startsWith('secret://')).map(([k]) => k);

      let values: Record<string, string>;
      try {
        const res = (await deps.client.call('run', { repo: deps.repo, command: req.command, args: req.args, handles, env: extraEnv })) as { values?: Record<string, unknown> };
        values = Object.fromEntries(Object.entries(res.values ?? {}).filter((e): e is [string, string] => typeof e[1] === 'string'));
      } catch (err) {
        return deny((err as Error).message);
      }
      for (const h of handles) if (values[h] === undefined) return deny(`the vault did not return ${h}`);

      session.touch();
      const env: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.env)) env[key] = value.startsWith('secret://') ? values[value]! : value;
      const injected = new Map(handles.map((h) => [h, values[h]!]));

      session.runStarted();
      let result;
      try {
        result = await deps.spawn(req.command, req.args, env);
      } finally {
        session.runFinished();
      }
      await audit('allowed', handles, invocation, result.code);
      return { exitCode: result.code, stdout: redact(result.stdout, injected), stderr: redact(result.stderr, injected) };
    },
  };
}

export type DashboardBroker = ReturnType<typeof createDashboardBroker>;
