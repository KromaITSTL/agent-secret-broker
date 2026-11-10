import path from 'node:path';
import picomatch from 'picomatch';
import { isTier } from './types.js';
import type { Grant, Policy, Tier } from './types.js';

/**
 * Normalize a filesystem path for policy matching.
 *
 * Returns null when the input cannot be normalized; callers must treat
 * null as deny, never as a wildcard.
 *
 * Separators are converted BEFORE collapsing, and collapsing uses
 * `path.posix.normalize` rather than `path.resolve`. Both choices are
 * deliberate and load-bearing:
 *
 *   - `path.resolve` dispatches on the host OS. On POSIX a backslash is an
 *     ordinary filename character, so `path.resolve('c:\\a\\..\\b')` sees one
 *     opaque segment and never collapses the `..`. Converting separators
 *     afterwards would then yield a normalized-looking string that still
 *     contains a live `../`, which is exactly the traversal this function
 *     exists to prevent.
 *   - `path.posix.normalize` is pure string manipulation over `/`-separated
 *     segments, so it behaves identically on Windows, macOS, and Linux. The
 *     broker runs on at least two of those.
 *
 * A traversal that escapes the drive root (`c:/a/../../x`) collapses to a
 * relative path, which then matches no absolute policy glob. That is deny,
 * which is the correct failure direction.
 */
export function normalizePath(p: string): string | null {
  if (!p || p.trim() === '') return null;
  const forward = p.replace(/\\/g, '/');
  const collapsed = path.posix.normalize(forward).toLowerCase();
  return collapsed.length > 1 ? collapsed.replace(/\/+$/, '') : collapsed;
}

/**
 * Normalize a glob pattern for matching. Deliberately does NOT use
 * normalizePath: path collapsing would eat the wildcards.
 */
function normalizePattern(pattern: string): string {
  return pattern.replace(/\\/g, '/').toLowerCase().replace(/\/+$/, '');
}

/**
 * A rule matches when the cwd is the granted directory itself (including
 * name-prefix globs like 'c:/work/client-*' matching 'c:/work/client-acme')
 * or anything beneath it. Two picomatch checks express that: the pattern
 * as written, and the pattern with '/**' appended. A single rewritten
 * pattern cannot cover both, because picomatch's `*` never crosses `/`.
 * A rule with `exact: true` skips the subtree check.
 */
export function matchWorkspace(policy: Policy, cwd: string): Grant | null {
  const normalized = normalizePath(cwd);
  if (normalized === null) return null;

  for (const rule of policy.workspaces) {
    const pattern = normalizePattern(rule.match);
    const self = picomatch(pattern, { dot: true });
    const subtree = picomatch(pattern + '/**', { dot: true });
    if (self(normalized) || (!rule.exact && subtree(normalized))) {
      const tiers = Array.isArray(rule.tier) ? rule.tier : [rule.tier];
      return { tiers, allow: rule.allow, commands: rule.commands, env: rule.env };
    }
  }
  return null;
}

/** Human-readable tier label for status and audit output: 'personal' or 'personal+production'. */
export function tierLabel(grant: Grant | null): string | null {
  return grant && grant.tiers.length > 0 ? grant.tiers.join('+') : null;
}

const HANDLE_RE = /^secret:\/\/([a-z0-9-]+)\/([^/]+)$/;

export function parseHandle(handle: string): { tier: Tier; name: string } | null {
  const m = HANDLE_RE.exec(handle);
  if (!m) return null;
  const [, tier, name] = m;
  if (!isTier(tier)) return null;
  if (!name) return null;
  return { tier: tier as Tier, name };
}

export function isHandleAllowed(grant: Grant, handle: string): boolean {
  const parsed = parseHandle(handle);
  if (!parsed) return false;
  if (!grant.tiers.includes(parsed.tier)) return false;
  if (grant.allow.length === 0) return false;
  return picomatch(grant.allow)(parsed.name);
}

export function isCommandAllowed(grant: Grant, command: string, args: string[]): boolean {
  if (grant.commands.length === 0) return false;
  const invocation = [command, ...args].join(' ');
  // dot: true so '**' also covers args with dot-folders (e.g. '.playwright-mcp/x.mjs').
  return picomatch(grant.commands, { dot: true })(invocation);
}

/**
 * Whether a non-handle env var may pass through to the child. Deny by
 * default: without this gate, an agent-chosen NODE_OPTIONS or LD_PRELOAD
 * runs arbitrary code inside the child that legitimately holds the secret,
 * bypassing the command allowlist entirely.
 */
export function isEnvKeyAllowed(grant: Grant, key: string): boolean {
  const patterns = grant.env ?? [];
  if (patterns.length === 0) return false;
  return picomatch(patterns)(key);
}

/**
 * Env names the child runtime itself reads. A secret handle landing in one of these lets
 * the agent choose a loader, proxy or search path that runs with the value, so they are
 * refused outright regardless of policy.
 */
const RESERVED_ENV_RE = /^(PATH|PATHEXT|NODE_OPTIONS|NODE_PATH|BASH_ENV|ENV|PYTHONPATH|PYTHONSTARTUP|LD_.*|DYLD_.*|.*_PROXY)$/i;

export function isReservedEnvKey(key: string): boolean {
  return RESERVED_ENV_RE.test(key);
}

/**
 * Whether a command allowlist lets the agent run an interpreter with free arguments,
 * which is the same as letting it print the secret. Checked by matching the patterns
 * against canary invocations rather than by string-comparing to '*'.
 */
const EXFIL_CANARIES = [
  'x', 'node -p process.env.X', 'node -e 1', 'npx -y x', 'sh -c 1', 'bash -c 1',
  'powershell -c 1', 'pwsh -c 1', 'cmd /c x', 'python -c 1', 'python3 -c 1',
];

export function isExfilCapable(commands: string[]): boolean {
  if (commands.length === 0) return false;
  const match = picomatch(commands, { dot: true });
  return EXFIL_CANARIES.some((c) => match(c));
}
