/**
 * One-time conversion from policy.json rules to dashboard approvals. It reads only the local
 * audit log (names and commands, never values) and proposes, per repo, the secrets agents
 * actually used and the commands that used them. Nothing is approved here: each proposal
 * becomes an access request that the operator approves on the dashboard.
 */
import type { AuditEntry } from './audit.js';
import { isExfilCapable } from './policy.js';

export interface ProposedItem {
  handle: string;
  commands: string[];
}

export interface Proposal {
  repo: string;
  workspaces: string[];
  items: ProposedItem[];
  firstUsed: string;
  lastUsed: string;
  runs: number;
}

export interface ConversionResult {
  proposals: Proposal[];
  /** Command lines left out: one-off scripts in temporary folders, or patterns that could print a secret. */
  skipped: Array<{ repo: string; command: string; why: string }>;
  /** Folders that used secrets but have no git origin remote, so nothing can be approved for them. */
  noRepo: string[];
}

const INTERPRETERS = new Set(['node', 'python', 'python3', 'deno', 'bun']);
const SCRIPT_RE = /\.(m?js|cjs|ts|mts|py)$/i;

/**
 * The approval pattern for a logged command line, plus ` *` when more arguments followed:
 * - an interpreter keeps everything up to its script (`node scripts/deploy.js get x` becomes
 *   `node scripts/deploy.js *`; `node node_modules/tsx/dist/cli.mjs scripts/a.ts` keeps both);
 * - anything else keeps the program and up to two subcommands before the first flag
 *   (`supabase db push --linked` becomes `supabase db push *`).
 */
export function commandPattern(command: string): string {
  const words = command.trim().split(/\s+/).filter(Boolean);
  let keep = 0;
  if (INTERPRETERS.has(words[0] ?? '')) {
    keep = 1;
    for (let i = 1; i < words.length; i++) {
      if (words[i]!.startsWith('-')) break;
      keep = i + 1;
      // A runner like tsx is itself a script; keep going to the script it runs.
      if (SCRIPT_RE.test(words[i]!) && !/node_modules/.test(words[i]!)) break;
    }
  } else {
    for (const w of words) {
      if (keep > 0 && (w.startsWith('-') || keep >= 3)) break;
      keep++;
    }
  }
  const head = words.slice(0, keep).join(' ');
  return keep < words.length ? `${head} *` : head;
}

/** Scripts run from a temporary or scratch folder were one-offs; they are not carried over. */
function isOneOff(command: string): boolean {
  return /[\\/](temp|tmp|scratchpad)[\\/]/i.test(command);
}

export function proposeRequests(entries: AuditEntry[], repoOf: (workspace: string) => string | null): ConversionResult {
  const byRepo = new Map<string, { workspaces: Set<string>; items: Map<string, Set<string>>; first: string; last: string; runs: number }>();
  const noRepo = new Set<string>();
  const skipped = new Map<string, { repo: string; command: string; why: string }>();
  for (const e of entries) {
    if (e.outcome !== 'allowed' || !Array.isArray(e.handles) || e.handles.length === 0 || !e.workspace) continue;
    const repo = repoOf(e.workspace);
    if (!repo) {
      noRepo.add(e.workspace);
      continue;
    }
    const p = byRepo.get(repo) ?? { workspaces: new Set<string>(), items: new Map<string, Set<string>>(), first: e.ts, last: e.ts, runs: 0 };
    p.workspaces.add(e.workspace);
    p.runs++;
    if (e.ts < p.first) p.first = e.ts;
    if (e.ts > p.last) p.last = e.ts;
    const pattern = commandPattern(e.command);
    // Only the kept program and script count: a project script that took a temp file as an argument is not a one-off.
    const why = isOneOff(pattern) ?'one-off script in a temporary folder' : isExfilCapable([pattern]) ? 'could print the secret' : null;
    if (why) {
      skipped.set(`${repo} ${pattern}`, { repo, command: pattern, why });
      continue;
    }
    for (const h of e.handles) {
      const cmds = p.items.get(h) ?? new Set<string>();
      cmds.add(pattern);
      p.items.set(h, cmds);
    }
    byRepo.set(repo, p);
  }
  const proposals = [...byRepo].filter(([, p]) => p.items.size > 0).sort(([a], [b]) => a.localeCompare(b)).map(([repo, p]) => ({
    repo,
    workspaces: [...p.workspaces].sort(),
    items: [...p.items].sort(([a], [b]) => a.localeCompare(b)).map(([handle, cmds]) => ({ handle, commands: [...cmds].sort() })),
    firstUsed: p.first,
    lastUsed: p.last,
    runs: p.runs,
  }));
  return { proposals, skipped: [...skipped.values()], noRepo: [...noRepo].sort() };
}

/** Parse audit.jsonl text, skipping lines that are not audit entries. */
export function parseAudit(text: string): AuditEntry[] {
  const out: AuditEntry[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line) as AuditEntry;
      if (e && typeof e === 'object' && typeof e.workspace === 'string' && typeof e.command === 'string') out.push(e);
    } catch {
      // not an audit line
    }
  }
  return out;
}
