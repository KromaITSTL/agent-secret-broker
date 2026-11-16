/**
 * npm run convert-policy            show what would be requested (writes nothing)
 * npm run convert-policy -- --create  file one access request per repo on the dashboard
 *
 * Run by the operator once, before switching to dashboard approvals. Requests still need
 * approving on the dashboard; this approves nothing.
 */
import { readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseAudit, proposeRequests } from './convert.js';
import { DashboardClient, gitOrigin, repoFromRemote } from './dashboard.js';
import { loadTierToken } from './keychain.js';

async function main(): Promise<void> {
  const create = process.argv.includes('--create');
  const auditPath = path.join(os.homedir(), '.secret-broker', 'audit.jsonl');
  const entries = parseAudit(await readFile(auditPath, 'utf8').catch(() => ''));
  const repos = new Map<string, string | null>();
  for (const w of new Set(entries.map((e) => e.workspace))) {
    const origin = await gitOrigin(w);
    repos.set(w, origin ? repoFromRemote(origin) : null);
  }
  const { proposals, skipped, noRepo } = proposeRequests(entries, (w) => repos.get(w) ?? null);

  const token = create ? loadTierToken('runner') : null;
  if (create && !token) {
    process.stderr.write('No runner token stored. Create one on the Machines page (tick nothing), then run: npm run store-token runner\n');
    process.exit(1);
  }
  const client = token ? new DashboardClient(token) : null;

  for (const p of proposals) {
    process.stdout.write(`\n${p.repo}  (${p.runs} runs, ${p.firstUsed.slice(0, 10)} to ${p.lastUsed.slice(0, 10)}; ${p.workspaces.join(', ')})\n`);
    for (const i of p.items) process.stdout.write(`  ${i.handle}\n    ${i.commands.join('\n    ')}\n`);
    if (!client) continue;
    // Only secrets that still exist and are visible to this repo; a request with a missing one would be refused whole.
    const listed = (await client.call('list', { repo: p.repo }).catch(() => ({ secrets: [] }))) as { secrets?: Array<{ handle: string }> };
    const exists = new Set((listed.secrets ?? []).map((s) => s.handle));
    const items = p.items.filter((i) => exists.has(i.handle));
    const missing = p.items.filter((i) => !exists.has(i.handle)).map((i) => i.handle);
    if (missing.length) process.stdout.write(`  skipped (not in the vault or not visible to this repo): ${missing.join(', ')}\n`);
    // A request holds at most 25 secrets.
    for (let i = 0; i < items.length; i += 25) {
      try {
        const r = (await client.call('request_access', {
          repo: p.repo,
          reason: `Carried over from this PC's local policy: what agents used here from ${p.firstUsed.slice(0, 10)} to ${p.lastUsed.slice(0, 10)}.`,
          items: items.slice(i, i + 25),
        })) as { approvalUrl?: string };
        process.stdout.write(`  request filed: ${r.approvalUrl ?? '(no link returned)'}\n`);
      } catch (err) {
        process.stdout.write(`  request refused: ${(err as Error).message}\n`);
      }
    }
  }
  if (skipped.length) {
    process.stdout.write('\nLeft out (approve these by hand if still needed):\n');
    for (const s of skipped) process.stdout.write(`  ${s.repo}: ${s.command.slice(0, 120)}  (${s.why})\n`);
  }
  if (noRepo.length) process.stdout.write(`\nNo git origin remote, so nothing can be approved for: ${noRepo.join(', ')}\n`);
  if (!proposals.length) process.stdout.write('No secret use found in the local audit log.\n');
  if (proposals.length) {
    process.stdout.write('\nExtra non-secret environment variables are not in the log, so they are not carried over. If a converted run needs one, the agent will ask again.\n');
  }
  if (!create && proposals.length) process.stdout.write('\nNothing was filed. Run again with --create to file these as requests on the dashboard.\n');
}

main().catch((err: unknown) => {
  process.stderr.write(`convert-policy failed: ${String(err)}\n`);
  process.exit(1);
});
