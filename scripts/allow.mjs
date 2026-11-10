// Grant the current project access to named secret-broker entries.
// Run by the user, never by an agent on its own: running it IS the approval.
//
// Run it from the root of the project you are granting (it grants the current directory):
//   node <path to secret-broker>/scripts/allow.mjs ENTRY [ENTRY...] [--tier client-work]
//   node <path to secret-broker>/scripts/allow.mjs            # show this project's rule
//
// Access is per entry, not per command: rules created here allow any command ("**").
// Edits ~/.secret-broker/policy.json. The broker reads policy at startup, so restart the
// Claude session (or reconnect the secret-broker MCP server) for changes to apply.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Vault names: personal, production, or a project vault such as acme-finance.
const VAULT_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const policyPath = path.join(os.homedir(), '.secret-broker', 'policy.json');
const norm = p => path.posix.normalize(p.replace(/\\/g, '/')).toLowerCase().replace(/\/+$/, '');

const names = [];
let tier = null;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--tier') tier = argv[++i];
  else names.push(argv[i]);
}
if (tier && !VAULT_RE.test(tier)) fail(`"${tier}" is not a valid vault name (lowercase letters, digits, dashes)`);
if (names.some(n => !n || n.includes('/'))) fail('entry names cannot be empty or contain "/"');

const policy = existsSync(policyPath) ? JSON.parse(readFileSync(policyPath, 'utf8')) : { workspaces: [] };
const cwd = norm(process.cwd());
let rule = policy.workspaces.find(r => norm(r.match) === cwd);

if (!names.length && !tier) {
  console.log(rule ? summary(rule) : `No secret-broker rule for ${cwd}.`);
  process.exit(0);
}
if (!rule) {
  if (!tier) fail(`no rule for ${cwd} yet; pass --tier <vault> (e.g. personal, production, acme-finance) to create one`);
  rule = { match: cwd, tier, allow: [], commands: [] };
  policy.workspaces.unshift(rule); // first match wins, so the project rule goes before broader ones
} else if (tier) {
  const tiers = [...new Set([...[].concat(rule.tier), tier])]; // add a tier, never drop one
  rule.tier = tiers.length === 1 ? tiers[0] : tiers;
}
rule.allow = [...new Set([...(rule.allow ?? []), ...names])];
if (!rule.commands?.length) rule.commands = ['**'];

mkdirSync(path.dirname(policyPath), { recursive: true });
writeFileSync(policyPath, JSON.stringify(policy, null, 2) + '\n');
console.log(summary(rule));
console.log('Restart the Claude session (or reconnect secret-broker in /mcp) for this to take effect.');

function summary(r) {
  return [`Rule for ${r.match}`, `  tier:     ${[].concat(r.tier).join(', ')}`,
    `  allow:    ${(r.allow ?? []).join(', ') || '(none)'}`, `  commands: ${(r.commands ?? []).join(' | ') || '(none)'}`].join('\n');
}
function fail(msg) { console.error(`allow: ${msg}`); process.exit(1); }
