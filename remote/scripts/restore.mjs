#!/usr/bin/env node
// Decrypt a backup with your recovery kit, then either write it back into the
// vault or save a decrypted copy.
//
//   npm run restore -- <backup.json>                 restore into the vault
//   npm run restore -- <backup.json> --out plain.json   decrypted copy (careful)
//   add --kit <file> to skip the prompt for the recovery kit path
import { readFileSync, writeFileSync } from 'node:fs';
import { ask, decryptBackup, parseKit } from './lib.mjs';

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

async function main() {
  const file = argv.find((a) => !a.startsWith('--') && a !== flag('--out') && a !== flag('--kit'));
  if (!file) throw new Error('Usage: npm run restore -- <backup.json> [--out plain.json] [--kit recovery-kit.txt]');
  const envelope = JSON.parse(readFileSync(file, 'utf8'));
  const kitPath = flag('--kit') ?? (await ask('Path to your recovery kit file: '));
  const { privatePem } = parseKit(readFileSync(kitPath, 'utf8'));
  const snapshot = JSON.parse(await decryptBackup(privatePem, envelope));
  const live = snapshot.secrets.filter((s) => !s.deleted).length;
  console.log(`Backup from ${snapshot.exportedAt}: ${live} secret(s), ${snapshot.grants.length} repo approval(s), ${snapshot.machines.length} machine(s).`);

  const out = flag('--out');
  if (out) {
    writeFileSync(out, JSON.stringify(snapshot, null, 2), { mode: 0o600 });
    console.log(`Decrypted copy written to ${out}. It contains every secret in plain text: delete it when done.`);
    return;
  }

  const token = process.env.SECRET_BROKER_IMPORT_TOKEN || (await ask('Machine token that can import (Machines page, "Can import"): ', { hidden: true }));
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'sbv') throw new Error(token.length === 0 ? 'No token received (the paste may not have gone through). Try right-click to paste, or set SECRET_BROKER_IMPORT_TOKEN first.' : `That is not a vault machine token (got ${token.length} characters starting "${token.slice(0, 4)}"; it should start "sbv."). Create one on the Machines page with "Can import" ticked.`);
  const origin = Buffer.from(parts[1], 'base64url').toString('utf8');
  const res = await fetch(`${origin}/api/v1/import`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ snapshot }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Restore failed (${res.status}): ${body.error ?? 'unknown error'}`);
  console.log(`Restored into ${origin}: ${body.secrets} secret(s) written; unchanged secrets were skipped. Machines, approvals and vault settings are not restored by token (${body.skipped?.machines ?? 0} machine(s), ${body.skipped?.grants ?? 0} approval(s) skipped); re-create them in the admin UI.`);
}

main().catch((err) => {
  console.error(`\n${err.message}`);
  process.exit(1);
});
