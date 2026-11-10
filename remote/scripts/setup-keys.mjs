#!/usr/bin/env node
// Creates the vault master key and the backup key pair, writes your recovery
// kit, and stores the Worker secrets with wrangler (values go over stdin).
//
//   npm run setup-keys                    first-time setup
//   npm run setup-keys -- --rotate-master new master key, keeps backup keys
//   npm run setup-keys -- --dev           write .dev.vars for local testing only
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { ask, kitText, newBackupKeyPair, newMasterKey, parseKit, wrangler } from './lib.mjs';

const argv = process.argv.slice(2);
const rotate = argv.includes('--rotate-master');
const dev = argv.includes('--dev');
const stamp = new Date().toISOString().slice(0, 10);

async function existingSecrets() {
  try {
    return JSON.parse(await wrangler(['secret', 'list', '--format', 'json'])).map((s) => s.name);
  } catch {
    return [];
  }
}

async function main() {
  if (dev) {
    const master = await newMasterKey();
    const { publicPem } = await newBackupKeyPair();
    const lines = existsSync('.dev.vars') ? readFileSync('.dev.vars', 'utf8').split('\n').filter((l) => !/^(VAULT_MASTER_KEY|BACKUP_PUBLIC_KEY)=/.test(l)) : [];
    lines.push(`VAULT_MASTER_KEY=${master}`, `BACKUP_PUBLIC_KEY="${publicPem.trim().replace(/\n/g, '\\n')}"`);
    writeFileSync('.dev.vars', lines.filter(Boolean).join('\n') + '\n');
    console.log('Wrote throwaway dev keys to .dev.vars (local wrangler dev only).');
    return;
  }

  const names = await existingSecrets();

  if (rotate) {
    if (!names.includes('VAULT_MASTER_KEY')) throw new Error('No VAULT_MASTER_KEY on the Worker yet. Run without --rotate-master first.');
    const kitPath = await ask('Path to your current recovery kit file: ');
    const old = parseKit(readFileSync(kitPath, 'utf8'));
    const master = await newMasterKey();
    const file = `secret-broker-recovery-kit-${stamp}-rotated.txt`;
    writeFileSync(file, kitText({ master, publicPem: old.publicPem, privatePem: old.privatePem, note: 'Master key rotated. The previous kit is obsolete once rotation is finished.' }), { mode: 0o600 });
    await wrangler(['secret', 'put', 'VAULT_MASTER_KEY_PREVIOUS'], old.master);
    await wrangler(['secret', 'put', 'VAULT_MASTER_KEY'], master);
    console.log(`\nNew recovery kit: ${file}`);
    console.log('Next: Settings page > "Re-encrypt with current key". Then: npx wrangler secret delete VAULT_MASTER_KEY_PREVIOUS');
    return;
  }

  if (names.includes('VAULT_MASTER_KEY') && !argv.includes('--force')) {
    throw new Error(
      'This Worker already has a VAULT_MASTER_KEY. Replacing it would make every stored secret unreadable.\n' +
        'To change it safely use --rotate-master. (--force overwrites anyway; only for an empty vault.)',
    );
  }

  console.log('Generating keys (the 4096-bit backup key takes a few seconds)...');
  const master = await newMasterKey();
  const { publicPem, privatePem } = await newBackupKeyPair();
  const file = `secret-broker-recovery-kit-${stamp}.txt`;
  writeFileSync(file, kitText({ master, publicPem, privatePem }), { mode: 0o600 });
  console.log(`Recovery kit written to ${file}`);

  await wrangler(['secret', 'put', 'VAULT_MASTER_KEY'], master);
  await wrangler(['secret', 'put', 'BACKUP_PUBLIC_KEY'], publicPem);
  console.log('Stored VAULT_MASTER_KEY and BACKUP_PUBLIC_KEY on the Worker.');
  console.log(`\nNOW: save ${file} in your password manager and print it, then delete the file.`);
}

main().catch((err) => {
  console.error(`\n${err.message}`);
  process.exit(1);
});
