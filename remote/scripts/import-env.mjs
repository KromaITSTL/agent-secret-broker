#!/usr/bin/env node
// Move a project's .env into a vault, so client credentials stop living in files.
//
//   npm run import-env -- <vault> <path\to\.env> [--overwrite] [--skip KEY1,KEY2] [--yes] [--delete]
//
// Needs a machine token with "Can import" (Machines page). Values are sent over
// HTTPS straight into the vault; nothing is printed.
import { readFileSync, unlinkSync } from 'node:fs';
import { ask } from './lib.mjs';

const NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;

/** dotenv-style parser: comments, `export`, single/double quotes, \n escapes, multi-line double quotes. */
export function parseEnv(text) {
  const out = [];
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.slice(7).trim();
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let rest = line.slice(eq + 1).trim();
    let value;
    if (rest.startsWith('"')) {
      // Scan for the closing unescaped quote, continuing onto later lines if needed.
      let buf = rest.slice(1);
      let raw = null;
      for (;;) {
        let j = 0;
        for (; j < buf.length; j++) {
          if (buf[j] === '\\') j++;
          else if (buf[j] === '"') break;
        }
        if (j < buf.length) {
          raw = buf.slice(0, j);
          break;
        }
        if (i + 1 >= lines.length) {
          raw = buf;
          break;
        }
        buf += '\n' + lines[++i];
      }
      value = raw.replace(/\\(.)/g, (_m, c) => ({ n: '\n', r: '\r', t: '\t' })[c] ?? c);
    } else if (rest.startsWith("'")) {
      const end = rest.indexOf("'", 1);
      value = end < 0 ? rest.slice(1) : rest.slice(1, end);
    } else {
      const hash = rest.search(/\s#/);
      value = (hash >= 0 ? rest.slice(0, hash) : rest).trim();
    }
    out.push({ key, value });
  }
  return out;
}

async function main() {
  const argv = process.argv.slice(2);
  const flag = (n) => argv.includes(n);
  const opt = (n) => {
    const i = argv.indexOf(n);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const positional = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--skip');
  const [vault, file] = positional;
  if (!vault || !file) throw new Error('Usage: npm run import-env -- <vault> <path to .env> [--overwrite] [--skip KEY1,KEY2] [--yes] [--delete]');

  const skip = new Set((opt('--skip') ?? '').split(',').map((s) => s.trim()).filter(Boolean));
  const parsed = parseEnv(readFileSync(file, 'utf8'));
  const bad = parsed.filter((p) => !NAME_RE.test(p.key)).map((p) => p.key);
  if (bad.length) throw new Error(`These names can't be stored as-is: ${bad.join(', ')} (letters, digits, _ . - only)`);
  const empty = parsed.filter((p) => p.value === '').map((p) => p.key);
  const items = parsed.filter((p) => p.value !== '' && !skip.has(p.key));

  console.log(`\n${file}: ${parsed.length} entr${parsed.length === 1 ? 'y' : 'ies'}`);
  for (const p of items) console.log(`  import  ${p.key}`);
  for (const k of skip) console.log(`  skip    ${k}`);
  for (const k of empty) console.log(`  skip    ${k} (empty)`);
  if (items.length === 0) throw new Error('Nothing to import.');
  console.log('\nTip: plain settings like NODE_ENV or PORT do not need to be secrets; leave them out with --skip.');

  if (!flag('--yes')) {
    const ok = await ask(`Import ${items.length} value(s) into vault "${vault}"? [y/N] `);
    if (!/^y(es)?$/i.test(ok)) throw new Error('Cancelled.');
  }

  const token = process.env.SECRET_BROKER_IMPORT_TOKEN || (await ask('Machine token that can import (input hidden): ', { hidden: true }));
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'sbv') throw new Error(token.length === 0 ? 'No token received (the paste may not have gone through). Try right-click to paste, or set SECRET_BROKER_IMPORT_TOKEN first.' : `That is not a vault machine token (got ${token.length} characters starting "${token.slice(0, 4)}"; it should start "sbv."). Create one on the Machines page with "Can import" ticked.`);
  const origin = Buffer.from(parts[1], 'base64url').toString('utf8');
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const vres = await fetch(`${origin}/api/v1/vaults`, { headers });
  const vbody = await vres.json().catch(() => ({}));
  if (!vres.ok) throw new Error(`Vault refused the token (${vres.status}): ${vbody.error ?? ''}`);
  if (!vbody.vaults.some((v) => v.slug === vault)) {
    throw new Error(`There is no vault named "${vault}". Existing: ${vbody.vaults.map((v) => v.slug).join(', ')}. Create it on the Vaults page first.`);
  }

  const res = await fetch(`${origin}/api/v1/import`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ overwrite: flag('--overwrite'), items: items.map((p) => ({ tier: vault, name: p.key, value: p.value })) }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Import failed (${res.status}): ${body.error ?? 'unknown error'}`);
  console.log(`\nImported into ${vault}: ${body.created} new, ${body.updated} replaced, ${body.skipped} unchanged or already there${flag('--overwrite') ? '' : ' (use --overwrite to replace)'}.`);

  console.log('\nFor the local broker (secret_run), map env vars to handles like this:');
  console.log(JSON.stringify(Object.fromEntries(items.map((p) => [p.key, `secret://${vault}/${p.key}`])), null, 2));

  if (flag('--delete')) {
    unlinkSync(file);
    console.log(`\nDeleted ${file}.`);
  } else {
    console.log(`\nCheck the Secrets page, then delete ${file} (or re-run with --delete).`);
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('import-env.mjs')) {
  main().catch((err) => {
    console.error(`\n${err.message}`);
    process.exit(1);
  });
}
