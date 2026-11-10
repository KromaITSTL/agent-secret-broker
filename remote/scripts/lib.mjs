// Shared helpers for the local scripts. Node 18+ (WebCrypto built in), no dependencies.
import { createInterface } from 'node:readline';
import { spawn } from 'node:child_process';

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = (u8) => Buffer.from(u8).toString('base64');
export const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

export function pem(bytes, label) {
  return `-----BEGIN ${label}-----\n${b64(bytes).replace(/(.{64})/g, '$1\n').trim()}\n-----END ${label}-----\n`;
}

export function pemBody(text, label) {
  const m = new RegExp(`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`).exec(text);
  if (!m) throw new Error(`no ${label} found`);
  return unb64(m[1].replace(/\s+/g, ''));
}

export async function newMasterKey() {
  return b64(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

export async function newBackupKeyPair() {
  const kp = await subtle.generateKey(
    { name: 'RSA-OAEP', hash: 'SHA-256', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['encrypt', 'decrypt'],
  );
  return {
    publicPem: pem(new Uint8Array(await subtle.exportKey('spki', kp.publicKey)), 'PUBLIC KEY'),
    privatePem: pem(new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey)), 'PRIVATE KEY'),
  };
}

/** Mirrors decryptBackup() in src/crypto.ts. */
export async function decryptBackup(privatePemText, envelope) {
  if (envelope.format !== 'secret-broker-backup' || envelope.version !== 1) throw new Error('not a secret-broker backup file');
  const RSA = { name: 'RSA-OAEP', hash: 'SHA-256' };
  const priv = await subtle.importKey('pkcs8', pemBody(privatePemText, 'PRIVATE KEY'), RSA, false, ['decrypt']);
  let raw;
  try {
    raw = new Uint8Array(await subtle.decrypt(RSA, priv, unb64(envelope.wrappedKey)));
  } catch {
    throw new Error('this recovery kit does not match the backup');
  }
  const key = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(envelope.iv), additionalData: enc.encode(`sb-backup|v1|${envelope.createdAt}`) },
    key,
    unb64(envelope.ct),
  );
  return dec.decode(pt);
}

export function parseKit(text) {
  const master = /^VAULT_MASTER_KEY=(\S+)$/m.exec(text)?.[1];
  const priv = /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/.exec(text)?.[0];
  const pub = /-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/.exec(text)?.[0];
  if (!master || !priv || !pub) throw new Error('that file is not a secret-broker recovery kit');
  return { master, privatePem: priv + '\n', publicPem: pub + '\n' };
}

export function kitText({ master, publicPem, privatePem, note }) {
  return `SECRET-BROKER RECOVERY KIT
Created ${new Date().toISOString()}${note ? `\n${note}` : ''}

Keep this somewhere safe and offline: your password manager (as a secure
note) AND a printed copy. Then delete this file from your computer.

With this kit you can:
  - decrypt any backup:            npm run restore -- <backup.json>
  - rebuild the vault from scratch (new Worker + restore)
Without it, backups cannot be opened by anyone, including you.

VAULT_MASTER_KEY=${master}

Backup private key (decrypts backups; never upload it anywhere):
${privatePem}
Backup public key (already set on the Worker as BACKUP_PUBLIC_KEY):
${publicPem}`;
}

export function ask(question, { hidden = false } = {}) {
  return new Promise((resolve, reject) => {
    const tty = !!process.stdin.isTTY;
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: tty });
    let answered = false;
    rl.on('close', () => {
      if (!answered) reject(new Error('no input received'));
    });
    if (hidden && tty) {
      rl._writeToOutput = (s) => {
        if (s.includes(question)) rl.output.write(s);
      };
    }
    rl.question(question, (answer) => {
      answered = true;
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(answer.trim());
    });
  });
}

/** Run `npx wrangler ...` with the value on stdin, so it never appears in arguments or history. */
export function wrangler(args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn('npx', ['wrangler', ...args], { shell: process.platform === 'win32', stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`wrangler ${args[0]} ${args[1] ?? ''} failed:\n${err || out}`))));
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}
