/**
 * Vault cryptography. WebCrypto only, so the same code runs in the Worker and
 * in Node (restore script, tests).
 *
 * Secrets: envelope encryption. Each stored version gets a fresh random
 * 256-bit data key; the value is AES-256-GCM encrypted under it, and the data
 * key is AES-256-GCM wrapped under the master key. Both use additional
 * authenticated data that names the tier, secret and version, so a stored
 * ciphertext cannot be moved to a different secret or version and still
 * decrypt. The master key lives only in the Worker secret VAULT_MASTER_KEY
 * (and your offline recovery kit).
 *
 * Backups: hybrid public-key encryption. A random AES-256-GCM key encrypts
 * the snapshot and is wrapped with RSA-OAEP-4096 (SHA-256) to BACKUP_PUBLIC_KEY.
 * The private key never touches Cloudflare, so the Worker can write backups
 * but cannot read them.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

export function toB64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

async function aesKey(raw: Uint8Array, usages: Array<'encrypt' | 'decrypt'>): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('AES key must be 32 bytes');
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, usages);
}

async function gcmEncrypt(key: CryptoKey, data: Uint8Array, aad: string): Promise<{ iv: string; ct: string }> {
  const iv = random(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, data));
  return { iv: toB64(iv), ct: toB64(ct) };
}

async function gcmDecrypt(key: CryptoKey, iv: string, ct: string, aad: string): Promise<Uint8Array> {
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv), additionalData: enc.encode(aad) }, key, fromB64(ct)),
    );
  } catch {
    throw new Error('decryption failed (wrong key, or data was tampered with or moved)');
  }
}

// ---------- master key ----------

export interface MasterKey {
  id: string;
  key: CryptoKey;
}

/** Short fingerprint so each stored item records which master key wrapped it. */
export async function keyId(raw: Uint8Array): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
  return [...h.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function loadMasterKey(b64: string | undefined): Promise<MasterKey | null> {
  if (!b64?.trim()) return null;
  let raw: Uint8Array;
  try {
    raw = fromB64(b64.trim());
  } catch {
    throw new Error('master key is not valid base64');
  }
  if (raw.length !== 32) throw new Error(`master key must be 32 bytes (got ${raw.length})`);
  return { id: await keyId(raw), key: await aesKey(raw, ['encrypt', 'decrypt']) };
}

export function generateMasterKey(): string {
  return toB64(random(32));
}

// ---------- secrets ----------

export interface Sealed {
  /** Format version. */
  f: 1;
  /** Master key fingerprint used to wrap the data key. */
  kid: string;
  iv: string;
  ct: string;
  wiv: string;
  wk: string;
}

function valueAad(tier: string, name: string, version: number) {
  return `sb-value|v1|${tier}|${name}|${version}`;
}
function keyAad(tier: string, name: string, version: number) {
  return `sb-dek|v1|${tier}|${name}|${version}`;
}

export async function sealValue(master: MasterKey, tier: string, name: string, version: number, value: string): Promise<Sealed> {
  const dekRaw = random(32);
  const dek = await aesKey(dekRaw, ['encrypt']);
  const v = await gcmEncrypt(dek, enc.encode(value), valueAad(tier, name, version));
  const w = await gcmEncrypt(master.key, dekRaw, keyAad(tier, name, version));
  dekRaw.fill(0);
  return { f: 1, kid: master.id, iv: v.iv, ct: v.ct, wiv: w.iv, wk: w.ct };
}

/** `keys` holds the current master key and, during rotation, the previous one. */
export async function openValue(keys: MasterKey[], tier: string, name: string, version: number, s: Sealed): Promise<string> {
  const master = keys.find((k) => k.id === s.kid);
  if (!master) throw new Error(`no master key loaded with id ${s.kid} (is VAULT_MASTER_KEY_PREVIOUS needed?)`);
  const dekRaw = await gcmDecrypt(master.key, s.wiv, s.wk, keyAad(tier, name, version));
  const dek = await aesKey(dekRaw, ['decrypt']);
  dekRaw.fill(0);
  return dec.decode(await gcmDecrypt(dek, s.iv, s.ct, valueAad(tier, name, version)));
}

/** Re-wrap only the data key under a new master key; the value ciphertext is untouched. */
export async function rewrap(keys: MasterKey[], next: MasterKey, tier: string, name: string, version: number, s: Sealed): Promise<Sealed> {
  if (s.kid === next.id) return s;
  const old = keys.find((k) => k.id === s.kid);
  if (!old) throw new Error(`no master key loaded with id ${s.kid}`);
  const dekRaw = await gcmDecrypt(old.key, s.wiv, s.wk, keyAad(tier, name, version));
  const w = await gcmEncrypt(next.key, dekRaw, keyAad(tier, name, version));
  dekRaw.fill(0);
  return { ...s, kid: next.id, wiv: w.iv, wk: w.ct };
}

// ---------- connection tokens (deploy targets) ----------
// Same envelope as sealValue but bound to `conn:<id>`, so a sealed token can never open as a
// secret value (or as another connection's token), and the reverse.

const tokenAad = (connId: string) => `sb-conn|v1|conn:${connId}`;
const tokenKeyAad = (connId: string) => `sb-conn-dek|v1|conn:${connId}`;

export async function sealToken(master: MasterKey, connId: string, token: string): Promise<Sealed> {
  const dekRaw = random(32);
  const dek = await aesKey(dekRaw, ['encrypt']);
  const v = await gcmEncrypt(dek, enc.encode(token), tokenAad(connId));
  const w = await gcmEncrypt(master.key, dekRaw, tokenKeyAad(connId));
  dekRaw.fill(0);
  return { f: 1, kid: master.id, iv: v.iv, ct: v.ct, wiv: w.iv, wk: w.ct };
}

export async function openToken(keys: MasterKey[], connId: string, s: Sealed): Promise<string> {
  const master = keys.find((k) => k.id === s.kid);
  if (!master) throw new Error(`no master key loaded with id ${s.kid} (is VAULT_MASTER_KEY_PREVIOUS needed?)`);
  const dekRaw = await gcmDecrypt(master.key, s.wiv, s.wk, tokenKeyAad(connId));
  const dek = await aesKey(dekRaw, ['decrypt']);
  dekRaw.fill(0);
  return dec.decode(await gcmDecrypt(dek, s.iv, s.ct, tokenAad(connId)));
}

export async function rewrapToken(keys: MasterKey[], next: MasterKey, connId: string, s: Sealed): Promise<Sealed> {
  if (s.kid === next.id) return s;
  const old = keys.find((k) => k.id === s.kid);
  if (!old) throw new Error(`no master key loaded with id ${s.kid}`);
  const dekRaw = await gcmDecrypt(old.key, s.wiv, s.wk, tokenKeyAad(connId));
  const w = await gcmEncrypt(next.key, dekRaw, tokenKeyAad(connId));
  dekRaw.fill(0);
  return { ...s, kid: next.id, wiv: w.iv, wk: w.ct };
}

// ---------- backups ----------

const RSA = { name: 'RSA-OAEP', hash: 'SHA-256' } as const;

function pemBody(pem: string, label: string): Uint8Array {
  const m = new RegExp(`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`).exec(pem);
  if (!m) throw new Error(`expected a PEM ${label}`);
  return fromB64(m[1]!.replace(/\s+/g, ''));
}

function toPem(bytes: Uint8Array, label: string): string {
  const b64 = toB64(bytes).replace(/(.{64})/g, '$1\n').trim();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

export async function generateBackupKeyPair(): Promise<{ publicPem: string; privatePem: string }> {
  const kp = (await crypto.subtle.generateKey(
    { ...RSA, modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey('spki', kp.publicKey)) as ArrayBuffer);
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey('pkcs8', kp.privateKey)) as ArrayBuffer);
  return { publicPem: toPem(spki, 'PUBLIC KEY'), privatePem: toPem(pkcs8, 'PRIVATE KEY') };
}

export interface BackupEnvelope {
  format: 'secret-broker-backup';
  version: 1;
  createdAt: string;
  alg: 'RSA-OAEP-SHA256+AES-256-GCM';
  wrappedKey: string;
  iv: string;
  ct: string;
}

export async function encryptBackup(publicPem: string, plaintext: string, createdAt = new Date().toISOString()): Promise<BackupEnvelope> {
  const pub = await crypto.subtle.importKey('spki', pemBody(publicPem, 'PUBLIC KEY'), RSA, false, ['encrypt']);
  const raw = random(32);
  const key = await aesKey(raw, ['encrypt']);
  const aad = `sb-backup|v1|${createdAt}`;
  const body = await gcmEncrypt(key, enc.encode(plaintext), aad);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt(RSA, pub, raw));
  raw.fill(0);
  return { format: 'secret-broker-backup', version: 1, createdAt, alg: 'RSA-OAEP-SHA256+AES-256-GCM', wrappedKey: toB64(wrapped), iv: body.iv, ct: body.ct };
}

export async function decryptBackup(privatePem: string, env: BackupEnvelope): Promise<string> {
  if (env.format !== 'secret-broker-backup' || env.version !== 1) throw new Error('not a secret-broker backup');
  const priv = await crypto.subtle.importKey('pkcs8', pemBody(privatePem, 'PRIVATE KEY'), RSA, false, ['decrypt']);
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(await crypto.subtle.decrypt(RSA, priv, fromB64(env.wrappedKey)));
  } catch {
    throw new Error('this private key does not match the backup');
  }
  const key = await aesKey(raw, ['decrypt']);
  return dec.decode(await gcmDecrypt(key, env.iv, env.ct, `sb-backup|v1|${env.createdAt}`));
}

// ---------- machine tokens ----------

export async function sha256Hex(s: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomToken(bytes = 32): string {
  return toB64(random(bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
