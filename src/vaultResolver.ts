import { ResolutionError } from './resolver.js';
import type { SecretResolver } from './resolver.js';
import type { Tier } from './types.js';

export type FetchFn = typeof fetch;

/** Vault machine tokens look like sbv.<base64url origin>.<id>.<secret>. */
export const VAULT_TOKEN_PATTERN = /^sbv\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export function isVaultToken(token: string | null | undefined): token is string {
  return !!token && VAULT_TOKEN_PATTERN.test(token.trim());
}

/** The vault's origin is embedded in the token, so no extra config is needed. */
export function vaultOrigin(token: string): string {
  const encoded = token.trim().split('.')[1] ?? '';
  const origin = Buffer.from(encoded, 'base64url').toString('utf8');
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    throw new ResolutionError('vault token has an invalid origin');
  }
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
  if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) {
    throw new ResolutionError('vault token origin must be https');
  }
  return u.origin;
}

/**
 * Reads one tier from the secret-broker vault (the Cloudflare Worker) with a
 * machine token. Everything the token can read in the tier is loaded once and
 * cached in memory for the life of the broker process.
 */
export class VaultResolver implements SecretResolver {
  private cache: Map<string, string> | null = null;

  constructor(
    private readonly token: string,
    private readonly tier: Tier,
    private readonly fetchFn: FetchFn = fetch,
  ) {}

  private async load(): Promise<Map<string, string>> {
    if (this.cache) return this.cache;
    const origin = vaultOrigin(this.token);
    let res: Response;
    try {
      res = await this.fetchFn(`${origin}/api/v1/secrets?tier=${encodeURIComponent(this.tier)}`, {
        headers: { Authorization: `Bearer ${this.token.trim()}`, Accept: 'application/json' },
        signal: AbortSignal.timeout(20_000),
      });
    } catch (err) {
      throw new ResolutionError(`could not reach the vault at ${origin}: ${(err as Error).message}`);
    }
    const body = (await res.json().catch(() => ({}))) as { secrets?: Record<string, unknown>; error?: string };
    if (!res.ok) {
      const hint =
        res.status === 401 ? ' (token revoked or wrong; create a new one on the Machines page)'
        : res.status === 403 ? ` (this token is not allowed to read tier ${this.tier})`
        : res.status === 423 ? ' (the vault is frozen; unfreeze it in Settings)'
        : '';
      throw new ResolutionError(`vault refused tier ${this.tier}: HTTP ${res.status}${hint}`);
    }
    const map = new Map<string, string>();
    for (const [k, v] of Object.entries(body.secrets ?? {})) if (typeof v === 'string') map.set(k, v);
    this.cache = map;
    return map;
  }

  async resolve(tier: Tier, name: string): Promise<string> {
    const value = (await this.load()).get(name);
    if (value === undefined) throw new ResolutionError(`no secret named ${name} in tier ${tier}`);
    return value;
  }

  async list(_tier: Tier): Promise<string[]> {
    return [...(await this.load()).keys()];
  }
}
