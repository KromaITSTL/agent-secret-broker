import { Entry } from '@napi-rs/keyring';
import type { Tier } from './types.js';
import { isVaultToken } from './vaultResolver.js';

export const SERVICE_NAME = 'secret-broker';

export type TokenReader = (service: string, account: string) => string | null;

const defaultReader: TokenReader = (service, account) => {
  const entry = new Entry(service, account);
  return entry.getPassword();
};

/**
 * Load one tier's vault machine token. Returns null on any failure, and for a
 * stored value that is not a vault machine token, so the caller denies rather
 * than falling back to another tier's credentials.
 */
export function loadTierToken(tier: Tier, read: TokenReader = defaultReader): string | null {
  try {
    const token = read(SERVICE_NAME, tier);
    return isVaultToken(token) ? token : null;
  } catch {
    return null;
  }
}

export type TokenWriter = (service: string, account: string, token: string) => void;

const defaultWriter: TokenWriter = (service, account, token) => {
  new Entry(service, account).setPassword(token);
};

/**
 * Store one tier's access token. Writes through the same library that
 * loadTierToken reads with, so the platform-specific storage format can
 * never drift between the two.
 *
 * Surrounding whitespace is stripped, but nothing else is: a token mangled
 * by a bad paste is rejected here rather than surfacing later as an opaque
 * authentication failure from the vault.
 */
export function storeTierToken(
  tier: Tier,
  token: string,
  write: TokenWriter = defaultWriter,
): void {
  const trimmed = token.trim();
  if (trimmed === '') {
    throw new Error('refusing to store an empty token');
  }
  if (!isVaultToken(trimmed)) {
    throw new Error(
      'refusing to store a malformed access token: expected a vault machine '
      + "token (sbv.…), created on the vault's Machines page. "
      + 'Re-copy it without any surrounding punctuation.',
    );
  }
  write(SERVICE_NAME, tier, trimmed);
}
