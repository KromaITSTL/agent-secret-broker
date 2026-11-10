import type { Env } from './env';
import type { VaultApi } from './vault-do';

export function vaultFor(env: Pick<Env, 'VAULT'>): VaultApi {
  return env.VAULT.get(env.VAULT.idFromName('vault')) as unknown as VaultApi;
}
