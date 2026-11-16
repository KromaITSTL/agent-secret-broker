/**
 * Builds the broker for a request: the claude.ai connector (index.ts) and the local broker's
 * machine API (api.ts) share it, so both see the same vaults, approvals and audit log.
 */
import policyJson from '../policy.json';
import { createBroker, type AuditEvent, type Broker, type SecretSource } from './broker';
import type { Env } from './env';
import type { Grants } from './grants';
import { validatePolicy, type Policy } from './policy';
import { vaultFor } from './vault-client';

// Optional static rules, bundled at deploy time. Normally empty: access is
// granted per repo on the approval page instead.
let policy: Policy | null = null;
let policyError: string | null = null;
try {
  policy = validatePolicy(policyJson);
} catch (err) {
  policyError = (err as Error).message;
}

/** Null when the bundled policy.json is invalid; `staticPolicyError()` says why. */
export function staticPolicy(): Policy | null {
  return policy;
}

export function staticPolicyError(): string | null {
  return policyError;
}

/** Every event lands in the vault's audit log (and Workers Logs). Never values. */
export function brokerFor(env: Env, user: string, publicUrl: string, waitUntil: (p: Promise<unknown>) => void): Broker {
  const vault = vaultFor(env);
  const source: SecretSource = {
    vaults: async () => (await vault.listVaults()).map(({ slug, name, strict, repos }) => ({ slug, name, strict, repos })),
    load: (tier) => vault.loadTier(tier),
    loginInfo: (t, n) => vault.loginInfo(t, n),
    readSecret: (t, n) => vault.readSecret(t, n),
    requestVault: (input) => vault.requestVault(input),
  };
  const audit = (e: AuditEvent) => {
    console.log(JSON.stringify(e));
    const { event, user: by, ...rest } = e;
    waitUntil(vault.log({ event, by, ...rest }).catch(() => {}));
  };
  return createBroker({ policy: policy!, grants: vault as unknown as Grants, source, user, audit, publicUrl });
}
