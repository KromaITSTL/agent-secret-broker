import { DurableObject } from 'cloudflare:workers';
import { encryptBackup, loadMasterKey, type MasterKey } from './crypto';
import type { Env } from './env';
import { GrantLogic, type AccessItem, type ApprovalLimits, type KvLike, type RepoGrant, type VaultRules } from './grants';
import type { Tier } from './policy';
import { DeployLogic, type PushInput } from './deploy';
import { VaultLogic, type ImportItem, type LinkItem, type LoginFields, type Provider, type Snapshot } from './store';

/**
 * One Durable Object instance holds the whole vault: secrets, approvals,
 * machine tokens, audit log and settings. A Durable Object (not KV) because
 * approvals, revokes and the freeze switch must take effect immediately.
 */
export class Vault extends DurableObject<Env> {
  private keysP: Promise<{ current: MasterKey | null; all: MasterKey[] }> | null = null;

  private keys() {
    this.keysP ??= (async () => {
      const current = await loadMasterKey(this.env.VAULT_MASTER_KEY);
      const previous = await loadMasterKey(this.env.VAULT_MASTER_KEY_PREVIOUS);
      return { current, all: [current, previous].filter((k): k is MasterKey => !!k) };
    })();
    return this.keysP;
  }
  private get kv(): KvLike {
    return this.ctx.storage as unknown as KvLike;
  }
  private async v(): Promise<VaultLogic> {
    return new VaultLogic(this.kv, await this.keys());
  }
  private g(): GrantLogic {
    return new GrantLogic(this.kv);
  }
  /** Strictness and repo links come from the vault registry, never from the caller. */
  private async rules(): Promise<VaultRules> {
    const vaults = await (await this.v()).listVaults();
    const by = new Map(vaults.map((x) => [x.slug, x]));
    const logins = new Set((await (await this.v()).listSecrets()).filter((m) => m.kind === 'login').map((m) => `secret://${m.tier}/${m.name}`));
    return { isStrict: (t) => by.get(t)?.strict ?? true, reposFor: (t) => by.get(t)?.repos, isLogin: (h) => logins.has(h) };
  }

  // vaults
  async listVaults() { return (await this.v()).listVaults(); }
  async getVault(slug: string) { return (await this.v()).getVault(slug); }
  async createVault(input: { slug: string; name: string; strict?: boolean; repos?: string[]; by: string }) { return (await this.v()).createVault(input); }
  async updateVault(slug: string, patch: { name?: string; strict?: boolean; repos?: string[] }, by: string) { return (await this.v()).updateVault(slug, patch, by); }
  async deleteVault(slug: string, by: string) { return (await this.v()).deleteVault(slug, by); }
  async requestVault(input: { slug: string; name: string; repo: string; reason: string; requestedBy: string }) { return (await this.v()).requestVault(input); }
  async getVaultRequest(id: string) { return (await this.v()).getVaultRequest(id); }
  async listVaultRequests() { return (await this.v()).listVaultRequests(); }
  async approveVaultRequest(id: string, by: string, opts: { strict: boolean; slug?: string; name?: string }) { return (await this.v()).approveVaultRequest(id, by, opts); }
  async denyVaultRequest(id: string, by: string) { return (await this.v()).denyVaultRequest(id, by); }

  // secrets
  async listSecrets(trash = false) { return (await this.v()).listSecrets({ trash }); }
  async getMeta(tier: string, name: string) { return (await this.v()).getMeta(tier, name); }
  async putSecret(tier: string, name: string, value: string, by: string, note?: string, login?: LoginFields, kind?: 'config') { return (await this.v()).putSecret(tier, name, value, by, note, login, kind); }
  async convertToConfig(tier: string, name: string, by: string) { return (await this.v()).convertToConfig(tier, name, by); }
  /** Plaintext config values: admin dashboard only, never a machine-token route or MCP tool. */
  async configValues() { return (await this.v()).configValues(); }
  async updateLogin(tier: string, name: string, login: LoginFields, by: string) { return (await this.v()).updateLogin(tier, name, login, by); }
  async readSecret(tier: string, name: string) { return (await this.v()).readSecret(tier, name); }
  async loginInfo(tier: string, name: string) { return (await this.v()).loginInfo(tier, name); }
  async restoreVersion(tier: string, name: string, v: number, by: string) { return (await this.v()).restoreVersion(tier, name, v, by); }
  async deleteSecret(tier: string, name: string, by: string) { return (await this.v()).deleteSecret(tier, name, by); }
  async moveSecret(tier: string, name: string, toVault: string, by: string) { return (await this.v()).moveSecret(tier, name, toVault, by); }
  async undeleteSecret(tier: string, name: string, by: string) { return (await this.v()).undeleteSecret(tier, name, by); }
  async purge(tier: string, name: string, by: string) { return (await this.v()).purge(tier, name, by); }
  async loadTier(tier: Tier): Promise<Map<string, string>> { return (await this.v()).loadTier(tier); }
  async importSecrets(items: ImportItem[], by: string, overwrite: boolean) { return (await this.v()).importSecrets(items, by, overwrite); }
  async rotate(by: string) { return (await this.v()).rotate(by); }
  async keyUsage() { return (await this.v()).keyUsage(); }
  async currentKeyId() { return (await this.keys()).current?.id ?? null; }

  // settings + audit
  async isFrozen() { return (await this.v()).isFrozen(); }
  async setFrozen(frozen: boolean, by: string) { return (await this.v()).setFrozen(frozen, by); }
  async registrationStatus() { return (await this.v()).registrationStatus(); }
  async openRegistration(by: string) { return (await this.v()).openRegistration(by); }
  async closeRegistration(by: string) { return (await this.v()).closeRegistration(by); }
  async takeRegistration(info: { name: string; hosts: string[] }) { return (await this.v()).takeRegistration(info); }
  async log(entry: { event: string; by: string; [k: string]: unknown }) { return (await this.v()).log(entry); }
  async listAudit(limit?: number) { return (await this.v()).listAudit(limit); }

  // machines
  async createMachine(input: { name: string; tiers: string[]; canImport: boolean; by: string; origin: string }) { return (await this.v()).createMachine(input); }
  async listMachines() { return (await this.v()).listMachines(); }
  async revokeMachine(id: string, by: string) { return (await this.v()).revokeMachine(id, by); }
  async authMachine(token: string) { return (await this.v()).authMachine(token); }

  // deploy targets (the connection token and raw version reads are deliberately not exposed)
  async listConnections() { return (await this.v()).listConnections(); }
  async getConnection(id: string) { return (await this.v()).getConnection(id); }
  async addConnection(input: { provider: Provider; name: string; accountId: string; token: string; by: string }) { return (await this.d()).addConnection(input); }
  async replaceConnectionToken(id: string, token: string, by: string) { return (await this.d()).replaceConnectionToken(id, token, by); }
  async removeConnection(id: string, by: string) { return (await this.v()).removeConnection(id, by); }
  async listTargets(connectionId: string) { return (await this.d()).listTargets(connectionId); }
  async getLink(connectionId: string, targetId: string) { return (await this.v()).getLink(connectionId, targetId); }
  async listLinks() { return (await this.v()).listLinks(); }
  async saveLink(input: { connectionId: string; targetId: string; targetName: string; items: LinkItem[]; by: string }) { return (await this.v()).saveLink(input); }
  async linkSummaries() { return (await this.v()).linkSummaries(); }
  async listPushes(page: number, filter?: { connectionId: string; targetId: string }) { return (await this.v()).listPushes(page, filter); }
  async reviewPush(connectionId: string, targetId: string, versions?: Record<string, number>) { return (await this.d()).reviewPush(connectionId, targetId, versions); }
  async pushTarget(input: PushInput) { return (await this.d()).pushTarget(input); }
  async redeployTarget(connectionId: string, targetId: string, pushId: string | undefined, by: string) { return (await this.d()).redeployTarget(connectionId, targetId, pushId, by); }
  private async d(): Promise<DeployLogic> { return new DeployLogic(await this.v(), { fetchFn: (u, i) => fetch(u, i), planKey: this.env.COOKIE_ENCRYPTION_KEY }); }

  // approvals
  async createRequest(input: { repo: string; reason: string; items: AccessItem[]; requestedBy: string }) { return this.g().createRequest(input, await this.rules()); }
  getRequest(id: string) { return this.g().getRequest(id); }
  listRequests() { return this.g().listRequests(); }
  async approve(id: string, selected: number[], approvedBy: string, limits: ApprovalLimits = {}) { return this.g().approve(id, selected, approvedBy, limits, await this.rules()); }
  deny(id: string) { return this.g().deny(id); }
  getGrant(repo: string) { return this.g().getGrant(repo); }
  listGrants() { return this.g().listGrants(); }
  revoke(repo: string, index?: number) { return this.g().revoke(repo, index); }
  consume(repo: string, ruleId: string) { return this.g().consume(repo, ruleId); }
  refund(repo: string, ruleId: string) { return this.g().refund(repo, ruleId); }

  // backups
  /** Snapshot encrypted to BACKUP_PUBLIC_KEY. This Worker cannot decrypt what it returns. */
  async createBackup(by: string): Promise<{ createdAt: string; body: string }> {
    if (!this.env.BACKUP_PUBLIC_KEY) throw new Error('BACKUP_PUBLIC_KEY is not configured; run npm run setup-keys');
    const v = await this.v();
    const snap = await v.exportSnapshot(await this.g().listGrants());
    const env = await encryptBackup(this.env.BACKUP_PUBLIC_KEY, JSON.stringify(snap), snap.exportedAt);
    await v.log({ event: 'backup_created', by, secrets: snap.secrets.length });
    return { createdAt: snap.exportedAt, body: JSON.stringify(env) };
  }

  async restoreSnapshot(snap: Snapshot, by: string, overwriteTiers?: Tier[]) {
    const r = await (await this.v()).restoreSnapshot(snap, by, overwriteTiers);
    const grants = await this.g().importGrants((snap.grants ?? []) as RepoGrant[]);
    return { ...r, grants };
  }
}

/** Typed stub for the single vault instance. */
export type VaultApi = Pick<Vault, Exclude<keyof Vault, keyof DurableObject | 'fetch' | 'alarm'>>;
