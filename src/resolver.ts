import type { Tier } from './types.js';

export class ResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResolutionError';
  }
}

/**
 * Routes each call to the resolver holding that tier's token, so a
 * multi-tier grant never hands one tier's machine account another tier's
 * lookups. A tier with no resolver fails closed.
 */
export class TierRouter implements SecretResolver {
  constructor(private readonly byTier: Partial<Record<Tier, SecretResolver>>) {}

  private pick(tier: Tier): SecretResolver {
    const r = this.byTier[tier];
    if (!r) throw new ResolutionError(`no token loaded for tier ${tier}`);
    return r;
  }

  resolve(tier: Tier, name: string): Promise<string> {
    return this.pick(tier).resolve(tier, name);
  }

  list(tier: Tier): Promise<string[]> {
    return this.pick(tier).list(tier);
  }
}

export interface SecretResolver {
  resolve(tier: Tier, name: string): Promise<string>;
  /**
   * Names of the secrets readable in this tier. Names only, never values.
   * Required so `secret_list` can return the real handles available.
   */
  list(tier: Tier): Promise<string[]>;
}

export class FakeResolver implements SecretResolver {
  readonly calls: Array<{ tier: Tier; name: string }> = [];

  constructor(private readonly seed: Record<string, string>) {}

  async resolve(tier: Tier, name: string): Promise<string> {
    this.calls.push({ tier, name });
    const value = this.seed[`${tier}/${name}`];
    if (value === undefined) {
      throw new ResolutionError(`no such secret: ${tier}/${name}`);
    }
    return value;
  }

  async list(tier: Tier): Promise<string[]> {
    const prefix = `${tier}/`;
    return Object.keys(this.seed)
      .filter((k) => k.startsWith(prefix))
      .map((k) => k.slice(prefix.length));
  }
}
