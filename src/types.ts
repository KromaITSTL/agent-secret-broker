/**
 * A vault name: `personal`, `production`, `client-work`, or one per project
 * (e.g. `acme-finance`). Lowercase letters, digits and dashes, 2-40 chars.
 */
export type Tier = string;

export const TIER_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;

export function isTier(value: unknown): value is Tier {
  return typeof value === 'string' && TIER_RE.test(value);
}

export interface WorkspaceRule {
  match: string;
  /**
   * One tier, or several for a directory that legitimately spans them (a
   * home folder that orchestrates every project). `allow` and `commands`
   * then apply across all of the listed tiers.
   */
  tier: Tier | Tier[];
  /**
   * Match the directory itself only, not anything beneath it. A multi-tier
   * rule on a parent folder should set this, or every project under it
   * without its own rule silently inherits all of those tiers.
   */
  exact?: boolean;
  allow: string[];
  commands: string[];
  /**
   * Names of non-handle env vars the agent may pass through to the child
   * (picomatch patterns). Absent or empty means none: an agent-chosen
   * NODE_OPTIONS / LD_PRELOAD etc. would turn any allowlisted interpreter
   * into arbitrary code that can read the injected secrets.
   */
  env?: string[];
}

export interface Policy {
  workspaces: WorkspaceRule[];
}

export interface Grant {
  tiers: Tier[];
  allow: string[];
  commands: string[];
  env?: string[];
}
