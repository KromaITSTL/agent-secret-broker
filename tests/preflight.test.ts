import { describe, it, expect } from 'vitest';
import { preflight } from '../src/preflight.js';

const ok = {
  policyExists: true,
  policyParsed: true,
  grantTier: 'client-work' as const,
  tokenPresent: true,
  prodWildcardCommands: false,
};

describe('preflight', () => {
  it('reports nothing when everything is present', () => {
    expect(preflight(ok)).toEqual([]);
  });

  it('reports a missing policy file with the path to create', () => {
    const issues = preflight({ ...ok, policyExists: false });
    expect(issues[0].code).toBe('POLICY_MISSING');
    expect(issues[0].remediation).toContain('.secret-broker/policy.json');
  });

  it('reports unparseable policy separately from missing', () => {
    expect(preflight({ ...ok, policyParsed: false })[0].code).toBe('POLICY_INVALID');
  });

  it('reports an unmatched workspace as a distinct, non-fatal issue', () => {
    const issues = preflight({ ...ok, grantTier: null });
    expect(issues.map((i) => i.code)).toContain('WORKSPACE_UNMATCHED');
  });

  it('reports a missing keychain token naming the tier', () => {
    const issues = preflight({ ...ok, tokenPresent: false });
    expect(issues[0].code).toBe('TOKEN_MISSING');
    expect(issues[0].message).toContain('client-work');
  });

  it('does not ask for a token when no workspace matched', () => {
    const codes = preflight({ ...ok, grantTier: null, tokenPresent: false }).map((i) => i.code);
    expect(codes).not.toContain('TOKEN_MISSING');
  });

  it('points a missing token at the vault Machines page and store-token', () => {
    const issues = preflight({ ...ok, tokenPresent: false });
    expect(issues[0].remediation).toContain('Machines page');
    expect(issues[0].remediation).toContain('npm run store-token client-work');
  });

  it('reports every issue at once rather than stopping at the first', () => {
    const issues = preflight({ ...ok, policyExists: false, tokenPresent: false });
    expect(issues).toHaveLength(2);
  });

  it('warns when a production rule allows wildcard commands', () => {
    const issues = preflight({ ...ok, prodWildcardCommands: true });
    expect(issues.map((i) => i.code)).toContain('PROD_WILDCARD_COMMANDS');
  });
});
