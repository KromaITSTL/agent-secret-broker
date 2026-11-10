export interface PreflightInput {
  policyExists: boolean;
  policyParsed: boolean;
  /** Granted tier label, or the first tier whose token is missing. */
  grantTier: string | null;
  tokenPresent: boolean;
  /** Any production rule whose commands let an interpreter run with free args (`*`, `**`, `node **`, ...). */
  prodWildcardCommands: boolean;
}

export interface PreflightIssue {
  code: string;
  message: string;
  remediation: string;
}

export function preflight(input: PreflightInput): PreflightIssue[] {
  const issues: PreflightIssue[] = [];

  if (!input.policyExists) {
    issues.push({
      code: 'POLICY_MISSING',
      message: 'No policy file found.',
      remediation: 'Create ~/.secret-broker/policy.json with a workspaces array.',
    });
  } else if (!input.policyParsed) {
    issues.push({
      code: 'POLICY_INVALID',
      message: 'Policy file exists but could not be parsed as JSON.',
      remediation: 'Fix the JSON syntax in ~/.secret-broker/policy.json.',
    });
  }

  if (input.grantTier === null) {
    issues.push({
      code: 'WORKSPACE_UNMATCHED',
      message: 'This working directory matches no policy rule, so no secrets are available.',
      remediation: 'Add a workspaces entry whose match glob covers this directory.',
    });
  } else if (!input.tokenPresent) {
    issues.push({
      code: 'TOKEN_MISSING',
      message: `No vault machine token stored for tier ${input.grantTier}, or the stored token is not a vault machine token (sbv.…).`,
      remediation: `Create a machine token on the vault's Machines page and store it with: npm run store-token ${input.grantTier} (hidden prompt, never an argument). See README.`,
    });
  }

  if (input.prodWildcardCommands) {
    issues.push({
      code: 'PROD_WILDCARD_COMMANDS',
      message: 'A production rule allows any command or an interpreter with free arguments ("*", "**", "node **"), so the agent can print the secret; the handles-only guarantee collapses to "no accidental leakage".',
      remediation: 'List explicit commands for production workspaces, e.g. "node scripts/deploy.js", not "node **".',
    });
  }

  return issues;
}
