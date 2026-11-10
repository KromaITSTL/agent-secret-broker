# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and the impact you expect. You
will get an acknowledgement; fixes and disclosure timing are handled on a best
effort basis, since this is a small project.

## In scope

- The local broker in `src/` (policy matching, handle resolution, redaction,
  keychain token handling, audit log).
- The Cloudflare Worker in `remote/` (vault storage and encryption, GitHub
  sign-in and the allowlist, approvals, the remote MCP connector, machine
  tokens, backups, deploy targets).
- The scripts in `scripts/` and `remote/scripts/`.

Out of scope: vulnerabilities in third-party services (Cloudflare,
Vercel, GitHub) or in dependencies themselves (report those upstream), and
anything that requires an attacker who already controls the operator's OS
account or Cloudflare account.

## Security model and known limits

- Single vault: administered by the allowlisted GitHub accounts
  (`ALLOWED_GITHUB_IDS`), each with full control. It is not multi-tenant.
- Local broker: the command allowlist is the guarantee. Rules that allow
  `**`, `*`, `node **` or any interpreter with free arguments let the agent
  print the secret. The policy file, audit log and stored tokens belong to the
  same OS user as the agent, so an agent with shell access can edit the policy
  and audit log, and can read a stored machine token from the OS keychain and
  then fetch every value that token can read straight from the vault, without
  touching the policy. Harness-level deny rules reduce this but do not remove
  it.
- Remote connector: approvals are keyed by a repo name the agent supplies, so
  it is a claimed boundary, not a verified one. Redaction of responses is best
  effort. Logins are different from API keys: an agent approved for a login
  receives the password.
- Machine tokens: a machine token returns every value in the vaults it is
  scoped to, in plain text, through the API, with no expiry and no host or
  repo limit. A token with "Can import" can also write values in those vaults.
- Sessions and connector tokens: dashboard sessions last 12 hours and there is
  no sign-out button. Connector access tokens last 1 hour, with a 30-day
  refresh token.
- Deploy targets: verified against the platform docs; behaviours such as
  Vercel upsert and branch-scoped variables should be confirmed on a low-risk
  project first.
- Provided as is; it has had internal review but no independent security
  audit.
