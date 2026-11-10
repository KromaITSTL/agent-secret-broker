# secret-broker

Per-workspace, per-session credential access for agent sessions. The agent
receives handles like `secret://client-work/globex-db-url`, never values.

## Security model and limits

Read this before relying on the broker.

- **Single vault.** The remote vault is administered by the allowlisted GitHub
  accounts (`ALLOWED_GITHUB_IDS`), each with full control. It is not
  multi-tenant and has no role model.
- **Local broker (this folder).** The command allowlist is the guarantee.
  Rules that allow `**`, `*`, `node **` or any interpreter with free
  arguments let the agent print the secret. The policy file, audit log and
  stored tokens belong to the same OS user as the agent, so an agent with
  shell access can edit the policy and audit log, and can read a stored
  machine token from the OS keychain and then fetch every value that token
  can read straight from the vault, without touching the policy.
  Harness-level deny rules (for example Claude Code deny rules for
  `~/.secret-broker/**`) reduce this but do not remove it.
- **Machine tokens.** A machine token returns every value in the vaults it is
  scoped to, in plain text, through the API, with no expiry and no host or
  repo limit. A token with "Can import" can also write values in those
  vaults. Scope each token to the vaults it needs and revoke it on the
  Machines page if it leaks.
- **Sessions and connector tokens.** Dashboard sessions last 12 hours and
  there is no sign-out button. Connector access tokens last 1 hour, with a
  30-day refresh token. See the recovery playbook in
  [`remote/README.md`](remote/README.md) to cut either off.
- **Remote connector (`remote/`).** Approvals are keyed by a repo name the
  agent supplies, so it is a claimed boundary, not a verified one. Redaction
  of responses is best effort. Logins are different from API keys: an agent
  approved for a login receives the password.
- **Deploy targets.** Behaviour was checked against the platform
  documentation, but things like Vercel upsert and branch-scoped variables
  should be confirmed on a low-risk project first.
- **As is.** Provided as is. It has had internal review but no independent
  security audit. See [SECURITY.md](SECURITY.md) for reporting issues.

## Install

```bash
npm install
npm run build
```

The broker reads secrets from the vault in `remote/`, a Cloudflare Worker you
deploy yourself; see [`remote/README.md`](remote/README.md). Create that
first, then store a machine token for each vault (below).

## Policy file

Rules live in `~/.secret-broker/policy.json`. Or add them from the project
folder you are granting, with
`node <path to this repo>/scripts/allow.mjs NAME... --tier <vault>` (it
grants the directory it is run from). Minimal example:

```json
{
  "workspaces": [
    {
      "match": "/home/me/code/my-project",
      "tier": "client-work",
      "allow": ["MY_PROJECT_*"],
      "commands": ["node scripts/migrate.mjs"],
      "env": ["NODE_ENV"]
    }
  ]
}
```

`match` is the absolute workspace directory (forward slashes, e.g.
`c:/work/my-project` on Windows), `tier` the vault (or an array of vaults),
`allow` the secret names that may be requested, `commands` the exact
invocations that may receive them, and `env` the optional non-secret
variables the agent may pass through. See "Policy notes" below.

## Storing tokens

The vault is the only backend. Deploy the Worker in `remote/` (see its
README), open its **Machines** page, create a machine token for this PC and
tick the vaults it needs. The token looks like `sbv.…`. Store it in the OS
keychain for each of those vaults (the same token works for several), under
Windows Credential Manager on Windows or the login Keychain on macOS:

```bash
npm run build
npm run store-token personal
npm run store-token client-work
npm run store-token production
```

Input is hidden. The token is never passed as an argument, so it stays out
of shell history and out of `ps` output. Never put a token in a file, a
shell history, or a chat window. Anything that is not a vault machine token
is refused, both when you store it and when the broker starts.

### Worked example

Create the token on the Machines page (tick `client-work`), copy it, then:

```powershell
cd <path to this repo>
npm run build
npm run store-token client-work
# Paste the client-work machine token (input hidden): <paste, Enter>
# stored client-work token in the OS keychain
```

Paste the whole token, including the leading `sbv.`. The entry lands in
Credential Manager under the service `secret-broker`, one per vault; on
macOS, in the login Keychain.

If a token was ever exposed (pasted somewhere visible), revoke it on the
Machines page, create a new one and store it; storing again overwrites the
old entry.

## Wiring into Claude Code

No secrets go in this config:

```json
{
  "mcpServers": {
    "secret-broker": {
      "command": "node",
      "args": ["<repo>/dist/index.js"]
    }
  }
}
```

The broker reads the keychain itself. Nothing sensitive is passed through
the agent.

## Wiring into Codex

Register the same stdio server in `~/.codex/config.toml`:

```toml
[mcp_servers.secret-broker]
command = "node"
args = ["<repo>/dist/index.js"]
```

## Policy notes

- `commands` patterns match the full invocation joined with spaces, and `*`
  does not cross `/`. `npx prisma *` therefore denies
  `npx prisma migrate --schema=prisma/schema.prisma`; write
  `npx prisma **` (or list the exact invocation) when args contain paths.
  Failure direction is always deny.
- The allowlist is the guarantee. `**`, `*`, `node **`, `npx **` or any
  interpreter with free arguments lets the agent print the value
  (`node -p process.env.X`), so for those rules the broker only prevents
  accidental leakage. `scripts/allow.mjs` creates rules with `**` by design (access
  is per entry); tighten `commands` by hand for production tiers. The broker
  warns at startup (`PROD_WILDCARD_COMMANDS`) when a production rule is
  exfil-capable.
- A handle may not be mapped to an env name the runtime itself reads
  (`PATH`, `NODE_OPTIONS`, `LD_*`, `*_PROXY`, ...); those are refused.
- Policy, audit log and tier tokens are owned by the same OS user the agent
  runs as. An agent with shell access can edit `policy.json`, run
  `allow.mjs` itself, or read a stored token from the keychain; the broker
  cannot stop that. Add Claude Code deny rules for `~/.secret-broker/**` and
  `scripts/allow.mjs` in the harness.
- Non-handle env vars are denied unless the workspace rule lists them in
  `env` (e.g. `"env": ["NODE_ENV"]`). Without this, an agent-chosen
  `NODE_OPTIONS` or `LD_PRELOAD` could run arbitrary code inside the child
  that holds the secrets.
- On Windows, `npm`/`npx` are `.cmd` shims that Node refuses to spawn
  without a shell (CVE-2024-27980), and the broker never uses a shell
  because that would defeat the command allowlist. Allowlist and invoke the
  underlying tool directly instead, e.g.
  `node C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js run deploy`.

## Vault names and tiers

The tier in a policy rule is the name of a vault on the Worker: `personal`,
`production`, and one per client project (e.g. `acme-finance`), so a workspace rule can use
`"tier": "acme-finance"` and handles look like `secret://acme-finance/DB_URL`.
Move a project's `.env` into its vault with `npm run import-env` in `remote/`,
then delete the file.

Revoking the machine in the vault cuts this PC off immediately, and
freezing the vault blocks it too.
