# secret-broker vault

Your own secret vault on Cloudflare Workers, with a web UI, per-repo
approvals, nightly encrypted backups, and a Claude connector that works on
claude.ai, Desktop and the phone apps. The local broker in the parent folder
(Claude Code) reads from the same vault.

## Quick start

Run these in this folder. The order matters: the GitHub OAuth app needs the
Worker URL, which the first deploy prints.

1. `npm install`
2. Create the storage: `npx wrangler kv namespace create OAUTH_KV` (paste the
   printed id over `REPLACE_WITH_YOUR_KV_NAMESPACE_ID` in `wrangler.jsonc`) and
   `npx wrangler r2 bucket create secret-broker-backups`.
3. In `wrangler.jsonc`, set `ALLOWED_GITHUB_IDS` to a comma-separated list of
   numeric GitHub ids. Find an id at `https://api.github.com/users/<login>`
   (the `id` field). Every listed account gets full admin rights.
4. `npm run deploy`. Note the URL it prints (`https://secret-broker.<subdomain>.workers.dev`).
   Wrangler may ask you to log in to Cloudflare first.
5. Create a GitHub OAuth app (GitHub > Settings > Developer settings > OAuth
   Apps) with the homepage set to the Worker URL and the authorization
   callback URL set to `<worker-url>/callback/web` (see
   [GitHub OAuth app](#github-oauth-app)).
6. Set its credentials: `npx wrangler secret put GITHUB_CLIENT_ID` and
   `npx wrangler secret put GITHUB_CLIENT_SECRET`.
7. Generate and set the cookie key: `openssl rand -hex 32`, then
   `npx wrangler secret put COOKIE_ENCRYPTION_KEY` and paste the output. The
   code uses it as an HMAC secret for session cookies, forms and review
   signatures. It must be at least 32 characters; `openssl rand -hex 32` gives 64.
8. `npm run setup-keys` creates the vault master key and the backup key pair,
   stores them as Worker secrets, and writes a recovery kit file
   (`secret-broker-recovery-kit-<date>.txt`). Put the kit in your password
   manager and on paper, then delete the file. Without it backups cannot be
   opened. See [How keys and backups protect you](#how-keys-and-backups-protect-you).
9. Set `PUBLIC_URL` in `wrangler.jsonc` to the deployed URL (a full
   `https://` URL, nothing else), then `npm run deploy` again. Left empty, the
   Worker uses whatever address each request arrives on; setting it pins
   approval links and the connector's OAuth metadata to one origin.
10. Open the Worker URL and sign in with an allowlisted GitHub account.
11. Open Connectors in the dashboard and press "Allow a new connection for 15
    minutes". Then, in Claude, add a custom connector with the URL
    `<worker-url>/mcp` and approve the sign-in. New app registration is closed
    the rest of the time.

## Security model and limits

- Single vault: administered by the allowlisted GitHub accounts (`ALLOWED_GITHUB_IDS`), each with full control. It is not multi-tenant.
- Approvals are keyed by a repo name the agent supplies, so the repo is a claimed boundary, not a verified one.
- Redaction of responses is best effort.
- Machine tokens return every value in the vaults they are scoped to, in plain text, through the API, with no expiry and no host or repo limit. A token with "Can import" can also write values in those vaults. Scope each token narrowly and revoke it on the Machines page if it leaks.
- Dashboard sessions last 12 hours and there is no sign-out button. Connector access tokens last 1 hour, with a 30-day refresh token.
- Client registration is closed by default. Pressing "Allow a new connection for 15 minutes" on the Connectors page opens a window of 15 minutes that accepts at most 5 registrations; it closes when either runs out or when you press Close now. Every registration and every successful connector sign-in is in the audit log, and registered apps are listed on the Connectors page, where Remove revokes one. A registration lasts 90 days and is renewed when the app is used in the second half of that period, so an app left idle for about six weeks or more can lose it and must be added again in a new window.
- Dashboard sign-in keeps no server state: the pending sign-in is a signed cookie that expires after 10 minutes, so opening the sign-in page writes nothing.
- `COOKIE_ENCRYPTION_KEY` must be at least 32 characters. With a missing or shorter key the Worker answers every request with a configuration error.
- Remaining limits: while the registration window is open, anyone who knows the address can register a client (it then shows on the Connectors page and in the audit log). Anyone who knows a registered app's client id can start sign-in attempts, each writing one short-lived KV entry. Like any public Worker, the request quota itself can be used up by anyone.
- Logins are different from API keys: an agent approved for a login receives the password.
- Deploy targets were checked against the platform docs; confirm behaviours such as Vercel upsert and branch-scoped variables on a low-risk project first.
- Provided as is; it has had internal review but no independent security audit. The local broker's limits are in the [root README](../README.md#security-model-and-limits); to report a problem see [SECURITY.md](../SECURITY.md).

## What's in it

- **Vaults**: `personal` and `production` are built in, plus one vault per client project (e.g. `acme-finance`). A project vault can be linked to its repos, so its secrets can never be approved for anyone else's repo. Production and project vaults are *strict*: approvals must name HTTP methods.
- **Secrets**: values are never shown again after saving. The last 20 versions are kept for undo, and deleted secrets sit in a 30-day trash.
- **Approvals**: Claude can see every secret *name*, but can only use a secret after you approve it for a specific repo and specific hosts. Approve from a link on your phone; revoke any time. Changes are immediate.
- **Machines**: tokens for your local broker and scripts, each limited to the vaults you tick.
- **Audit**: every use, request, approval, edit, login and backup. Never values.
- **Backups**: nightly to R2, kept 30 days, plus a download button. Encrypted to a key only your recovery kit holds; this server cannot read them.
- **Freeze**: one click stops every use of every secret.

## Claude's tools

| Tool | What it does |
|---|---|
| `secret_list` | Vaults and secret names this repo can use; which are approved and where they may go |
| `secret_request_vault` | Asks you to create a project vault linked to a repo; returns a link for you |
| `secret_request_access` | Asks you to approve secrets for a repo and hosts; returns a link for you |
| `secret_fetch` | One HTTPS request with `{{secret://vault/NAME}}` placeholders filled in; response redacted |
| `secret_reveal` | Username and password of an approved website login, for browser sign-in; audited, limited approvals count down |
| `secret_status` | Who's signed in, vaults and approvals for a repo |

Placeholders work in header values, the query string, the body and
`basic_auth`, but never in the hostname or path. Each secret in a request
must be approved for that repo, host, method and path, or nothing is sent.
Approvals in strict vaults must name methods (e.g. GET only).

## Logins and limited approvals

A login is a secret of kind `login` with a username, a password, a url and notes. The username, url and notes of every login are shown to any connected agent in `secret_list` without approval, so do not put secrets in them. Only the password needs approval.

For API keys the guarantee is that the agent never sees the value. For logins that cannot hold, because the agent has to type the password into a website. The guarantee becomes: only approved logins, only for approved repos, every reveal audited, limited in time or uses, and easy to rotate by changing the password.

On the dashboard you create and edit logins and use the Reveal button to see one. Each reveal is one-shot and writes an `admin_reveal` entry to the audit log. An agent asks for a login with `reveal: true` in `secret_request_access` instead of hosts; once you approve, it calls `secret_reveal`. `secret_fetch` still works with a login handle when the sign-in is a plain HTTP request, and agents are told to prefer it.

On the approval page you choose how long an approval lasts (`1 hour`, `24 hours`, `7 days` or `never`) and how many uses it allows (leave blank for unlimited, or enter up to 1000). Logins that are revealed, and everything in the `production` vault, default to 7 days; other API keys default to never. Each fetch or reveal counts as a use.

Expired or used-up approvals drop out of the agent's list but stay on the Approvals page with a grey tag and a revoke button. To approve again, the agent calls `secret_request_access` once more; the page opens pre-ticked, so re-approval is one click.

## Deploy targets

Deploy pushes items from a client vault to the place the client's app actually runs: a Vercel project or a Cloudflare Worker. It lives under **Deploy** in the dashboard and nowhere else. There is no agent tool, no API route and no machine token path for it; only a signed-in dashboard session can use it.

### Config items

Not every setting is a secret. An Azure client id or tenant id is safe to look at, and you want to see what is deployed. A vault item can therefore be one of two kinds you choose when you add it: a secret (write-only, as before) or **config** (shown in clear on the item page and in the Deploy review). Config items are versioned like secrets, but they are never shown to an agent as text; an agent still only gets a handle. Config items show with a `config` tag in the Secrets list.

A secret can be converted to config, one way only. The current value becomes visible in the dashboard; older versions stay hidden and cannot be restored, because they were written while the item was a secret. To go back, add a new secret.

### Connections

A connection is a token for one platform account. Add it on **Deploy, Connections**. The token is sealed on arrival, is checked once against the platform, and is never shown again, not in the dashboard, logs, audit entries, errors or backups (backups hold it sealed). To change it, use Replace token on the connection. You can have several connections per platform.

- **Vercel.** Enter the team id (starts with `team_`), or leave it empty for a personal account. Create a token under Vercel account settings, Tokens, scoped to that team. It needs to read and write environment variables on the projects you push to, and to create deployments if you want Redeploy.
- **Cloudflare.** Enter the account id (32 characters, on the Workers overview page). Create an API token with the **Workers Scripts: Edit** permission for that account only.

Use the narrowest token you can. If a token is ever exposed, rotate it at the platform and replace it here.

### Linking, review and push

1. **Link a target.** On Deploy, pick a connection, then a project or Worker, and tick the vault items to send. For each item you set the variable name it will have on the platform (letters, digits and underscores) and, on Vercel, which environments (production, preview, development; the first two are the default). Cloudflare has no environments. A variable name may be used only once per environment.
2. **Review push.** Nothing is sent from the link page. Review reads what is already on the platform and lists every variable with the item and version it will get, and a class: **new**, **update** (you pushed this item before and a newer version exists), **replace** (the variable already exists but this tool did not put it there), **up to date** (this item and version are what this tool last pushed there; the row starts unticked) or **missing** (the vault item was deleted; fix the link). Config items show the value now on Vercel next to the value after the push. Secrets never show a value either way.
3. **Replace rows are unticked.** Overwriting something this tool did not create needs a deliberate tick. New and update rows start ticked. The page carries a signature over exactly what you reviewed; if the platform or the vault changed since, the push is refused and you review again.
4. **Recreate.** On Vercel a variable cannot change its type or its set of environments in place, so such a row is deleted and created again. The review row says so and names the environments that will lose the variable because they are not in the link. Tick every environment row for that variable together.
5. **Push.** Every ticked row is sent, and each row reports its own result, so one failure does not hide the others. A failed row says what the platform answered, never the value.
6. **Redeploy (Vercel only).** Vercel applies new variables to the next deployment, so the result page offers **Redeploy**, which rebuilds the latest production deployment. Cloudflare has no such button because every secret change already creates a new Worker version.

### Cloudflare behaviour

Everything is stored as a Worker secret (`secret_text`), including config items. Plain Worker variables are overwritten by Workers Builds on each build, so a plain variable would silently vanish; secrets are not touched. Cloudflare never returns a secret's value, so the review cannot compare values. A row is classed by the Worker's live secret names: a name that is not there is new; for a name that is there, push history decides between up to date, update (this tool pushed this item there before) and replace.

### History and rollback

**Deploy, History** lists every push, per variable and environment, with the item, the version, the outcome and any Redeploy result. To roll back, open the review for the target and use **Pick other versions** to choose an older version of an item (for a config item, versions from before its conversion to config are not offered, and a push that asks for one is refused, because they stay secret), then review and push as normal.

### What is never shown

Connection tokens are never shown after entry. Secret values are never shown on any Deploy page, in history or in the audit log; config values appear only on the item page, truncated in the Secrets list, and on the review. The audit log records who pushed what to which target and how many rows succeeded, never a value. Backups include connections (sealed), links and history. The machine import script skips them, and restoring a backup never overwrites a live config item.

## New client project: the process

1. **Create the vault.** On the Vaults page, or let Claude call `secret_request_vault` and approve the link. Link it to the project's repo(s).
2. **Fill it.** Type values into the Secrets page, or import the project's existing `.env` and delete it:
   ```powershell
   npm run import-env -- acme-finance ../acme-dash/.env --skip NODE_ENV,PORT --delete
   ```
   (Needs a machine token with "Can import". It prints the env-to-handle mapping for the local broker.)
3. **Claude Code on your PC:** create a machine token for that vault, `npm run store-token acme-finance` in the repo root, and add a workspace rule with `"tier": "acme-finance"` (or, from that project's folder, `node <path to this repo>/scripts/allow.mjs NAME... --tier acme-finance`).
4. **Claude on the web or phone:** it requests access per secret and host; you approve from the link.

If a repo is unlinked from a vault, its access stops immediately, even where secrets were already approved.

## How keys and backups protect you

- Each value is encrypted with its own key (AES-256-GCM), and that key is encrypted with the **master key** (Worker secret `VAULT_MASTER_KEY`). Encrypted values are bound to their vault, name and version, so they can't be swapped between secrets.
- Backups are encrypted to the **backup public key**. Only the private key, which lives only in your recovery kit, can open them.
- `npm run setup-keys` creates both keys and the **recovery kit** file. Keep the kit in your password manager and on paper. **Without the kit, backups can't be opened by anyone.**
- `npm run setup-keys` refuses to replace an existing master key, since that would make every secret unreadable. Use `--rotate-master` to change it safely.

## GitHub OAuth app

Set the authorization callback URL to `<worker-url>/callback/web` (GitHub
matches it exactly). Both sign-ins, the connector and the vault pages, return
there. Leave wildcard matching off.

Claude's connector flow registers itself through dynamic client registration
(`/register`), which is closed until you open it from the Connectors page (15
minutes, at most 5 registrations). Even then only redirect URIs on `claude.ai`,
`claude.com`, `anthropic.com` or loopback are accepted (`REDIRECT_HOSTS` in
`src/env.ts`). Still read the client name and redirect host on the consent
page before approving.

Approvals are keyed by the `repo` string the agent passes, which the agent
chooses. A prompt-injected agent working in one repo can name another repo
and use its approvals, within the hosts and methods approved there. The
approval page therefore shows a claimed repo, not a verified one; keep
grants narrow.

## Recovery playbook

| What happened | What to do |
|---|---|
| Overwrote a secret by mistake | Vault > the secret > History > Make current |
| Deleted a secret | Vault > Trash > Restore (within 30 days) |
| Something looks wrong | Settings > Freeze vault, then check Audit |
| A machine token leaked | Machines > Revoke |
| A dashboard session cookie or the signing key leaked | Set a new `COOKIE_ENCRYPTION_KEY` (`openssl rand -hex 32`, then `npx wrangler secret put COOKIE_ENCRYPTION_KEY`); this signs everyone out and invalidates open forms |
| An app you do not recognise is connected, or a connector token leaked | Connectors > Remove (freeze the vault first if secrets may be in use) |
| An allowlisted GitHub account is compromised | Remove its id from `ALLOWED_GITHUB_IDS` and deploy; its dashboard sessions and connector tokens stop working at once |
| Vault data lost or Worker deleted | Redeploy, run `setup-keys` (new keys are fine), create an import machine, then `npm run restore -- backup.json` with your kit. Restore writes secret values only; re-create machines, approvals and vault settings in the UI. An import token replaces existing values only in vaults it is scoped to |
| After restoring a backup | `npm run restore` goes through the machine import, which skips connections, links and push history: re-add each connection under Deploy, Connections and re-create its links. Where a restore does bring connections back, any whose token could not be read (sealed under a master key that is not loaded; the restore counts them as unreadable) must likewise be re-added and their links re-created. |
| Need the plain values offline | `npm run restore -- backup.json --out plain.json` (delete it after) |

## Commands (run in this folder)

```powershell
npm run setup-keys                     # first time: master key, backup keys, recovery kit
npm run setup-keys -- --rotate-master  # new master key; then Settings > Re-encrypt
npm run restore -- <backup.json>       # decrypt with your kit and write back into the vault
npm run import-env -- <vault> <.env>   # move a project's .env into a vault
npm run check                          # type-check
npm test                               # tests
npx wrangler deploy                    # deploy
```

## Optional static rules

`policy.json` can hold rules that apply to every repo without approval (`tier`, `secrets`, `hosts`, `methods`, `paths`). It ships
empty, so everything goes through approvals.
