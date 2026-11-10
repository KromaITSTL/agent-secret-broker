# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

One person: a single operator, an individual or small consultancy managing client credentials, who is also a developer. The vault is a single vault administered by the allowlisted GitHub accounts (`ALLOWED_GITHUB_IDS`), each with full control; it is not multi-tenant. They use the vault from a desktop while coding and from a phone when Claude asks for access mid-task (the approval link arrives in a Claude chat, often away from the desk).

## Product Purpose

A self-hosted credential vault and broker on Cloudflare Workers for AI agents. Claude (web, desktop, mobile and Claude Code) can use secrets without ever seeing their values: it asks for access, the operator approves per repo and per destination host, and the broker injects the value server-side. Success means client credentials never sit in `.env` files, nothing is approved by accident, and a mistake or compromise can be stopped and undone quickly.

## Positioning

Approval is the product: every grant is bound to a repo, a vault, the hosts (and for strict vaults the HTTP methods and paths) a secret may be sent to, and lasts until it is revoked, expires, or runs out of uses. API keys and tokens are write-only in the UI and are never shown to an agent. Logins (website username and password) are the one exception: the operator can reveal one behind a button, and an agent approved for it receives the password, because a browser form cannot be filled any other way. The protection for logins is approval per project, a time or use limit, and an audit row for every reveal.

## Operating Context

- Approving an agent's request from a phone, often half-attended.
- Adding or rotating a secret on desktop while setting up a client project.
- Approving a reveal request and choosing how long, or how many times, the agent may use it.
- Creating one vault per client project, linked to that project's repos.
- Issuing machine tokens for the local broker (Claude Code) and import scripts.
- Investigating via the audit log; emergency freeze during an incident.
- Pushing a client's vault items to its Vercel project or Cloudflare Worker after reviewing every variable, and redeploying on Vercel.
- Nightly encrypted backups to R2; offline recovery kit.

## Capabilities and Constraints

- Vaults: `personal`, `production` (built in, strict), plus one per client project (optionally strict, optionally linked to repos). Terms: vault (older code says "tier"), secret, handle `secret://<vault>/<NAME>`, approval/grant, machine token, freeze.
- Secrets keep up to 20 versions; trash for 30 days; move between vaults keeps history.
- A login is a secret with a kind: username, site URL and notes shown in clear, password sealed. Approvals carry an optional expiry (1 hour, 24 hours, 7 days, never) and an optional use count (1 to 1000); expired and used-up approvals stay listed with a grey tag until revoked.
- Config items: shown in clear in the dashboard, versioned like secrets, never shown to agents as text; a secret converts to config one way.
- Deploy: connections to Vercel teams and Cloudflare accounts (tokens sealed, dashboard only), target links, a signed review step where replace rows must be ticked, push history per variable and environment with versions, Vercel redeploy.
- Server-rendered HTML from the Worker. CSP forbids all scripts; styles are inline; no third-party requests from the UI. Fonts and images may only be served from the Worker itself.
- Every POST carries a CSRF token; pages are `no-store`.

## Evidence on Hand

Real data only from the operator's vault; never show secret values anywhere except the one-shot reveal box after a deliberate click. Screenshots use local test data.

## Product Principles

1. Risk is the loudest thing on the page: production, wildcard hosts, denials and the frozen state must be unmistakable.
2. Irreversible actions take a deliberate second step; reversible ones stay one click.
3. Say exactly what will happen, to which repo, at which host, until when.
4. Works one-handed on a phone for approvals; desktop for administration.
5. Calm by default. Nothing decorative competes with a security decision.

## Accessibility & Inclusion

WCAG 2.2 AA: labelled fields, 4.5:1 text contrast in both themes, keyboard-complete flows, 24px minimum targets (44px for primary phone actions).
