# Agent instructions for projects using secret-broker

Canonical copy of the "Secret handling" block to paste into a consuming
project's CLAUDE.md / AGENTS.md.

---

## Secret handling

This project uses the `secret-broker` MCP server. Never read, print, copy, commit, or request the contents of `.env` files, vault secrets, machine tokens, Windows Credential Manager entries, or process environments.

When a task requires credentials:

1. Call `secret_status` first.
2. Continue only when `authorized` is `true` and `tier` is not null.
3. If unauthorized, stop and report the broker workspace, then ask the user to restart Claude from this project's root directory and configure its policy (edit `~/.secret-broker/policy.json`, or run `node <path to the secret-broker repo>/scripts/allow.mjs NAME... --tier <vault>` from the project folder you are granting).
4. Call `secret_list` to obtain the allowed `secret://tier/name` handles.
5. Run credentialed commands only through `secret_run`. Never resolve a handle yourself or run the command through the normal shell.
6. Map each required environment variable to its handle:

   ```json
   {
     "command": "node",
     "args": ["scripts/example.js"],
     "env": {
       "DATABASE_URL": "secret://personal/DATABASE_URL",
       "API_KEY": "secret://personal/API_KEY"
     }
   }
   ```

7. Use separate `command` and `args` fields. Do not construct a shell command string.
8. Only use commands allowed by the project policy. If denied, report the requested invocation and ask the user to approve it by editing `~/.secret-broker/policy.json`, or by running `node <path to the secret-broker repo>/scripts/allow.mjs NAME... --tier <vault>` from the project folder. Never work around the policy.
9. Non-secret environment values may be passed only when their names are included in the policy's pass-through environment list.
10. Treat broker output as redacted. Never attempt to reveal, reconstruct, log, echo, or validate a secret value.
11. Never ask the user to paste a secret into chat.
12. On Windows, do not invoke `npm` or `npx` directly through `secret_run`. Use `node` with the appropriate npm or npx JavaScript entry point and ensure that exact invocation is allowlisted.

---

## MCP registration (per agent, no secrets in config)

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

Codex equivalent: see README "Wiring into Codex".

---

## Claude on the web, Desktop and mobile (remote connector)

Paste this instead when the project is used through the remote
`secret-broker` connector rather than Claude Code:

## Secret handling (remote connector)

This project uses the `secret-broker` connector. Never ask for, print, reconstruct or guess secret values, and never ask the user to paste one into chat.

Client credentials live in a project vault (e.g. `secret://acme-finance/DB_URL`), never in `.env` files. Do not create or edit `.env` files with real credentials.

1. Call `secret_list` with this repo (`owner/name`) to see the vaults and secrets available to it, which are already approved, and where they may be sent. If this client project has no vault yet, call `secret_request_vault` and give the user the link.
2. If you need a secret that isn't approved, call `secret_request_access` with the repo, a one-line reason, and for each secret the exact host(s) it will go to. For strict vaults (production and client projects), also list the methods. Show the user the approval link and wait for them to approve.
3. Make API calls only with `secret_fetch`, passing the repo and `{{secret://tier/NAME}}` placeholders in a header, the query string, the body, or `basic_auth`.
4. Ask for the narrowest hosts and methods the task needs. If a call is denied, report it; never work around it.
5. Website logins (`kind: "login"` in `secret_list`) can be requested with `reveal: true` instead of hosts; once approved, `secret_reveal` returns the username and password for signing in through a browser. Type the password only into the site's sign-in form; never print or repeat it.
6. Prefer `secret_fetch` over `secret_reveal` whenever the sign-in can be done as an HTTP request.
7. Approvals may expire or run out of uses (`expiresAt` and `usesLeft` in `secret_list`). If a call is denied for that reason, call `secret_request_access` again and ask the user to approve.
