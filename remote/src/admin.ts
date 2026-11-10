/**
 * Admin pages: secrets (add, replace, history, trash), machines, audit,
 * backups and settings (freeze, key rotation).
 *
 * Values go in, never out: no page or response here contains a secret value.
 * Every POST needs a signed-in allowlisted session and a CSRF token.
 */
import type { Hono } from 'hono';
import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';
import { allowedIds, type Env } from './env';
import type { AuditEntry, LoginFields, PublicMachine, SecretMeta, VaultInfo, VaultRequest } from './store';
import { vaultFor } from './vault-client';
import type { VaultApi } from './vault-do';
import { registerDeployRoutes } from './deploy-routes';
import { confirmAction, csrfToken, done, esc, hidden, nav, navStatus, page, requireSession, safeEqual, SECURITY_HEADERS, seeOther, stamp, type NavStatus, type Session } from './web';

type App<B extends Env> = Hono<{ Bindings: B }>;

/** The few provider helpers the Connectors page uses. */
export type OAuthApi = Pick<OAuthHelpers, 'listClients' | 'listUserGrants' | 'lookupClient' | 'deleteClient'>;

export interface AdminDeps {
  vault?: (env: Env) => VaultApi;
  /** Overridable for tests; defaults to the OAUTH_PROVIDER binding the provider injects. */
  oauth?: (env: Env) => OAuthApi;
}

const when = (ms?: number) => stamp(ms);

function vaultSelect(vaults: VaultInfo[], selected?: string, name = 'tier', placeholder?: string): string {
  return `<select name="${name}" required>${placeholder ? `<option value="" disabled selected>${esc(placeholder)}</option>` : ''}${vaults.map((v) => `<option value="${esc(v.slug)}"${v.slug === selected ? ' selected' : ''}>${esc(v.name)} (${esc(v.slug)})</option>`).join('')}</select>`;
}

function vaultTag(v: Pick<VaultInfo, 'slug' | 'kind' | 'strict'>): string {
  const cls = v.kind === 'production' ? 'prod' : '';
  return `<span class="tag ${cls}">${esc(v.slug)}</span>`;
}

function splitRepos(raw: unknown): string[] {
  return String(raw ?? '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
}

const VALUE_FIELD = `<textarea name="value" required autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Paste the value. It will not be shown again."></textarea>`;

function secretsTable(list: SecretMeta[], trash: boolean, csrf: string, approvedFor: Map<string, number> = new Map(), configs: Map<string, string> = new Map()): string {
  if (list.length === 0) return '';
  return '<div class="list">' + list
    .map((m) => {
      const link = `/vault/s/${encodeURIComponent(m.tier)}/${encodeURIComponent(m.name)}`;
      const handle = `${m.tier}/${m.name}`;
      const actions = trash
        ? `<form class="inline" method="post" action="${link}/undelete">${hidden(csrf)}<button>Restore</button></form>
           ${confirmAction({ label: 'Delete forever', action: `${link}/purge`, fields: { csrf }, consequence: `<code>${esc(m.name)}</code> and all ${m.versions?.length ?? 1} saved version(s) are erased. This cannot be undone, and backups made after now will not have it.`, aria: `Delete ${m.name} forever` })}`
        : `<a href="${link}" aria-label="Manage ${esc(m.name)}">Manage</a>`;
      const tierTag = m.tier === 'production' ? '<span class="tag prod">production</span>' : `<span class="tag">${esc(m.tier)}</span>`;
      const n = approvedFor.get(handle) ?? 0;
      const cv = m.kind === 'config' && !trash ? configs.get(handle) : undefined;
      const cfg = cv === undefined ? '' : `<code class="cval">${esc(cv.length > 40 ? cv.slice(0, 40) + '…' : cv)}</code> `;
      const use = trash ? `deleted ${when(m.deletedAt)}` : `${n ? `approved for ${n} repo${n === 1 ? '' : 's'}` : 'not approved anywhere'} · v${m.current} · updated ${when(m.updatedAt)}`;
      return `<div class="srow"><div class="sname"><code>${esc(m.name)}</code>${tierTag}${m.kind === 'login' ? '<span class="tag">login</span>' : ''}${m.kind === 'config' ? '<span class="tag">config</span>' : ''}</div>
<div class="smeta">${cfg}${use}</div><div class="sact">${actions}</div></div>`;
    })
    .join('') + '</div>';
}

export function registerAdminRoutes<B extends Env>(app: App<B>, deps: AdminDeps = {}): void {
  const vault = deps.vault ?? ((env: Env) => vaultFor(env));
  const oauth = deps.oauth ?? ((env: Env) => (env as Env & { OAUTH_PROVIDER: OAuthHelpers }).OAUTH_PROVIDER);

  /** Session + CSRF for a POST; returns the session and parsed form, or an error response. */
  async function post(req: Request, env: Env): Promise<{ s: Session; form: FormData; st: NavStatus } | Response> {
    const s = await requireSession(req, env);
    if (s instanceof Response) return s;
    const form = await req.formData();
    const expected = await csrfToken(env.COOKIE_ENCRYPTION_KEY, s, 'admin');
    if (!safeEqual(String(form.get('csrf') ?? ''), expected))
      return page('Expired', '<h1>This form expired</h1><p>Nothing was changed. Forms stop working after a while or when you sign in again. <a href="/vault">Start again</a></p>', 403);
    return { s, form, st: await navStatus(vault(env), req.url) };
  }

  async function get(req: Request, env: Env): Promise<{ s: Session; csrf: string; st: NavStatus } | Response> {
    const s = await requireSession(req, env);
    if (s instanceof Response) return s;
    const [csrf, st] = await Promise.all([csrfToken(env.COOKIE_ENCRYPTION_KEY, s, 'admin'), navStatus(vault(env), req.url)]);
    return { s, csrf, st };
  }

  const fail = (s: Session, active: string, err: unknown, back: string, st: NavStatus = {}) =>
    page('Error', `${nav(active, s.login, st)}<h1>That didn't work</h1><p>${esc((err as Error).message)}</p><p class="muted">Nothing was changed.</p><p><a href="${esc(back)}">Go back</a></p>`, 400);

  // ---------- vault ----------

  app.get('/vault', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const v = vault(c.env);
    const [all, vaults, grants, configs] = await Promise.all([v.listSecrets(false), v.listVaults(), v.listGrants(), v.configValues()]);
    const approvedFor = new Map<string, number>();
    for (const g of grants) for (const h of new Set(g.rules.filter((r) => r.state === 'live').flatMap((r) => r.secrets.map((n) => `${[r.tier].flat()[0]}/${n}`)))) approvedFor.set(h, (approvedFor.get(h) ?? 0) + 1);
    const logins = c.req.query('kind') === 'login';
    const sel = logins ? '' : (c.req.query('v') ?? '');
    const list = logins ? all.filter((m) => m.kind === 'login') : sel ? all.filter((m) => m.tier === sel) : all;
    const count = (slug: string) => all.filter((m) => m.tier === slug).length;
    const tabs = [
      `<a href="/vault"${sel || logins ? '' : ' class="on" aria-current="page"'}>All (${all.length})</a>`,
      ...vaults.map((x) => `<a href="/vault?v=${encodeURIComponent(x.slug)}"${x.slug === sel ? ' class="on" aria-current="page"' : ''}>${esc(x.slug)} (${count(x.slug)})</a>`),
      `<a href="/vault?kind=login"${logins ? ' class="on" aria-current="page"' : ''}>logins (${all.filter((m) => m.kind === 'login').length})</a>`,
    ].join('');
    const empty = logins ? 'No logins yet.' : sel ? `No secrets in ${esc(sel)} yet.` : 'No secrets yet.';
    return page(
      'Secrets',
      `${nav('/vault', a.s.login, a.st)}<h1>Secrets</h1>
<p class="muted">API keys and tokens are never shown after saving; config items are shown in clear. A login's password can be revealed on its page; each reveal is recorded in the audit trail. <a href="/vault/trash">Trash</a> · <a href="/vaults">Manage vaults</a></p>
<div class="tabs">${tabs}</div>
<div class="creates"><details class="add"${all.length ? '' : ' open'}><summary>Add a secret</summary><div class="card"><form method="post" action="/vault/add">${hidden(a.csrf)}
<label class="f">Vault</label>${vaultSelect(vaults, sel || 'personal')}
<label class="f">Name</label><input type="text" name="name" required pattern="[A-Za-z0-9_.\\-]{1,128}" title="Letters, numbers, dot, dash and underscore, up to 128 characters" placeholder="GITHUB_TOKEN" autocomplete="off" autocapitalize="off" spellcheck="false">
<fieldset><legend>Kind</legend><label><input type="radio" name="kind" value="secret" checked> Secret (write-only)</label> <label><input type="radio" name="kind" value="config"> Config (shown here in clear, never to agents as text)</label></fieldset>
<label class="f">Value</label>${VALUE_FIELD}
<div class="row"><button class="primary">Add</button></div></form></div></details>
<details class="add quiet"><summary>New login</summary><div class="card"><form method="post" action="/vault/add-login">${hidden(a.csrf)}
<label class="f">Vault</label>${vaultSelect(vaults, sel || 'personal')}
<label class="f">Name</label><input type="text" name="name" required pattern="[A-Za-z0-9_.\\-]{1,128}" title="Letters, numbers, dot, dash and underscore, up to 128 characters" placeholder="PORTAL_LOGIN" autocomplete="off" autocapitalize="off" spellcheck="false">
<label class="f">Username</label><input type="text" name="username" required maxlength="256" autocomplete="off" autocapitalize="off" spellcheck="false">
<label class="f">Password</label><input type="password" name="password" required autocomplete="new-password">
<label class="f">Login URL (optional)</label><input type="url" name="url" maxlength="2048" placeholder="https://portal.example.com/login">
<label class="f">Notes (shown to agents, not for secrets)</label><textarea name="notes" maxlength="2000"></textarea>
<div class="row"><button class="primary">Add login</button></div></form></div></details></div>
${secretsTable(list, false, a.csrf, approvedFor, configs) || `<div class="card"><p><strong>${empty}</strong></p><p class="muted">Use Add a secret above, run <code>npm run import-env</code> on your PC for a project's .env file.</p></div>`}`,
    );
  });

  app.post('/vault/add', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const tier = String(a.form.get('tier') ?? '');
    const name = String(a.form.get('name') ?? '').trim();
    try {
      const existing = await vault(c.env).getMeta(tier, name);
      if (existing && !existing.deletedAt) throw new Error(`${tier}/${name} already exists. Open it and use Replace, so the old value is kept in history.`);
      await vault(c.env).putSecret(tier, name, String(a.form.get('value') ?? ''), a.s.login, undefined, undefined, a.form.get('kind') === 'config' ? 'config' : undefined);
    } catch (err) {
      return fail(a.s, '/vault', err, '/vault', a.st);
    }
    return seeOther(done(`/vault?v=${encodeURIComponent(tier)}`, 'added'));
  });

  app.post('/vault/add-login', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const tier = String(a.form.get('tier') ?? '');
    const name = String(a.form.get('name') ?? '').trim();
    const login: LoginFields = { username: String(a.form.get('username') ?? ''), url: String(a.form.get('url') ?? ''), notes: String(a.form.get('notes') ?? '') };
    try {
      const existing = await vault(c.env).getMeta(tier, name);
      if (existing && !existing.deletedAt) throw new Error(`${tier}/${name} already exists. Open it and use Replace, so the old value is kept in history.`);
      await vault(c.env).putSecret(tier, name, String(a.form.get('password') ?? ''), a.s.login, undefined, login);
    } catch (err) {
      return fail(a.s, '/vault', err, '/vault', a.st);
    }
    return seeOther(done(`/vault?v=${encodeURIComponent(tier)}`, 'added'));
  });

  app.get('/vault/trash', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const list = await vault(c.env).listSecrets(true);
    return page('Trash', `${nav('/vault', a.s.login, a.st)}<h1>Trash</h1><p class="muted">Deleted secrets are kept for 30 days, then removed for good. Claude and machines cannot use them.</p>${secretsTable(list, true, a.csrf) || '<div class="card"><p class="muted">Trash is empty.</p></div>'}`);
  });

  /** Replace form, shared by logins (inside the Login card) and plain secrets (the Value card). */
  function replaceForm(meta: SecretMeta, base: string, csrf: string): string {
    if (meta.deletedAt) return '';
    return `<details class="add quiet edit"><summary>${meta.kind === 'login' ? 'Replace password' : 'Replace value'}</summary><form method="post" action="${base}/replace">${hidden(csrf)}<label class="f">New value (the current one stays in history)</label>${VALUE_FIELD}
<div class="row"><button class="primary">Save new value</button></div></form></details>`;
  }

  function loginSection(meta: SecretMeta, base: string, csrf: string, revealed?: string): string {
    const l = meta.login!;
    const reveal = meta.deletedAt
      ? ''
      : revealed === undefined
        ? `<form method="post" action="${base}/reveal">${hidden(csrf)}<div class="row"><button>Reveal password</button><span class="muted">Shown once, on this page only, and recorded in the audit trail.</span></div></form>`
        : `<span class="revealed-label">Password</span><pre class="reveal" aria-label="Revealed password">${esc(revealed)}</pre>
<div class="row"><span class="state">Revealed just now</span><a href="${base}">Hide password</a></div>`;
    return `<h2>Login</h2><div class="card"><dl><dt>Username</dt><dd><code>${esc(l.username)}</code></dd>
${l.url ? `<dt>URL</dt><dd><a href="${esc(l.url)}" rel="noreferrer">${esc(l.url)}</a></dd>` : ''}
${l.notes ? `<dt>Notes</dt><dd>${esc(l.notes)}</dd>` : ''}</dl>
${reveal}
${meta.deletedAt ? '' : `<hr><details class="add quiet edit"><summary>Edit login details</summary><form method="post" action="${base}/login">${hidden(csrf)}
<label class="f">Username</label><input type="text" name="username" required maxlength="256" value="${esc(l.username)}" autocomplete="off" autocapitalize="off" spellcheck="false">
<label class="f">Login URL (optional)</label><input type="url" name="url" maxlength="2048" value="${esc(l.url ?? '')}">
<label class="f">Notes (shown to agents, not for secrets)</label><textarea name="notes" maxlength="2000">${esc(l.notes ?? '')}</textarea>
<div class="row"><button class="primary">Save login details</button></div></form></details>
${replaceForm(meta, base, csrf)}`}</div>`;
  }

  async function secretPage(env: Env, a: { s: Session; csrf: string; st: NavStatus }, tier: string, name: string, revealed?: string): Promise<Response> {
    const v = vault(env);
    let meta: SecretMeta | null;
    try {
      meta = await v.getMeta(tier, name);
    } catch (err) {
      return fail(a.s, '/vault', err, '/vault', a.st);
    }
    if (!meta) return page('Not found', `${nav('/vault', a.s.login, a.st)}<h1>Not found</h1>`, 404);
    const base = `/vault/s/${encodeURIComponent(meta.tier)}/${encodeURIComponent(meta.name)}`;
    const handle = `secret://${meta.tier}/${meta.name}`;
    const isLogin = meta.kind === 'login' && Boolean(meta.login);
    const isConfig = meta.kind === 'config';
    // Config text only through configValues, which applies the configSince rule.
    const cfgValue = isConfig && !meta.deletedAt ? (await v.configValues()).get(`${meta.tier}/${meta.name}`) : undefined;
    const vaults = await v.listVaults();
    const grants = (await v.listGrants()).filter((g) => g.rules.some((r) => r.state === 'live' && [r.tier].flat().includes(meta!.tier) && r.secrets.includes(meta!.name)));
    const versions = [...meta.versions]
      .reverse()
      .map(
        (ver) => `<tr><td>v${ver.v}${ver.v === meta!.current ? ' <span class="tag ok">current</span>' : ''}</td><td>${when(ver.createdAt)}</td><td>${esc(ver.by)}</td><td>${esc(ver.note ?? '')}</td>
<td>${ver.v === meta!.current || meta!.deletedAt || (isConfig && ver.v < (meta!.configSince ?? meta!.current)) ? '' : `<form class="inline" method="post" action="${base}/restore">${hidden(a.csrf)}<input type="hidden" name="v" value="${ver.v}"><button>Make current</button></form>`}</td></tr>`,
      )
      .join('');
    const first = isLogin
      ? loginSection(meta, base, a.csrf, revealed)
      : meta.deletedAt
        ? ''
        : isConfig
          ? `<h2>Value</h2><div class="card"><pre class="reveal" aria-label="Config value">${esc(cfgValue ?? '')}</pre><p class="muted">Config: shown in the dashboard, never shown to agents as text. Agents can still send it under an approval.</p>
<details class="add quiet edit"><summary>Edit value</summary><form method="post" action="${base}/edit">${hidden(a.csrf)}<label class="f">New value (the current one stays in history)</label><textarea name="value" required autocomplete="off" autocapitalize="off" spellcheck="false">${esc(cfgValue ?? '')}</textarea>
<div class="row"><button class="primary">Save new value</button></div></form></details></div>`
          : `<h2>Value</h2><div class="card"><p class="muted">Write-only: the value is never shown after saving, here or to an agent.</p>${replaceForm(meta, base, a.csrf)}</div>`;
    const access = `<h2>Access</h2>${isLogin ? '<p class="muted">Agents approved to reveal this login can see the password too.</p>' : ''}${grants.length ? `<div class="list">${grants.map((g) => `<div class="srow"><div class="sname"><code>${esc(g.repo)}</code></div><div class="sact"><a href="/approvals">Review</a></div></div>`).join('')}</div>` : '<p class="muted">No repo can use it yet. Claude asks for access when a task needs it.</p>'}`;
    const danger = meta.deletedAt
      ? ''
      : `<h2>Danger zone</h2><div class="card"><form method="post" action="${base}/move">${hidden(a.csrf)}
<label class="f">Move to another vault</label>${vaultSelect(vaults.filter((x) => x.slug !== meta!.tier), undefined, 'to', 'Choose a vault')}
<p class="muted">Keeps its full history. Its handle becomes <code>secret://&lt;new vault&gt;/${esc(meta.name)}</code>, so approvals for the old handle stop applying${grants.length ? ` (currently approved for ${grants.map((g) => esc(g.repo)).join(', ')})` : ''}.</p>
<div class="row"><button>Move</button></div></form><hr>
${isLogin || isConfig ? '' : confirmAction({ label: 'Convert to config', action: `${base}/convert`, fields: { csrf: a.csrf }, consequence: 'Its current value will be shown on this page and in the Secrets list. Older versions stay hidden. This cannot be undone: config never becomes a secret again.', quiet: true }) + '<hr>'}
<form method="post" action="${base}/delete">${hidden(a.csrf)}<div class="row"><button class="danger">Move to trash</button><span class="muted">Recoverable from Trash for 30 days.</span></div></form></div>`;
    return page(
      meta.name,
      `${nav('/vault', a.s.login, a.st)}<a class="back" href="/vault?v=${encodeURIComponent(meta.tier)}">← Secrets</a><h1><code>${esc(meta.name)}</code>${vaultTag({ slug: meta.tier, kind: meta.tier === 'production' ? 'production' : 'project', strict: false })}</h1>
<p class="muted">Handle <code>${esc(handle)}</code>${meta.deletedAt ? ' · <strong class="prod">in trash</strong>' : ''} · <a href="/audit?q=${encodeURIComponent(handle)}">Audit trail</a></p>
${first}
${access}
<h2>History</h2><table><tr><th>Version</th><th>Saved</th><th>By</th><th>Note</th><th></th></tr>${versions}</table>
${danger}`,
    );
  }

  app.get('/vault/s/:tier/:name', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const { tier, name } = c.req.param();
    return secretPage(c.env, a, tier, name);
  });

  const secretAction = (path: string, fn: (v: VaultApi, tier: string, name: string, form: FormData, by: string) => Promise<unknown>, after: (tier: string, name: string) => string, flash: Parameters<typeof done>[1]) =>
    app.post(`/vault/s/:tier/:name/${path}`, async (c) => {
      const a = await post(c.req.raw, c.env);
      if (a instanceof Response) return a;
      const { tier, name } = c.req.param();
      try {
        await fn(vault(c.env), tier, name, a.form, a.s.login);
      } catch (err) {
        return fail(a.s, '/vault', err, `/vault/s/${encodeURIComponent(tier)}/${encodeURIComponent(name)}`, a.st);
      }
      return seeOther(done(after(tier, name), flash));
    });
  const detail = (t: string, n: string) => `/vault/s/${encodeURIComponent(t)}/${encodeURIComponent(n)}`;

  secretAction('login', (v, t, n, f, by) => v.updateLogin(t, n, { username: String(f.get('username') ?? ''), url: String(f.get('url') ?? ''), notes: String(f.get('notes') ?? '') }, by), detail, 'login_saved');
  secretAction('edit', (v, t, n, f, by) => v.putSecret(t, n, String(f.get('value') ?? ''), by), detail, 'config_saved');
  secretAction('convert', (v, t, n, _f, by) => v.convertToConfig(t, n, by), detail, 'converted');
  secretAction('replace', (v, t, n, f, by) => v.putSecret(t, n, String(f.get('value') ?? ''), by), detail, 'replaced');
  secretAction('restore', (v, t, n, f, by) => v.restoreVersion(t, n, Number(f.get('v')), by), detail, 'restored');
  secretAction('delete', (v, t, n, _f, by) => v.deleteSecret(t, n, by), () => '/vault', 'trashed');
  secretAction('undelete', (v, t, n, _f, by) => v.undeleteSecret(t, n, by), () => '/vault/trash', 'undeleted');
  secretAction('purge', (v, t, n, _f, by) => v.purge(t, n, by), () => '/vault/trash', 'purged');

  app.post('/vault/s/:tier/:name/reveal', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const { tier, name } = c.req.param();
    const v = vault(c.env);
    try {
      const meta = await v.getMeta(tier, name);
      if (!meta || meta.deletedAt || meta.kind !== 'login') throw new Error('only logins can be revealed');
      const value = await v.readSecret(tier, name);
      if (value === null) throw new Error('only logins can be revealed');
      await v.log({ event: 'admin_reveal', by: a.s.login, handle: `secret://${tier}/${name}` });
      const csrf = await csrfToken(c.env.COOKIE_ENCRYPTION_KEY, a.s, 'admin');
      return await secretPage(c.env, { s: a.s, csrf, st: { ...a.st, flash: 'Password revealed. This reveal is recorded in the audit trail.' } }, tier, name, value);
    } catch (err) {
      return fail(a.s, '/vault', err, detail(tier, name), a.st);
    }
  });

  app.post('/vault/s/:tier/:name/move', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const { tier, name } = c.req.param();
    try {
      const to = String(a.form.get('to') ?? '');
      if (!to) throw new Error('Choose the vault to move it to.');
      const moved = await vault(c.env).moveSecret(tier, name, to, a.s.login);
      return seeOther(done(detail(moved.tier, moved.name), 'moved'));
    } catch (err) {
      return fail(a.s, '/vault', err, detail(tier, name), a.st);
    }
  });

  // ---------- vaults ----------

  app.get('/vaults', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const v = vault(c.env);
    const [vaults, secrets, requests] = await Promise.all([v.listVaults(), v.listSecrets(false), v.listVaultRequests()]);
    const rows = vaults
      .map((x) => {
        const n = secrets.filter((m) => m.tier === x.slug).length;
        return `<div class="srow"><div class="sname"><strong>${esc(x.name)}</strong> ${vaultTag(x)}${x.strict ? '<span class="tag warn">strict</span>' : ''}</div>
<div class="smeta">${n} secret(s) · ${x.repos.length ? `linked to ${x.repos.map((r) => `<code>${esc(r)}</code>`).join(' ')}` : 'any repo'}</div>
<div class="sact"><a href="/vault?v=${encodeURIComponent(x.slug)}" aria-label="Secrets in ${esc(x.name)}">Secrets</a> <a href="/vaults/${encodeURIComponent(x.slug)}" aria-label="Edit ${esc(x.name)}">Edit</a></div></div>`;
      })
      .join('');
    const pend = requests
      .map((r) => `<a class="card cardlink" href="/approve-vault/${esc(r.id)}"><div class="what"><strong>New vault <code>${esc(r.slug)}</code></strong> for <code>${esc(r.repo)}</code><div class="muted">${esc(r.reason)}</div></div><span class="go">Review</span></a>`)
      .join('');
    return page(
      'Vaults',
      `${nav('/vaults', a.s.login, a.st)}<h1>Vaults</h1>
<p class="muted">Personal and Production are built in. Add one vault per client project so its credentials stay out of .env files and can only be approved for that project's repos.</p>
${pend ? `<h2>Requested by Claude</h2>${pend}` : ''}
<div class="list">${rows}</div>
<h2>New project vault</h2><div class="card"><form method="post" action="/vaults/create">${hidden(a.csrf)}
<label class="f">Display name</label><input type="text" name="name" required placeholder="Acme Corp - billing dashboard">
<label class="f">Vault id (used in handles: secret://<em>id</em>/NAME)</label><input type="text" name="slug" required pattern="[a-z0-9][a-z0-9\-]{1,39}" title="2 to 40 characters: lowercase letters, numbers and dashes" placeholder="acme-finance" autocomplete="off" autocapitalize="off" spellcheck="false">
<label class="f">Linked repos (owner/name, one per line). Its secrets can only be approved for these. Leave empty for any repo.</label><textarea name="repos" placeholder="acme/acme-finance-dash"></textarea>
<label class="check"><input type="checkbox" name="strict" value="1" checked> Strict: approvals must name HTTP methods (recommended for client credentials)</label>
<div class="row"><button class="primary">Create vault</button></div></form></div>`,
    );
  });

  app.post('/vaults/create', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      const info = await vault(c.env).createVault({
        slug: String(a.form.get('slug') ?? ''),
        name: String(a.form.get('name') ?? ''),
        strict: a.form.get('strict') === '1',
        repos: splitRepos(a.form.get('repos')),
        by: a.s.login,
      });
      return seeOther(done(`/vault?v=${encodeURIComponent(info.slug)}`, 'vault_created'));
    } catch (err) {
      return fail(a.s, '/vaults', err, '/vaults', a.st);
    }
  });

  app.get('/vaults/:slug', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const v = vault(c.env);
    const x = await v.getVault(c.req.param('slug'));
    if (!x) return page('Not found', `${nav('/vaults', a.s.login, a.st)}<h1>No such vault</h1>`, 404);
    const base = `/vaults/${encodeURIComponent(x.slug)}`;
    return page(
      x.name,
      `${nav('/vaults', a.s.login, a.st)}<a class="back" href="/vaults">← Vaults</a><h1>${esc(x.name)}</h1>
<p class="muted">Handles look like <code>secret://${esc(x.slug)}/NAME</code>${x.note ? ` · ${esc(x.note)}` : ''}</p>
<div class="card"><form method="post" action="${base}/update">${hidden(a.csrf)}
<label class="f">Display name</label><input type="text" name="name" value="${esc(x.name)}">
<label class="f">Linked repos (one per line; empty = any repo)</label><textarea name="repos">${esc(x.repos.join('\n'))}</textarea>
${x.kind === 'project' ? `<label class="check"><input type="checkbox" name="strict" value="1"${x.strict ? ' checked' : ''}> Strict: approvals must name HTTP methods</label>` : `<p class="muted">${x.strict ? 'Strict' : 'Not strict'} (built in).</p>`}
<div class="row"><button class="primary">Save</button></div></form></div>
<p class="muted">Unlinking a repo stops its access straight away, even where secrets were already approved for it.</p>
${x.kind === 'project' ? `<h2>Delete vault</h2><form method="post" action="${base}/delete">${hidden(a.csrf)}<button class="danger">Delete (only when empty)</button></form>` : ''}`,
    );
  });

  app.post('/vaults/:slug/update', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const slug = c.req.param('slug');
    try {
      const current = await vault(c.env).getVault(slug);
      await vault(c.env).updateVault(
        slug,
        {
          name: String(a.form.get('name') ?? ''),
          repos: splitRepos(a.form.get('repos')),
          ...(current?.kind === 'project' ? { strict: a.form.get('strict') === '1' } : {}),
        },
        a.s.login,
      );
    } catch (err) {
      return fail(a.s, '/vaults', err, `/vaults/${encodeURIComponent(slug)}`, a.st);
    }
    return seeOther(done('/vaults', 'vault_saved'));
  });

  app.post('/vaults/:slug/delete', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      await vault(c.env).deleteVault(c.req.param('slug'), a.s.login);
    } catch (err) {
      return fail(a.s, '/vaults', err, `/vaults/${encodeURIComponent(c.req.param('slug'))}`);
    }
    return seeOther(done('/vaults', 'vault_deleted'));
  });

  app.get('/approve-vault/:id', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const r: VaultRequest | null = await vault(c.env).getVaultRequest(c.req.param('id'));
    if (!r) return page('Not found', `${nav('/approvals', a.s.login, a.st)}<h1>Request not found</h1><p>It was already handled or has expired.</p>`, 404);
    return page(
      'New vault',
      `${nav('/approvals', a.s.login, a.st)}<h1>Create a project vault?</h1>
<p class="muted">Requested by ${esc(r.requestedBy)} · ${when(r.createdAt)}</p>
<div class="card"><dl><dt>For repo</dt><dd><code>${esc(r.repo)}</code></dd><dt>Reason</dt><dd>${esc(r.reason)}</dd></dl></div>
<p class="muted">The reason is written by the agent. Creating the vault grants nothing: it starts empty, and each secret in it still needs your approval.</p>
<form method="post">${hidden(a.csrf)}
<label class="f">Display name</label><input type="text" name="name" value="${esc(r.name)}">
<label class="f">Vault id</label><input type="text" name="slug" value="${esc(r.slug)}" pattern="[a-z0-9][a-z0-9\-]{1,39}" title="2 to 40 characters: lowercase letters, numbers and dashes">
<label class="check"><input type="checkbox" name="strict" value="1" checked> Strict: approvals must name HTTP methods</label>
<p class="muted">It will be linked to <code>${esc(r.repo)}</code> only; you can add more repos later.</p>
<div class="row"><button class="primary" name="action" value="approve">Create vault</button><button class="danger" name="action" value="deny">Deny</button></div></form>`,
    );
  });

  app.post('/approve-vault/:id', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const id = c.req.param('id');
    try {
      if (a.form.get('action') === 'deny') {
        await vault(c.env).denyVaultRequest(id, a.s.login);
        return seeOther(done('/approvals', 'vault_denied'));
      }
      const info = await vault(c.env).approveVaultRequest(id, a.s.login, {
        strict: a.form.get('strict') === '1',
        slug: String(a.form.get('slug') ?? '').trim() || undefined,
        name: String(a.form.get('name') ?? '').trim() || undefined,
      });
      return page(
        'Vault created',
        `${nav('/vaults', a.s.login, a.st)}<h1 class="ok">Vault ${esc(info.slug)} created</h1>
<p>Next, add its secrets: type them in on the <a href="/vault?v=${encodeURIComponent(info.slug)}">Secrets page</a>, or import the project's existing .env from your PC:</p>
<pre class="card">npm run import-env -- ${esc(info.slug)} C:\\path\\to\\project\\.env</pre>
<p class="muted">Then tell Claude to go ahead; it will request access to the secrets it needs.</p>`,
      );
    } catch (err) {
      return fail(a.s, '/approvals', err, `/approve-vault/${encodeURIComponent(id)}`, a.st);
    }
  });

  // ---------- machines ----------

  app.get('/machines', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const [list, vaults]: [PublicMachine[], VaultInfo[]] = await Promise.all([vault(c.env).listMachines(), vault(c.env).listVaults()]);
    const rows = list
      .map(
        (m) => `<tr><td>${esc(m.name)}</td><td>${m.tiers.length ? m.tiers.map((t) => (t === 'production' ? '<span class="tag prod">production</span>' : esc(t))).join(', ') : '—'}${m.canImport ? ' <span class="tag warn">import</span>' : ''}</td><td>${when(m.createdAt)}</td><td>${when(m.lastUsedAt)}</td>
<td>${confirmAction({ label: 'Revoke', action: `/machines/${encodeURIComponent(m.id)}/revoke`, fields: { csrf: a.csrf }, consequence: `<strong>${esc(m.name)}</strong> stops working immediately: its broker can no longer read ${esc(m.tiers.join(', ') || 'any vault')}. You would need to create and store a new token.`, aria: `Revoke ${m.name}` })}</td></tr>`,
      )
      .join('');
    return page(
      'Machines',
      `${nav('/machines', a.s.login, a.st)}<h1>Machines</h1>
<p class="muted">Tokens for your local broker (Claude Code) and the import and restore scripts. A machine can read every value in the vaults you tick; your local broker's policy decides which commands may use them.</p>
${list.length ? `<table><tr><th>Name</th><th>Vaults</th><th>Created</th><th>Last used</th><th></th></tr>${rows}</table>` : '<div class="card"><p class="muted">No machine tokens yet. Create one below for Claude Code on your PC, or for the import scripts.</p></div>'}
<h2>Add a machine</h2><div class="card"><form method="post" action="/machines/create">${hidden(a.csrf)}
<label class="f">Name</label><input type="text" name="name" required placeholder="Alice desktop - personal">
<fieldset class="group"><legend class="f">Vaults it can read</legend>${vaults.map((t) => (t.kind === 'production' ? `<label class="check risk"><input type="checkbox" name="tier" value="${esc(t.slug)}"> <span>${esc(t.name)} <code>${esc(t.slug)}</code><span class="tag prod">production</span><br><span class="prod">This machine could read every production value. No host or repo limits apply.</span></span></label>` : `<label class="check"><input type="checkbox" name="tier" value="${esc(t.slug)}"> ${esc(t.name)} <code>${esc(t.slug)}</code></label>`)).join('')}</fieldset>
<label class="check"><input type="checkbox" name="canImport" value="1"> Can import secrets (for import-env and restore; tick no vaults for an import-only token)</label>
<div class="row"><button class="primary">Create token</button></div></form></div>`,
    );
  });

  app.post('/machines/create', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      const origin = new URL(c.req.url).origin;
      const { token, machine } = await vault(c.env).createMachine({
        name: String(a.form.get('name') ?? ''),
        tiers: a.form.getAll('tier').map(String),
        canImport: a.form.get('canImport') === '1',
        by: a.s.login,
        origin,
      });
      return page(
        'Token created',
        `${nav('/machines', a.s.login, a.st)}<h1>Token for ${esc(machine.name)}</h1>
<p><strong>Copy it now. It is not stored and cannot be shown again.</strong></p><div class="tok">${esc(token)}</div>
<h2>Use it with your local broker</h2><p>In <code>secret-broker</code> (the repo root), for each vault this token covers (${esc(machine.tiers.join(', ') || 'none')}):</p>
<pre class="card">npm run store-token ${esc(machine.tiers[0] ?? 'personal')}</pre><p class="muted">and paste the token when asked. The same token can be stored for several vaults.</p>
<p><a href="/machines">Done</a></p>`,
      );
    } catch (err) {
      return fail(a.s, '/machines', err, '/machines', a.st);
    }
  });

  app.post('/machines/:id/revoke', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      await vault(c.env).revokeMachine(c.req.param('id'), a.s.login);
    } catch (err) {
      return fail(a.s, '/machines', err, '/machines', a.st);
    }
    return seeOther(done('/machines', 'machine_revoked'));
  });

  // ---------- connectors ----------

  app.get('/connectors', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const api = oauth(c.env);
    const cursor = c.req.query('cursor') || undefined;
    const [reg, clients] = await Promise.all([vault(c.env).registrationStatus(), api.listClients({ limit: 25, cursor })]);
    // Newest sign-in per app, across every allowed account.
    const signIn = new Map<string, { login: string; at: number }>();
    for (const id of allowedIds(c.env)) {
      for (const g of (await api.listUserGrants(id, { limit: 100 })).items) {
        const prev = signIn.get(g.clientId);
        if (!prev || g.createdAt * 1000 > prev.at) signIn.set(g.clientId, { login: String(g.metadata?.label ?? id), at: g.createdAt * 1000 });
      }
    }
    const rows = clients.items.map((cl) => {
      const hosts = [...new Set(cl.redirectUris.map((u) => (URL.canParse(u) ? new URL(u).hostname : u)))];
      const name = cl.clientName || 'Unnamed app';
      const last = signIn.get(cl.clientId);
      return `<tr><td>${esc(name)}</td><td>${hosts.map((h) => `<code>${esc(h)}</code>`).join(' ')}</td><td>${cl.registrationDate ? when(cl.registrationDate * 1000) : 'Unknown'}</td><td>${last ? `${esc(last.login)}, ${when(last.at)}` : '<span class="muted">No active sign-in</span>'}</td>
<td>${confirmAction({ label: 'Remove', action: `/connectors/${encodeURIComponent(cl.clientId)}/remove`, fields: { csrf: a.csrf }, consequence: `<strong>${esc(name)}</strong> is disconnected and its tokens are revoked. Allow up to a minute for that to reach every location. To use it again it must register and sign in again.`, aria: `Remove ${name}` })}</td></tr>`;
    });
    const origin = c.env.PUBLIC_URL || new URL(c.req.url).origin;
    const next = clients.cursor ? `<p><a href="/connectors?cursor=${encodeURIComponent(clients.cursor)}">Next page</a></p>` : '';
    return page(
      'Connectors',
      `${nav('/connectors', a.s.login, a.st)}<h1>Connectors</h1>
<p class="muted">Apps that reach this vault through the MCP connector, such as Claude. Each can list secret names and use the access you have approved. Remove any you do not recognise.</p>
<h2>New connections</h2><div class="card">${reg.left > 0
  ? `<p>Open until ${when(reg.until)}, ${reg.left} registration${reg.left === 1 ? '' : 's'} left. Any app that knows this address can register until then; it still cannot sign in without your GitHub account.</p>
<form method="post" action="/connectors/close">${hidden(a.csrf)}<button>Close now</button></form>`
  : `<p>Closed. No new app can register.</p>
<form method="post" action="/connectors/open">${hidden(a.csrf)}<button class="primary">Allow a new connection for 15 minutes</button></form>
<p class="muted">Open this just before you add the connector in Claude or another app. It closes by itself.</p>`}</div>
<h2>Connected apps</h2>${rows.length
  ? `<table><tr><th>App</th><th>Redirects to</th><th>Registered</th><th>Signed in</th><th></th></tr>${rows.join('')}</table>${next}`
  : `<div class="card"><p>No app has connected yet. Allow a new connection above, then add the connector in your app with this address:</p><p><code>${esc(origin)}/mcp</code></p></div>`}`,
    );
  });

  app.post('/connectors/open', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    await vault(c.env).openRegistration(a.s.login);
    return seeOther(done('/connectors', 'registration_opened'));
  });

  app.post('/connectors/close', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    await vault(c.env).closeRegistration(a.s.login);
    return seeOther(done('/connectors', 'registration_closed'));
  });

  app.post('/connectors/:clientId/remove', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      const clientId = c.req.param('clientId');
      const client = await oauth(c.env).lookupClient(clientId);
      await oauth(c.env).deleteClient(clientId);
      await vault(c.env).log({ event: 'connector_removed', by: a.s.login, clientId, clientName: (client?.clientName ?? '').slice(0, 100) });
    } catch (err) {
      return fail(a.s, '/connectors', err, '/connectors', a.st);
    }
    return seeOther(done('/connectors', 'connector_removed'));
  });

  // ---------- audit ----------

  app.get('/audit', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const entries: AuditEntry[] = await vault(c.env).listAudit(300);
    const view = c.req.query('view') === 'denied' ? 'denied' : 'all';
    const q = (c.req.query('q') ?? '').trim().slice(0, 200);
    const fields = (e: AuditEntry) => {
      const { at: _a, event: _e, by: _b, ...rest } = e;
      return Object.entries(rest)
        .filter(([, v]) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && v.length === 0))
        .map(([k, v]) => [k === 'tier' ? 'vault' : k === 'tiers' ? 'vaults' : k, v] as [string, unknown]);
    };
    const text = (v: unknown) => (Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v));
    const isDenied = (e: AuditEntry) => /denied/.test(e.event) || (e as { outcome?: string }).outcome === 'denied';
    const shown = entries.filter((e) => (view === 'denied' ? isDenied(e) : true) && (!q || `${e.event} ${e.by} ${fields(e).map(([k, v]) => `${k} ${text(v)}`).join(' ')}`.toLowerCase().includes(q.toLowerCase())));
    const detail = (e: AuditEntry) => fields(e).map(([k, v]) => `<span class="muted">${esc(k)}</span> ${esc(text(v))}`).join(' · ');
    const rows = shown.map((e) => `<tr${isDenied(e) ? ' class="denied"' : ''}><td>${when(e.at)}</td><td><code>${esc(e.event)}</code>${e.event === 'secret_reveal' || e.event === 'admin_reveal' ? ' <span class="tag warn">reveal</span>' : ''}</td><td>${esc(e.by)}</td><td>${detail(e)}</td></tr>`).join('');
    const denied = entries.filter(isDenied).length;
    const qs = (v: string) => `/audit?${new URLSearchParams({ ...(v === 'denied' ? { view: v } : {}), ...(q ? { q } : {}) })}`;
    return page('Audit', `${nav('/audit', a.s.login, a.st)}<h1>Audit</h1><p class="muted">Last 300 events, kept 180 days. Never contains values.</p>
<div class="tabs"><a href="${qs('all')}"${view === 'all' ? ' class="on" aria-current="true"' : ''}>All (${entries.length})</a><a href="${qs('denied')}"${view === 'denied' ? ' class="on" aria-current="true"' : ''}>Denied (${denied})</a></div>
<form class="filters" method="get" action="/audit" role="search">${view === 'denied' ? '<input type="hidden" name="view" value="denied">' : ''}<label class="sr" for="aq">Filter events</label><input type="search" id="aq" name="q" value="${esc(q)}" placeholder="Filter by repo, secret, machine or event"><button>Filter</button>${q ? `<a href="${view === 'denied' ? '/audit?view=denied' : '/audit'}">Clear</a>` : ''}</form>
${shown.length ? `<table class="audit"><tr><th>When</th><th>Event</th><th>By</th><th>Details</th></tr>${rows}</table>` : `<div class="card"><p class="muted">${entries.length ? 'No events match.' : 'Nothing recorded yet.'}</p></div>`}`);
  });

  // ---------- backups ----------

  app.get('/backups', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const listed = await c.env.BACKUPS.list({ prefix: 'backups/' });
    const objs = listed.objects.sort((x, y) => y.key.localeCompare(x.key));
    const newest = objs[0]?.uploaded.getTime();
    const ageH = newest ? (Date.now() - newest) / 3600_000 : Infinity;
    const health = !newest
      ? '<div class="banner frozen" role="status">No backup exists yet. Make one now.</div>'
      : ageH > 36
        ? `<div class="banner frozen" role="status">The newest backup is from ${when(newest)}, more than a day old. Check the nightly job, then back up now.</div>`
        : `<p class="ok"><strong>Last backup ${when(newest)}.</strong> <span class="muted">${objs.length} stored.</span></p>`;
    const rows = objs
      .map((o) => `<tr><td><code>${esc(o.key.replace('backups/', ''))}</code></td><td>${(o.size / 1024).toFixed(1)} KB</td><td><a href="/backups/download?key=${encodeURIComponent(o.key)}" aria-label="Download ${esc(o.key.replace('backups/', ''))}">Download</a></td></tr>`)
      .join('');
    return page(
      'Backups',
      `${nav('/backups', a.s.login, a.st)}<h1>Backups</h1>
<p class="muted">Made automatically every night and kept 30 days. Each is encrypted to your backup public key: only the private key in your recovery kit can open it, and this server cannot.</p>
${health}
<form method="post" action="/backups/run">${hidden(a.csrf)}<div class="row"><button class="primary">Back up now</button></div></form>
<h2>Stored</h2>${objs.length ? `<table><tr><th>File</th><th>Size</th><th></th></tr>${rows}</table>` : '<p class="muted">None yet.</p>'}
<h2>Restoring</h2><p class="muted">On your PC: <code>npm run restore -- backup-file.json</code> in <code>remote/</code> of the secret-broker repo. It asks for your recovery kit and either writes the secrets back into the vault (with a machine token that can import) or saves a decrypted copy.</p>`,
    );
  });

  app.post('/backups/run', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      await runBackup(c.env, a.s.login, vault(c.env));
    } catch (err) {
      return fail(a.s, '/backups', err, '/backups', a.st);
    }
    return seeOther(done('/backups', 'backup'));
  });

  app.get('/backups/download', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const key = c.req.query('key') ?? '';
    if (!/^backups\/[\w.:-]+\.json$/.test(key)) return page('Bad request', '<h1>Bad request</h1>', 400);
    const obj = await c.env.BACKUPS.get(key);
    if (!obj) return page('Not found', '<h1>Not found</h1>', 404);
    await vault(c.env).log({ event: 'backup_downloaded', by: a.s.login, key });
    return new Response(obj.body, {
      headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="secret-broker-${key.replace('backups/', '').replace(/:/g, '-')}"`, ...SECURITY_HEADERS },
    });
  });

  // ---------- settings ----------

  app.get('/settings', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const v = vault(c.env);
    const [frozen, usage, current] = await Promise.all([v.isFrozen(), v.keyUsage(), v.currentKeyId()]);
    const stale = Object.entries(usage).filter(([k]) => k !== current);
    return page(
      'Settings',
      `${nav('/settings', a.s.login, a.st)}<h1>Settings</h1>
<h2>Emergency freeze</h2><div class="card"><p>${frozen ? 'The vault is <strong>frozen</strong>.' : 'Stops every use of every secret by Claude and all machines, immediately. Editing still works.'}</p>
${frozen
  ? confirmAction({ label: 'Unfreeze', action: '/settings/freeze', fields: { csrf: a.csrf, frozen: '0' }, consequence: 'Every approved repo and machine can use its secrets again, straight away. Only unfreeze once the problem is dealt with.', confirm: 'Yes, unfreeze' })
  : `<form method="post" action="/settings/freeze">${hidden(a.csrf)}<input type="hidden" name="frozen" value="1"><button class="solid-danger">Freeze vault now</button></form>`}</div>

<h2>Master key</h2><div class="card"><p>Current key id <code>${esc(current ?? 'not set')}</code>.
${stale.length ? `<strong class="warn">${stale.reduce((n, [, c]) => n + c, 0)} stored value(s) still use an older key.</strong>` : 'Everything uses the current key.'}</p>
${stale.length ? `<form method="post" action="/settings/rotate">${hidden(a.csrf)}<button class="primary">Re-encrypt with current key</button></form>` : ''}
<p class="muted">To rotate: run <code>npm run setup-keys -- --rotate-master</code>, deploy, click Re-encrypt, then remove VAULT_MASTER_KEY_PREVIOUS.</p></div>
`,
    );
  });

  app.post('/settings/freeze', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const freeze = a.form.get('frozen') === '1';
    await vault(c.env).setFrozen(freeze, a.s.login);
    return seeOther(done('/settings', freeze ? 'frozen' : 'unfrozen'));
  });

  app.post('/settings/rotate', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      await vault(c.env).rotate(a.s.login);
    } catch (err) {
      return fail(a.s, '/settings', err, '/settings', a.st);
    }
    return seeOther(done('/settings', 'rotated'));
  });

  registerDeployRoutes(app, { vault, get, post, fail });
}

/** Shared by the button and the nightly cron: encrypted snapshot to R2, prune old ones (keep at least 7). */
export async function runBackup(env: Env, by: string, v: VaultApi = vaultFor(env)): Promise<string> {
  const { createdAt, body } = await v.createBackup(by);
  const key = `backups/${createdAt}.json`;
  await env.BACKUPS.put(key, body, { httpMetadata: { contentType: 'application/json' } });
  const listed = await env.BACKUPS.list({ prefix: 'backups/' });
  const sorted = listed.objects.sort((a, b) => b.key.localeCompare(a.key));
  const cutoff = Date.now() - 30 * 86400_000;
  for (const o of sorted.slice(7)) if (o.uploaded.getTime() < cutoff) await env.BACKUPS.delete(o.key);
  return key;
}
