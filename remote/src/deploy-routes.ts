/**
 * Deploy dashboard: connections, target links, signed review and push, history.
 *
 * Dashboard only: nothing here is reachable with a machine token, and no page shows a
 * connection token or a secret value. Config values appear only on the review page.
 */
import type { Hono } from 'hono';
import type { Plan, PlanRow } from './deploy';
import type { Env } from './env';
import { parseHandle } from './policy';
import {
  CONN_ID_RE, MAX_VAR, PUSH_ID_RE, TARGET_ID_RE, VAR_RE, VERCEL_ENVS, PAGE_SIZE, defaultVarName,
  type LinkItem, type Provider, type PublicConnection, type PushRecord, type SecretMeta, type VercelEnv,
} from './store';
import type { VaultApi } from './vault-do';
import { confirmAction, csrfToken, done, esc, hidden, nav, page, seeOther, stamp, type NavStatus, type Session } from './web';

export interface AdminKit {
  vault: (env: Env) => VaultApi;
  get: (req: Request, env: Env) => Promise<{ s: Session; csrf: string; st: NavStatus } | Response>;
  post: (req: Request, env: Env) => Promise<{ s: Session; form: FormData; st: NavStatus } | Response>;
  fail: (s: Session, active: string, err: unknown, back: string, st?: NavStatus) => Response;
}

const enc = encodeURIComponent;
const DEFAULT_ENVS: VercelEnv[] = ['production', 'preview'];

function tabs(on: 'targets' | 'history' | 'connections'): string {
  const t: Array<[string, string, string]> = [['/deploy', 'Targets', 'targets'], ['/deploy/history', 'History', 'history'], ['/deploy/connections', 'Connections', 'connections']];
  return `<div class="tabs">${t.map(([h, l, k]) => `<a href="${h}"${k === on ? ' class="on" aria-current="page"' : ''}>${l}</a>`).join('')}</div>`;
}

function pageNum(raw: string | undefined): number {
  const n = Number.parseInt(raw ?? '1', 10);
  return Number.isInteger(n) && n > 0 ? n : 1;
}

function pager(base: string, params: Record<string, string>, p: number, pages: number): string {
  if (pages <= 1) return '';
  const url = (n: number) => `${base}?${new URLSearchParams({ ...params, page: String(n) })}`;
  return `<p class="row">${p > 1 ? `<a href="${esc(url(p - 1))}">Previous</a>` : ''}<span class="muted">Page ${p} of ${pages}</span>${p < pages ? `<a href="${esc(url(p + 1))}">Next</a>` : ''}</p>`;
}

const providerLabel = (p: Provider) => (p === 'vercel' ? 'Vercel' : 'Cloudflare');
const providerTag = (p: Provider) => `<span class="tag">${providerLabel(p)}</span>`;
const targetUrl = (conn: string, target: string) => `/deploy/t/${enc(conn)}/${enc(target)}`;
const envText = (e?: readonly string[]) => (e && e.length ? e.join(', ') : '');
const envTags = (e?: readonly string[]) => (e ?? []).map((x) => `<span class="tag${x === 'production' ? ' prod' : ''}">${esc(x)}</span>`).join('');

function kindTag(kind?: string): string {
  return kind === 'config' || kind === 'login' ? `<span class="tag">${kind}</span>` : '';
}

function pushRecord(r: PushRecord, connName: string): string {
  const rows = r.rows
    .map((x) => `<div><code>${esc(x.handle)}</code> v${x.version} → <code>${esc(x.varName)}</code>${x.environments ? ` (${esc(envText(x.environments))})` : ''} <span class="tag ${x.action === 'failed' ? 'prod' : 'ok'}">${x.action}</span>${x.error ? ` <span class="muted">${esc(x.error)}</span>` : ''}</div>`)
    .join('');
  const re = r.redeploy
    ? `<div class="muted">Redeploy ${stamp(r.redeploy.at)}: ${r.redeploy.ok ? `started${r.redeploy.deploymentId ? ` (<code>${esc(r.redeploy.deploymentId)}</code>)` : ''}` : `failed${r.redeploy.error ? `, ${esc(r.redeploy.error)}` : ''}`}</div>`
    : '';
  return `<div class="srow push"><div class="sname">${stamp(r.at)} · ${esc(r.by)} · ${esc(connName)} / ${esc(r.targetName)}</div><div class="smeta">${rows || 'No rows.'}${re}</div></div>`;
}

export function registerDeployRoutes<B extends Env>(app: Hono<{ Bindings: B }>, kit: AdminKit): void {
  const { vault, get, post, fail } = kit;

  const notFound = (s: Session, st: NavStatus, what: string) =>
    page('Not found', `${nav('/deploy', s.login, st)}<h1>${esc(what)} not found</h1><p><a href="/deploy">Back to Deploy</a></p>`, 404);

  const ids = (conn: string, target: string) => CONN_ID_RE.test(conn) && TARGET_ID_RE.test(target);

  // ---------- targets ----------

  app.get('/deploy', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const v = vault(c.env);
    const [sums, conns] = await Promise.all([v.linkSummaries(), v.listConnections()]);
    const rows = sums.map(({ link, connection, changed, missing, lastPushAt }) => {
      const meta = [
        `${link.items.length} item${link.items.length === 1 ? '' : 's'}`,
        `${changed} changed since last push`,
        ...(missing ? [`${missing} missing in vault`] : []),
        lastPushAt ? `last push ${stamp(lastPushAt)}` : 'never pushed',
      ].join(' · ');
      return `<div class="srow"><div class="sname">${connection ? esc(connection.name) + providerTag(connection.provider) : 'removed connection'} ${esc(link.targetName)}</div><div class="smeta">${meta}</div><div class="sact">${connection ? `<a href="${esc(targetUrl(link.connectionId, link.targetId))}">Open link</a>` : ''}</div></div>`;
    });
    const linkForm = conns.length
      ? `<form method="get" action="/deploy/pick" class="card"><label class="f">Link a target</label><select name="conn">${conns.map((x) => `<option value="${esc(x.id)}">${esc(x.name)} (${providerLabel(x.provider)})</option>`).join('')}</select><div class="row"><button class="primary">Choose target</button></div></form>`
      : `<div class="card"><p><strong>No connections yet.</strong></p><p class="muted">Add a Vercel or Cloudflare token on the <a href="/deploy/connections">Connections</a> tab first.</p></div>`;
    return page('Deploy', `${nav('/deploy', a.s.login, a.st)}<h1>Deploy</h1>
<p class="muted">Push vault items to Vercel projects and Cloudflare Workers as environment variables. You review every change before it is sent.</p>${tabs('targets')}
${rows.length ? `<div class="list">${rows.join('')}</div>` : conns.length ? '<div class="card"><p class="muted">No linked targets yet.</p></div>' : ''}${linkForm}`);
  });

  app.get('/deploy/pick', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const connId = c.req.query('conn') ?? '';
    const conn = CONN_ID_RE.test(connId) ? await vault(c.env).getConnection(connId) : null;
    if (!conn) return notFound(a.s, a.st, 'Connection');
    let targets;
    try {
      targets = await vault(c.env).listTargets(conn.id);
    } catch (err) {
      return fail(a.s, '/deploy', err, '/deploy', a.st);
    }
    const q = (c.req.query('q') ?? '').trim().slice(0, 100);
    const list = targets
      .filter((t) => TARGET_ID_RE.test(t.id) && t.name.toLowerCase().includes(q.toLowerCase()))
      .sort((x, y) => x.name.localeCompare(y.name));
    const pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    const p = Math.min(pageNum(c.req.query('page')), pages);
    const rows = list.slice((p - 1) * PAGE_SIZE, p * PAGE_SIZE)
      .map((t) => `<div class="srow"><div class="sname">${esc(t.name)}</div><div class="smeta"><code>${esc(t.id)}</code></div><div class="sact"><a href="${esc(`${targetUrl(conn.id, t.id)}?name=${enc(t.name)}`)}">Choose</a></div></div>`)
      .join('');
    return page('Pick a target', `${nav('/deploy', a.s.login, a.st)}<h1>Pick a target</h1>
<p class="muted">${esc(conn.name)} (${providerLabel(conn.provider)}) · ${list.length} ${conn.provider === 'vercel' ? 'project' : 'Worker'}${list.length === 1 ? '' : 's'}${q ? ` matching "${esc(q)}"` : ''}</p>
<form class="filters" method="get" action="/deploy/pick" role="search"><input type="hidden" name="conn" value="${esc(conn.id)}"><label class="sr" for="pq">Filter by name</label><input type="search" id="pq" name="q" value="${esc(q)}" placeholder="Filter by name"><button>Filter</button>${q ? `<a href="/deploy/pick?conn=${enc(conn.id)}">Clear</a>` : ''}</form>
${rows ? `<div class="list">${rows}</div>` : '<div class="card"><p class="muted">Nothing matches.</p></div>'}${pager('/deploy/pick', { conn: conn.id, ...(q ? { q } : {}) }, p, pages)}
<p><a href="/deploy">Back to Targets</a></p>`);
  });

  // ---------- link editor ----------

  app.get('/deploy/t/:conn/:target', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const connId = c.req.param('conn');
    const targetId = c.req.param('target');
    if (!ids(connId, targetId)) return notFound(a.s, a.st, 'Target');
    const v = vault(c.env);
    const conn = await v.getConnection(connId);
    if (!conn) return notFound(a.s, a.st, 'Connection');
    const [link, secrets, recent] = await Promise.all([v.getLink(connId, targetId), v.listSecrets(false), v.listPushes(1, { connectionId: connId, targetId })]);
    const targetName = link?.targetName ?? (c.req.query('name') ?? '').trim().slice(0, 200);
    const shownName = targetName || targetId;
    const vercel = conn.provider === 'vercel';
    const linked = new Map((link?.items ?? []).map((i) => [i.handle, i]));
    const handleOf = (m: SecretMeta) => `secret://${m.tier}/${m.name}`;
    const present = new Set(secrets.map(handleOf));
    const byTier = new Map<string, SecretMeta[]>();
    for (const m of secrets) byTier.set(m.tier, [...(byTier.get(m.tier) ?? []), m]);
    const itemRow = (m: SecretMeta) => {
      const h = handleOf(m);
      const li = linked.get(h);
      const envs = li?.environments ?? DEFAULT_ENVS;
      const envBoxes = vercel
        ? `<div class="envs"><input type="hidden" name="envs:${esc(h)}" value="1">${VERCEL_ENVS.map((e) => `<label class="check"><input type="checkbox" name="env:${esc(h)}" value="${e}"${envs.includes(e) ? ' checked' : ''}> ${e}</label>`).join('')}</div>`
        : '';
      return `<div class="srow"><div class="sname"><label class="check"><input type="checkbox" name="item" value="${esc(h)}"${li ? ' checked' : ''}><span><code>${esc(m.name)}</code>${kindTag(m.kind)}</span></label></div>
<div class="smeta"><input type="text" name="var:${esc(h)}" value="${esc(li?.varName ?? defaultVarName(m.name))}" maxlength="${MAX_VAR}" aria-label="Variable name for ${esc(m.name)}" autocomplete="off" autocapitalize="off" spellcheck="false">${envBoxes}</div></div>`;
    };
    const fieldsets = [...byTier.entries()]
      .sort(([x], [y]) => x.localeCompare(y))
      .map(([tier, items]) => `<fieldset class="group"><legend class="f">${esc(tier)}</legend><div class="list">${items.map(itemRow).join('')}</div></fieldset>`)
      .join('');
    const gone = [...linked.values()].filter((i) => !present.has(i.handle));
    const goneHtml = gone.length
      ? `<h2>No longer in the vault</h2><div class="list">${gone.map((i) => `<div class="srow"><div class="sname"><code>${esc(i.handle)}</code><span class="tag warn">missing in vault</span></div><div class="smeta">${esc(i.varName)}. Saving the link drops it.</div></div>`).join('')}</div>`
      : '';
    const actions = link
      ? `<div class="card"><p><a href="${esc(targetUrl(connId, targetId))}/review">Review push</a></p>${
          vercel
            ? `<form method="post" action="${esc(targetUrl(connId, targetId))}/redeploy">${hidden(a.csrf)}<button>Redeploy</button> <span class="muted">Rebuilds the latest production deployment so it picks up new variables.</span></form>`
            : '<p class="muted">Each secret change already deployed a new Worker version.</p>'
        }</div>`
      : '';
    return page(shownName, `${nav('/deploy', a.s.login, a.st)}<h1>${esc(shownName)}</h1>
<p class="muted">${esc(conn.name)} ${providerTag(conn.provider)} · <code>${esc(targetId)}</code></p>${tabs('targets')}
<form method="post" action="${esc(targetUrl(connId, targetId))}/link">${hidden(a.csrf)}<input type="hidden" name="targetName" value="${esc(shownName)}">
${fieldsets || '<div class="card"><p class="muted">The vault has no items yet.</p></div>'}${goneHtml}
<div class="row"><button class="primary">Save link</button><span class="muted">Tick the items to push and name the variable each one becomes.</span></div></form>
${actions}
<h2>Recent pushes</h2>${recent.records.length ? `<div class="list">${recent.records.slice(0, 5).map((r) => pushRecord(r, conn.name)).join('')}</div><p class="muted"><a href="/deploy/history">All history</a></p>` : '<p class="muted">Nothing pushed yet.</p>'}`);
  });

  app.post('/deploy/t/:conn/:target/link', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const connId = c.req.param('conn');
    const targetId = c.req.param('target');
    const back = ids(connId, targetId) ? targetUrl(connId, targetId) : '/deploy';
    try {
      const conn = await vault(c.env).getConnection(connId);
      if (!conn) throw new Error('no such connection');
      const items: LinkItem[] = [];
      const seen = new Set<string>();
      for (const raw of a.form.getAll('item')) {
        const handle = String(raw);
        if (seen.has(handle)) continue;
        seen.add(handle);
        if (!parseHandle(handle)) throw new Error(`not a vault item: ${handle.slice(0, 80)}`);
        const varName = String(a.form.get(`var:${handle}`) ?? '').trim();
        if (!VAR_RE.test(varName) || varName.length > MAX_VAR) throw new Error(`${varName.slice(0, 40) || 'variable name'}: use A-Z, 0-9 and _, not starting with a digit (max ${MAX_VAR} characters)`);
        const item: LinkItem = { handle, varName };
        if (conn.provider === 'vercel') {
          const posted = a.form.getAll(`env:${handle}`).map(String);
          if (posted.some((e) => !VERCEL_ENVS.includes(e as VercelEnv))) throw new Error(`${varName}: unknown environment`);
          // the editor always sends the marker; without it the field is absent and the defaults apply
          if (a.form.has(`envs:${handle}`) && posted.length === 0) throw new Error(`${varName}: pick at least one environment`);
          item.environments = posted.length ? VERCEL_ENVS.filter((e) => posted.includes(e)) : [...DEFAULT_ENVS];
        }
        items.push(item);
      }
      const targetName = String(a.form.get('targetName') ?? '').trim() || targetId;
      await vault(c.env).saveLink({ connectionId: connId, targetId, targetName, items, by: a.s.login });
    } catch (err) {
      return fail(a.s, '/deploy', err, back, a.st);
    }
    return seeOther(done(back, 'link_saved'));
  });

  // ---------- review and push ----------

  function reviewBody(plan: Plan, url: string, csrf: string): string {
    const conn = plan.connection;
    const rows = plan.rows;
    const handles = [...new Map(rows.filter((r) => r.cls !== 'missing').map((r) => [r.handle, r])).values()];
    const selects = handles
      .map((r) => `<label class="f">${`<code>${esc(r.handle)}</code>`}</label><select name="ver">${r.versions.map((n, i) => `<option value="${esc(r.handle)}@${n}"${n === r.version ? ' selected' : ''}>v${n}${i === 0 ? ' (current)' : ''}</option>`).join('')}</select>`)
      .join('');
    const reviewForm = handles.length
      ? `<details class="add quiet"><summary>Pick other versions</summary><form method="get" action="${esc(url)}" class="card">${selects}<div class="row"><button>Re-review</button><span class="muted">Changing a version means reviewing again.</span></div></form></details>`
      : '';

    const lose = (r: PlanRow): string[] => {
      const keep = new Set(rows.filter((x) => x.varName === r.varName).flatMap((x) => x.environments ?? []));
      return (r.existingEnvs ?? []).filter((e) => !keep.has(e as VercelEnv));
    };
    const rowHtml = (r: PlanRow): string => {
      if (r.cls === 'missing') {
        return `<div class="srow"><div class="sname"><code>${esc(r.varName)}</code>${r.environments ? ` <span class="muted">${esc(envText(r.environments))}</span>` : ''}</div><div class="smeta"><code>${esc(r.handle)}</code> is no longer in the vault. Remove it from the link.</div></div>`;
      }
      const notes: string[] = [];
      if (r.recreate) {
        const gone = lose(r);
        notes.push(`will be recreated (type or environments differ)${gone.length ? `; removed from ${esc(gone.join(', '))}` : ''}`);
      }
      if (r.branchScoped) notes.push('a branch-scoped variable with this name exists and is left alone');
      if (r.oldValue !== undefined) notes.push(`Now: <code>${esc(r.oldValue)}</code> · After push: <code>${esc(r.newValue ?? '')}</code>`);
      else if (r.cls === 'replace') notes.push('exists, will be overwritten, value cannot be compared' + (r.newValue !== undefined ? ` · After push: <code>${esc(r.newValue)}</code>` : ''));
      const box = `<input type="checkbox" name="tick" value="${esc(r.key)}"${r.ticked ? ' checked' : ''}>`;
      return `<div class="srow${r.cls === 'uptodate' ? ' muted' : r.cls === 'replace' || r.recreate ? ' risk' : ''}"><div class="sname"><label class="check">${box}<span><code>${esc(r.varName)}</code>${envTags(r.environments)}</span></label></div>
<div class="smeta"><code>${esc(r.handle)}</code> v${r.version}${kindTag(r.kind ?? undefined)}${notes.map((n) => `<div>${n}</div>`).join('')}</div></div>`;
    };
    const groups: Array<[string, PlanRow['cls']]> = [['New', 'new'], ['Update', 'update'], ['Replace', 'replace'], ['Up to date', 'uptodate'], ['Missing in vault', 'missing']];
    const sections = groups
      .map(([title, cls]) => {
        const g = rows.filter((r) => r.cls === cls);
        return g.length ? `<h2>${title}</h2><div class="list">${g.map(rowHtml).join('')}</div>` : '';
      })
      .join('');

    const s = plan.summary;
    const n = s.new + s.update + s.replace;
    const tickedRows = rows.filter((r) => r.ticked && r.cls !== 'missing');
    const parts = (['new', 'update', 'replace'] as const).map((c) => [c, tickedRows.filter((r) => r.cls === c).length] as const).filter(([, k]) => k > 0).map(([l, k]) => `${k} ${l}`).join(', ');
    const summary = `${esc(conn.name)} / ${esc(plan.targetName)}. Ticked when this page opened: ${tickedRows.length} of ${n}${parts ? ` (${parts})` : ''}.${s.replace > 0 ? ' Replace rows go only if you tick them; re-check any you change.' : ''}`;
    const sig = esc(plan.sig);
    const pushable = rows.some((r) => r.cls !== 'missing');
    const vers = handles.map((r) => `<input type="hidden" name="ver" value="${esc(r.handle)}@${r.version}">`).join('');
    return `<h1>Review push</h1>
<p>Connection <strong>${esc(conn.name)}</strong> (${esc(conn.provider)}) · Target <strong>${esc(plan.targetName)}</strong></p>
${plan.cloudflareNote ? '<p class="muted">Cloudflare stores every variable as a secret, config included, so a Workers Builds deploy never wipes it. Each change deploys a new Worker version.</p>' : ''}
${reviewForm}
<form method="post" action="${esc(url.replace(/\/review$/, ''))}/push">${hidden(csrf)}<input type="hidden" name="sig" value="${sig}">${vers}
${sections || '<div class="card"><p class="muted">This link has no items.</p></div>'}
${pushable ? `<div class="decide-bar"><p class="summary">${summary}</p><div class="row"><button class="primary">Push</button></div></div>` : ''}</form>
<p><a href="${esc(url.replace(/\/review$/, ''))}">Back to the target</a></p>`;
  }

  app.get('/deploy/t/:conn/:target/review', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const connId = c.req.param('conn');
    const targetId = c.req.param('target');
    if (!ids(connId, targetId)) return notFound(a.s, a.st, 'Target');
    const back = targetUrl(connId, targetId);
    const versions: Record<string, number> = {};
    for (const raw of c.req.queries('ver') ?? []) {
      const at = raw.lastIndexOf('@');
      const n = Number(raw.slice(at + 1));
      if (at > 0 && Number.isInteger(n) && n > 0) versions[raw.slice(0, at)] = n;
    }
    try {
      const plan = await vault(c.env).reviewPush(connId, targetId, versions);
      return page('Review push', `${nav('/deploy', a.s.login, a.st)}${reviewBody(plan, `${back}/review`, a.csrf)}`);
    } catch (err) {
      return fail(a.s, '/deploy', err, back, a.st);
    }
  });

  app.post('/deploy/t/:conn/:target/push', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const connId = c.req.param('conn');
    const targetId = c.req.param('target');
    const back = ids(connId, targetId) ? targetUrl(connId, targetId) : '/deploy';
    const versions: Record<string, number> = {};
    for (const raw of a.form.getAll('ver').map(String)) {
      const at = raw.lastIndexOf('@');
      const n = Number(raw.slice(at + 1));
      if (at > 0 && Number.isInteger(n) && n > 0) versions[raw.slice(0, at)] = n;
    }
    try {
      const rec = await vault(c.env).pushTarget({ connectionId: connId, targetId, versions, ticked: a.form.getAll('tick').map(String), sig: String(a.form.get('sig') ?? ''), by: a.s.login });
      const conn = await vault(c.env).getConnection(connId);
      return page('Push result', resultBody(a.s, a.st, rec, conn, back, await csrfToken(c.env.COOKIE_ENCRYPTION_KEY, a.s, 'admin')));
    } catch (err) {
      return fail(a.s, '/deploy', err, ids(connId, targetId) ? `${back}/review` : '/deploy', a.st);
    }
  });

  function resultBody(s: Session, st: NavStatus, rec: PushRecord, conn: PublicConnection | null, back: string, csrf: string): string {
    const rows = rec.rows
      .map((r) => `<tr><td><code>${esc(r.varName)}</code></td><td>${esc(envText(r.environments))}</td><td><code>${esc(r.handle)}</code> v${r.version}</td><td>${r.action === 'failed' ? `<span class="tag prod">failed</span> ${esc(r.error ?? '')}` : `<span class="tag ok">${r.action}</span>`}</td></tr>`)
      .join('');
    const redeploy = conn?.provider === 'vercel'
      ? `<form method="post" action="${esc(back)}/redeploy">${hidden(csrf)}<input type="hidden" name="push" value="${esc(rec.id)}"><button>Redeploy</button> <span class="muted">New variables reach the site after a redeploy.</span></form>`
      : '';
    return `${nav('/deploy', s.login, st)}<h1>Push result</h1><p class="muted">${esc(conn?.name ?? 'removed connection')} / ${esc(rec.targetName)} · ${stamp(rec.at)}</p>
${rows ? `<table><tr><th>Variable</th><th>Environments</th><th>Item</th><th>Outcome</th></tr>${rows}</table>` : '<div class="card"><p class="muted">Nothing was pushed.</p></div>'}
${redeploy}<p><a href="${esc(back)}">Back to the target</a> · <a href="/deploy/history">History</a></p>`;
  }

  app.post('/deploy/t/:conn/:target/redeploy', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const connId = c.req.param('conn');
    const targetId = c.req.param('target');
    const back = ids(connId, targetId) ? targetUrl(connId, targetId) : '/deploy';
    try {
      const pushId = String(a.form.get('push') ?? '') || undefined;
      if (pushId !== undefined && (pushId.length > 64 || !PUSH_ID_RE.test(pushId))) throw new Error('that push id is not valid');
      const r = await vault(c.env).redeployTarget(connId, targetId, pushId, a.s.login);
      if (!r.ok) throw new Error(r.error ?? 'redeploy failed');
    } catch (err) {
      return fail(a.s, '/deploy', err, back, a.st);
    }
    return seeOther(done(back, 'redeployed'));
  });

  // ---------- history ----------

  app.get('/deploy/history', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const v = vault(c.env);
    const [res, conns] = await Promise.all([v.listPushes(pageNum(c.req.query('page'))), v.listConnections()]);
    const names = new Map(conns.map((x) => [x.id, x.name]));
    return page('Deploy history', `${nav('/deploy', a.s.login, a.st)}<h1>Deploy</h1>${tabs('history')}
<p class="muted">${res.total} push${res.total === 1 ? '' : 'es'}, newest first. Values are never recorded.</p>
${res.records.length ? `<div class="list">${res.records.map((r) => pushRecord(r, names.get(r.connectionId) ?? 'removed connection')).join('')}</div>` : '<div class="card"><p class="muted">Nothing pushed yet.</p></div>'}${pager('/deploy/history', {}, res.page, res.pages)}`);
  });

  // ---------- connections ----------

  app.get('/deploy/connections', async (c) => {
    const a = await get(c.req.raw, c.env);
    if (a instanceof Response) return a;
    const conns = await vault(c.env).listConnections();
    const check = (x: PublicConnection) =>
      x.lastCheckedAt === undefined ? '<span class="muted">not checked</span>'
        : `${x.lastCheckOk ? '<span class="tag ok">ok</span>' : '<span class="tag prod">failed</span>'} ${x.lastCheckOk ? '' : `${esc(x.lastCheckError ?? '')} `}<span class="muted">${stamp(x.lastCheckedAt)}</span>`;
    const rows = conns.map((x) => `<tr><td>${esc(x.name)}</td><td>${providerLabel(x.provider)}</td><td>${x.accountId ? `<code>${esc(x.accountId)}</code>` : 'personal'}</td><td>${check(x)}</td><td>
<details class="add quiet edit"><summary>Replace token</summary><form method="post" action="/deploy/connections/${enc(x.id)}/token">${hidden(a.csrf)}<label class="f">New token</label><input type="password" name="token" required maxlength="4096" autocomplete="off"><div class="row"><button class="primary">Replace token</button></div></form></details>
${confirmAction({ label: 'Remove', action: `/deploy/connections/${enc(x.id)}/remove`, fields: { csrf: a.csrf }, consequence: 'Links to its targets are removed. Push history is kept.', aria: `Remove ${x.name}` })}</td></tr>`).join('');
    return page('Connections', `${nav('/deploy', a.s.login, a.st)}<h1>Deploy</h1>${tabs('connections')}
<p class="muted">A connection holds one API token. It is stored encrypted and is never shown again.</p>
${rows ? `<table><tr><th>Name</th><th>Provider</th><th>Account</th><th>Last check</th><th></th></tr>${rows}</table>` : '<div class="card"><p class="muted">No connections yet.</p></div>'}
<details class="add"${conns.length ? '' : ' open'}><summary>Add a connection</summary><div class="card"><form method="post" action="/deploy/connections/add">${hidden(a.csrf)}
<label class="f">Provider</label><select name="provider"><option value="vercel">Vercel</option><option value="cloudflare">Cloudflare</option></select>
<label class="f">Name</label><input type="text" name="name" required maxlength="60" placeholder="Acme Vercel" autocomplete="off">
<label class="f">Account id (Vercel team id like team_abc, empty for a personal account; Cloudflare account id)</label><input type="text" name="accountId" maxlength="64" autocomplete="off" autocapitalize="off" spellcheck="false">
<label class="f">API token</label><input type="password" name="token" required maxlength="4096" autocomplete="off">
<div class="row"><button class="primary">Save and check</button></div></form></div></details>`);
  });

  app.post('/deploy/connections/add', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      const provider = String(a.form.get('provider') ?? '');
      if (provider !== 'vercel' && provider !== 'cloudflare') throw new Error('pick Vercel or Cloudflare');
      await vault(c.env).addConnection({ provider, name: String(a.form.get('name') ?? ''), accountId: String(a.form.get('accountId') ?? '').trim(), token: String(a.form.get('token') ?? ''), by: a.s.login });
    } catch (err) {
      return fail(a.s, '/deploy', err, '/deploy/connections', a.st);
    }
    return seeOther(done('/deploy/connections', 'conn_added'));
  });

  app.post('/deploy/connections/:id/token', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      await vault(c.env).replaceConnectionToken(c.req.param('id'), String(a.form.get('token') ?? ''), a.s.login);
    } catch (err) {
      return fail(a.s, '/deploy', err, '/deploy/connections', a.st);
    }
    return seeOther(done('/deploy/connections', 'conn_token_replaced'));
  });

  app.post('/deploy/connections/:id/remove', async (c) => {
    const a = await post(c.req.raw, c.env);
    if (a instanceof Response) return a;
    try {
      await vault(c.env).removeConnection(c.req.param('id'), a.s.login);
    } catch (err) {
      return fail(a.s, '/deploy', err, '/deploy/connections', a.st);
    }
    return seeOther(done('/deploy/connections', 'conn_removed'));
  });
}
