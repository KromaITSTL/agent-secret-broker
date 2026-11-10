/**
 * Browser-facing approval pages: sign in with GitHub, approve or deny an
 * agent's access request, and list or revoke existing approvals.
 *
 * These pages are the only way a request becomes a grant, so they carry the
 * security weight: allowlisted GitHub sign-in, an HMAC-signed session cookie,
 * per-user per-request CSRF tokens, SameSite cookies, no framing, and every
 * agent-supplied string HTML-escaped.
 */
import type { Hono } from 'hono';
import { assertSessionKey, isAllowedUser, type Env } from './env';
import { isLive, type AccessRequest, type ApprovalLimits, type Grants, type GrantRule, type ListedGrant, type RepoGrant } from './grants';
import { vaultFor } from './vault-client';
import { parseHandle } from './policy';

const SESSION_COOKIE = '__Host-sb_session';
const LOGIN_COOKIE = '__Host-sb_login';
const SESSION_TTL_S = 12 * 3600;
const LOGIN_TTL_S = 600;
const enc = new TextEncoder();

// ---------- signing ----------

export async function hmacHex(secret: string, data: string): Promise<string> {
  assertSessionKey(secret);
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
  return [...sig].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export interface Session {
  githubId: string;
  login: string;
  exp: number;
}

export async function signSession(secret: string, s: Session): Promise<string> {
  const payload = btoa(JSON.stringify(s)).replace(/=+$/, '');
  return `${payload}.${await hmacHex(secret, `session:${payload}`)}`;
}

export async function readSession(secret: string, cookieHeader: string | null, now = Date.now()): Promise<Session | null> {
  const raw = getCookie(cookieHeader, SESSION_COOKIE);
  if (!raw) return null;
  const [payload, sig] = raw.split('.');
  if (!payload || !sig || !safeEqual(sig, await hmacHex(secret, `session:${payload}`))) return null;
  try {
    const s = JSON.parse(atob(payload)) as Session;
    return s.exp * 1000 > now ? s : null;
  } catch {
    return null;
  }
}

export function csrfToken(secret: string, s: Session, purpose: string): Promise<string> {
  return hmacHex(secret, `csrf:${s.githubId}:${purpose}`);
}

function getCookie(header: string | null, name: string): string | null {
  for (const part of (header ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

// ---------- html ----------

export function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

const FAVICON =
  "data:image/svg+xml," +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#1f6f66"/><circle cx="16" cy="13.5" r="4.5" fill="none" stroke="#fff" stroke-width="2.6"/><path d="M16 17.5v7" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/></svg>`,
  );

const CSS = `
@font-face{font-family:"Plex Sans";src:url(/fonts/ibm-plex-sans-latin-wght-normal.woff2) format("woff2");font-weight:100 700;font-display:swap}
@font-face{font-family:"Plex Mono";src:url(/fonts/ibm-plex-mono-latin-400-normal.woff2) format("woff2");font-weight:400;font-display:swap}
@font-face{font-family:"Plex Mono";src:url(/fonts/ibm-plex-mono-latin-500-normal.woff2) format("woff2");font-weight:500 700;font-display:swap}
:root{color-scheme:light;
--bg:#f6f5f2;--bg2:#efede8;--surface:#fffffe;--fg:#1d1b18;--fg2:#45413b;--muted:#68625a;--line:#e2ded5;--line2:#cfc9be;--field:#8a8377;
--accent:#1f6f66;--accent-fg:#fff;--accent-soft:#e3efec;
--danger:#b3261e;--danger-soft:#f9e7e4;--danger-line:#e8b4ad;--warn:#8a5208;--warn-soft:#f6ecd9;--ok:#2d6a3e;--ok-soft:#e4f0e4;
--sans:"Plex Sans","Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
--mono:"Plex Mono","Cascadia Code",ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;
--bg:#141412;--bg2:#1b1a18;--surface:#1d1c19;--fg:#ecebe6;--fg2:#c9c5bd;--muted:#99938a;--line:#2d2b27;--line2:#3d3a34;--field:#78746a;
--accent:#5fb5a8;--accent-fg:#0d1f1c;--accent-soft:#1b2c29;
--danger:#f08b80;--danger-soft:#2f1b18;--danger-line:#6b302a;--warn:#e0b16a;--warn-soft:#30261a;--ok:#86c99a;--ok-soft:#1b2a1f}}
*{box-sizing:border-box}
fieldset.group{border:0;margin:0;padding:0;min-width:0}
fieldset.group>legend{padding:0}
html{-webkit-text-size-adjust:100%;scroll-padding-top:72px;scroll-padding-bottom:140px;scrollbar-color:var(--line2) transparent}
body{margin:0;min-height:100dvh;background:var(--bg);color:var(--fg);font:15px/1.55 var(--sans);font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased;caret-color:var(--accent)}
::selection{background:color-mix(in srgb,var(--accent) 28%,transparent);color:var(--fg)}
main{max-width:960px;margin:0 auto;padding:0 20px 80px}
a{color:var(--accent);text-decoration:underline;text-decoration-color:color-mix(in srgb,var(--accent) 40%,transparent);text-underline-offset:3px;text-decoration-thickness:1px;transition:text-decoration-color .15s}
a:hover{text-decoration-color:currentColor}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:5px}
h1{font-size:28px;line-height:1.2;letter-spacing:-.02em;font-weight:600;margin:32px 0 8px;text-wrap:balance}
h1 .tag{vertical-align:6px}
h2{font-size:16px;line-height:1.3;font-weight:600;letter-spacing:-.005em;margin:40px 0 12px}
p{max-width:68ch;text-wrap:pretty}
.muted{color:var(--muted);font-size:14px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.prod{color:var(--danger)}
code{font:13px/1.4 var(--mono);background:var(--bg2);border:1px solid var(--line);padding:1px 5px;border-radius:5px;overflow-wrap:anywhere}
h1 code{font:500 25px/1.25 var(--mono);letter-spacing:-.01em;background:none;border:0;padding:0}
pre{font:13px/1.55 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere}
.skip{position:absolute;left:12px;top:-60px;z-index:20;padding:10px 14px;border-radius:9px;background:var(--fg);color:var(--bg)}
.skip:focus{top:12px}
details.confirm .c-close,details.confirm[open] .c-open{display:none}
details.confirm[open] .c-close{display:inline}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}

/* top bar */
.top{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:saturate(1.3) blur(10px);-webkit-backdrop-filter:saturate(1.3) blur(10px);border-bottom:1px solid var(--line)}
.bar{max-width:960px;margin:0 auto;padding:0 20px;min-height:60px;display:flex;align-items:center;gap:20px}
.brand{display:flex;align-items:center;gap:9px;font-weight:600;letter-spacing:-.01em;color:var(--fg);text-decoration:none;flex:none}
.brand svg{width:24px;height:24px;flex:none}
.top nav{display:flex;gap:2px;flex-wrap:wrap;flex:1;min-width:0}
.top nav a{display:inline-flex;align-items:center;gap:6px;padding:7px 11px;border-radius:9px;font-size:14px;font-weight:500;color:var(--fg2);text-decoration:none;transition:background .15s,color .15s}
.top nav a:hover{background:var(--bg2);color:var(--fg)}
.top nav a.on{background:var(--surface);color:var(--fg);box-shadow:inset 0 0 0 1px var(--line2)}
.count{display:inline-grid;place-items:center;min-width:19px;height:19px;padding:0 5px;border-radius:999px;background:var(--danger);color:var(--surface);font:600 11.5px/1 var(--sans)}
.who{flex:none;display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted)}
.who i{width:26px;height:26px;border-radius:9px;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;font:600 12px/1 var(--sans);font-style:normal;text-transform:uppercase}

/* status strips */
.banner{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:12px 16px;border-radius:12px;margin:20px 0 0;font-size:14px}
.banner.frozen{background:var(--danger-soft);color:var(--danger);border:1px solid var(--danger-line);font-weight:600}
.banner>span{flex:1;min-width:min(240px,100%)}
.banner.frozen::before{flex:none;content:"";width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 0 4px color-mix(in srgb,currentColor 22%,transparent)}
.banner.frozen a{color:inherit;margin-left:auto;font-weight:500}
.flash{background:var(--ok-soft);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent);font-weight:500}

/* surfaces: one elevation, a border */
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:20px;margin:12px 0}
.card>:first-child{margin-top:0}.card>:last-child{margin-bottom:0}
.split{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
a.cardlink{display:flex;align-items:center;gap:14px;text-decoration:none;color:var(--fg);transition:border-color .15s,background .15s}
a.cardlink:hover{border-color:var(--line2);background:color-mix(in srgb,var(--surface) 60%,var(--bg2))}
a.cardlink .go{margin-left:auto;flex:none;font-size:14px;font-weight:600;color:var(--accent)}
a.cardlink .what{min-width:0}

/* tags */
.tag{display:inline-flex;align-items:center;gap:5px;font:500 12px/1 var(--sans);padding:4px 7px;border-radius:5px;margin-left:8px;vertical-align:1px;background:var(--bg2);color:var(--fg2);border:1px solid var(--line);white-space:nowrap}
.tag.prod{background:var(--danger-soft);color:var(--danger);border-color:var(--danger-line)}
.tag.warn{background:var(--warn-soft);color:var(--warn);border-color:color-mix(in srgb,var(--warn) 30%,transparent)}
.tag.ok{background:var(--ok-soft);color:var(--ok);border-color:color-mix(in srgb,var(--ok) 30%,transparent)}
.tag.prod::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}

/* vault filter */
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:20px 0 8px}
.tabs a{font-size:14px;font-weight:500;padding:8px 12px;border-radius:9px;text-decoration:none;color:var(--fg2);background:var(--surface);border:1px solid var(--line);transition:border-color .15s}
.tabs a:hover{border-color:var(--line2)}
.tabs a.on{background:var(--fg);border-color:var(--fg);color:var(--bg)}

/* row lists */
.list{background:var(--surface);border:1px solid var(--line);border-radius:12px;margin:12px 0;overflow:hidden}
.lhead{padding:12px 18px;border-bottom:1px solid var(--line);background:var(--bg2)}
.lhead h3{margin:0;font-size:15px}
.lhead h3 code{font:500 14px/1.4 var(--mono);background:none;border:0;padding:0}
.srow{display:grid;grid-template-columns:1fr auto;gap:4px 16px;padding:14px 18px;border-top:1px solid var(--line)}
.srow:first-child,.lhead+.srow{border-top:0}
.sname{font-weight:600;min-width:0}
.sname code{font:500 14px/1.4 var(--mono);background:none;border:0;padding:0}
.smeta{grid-column:1;color:var(--muted);font-size:13px}
.smeta code{font-size:13px}
.sact{grid-column:2;grid-row:1/span 2;align-self:center;display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;align-items:center}
.sact a{display:inline-flex;align-items:center;min-height:36px;font-size:14px;font-weight:500;padding:0 13px;border-radius:9px;text-decoration:none;color:var(--fg);border:1px solid var(--line2);background:var(--surface);transition:background .15s}
.sact a:hover{background:var(--bg2)}
.srow.risk{background:color-mix(in srgb,var(--danger-soft) 55%,var(--surface))}
.srow .dl{grid-column:1/-1}

/* disclosures: add form, two-step confirm */
details.add{margin:16px 0}
details.add>summary{list-style:none;display:inline-flex;align-items:center;gap:8px;min-height:40px;cursor:pointer;font-weight:600;font-size:14px;padding:0 16px;border-radius:9px;background:var(--accent);color:var(--accent-fg);transition:filter .15s,transform .1s;user-select:none}
details.add>summary::-webkit-details-marker,details.confirm>summary::-webkit-details-marker{display:none}
details.add>summary::before{content:"+";font-size:16px;line-height:1;font-weight:400;transition:transform .2s}
details.add[open]>summary{background:var(--surface);color:var(--fg);box-shadow:inset 0 0 0 1px var(--line2)}
details.add[open]>summary::before{transform:rotate(45deg)}
details.add>summary:hover{filter:brightness(1.07)}
details.add.quiet>summary{background:var(--surface);color:var(--fg);box-shadow:inset 0 0 0 1px var(--line2)}
details.add.edit>summary::before{content:"";width:6px;height:6px;margin:0 2px 3px;border:solid currentColor;border-width:0 1.5px 1.5px 0;transform:rotate(45deg)}
details.add.edit[open]>summary::before{transform:rotate(225deg);margin-bottom:-3px}
details.add.edit>form,details.add.edit>.panel{margin-top:4px}
.creates{display:flex;flex-wrap:wrap;gap:0 10px;margin:16px 0}
.creates details.add{margin:0}
.creates details.add[open]{flex-basis:100%}
.creates details.add[open]>.card{margin-bottom:16px}
details.confirm{display:inline-block}
details.confirm>summary{list-style:none;display:inline-flex;align-items:center;min-height:36px;padding:0 13px;border-radius:9px;cursor:pointer;font-size:14px;font-weight:600;color:var(--danger);border:1px solid var(--danger-line);background:var(--surface);user-select:none;transition:background .15s}
details.confirm>summary:hover{background:var(--danger-soft)}
details.confirm.quiet>summary{color:var(--fg2);border-color:var(--line2)}
details.confirm.quiet>summary:hover{background:var(--bg2)}
.inactive+.srow{border-top:0}
h4.inactive{margin:0;padding:10px 18px;border-top:1px solid var(--line);background:var(--bg2);font-size:13px;font-weight:500;color:var(--muted)}
details.confirm[open]{display:block;width:100%;margin-top:8px}
details.confirm[open]>summary{color:var(--muted);border-color:var(--line2)}
.confirm-body{margin-top:10px;padding:14px 16px;border-radius:12px;background:var(--danger-soft);border:1px solid var(--danger-line);text-align:left}
.confirm-body p{margin:0 0 12px;color:var(--fg);font-size:14px}

/* forms */
.item{transition:background .15s,border-color .15s}
.item .pick{display:flex;gap:14px;align-items:flex-start;cursor:pointer}
.item .pick input{margin-top:2px}
.item .what{display:block;min-width:0;flex:1}
.item .head{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px}
.item .head .tag{margin-left:0}
.item .itemdetail{margin:0 0 0 34px}
.item .itemdetail dl{margin:10px 0 0}
.item .why{display:block;margin:10px 0 0;color:var(--fg2);font-size:14px;max-width:68ch}
.item.risk{background:var(--danger-soft);border-color:var(--danger-line)}
.item.risk .why{color:var(--danger);font-weight:500}
.item:not(.risk):has(.pick input:not(:checked)){background:var(--bg);border-style:dashed}
.item.risk:has(.pick input:checked){border-color:var(--danger);box-shadow:inset 0 0 0 1px var(--danger)}
.item.risk:has(.pick input:not(:checked)){border-style:dashed}
.limits{border:0;border-top:1px solid var(--line);min-width:0;display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px 16px;margin:16px 0 0 34px;padding:16px 0 0}
.item.risk .limits{border-top-color:var(--danger-line)}
.lim{display:flex;flex-direction:column;gap:6px}
.lim label{font-size:13px;font-weight:500;color:var(--fg2)}
.lim select{width:200px}
.lim input[type=number]{width:180px}
.decide-bar{margin-top:20px}
.decide-bar .summary{margin:0;font-size:14px;color:var(--fg2)}
.decide-bar .summary strong{color:var(--fg);font-weight:600}
.decide-bar .row{margin-top:12px}
label.f,legend.f{display:block;font-size:14px;font-weight:500;color:var(--fg2);margin:18px 0 6px}
label.f:first-of-type{margin-top:2px}
label.check{display:flex;gap:10px;align-items:flex-start;min-height:28px;padding:3px 0;margin-top:10px;font-size:14px;color:var(--fg2);cursor:pointer}
input[type=checkbox]{accent-color:var(--accent);width:20px;height:20px;margin:0;flex:none}
label.check input{margin-top:1px}
label.check.risk{padding:10px 12px;border-radius:9px;background:var(--danger-soft);border:1px solid var(--danger-line)}
label.check.risk .prod{font-size:13px}
input[type=text],input[type=password],input[type=search],input[type=number],input[type=url],select,textarea{font:inherit;font-size:15px;width:100%;min-height:44px;padding:10px 12px;border-radius:9px;border:1px solid var(--field);background:var(--bg);color:var(--fg);transition:border-color .15s,box-shadow .15s}
::placeholder{color:var(--muted);opacity:1}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:0;border-color:var(--accent);background:var(--surface)}
textarea{font:14px/1.5 var(--mono);min-height:96px;resize:vertical}
select{appearance:none;-webkit-appearance:none;padding-right:36px;background-image:linear-gradient(45deg,transparent 50%,var(--muted) 50%),linear-gradient(135deg,var(--muted) 50%,transparent 50%);background-position:calc(100% - 18px) 52%,calc(100% - 13px) 52%;background-size:5px 5px;background-repeat:no-repeat}
form.inline{display:inline}
.envs{display:flex;gap:2px 14px;flex-wrap:wrap}
.envs label.check{margin-top:4px}
.smeta input[type=text]{max-width:340px;min-height:36px;padding:6px 10px;font:500 13px/1.4 var(--mono)}
.srow.muted{color:var(--muted)}
.srow.push .smeta{grid-column:1/-1}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:20px}
.row .muted{margin:0}
button{font:inherit;font-size:14px;font-weight:600;min-height:40px;padding:0 16px;border-radius:9px;border:1px solid var(--line2);background:var(--surface);color:var(--fg);cursor:pointer;transition:background .15s,filter .15s,transform .1s}
button:hover{background:var(--bg2)}
button:active,details>summary:active{transform:translateY(1px)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}
button.primary:hover{filter:brightness(1.08);background:var(--accent)}
button.danger{color:var(--danger);border-color:var(--danger-line)}
button.danger:hover{background:var(--danger-soft)}
button.solid-danger{background:var(--danger);border-color:var(--danger);color:var(--surface)}
button.solid-danger:hover{filter:brightness(1.08);background:var(--danger)}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:16px 0 4px}
.filters input{flex:1;min-width:200px}

/* definitions + tables */
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:10px 0 0;font-size:14px}
dt{color:var(--muted)}dd{margin:0;min-width:0}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:14px;background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:12px 0}
th{text-align:left;font-size:13px;font-weight:600;color:var(--fg2);background:var(--bg2);padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:11px 14px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:first-child td{border-top:0}
td:first-child{white-space:nowrap}
td code{white-space:nowrap;overflow-wrap:normal}
tr.denied td{background:color-mix(in srgb,var(--danger-soft) 70%,var(--surface))}
tr.denied td:nth-child(2) code{color:var(--danger);border-color:var(--danger-line)}
table.audit td:nth-child(1){color:var(--muted);font-size:13px}
table.audit td:nth-child(3){white-space:nowrap}
table.audit td:nth-child(4){color:var(--fg2);font-size:13px;overflow-wrap:anywhere}
pre.reveal{margin:16px 0 0;padding:16px 18px;font:500 14px/1.4 var(--mono);background:var(--surface);border:1px solid var(--line2);border-radius:9px;user-select:all;white-space:pre-wrap;overflow-wrap:anywhere}
.revealed-label{display:block;margin-top:16px;font-size:13px;font-weight:500;color:var(--fg2)}
.revealed-label+pre.reveal{margin-top:6px}
.state{display:inline-flex;align-items:center;min-height:40px;padding:0 14px;border-radius:9px;border:1px dashed var(--line2);font-size:14px;font-weight:500;color:var(--muted)}
.card hr{border:0;border-top:1px solid var(--line);margin:20px 0}
.tok{font:14px/1.6 var(--mono);word-break:break-all;padding:16px;border:1.5px dashed var(--accent);background:var(--accent-soft);border-radius:12px;user-select:all}
.back{display:inline-flex;align-items:center;min-height:32px;margin:20px 0 -16px;font-size:14px;text-decoration:none;color:var(--muted)}
.back:hover{color:var(--fg)}

/* centred pages (sign-in, results) */
main.solo{max-width:540px;padding-top:12vh}
main.solo>.brand{margin:0 0 14px 4px}
main.solo h1{margin-top:4px}

@media (max-width:640px){
 main{padding:0 16px 64px}
 .top{position:static}
 .bar{padding:10px 16px 8px;gap:8px 12px;flex-wrap:wrap}
 .top nav{order:3;flex-basis:100%;gap:4px;margin:0 -6px}
 .top nav a{padding:9px 10px}
 .who{margin-left:auto}
 .who>span{display:none}
 h1{margin-top:24px}
 .card{padding:16px}
 .srow{grid-template-columns:1fr;padding:14px}
 .sact{grid-column:1;grid-row:auto;justify-content:flex-start;margin-top:6px}
 button{min-height:44px}
 .sact a,details.confirm>summary{min-height:40px}
 details.add>summary{min-height:44px}
 .item .itemdetail{margin-left:0}
 table,tbody,tr,td{display:block}
 thead{display:none}
 tr{padding:12px 14px;border-top:1px solid var(--line)}
 tbody tr:first-child{border-top:0}
 td{padding:2px 0;border:0;white-space:normal}
 td[data-label]::before{content:attr(data-label) " ";color:var(--muted);font-size:13px}
 td:first-child{white-space:normal}
 td code{white-space:normal;overflow-wrap:anywhere}
 tr.denied{background:color-mix(in srgb,var(--danger-soft) 70%,var(--surface))}
 tr.denied td{background:none}
 .limits{margin-left:0;flex-direction:column;align-items:stretch}
 .lim select,.lim input[type=number]{width:100%}
 .decide-bar{position:sticky;bottom:0;z-index:5;margin:20px -16px 0;padding:12px 16px calc(12px + env(safe-area-inset-bottom));background:color-mix(in srgb,var(--bg) 94%,transparent);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-top:1px solid var(--line)}
 .decide-bar .row{margin-top:10px;flex-wrap:nowrap}
 .decide-bar .row button{flex:1}
 dl{grid-template-columns:1fr;gap:0}
 dd{margin-bottom:8px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
`;

const BRAND = `<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="var(--accent)"/><circle cx="16" cy="13.5" r="4.5" fill="none" stroke="var(--accent-fg)" stroke-width="2.6"/><path d="M16 17.5v7" stroke="var(--accent-fg)" stroke-width="2.6" stroke-linecap="round"/></svg>`;

export function page(title: string, body: string, status = 200, extraHeaders: Record<string, string> = {}): Response {
  // Pages with the signed-in top bar get the full layout; the rest (sign-in, results) are a centred card.
  const top = body.startsWith('<header class="top">') ? body.indexOf('</header>') + 9 : 0;
  const shell = top
    ? `<a class="skip" href="#main">Skip to content</a>${body.slice(0, top)}<main id="main">${body.slice(top)}</main>`
    : `<main class="solo" id="main"><a class="brand" href="/vault">${BRAND}<span>Vault</span></a><div class="card">${body}</div></main>`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><link rel="icon" href="${FAVICON}">
<link rel="preload" href="/fonts/ibm-plex-sans-latin-wght-normal.woff2" as="font" type="font/woff2" crossorigin>
<title>${esc(title)} · Vault</title><style>${CSS}</style></head><body>${enhance(shell)}</body></html>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, ...extraHeaders } });
}

/**
 * Accessibility pass over the finished markup, so every page gets it without
 * repeating ids by hand: ties each `label.f` to the field after it, and gives
 * tables a real header row plus per-cell labels for the stacked phone layout.
 */
export function enhance(html: string): string {
  let n = 0;
  html = html.replace(/<label class="f">([\s\S]*?)<\/label>(\s*)<(input|select|textarea)\b/g, (_m, text: string, ws: string, tag: string) => {
    const id = `f${++n}`;
    return `<label class="f" for="${id}">${text}</label>${ws}<${tag} id="${id}"`;
  });
  return html.replace(/<table([^>]*)>([\s\S]*?)<\/table>/g, (_m, attrs: string, inner: string) => {
    const head = /^\s*<tr>((?:\s*<th>[\s\S]*?<\/th>)+)\s*<\/tr>/.exec(inner);
    if (!head) return `<table${attrs}>${inner}</table>`;
    const labels = [...head[1]!.matchAll(/<th>([\s\S]*?)<\/th>/g)].map((m) => m[1]!.replace(/<[^>]+>/g, '').trim());
    const thead = `<thead><tr>${labels.map((l) => (l ? `<th scope="col">${l}</th>` : '<th scope="col"><span class="sr">Actions</span></th>')).join('')}</tr></thead>`;
    const body = inner.slice(head[0].length).replace(/<tr([^>]*)>([\s\S]*?)<\/tr>/g, (_r, trAttrs: string, cells: string) => {
      let i = 0;
      return `<tr${trAttrs}>${cells.replace(/<td>/g, () => {
        const l = labels[i++];
        return l ? `<td data-label="${l}">` : '<td>';
      })}</tr>`;
    });
    return `<table${attrs}>${thead}<tbody>${body}</tbody></table>`;
  });
}

/**
 * A destructive action that needs a second, deliberate click: the summary
 * opens a panel that says what will happen, and only its button submits.
 * Works without JavaScript and from the keyboard.
 */
export function confirmAction(o: { label: string; action: string; fields: Record<string, string>; consequence: string; confirm?: string; aria?: string; quiet?: boolean }): string {
  const inputs = Object.entries(o.fields).map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join('');
  return `<details class="confirm${o.quiet ? ' quiet' : ''}"><summary><span class="c-open">${esc(o.label)}${o.aria ? `<span class="sr">${esc(o.aria.startsWith(o.label) ? o.aria.slice(o.label.length) : ` (${o.aria})`)}</span>` : ''}</span><span class="c-close">Cancel</span></summary><div class="confirm-body"><p>${o.consequence}</p>
<form method="post" action="${esc(o.action)}">${inputs}<button class="solid-danger">${esc(o.confirm ?? `Yes, ${o.label.toLowerCase()}`)}</button></form></div></details>`;
}

function destination(i: { hosts?: string[]; methods?: string[]; paths?: string[] }): string {
  const hosts = i.hosts ?? [];
  const wild = hosts.some((h) => h.startsWith('*.'));
  return `<dl><dt>Sent to</dt><dd>${hosts.map((h) => `<code>${esc(h)}</code>`).join(' ')}${wild ? '<span class="tag warn">any subdomain</span>' : ''}</dd>
<dt>Methods</dt><dd>${esc((i.methods ?? ['any']).join(', '))}</dd>
<dt>Paths</dt><dd>${(i.paths ?? ['/**']).map((p) => `<code>${esc(p)}</code>`).join(' ')}</dd></dl>`;
}

const isReveal = (it: { reveal?: true; action?: 'fetch' | 'reveal' }): boolean => it.reveal === true || it.action === 'reveal';

/** What an item does, for people: reveal items have no hosts, so they never reach `destination`. */
function itemDetail(it: { hosts?: string[]; methods?: string[]; paths?: string[]; reveal?: true; action?: 'fetch' | 'reveal' }): string {
  return isReveal(it) ? '<dl><dt>Access</dt><dd>Reveal to agent</dd></dl>' : destination(it);
}

function tierTag(handle: string): string {
  const tier = parseHandle(handle)?.tier;
  return tier === 'production' ? '<span class="tag prod">production</span>' : tier ? `<span class="tag">${esc(tier)}</span>` : '';
}

/** Why an approval item deserves a deliberate tick, or null when it is routine. */
function riskOf(it: { handle: string; hosts?: string[]; paths?: string[]; reveal?: true }): string | null {
  const prod = parseHandle(it.handle)?.tier === 'production';
  if (it.reveal === true) return prod ? 'Production login. Approving lets this repo reveal its password to the agent.' : null;
  const wild = (it.hosts ?? []).filter((h) => h.startsWith('*.'));
  const anyPath = !it.paths || it.paths.includes('/**');
  if (!prod && !wild.length) return null;
  const where = wild.length ? `any subdomain of ${wild.map((h) => esc(h.slice(2))).join(', ')}` : (it.hosts ?? []).map(esc).join(', ');
  return `${prod ? 'Production secret. ' : ''}Approving lets this repo send it to ${where}${anyPath ? ', any path' : ''}, until you revoke it.`;
}

export const EXPIRY_MS: Record<string, number | null> = { '1h': 3_600_000, '24h': 86_400_000, '7d': 604_800_000, never: null };
const EXPIRY_LABELS: Record<string, string> = { '1h': '1 hour', '24h': '24 hours', '7d': '7 days', never: 'Never' };

/** Remaining time and uses for a live rule; empty when unlimited or no longer live. */
export function limitText(r: Pick<GrantRule, 'expiresAt' | 'usesLeft'>, now: number): string {
  if (!isLive(r, now)) return '';
  const parts: string[] = [];
  if (r.expiresAt !== undefined) {
    const left = r.expiresAt - now;
    parts.push(left >= 86_400_000 ? `expires in ${Math.floor(left / 86_400_000)} d` : left >= 3_600_000 ? `expires in ${Math.floor(left / 3_600_000)} h` : `expires in ${Math.max(1, Math.ceil(left / 60_000))} min`);
  }
  if (r.usesLeft !== undefined) parts.push(r.usesLeft === 1 ? '1 use left' : `${r.usesLeft} uses left`);
  return parts.join(' · ');
}

/** Production items (fetch or reveal) default to 7 days; other reveals to 7 days; other fetches never expire. Shared by the form and the absent-field fallback. */
function defaultExpiry(it: { handle: string; reveal?: true }): string {
  return it.reveal === true || parseHandle(it.handle)?.tier === 'production' ? '7d' : 'never';
}

/** Reads expiry_<i> and uses_<i> for each ticked item. A string result is the error; tampered values never fall back to unlimited. */
function parseLimits(form: FormData, req: AccessRequest, selected: number[]): ApprovalLimits | string {
  const limits: ApprovalLimits = {};
  for (const i of selected) {
    const item = req.items[i];
    if (!item) continue;
    const raw = form.get(`expiry_${i}`);
    const key = raw === null ? defaultExpiry(item) : String(raw);
    if (!Object.hasOwn(EXPIRY_MS, key)) return 'unknown duration';
    const ttl = EXPIRY_MS[key];
    const usesRaw = String(form.get(`uses_${i}`) ?? '').trim();
    let uses: number | undefined;
    if (usesRaw !== '') {
      uses = /^\d+$/.test(usesRaw) ? Number(usesRaw) : NaN;
      if (!(uses >= 1 && uses <= 1000)) return 'uses must be a whole number from 1 to 1000';
    }
    limits[i] = { ...(ttl != null ? { ttlMs: ttl } : {}), ...(uses !== undefined ? { uses } : {}) };
  }
  return limits;
}

/** Expires and Uses for one item. Production reveals start at one use; production items default to 7 days. */
function limitFields(it: { handle: string; reveal?: true }, i: number): string {
  const def = defaultExpiry(it);
  const oneUse = it.reveal === true && parseHandle(it.handle)?.tier === 'production';
  return `<fieldset class="limits"><legend class="sr">Limits for ${esc(it.handle)}</legend><div class="lim"><label for="expiry-${i}">Expires</label><select id="expiry-${i}" name="expiry_${i}">${Object.keys(EXPIRY_MS).map((k) => `<option value="${k}"${k === def ? ' selected' : ''}>${EXPIRY_LABELS[k]}</option>`).join('')}</select></div>
<div class="lim"><label for="uses-${i}">Uses</label><input type="number" id="uses-${i}" name="uses_${i}" min="1" max="1000" inputmode="numeric" placeholder="No limit"${oneUse ? ' value="1"' : ''} aria-describedby="uses-help"></div></fieldset>`;
}

export function renderRequest(req: AccessRequest, csrf: string, user: string, st: NavStatus = {}, existing?: RepoGrant | null): string {
  let risky = 0;
  let ticked = 0;
  let tickedReveals = 0;
  const items = req.items
    .map((it, i) => {
      const why = riskOf(it);
      const reveal = it.reveal === true;
      if (why) risky++;
      else {
        ticked++;
        if (reveal) tickedReveals++;
      }
      // A reveal says one thing: the red risk sentence for production, the plain one otherwise.
      const note = why ?? (reveal ? 'The agent will see this password once approved.' : '');
      return `<div class="card item${why ? ' risk' : ''}${reveal ? ' reveal' : ''}"><label class="pick"><input type="checkbox" name="item" value="${i}"${why ? '' : ' checked'}>
<span class="what"><span class="head"><code>${esc(it.handle)}</code>${tierTag(it.handle)}${reveal ? '<span class="tag warn">reveal</span>' : ''}</span></span></label>
<div class="itemdetail">${reveal ? '' : itemDetail(it)}${note ? `<span class="why">${note}</span>` : ''}</div>
${limitFields(it, i)}</div>`;
    })
    .join('');
  const already = existing?.rules.some((r) => isLive(r, Date.now()))
    ? `<h2>Already approved for this repo</h2><p class="muted">${existing.rules.filter((r) => isLive(r, Date.now())).flatMap((r) => r.secrets.map((s) => `<code>secret://${esc(r.tier)}/${esc(s)}</code>${r.tier === 'production' ? '<span class="tag prod">production</span>' : ''}`)).join(' ')} · <a href="/approvals">Manage</a></p>`
    : '';
  const n = req.items.length;
  return `${nav('/approvals', user, st)}<h1>Access for <code>${esc(req.repo)}</code></h1>
<p>${esc(req.reason)}</p>
<p class="muted">Reason written by the agent · ${esc(req.requestedBy)} · ${esc(stamp(req.createdAt))}</p>
<form method="post"><input type="hidden" name="csrf" value="${esc(csrf)}">
<p class="muted" id="uses-help">Each item has its own limits. One use is one agent call; leave Uses blank for no limit.</p>
${items}
${risky ? `<p class="muted">${risky === 1 ? 'The item marked in red starts unticked' : `The ${risky} items marked in red start unticked`}. Tick it only if this repo really needs it.</p>` : ''}
<div class="decide-bar"><p class="summary"><strong>Ticked when this page opened: ${ticked} of ${n}.</strong> ${tickedReveals} reveal${tickedReveals === 1 ? '' : 's'}, 0 production.${risky ? ' Re-check any you changed.' : ''}</p>
<div class="row decide"><button class="primary" name="action" value="approve">Approve ticked</button>
<button class="danger" name="action" value="deny">Deny all</button></div></div></form>
${already}`;
}

/** Live rules first, then expired and used-up ones under a muted subheading; indexes stay the grant's own so Revoke hits the right rule. */
function ruleRows(g: ListedGrant, csrf: string): string {
  const now = Date.now();
  const row = (r: ListedGrant['rules'][number], i: number): string => {
    const live = isLive(r, now);
    const handles = r.secrets.map((s) => `secret://${[r.tier].flat()[0]}/${s}`);
    const prod = [r.tier].flat().includes('production');
    const wide = prod || (r.hosts ?? []).some((h) => h.startsWith('*.'));
    const life = live ? limitText(r, now) || 'no expiry, no use limit' : '';
    return `<div class="srow${wide && live ? ' risk' : ''}"><div class="sname">${handles.map((h) => `<code>${esc(h)}</code>`).join(' · ')}${prod ? '<span class="tag prod">production</span>' : ''}${r.action === 'reveal' ? '<span class="tag warn">reveal</span>' : ''}</div>
<div class="smeta">${r.description ? `${esc(r.description)} · ` : ''}approved by ${esc(r.approvedBy)}, ${esc(stamp(r.approvedAt))}${life ? ` · ${esc(life)}` : ''}${r.state === 'expired' ? '<span class="tag muted">expired</span>' : r.state === 'used_up' ? '<span class="tag muted">used up</span>' : ''}</div>
<div class="sact">${confirmAction({ label: 'Revoke', action: '/approvals/revoke', fields: { csrf, repo: g.repo, index: String(i) }, consequence: `Stops <code>${esc(g.repo)}</code> using ${handles.map((h) => `<code>${esc(h)}</code>`).join(', ')}.`, aria: `Revoke ${handles.join(', ')} for ${g.repo}`, quiet: !live })}</div>
<div class="dl">${itemDetail(r)}</div></div>`;
  };
  const all = g.rules.map((r, i) => ({ r, i }));
  const liveRows = all.filter((x) => isLive(x.r, now)).map((x) => row(x.r, x.i)).join('');
  const dead = all.filter((x) => !isLive(x.r, now)).map((x) => row(x.r, x.i)).join('');
  return `${liveRows}${dead ? `<h4 class="inactive">No longer active</h4>${dead}` : ''}`;
}

export function renderApprovals(
  grants: ListedGrant[],
  pending: AccessRequest[],
  csrf: string,
  user: string,
  vaultPending: Array<{ id: string; slug: string; repo: string; reason: string }> = [],
  st: NavStatus = {},
): string {
  const vp = vaultPending.map(
    (r) => `<a class="card cardlink" href="/approve-vault/${esc(r.id)}"><div class="what"><strong>New vault <code>${esc(r.slug)}</code></strong> for <code>${esc(r.repo)}</code><div class="muted">${esc(r.reason)}</div></div><span class="go">Review</span></a>`,
  );
  const ap = pending.map((r) => {
    const risky = r.items.filter((it) => riskOf(it)).length;
    return `<a class="card cardlink" href="/approve/${esc(r.id)}"><div class="what"><strong><code>${esc(r.repo)}</code></strong> · ${r.items.length} secret${r.items.length === 1 ? '' : 's'}${risky ? `<span class="tag prod">${risky} need care</span>` : ''}<div class="muted">${esc(r.reason)}</div></div><span class="go">Review</span></a>`;
  });
  const pend = vp.length || ap.length ? [...vp, ...ap].join('') : '<p class="muted">Nothing is waiting. When Claude asks for a secret, the request shows up here and in the chat as a link.</p>';
  const gr = grants.length
    ? grants
        .map(
          (g) => `<section class="list" aria-label="${esc(g.repo)}"><div class="lhead split"><h3><code>${esc(g.repo)}</code></h3>${confirmAction({
            label: 'Revoke all',
            action: '/approvals/revoke',
            fields: { csrf, repo: g.repo },
            consequence: `<code>${esc(g.repo)}</code> loses access to all ${g.rules.reduce((n, r) => n + r.secrets.length, 0)} approved secret(s) straight away. Claude will have to ask again.`,
            aria: `Revoke all access for ${g.repo}`,
          })}</div>
${ruleRows(g, csrf)}</section>`,
        )
        .join('')
    : '<p class="muted">Nothing approved yet.</p>';
  return `${nav('/approvals', user, st)}<h1>Approvals</h1>
<h2>Waiting for you</h2>${pend}<h2>Approved</h2>${gr}`;
}

/** One timestamp format everywhere: 2026-10-07 15:53 UTC. */
export function stamp(ms?: number | string | null): string {
  if (ms === undefined || ms === null || ms === '') return '—';
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

export async function requireSession(req: Request, env: Env): Promise<Session | Response> {
  const s = await readSession(env.COOKIE_ENCRYPTION_KEY, req.headers.get('Cookie'));
  if (s && isAllowedUser(env, s.githubId)) return s;
  const u = new URL(req.url);
  return Response.redirect(new URL(`/login?next=${encodeURIComponent(u.pathname + u.search)}`, u).href, 302);
}

const NAV: Array<[string, string]> = [
  ['/vault', 'Secrets'],
  ['/vaults', 'Vaults'],
  ['/approvals', 'Approvals'],
  ['/machines', 'Machines'],
  ['/connectors', 'Connectors'],
  ['/deploy', 'Deploy'],
  ['/audit', 'Audit'],
  ['/backups', 'Backups'],
  ['/settings', 'Settings'],
];

export interface NavStatus {
  frozen?: boolean;
  pending?: number;
  flash?: string;
}

/** Fixed confirmation messages, picked by key so nothing from the URL is echoed. */
const FLASH: Record<string, string> = {
  added: 'Secret saved.',
  converted: 'Converted to config. Its value is now shown here.',
  config_saved: 'Config saved. The previous value is kept in history.',
  login_saved: 'Login details saved.',
  replaced: 'New value saved. The previous one is kept in history.',
  restored: 'That version is current again.',
  trashed: 'Moved to trash. You can restore it from Trash for 30 days.',
  undeleted: 'Restored from trash.',
  purged: 'Deleted for good.',
  moved: 'Moved. Approvals for the old handle no longer apply.',
  vault_created: 'Vault created. Add its secrets below.',
  vault_saved: 'Vault saved.',
  vault_deleted: 'Vault deleted.',
  vault_denied: 'Vault request denied.',
  machine_revoked: 'Token revoked. That machine can no longer read secrets.',
  registration_opened: 'New connections allowed for 15 minutes.',
  registration_closed: 'New connections closed.',
  connector_removed: 'App removed. Its tokens are revoked.',
  backup: 'Backup saved.',
  frozen: 'Vault frozen. No secret can be used until you unfreeze it.',
  unfrozen: 'Vault unfrozen. Approved access works again.',
  rotated: 'Everything is re-encrypted with the current key.',
  revoked: 'Access revoked.',
  conn_added: 'Connection saved.',
  conn_token_replaced: 'Token replaced.',
  conn_removed: 'Connection removed. Its push history is kept.',
  link_saved: 'Link saved.',
  redeployed: 'Redeploy started.',
};

export function seeOther(location: string): Response {
  return new Response(null, { status: 303, headers: { Location: location, ...SECURITY_HEADERS } });
}

export function hidden(csrf: string): string {
  return `<input type="hidden" name="csrf" value="${esc(csrf)}">`;
}

/** Add a confirmation key to a redirect target. */
export function done(location: string, key: keyof typeof FLASH & string): string {
  return `${location}${location.includes('?') ? '&' : '?'}done=${key}`;
}

/** Freeze state, waiting requests and any confirmation, for the top bar. Never throws. */
export async function navStatus(store: unknown, url: string): Promise<NavStatus> {
  const s = store as { isFrozen?: () => Promise<boolean>; listRequests?: () => Promise<unknown[]>; listVaultRequests?: () => Promise<unknown[]> };
  const key = new URL(url).searchParams.get('done') ?? '';
  const [frozen, a, b] = await Promise.all([
    s.isFrozen?.().catch(() => false) ?? false,
    s.listRequests?.().catch(() => []) ?? [],
    s.listVaultRequests?.().catch(() => []) ?? [],
  ]);
  return { frozen: Boolean(frozen), pending: (a?.length ?? 0) + (b?.length ?? 0), flash: Object.hasOwn(FLASH, key) ? FLASH[key] : undefined };
}

export function nav(active: string, user: string, st: NavStatus = {}): string {
  const links = NAV.map(([href, label]) => {
    const badge = href === '/approvals' && st.pending ? ` <span class="count">${st.pending}<span class="sr"> waiting</span></span>` : '';
    return `<a href="${href}"${href === active ? ' class="on" aria-current="page"' : ''}>${label}${badge}</a>`;
  }).join('');
  const frozen = st.frozen
    ? `<div class="banner frozen" role="status"><span>Vault is frozen: no secret can be used by Claude or any machine.</span>${active === '/settings' ? '' : '<a href="/settings">Unfreeze in Settings</a>'}</div>`
    : '';
  const flash = st.flash ? `<div class="banner flash" role="status">${esc(st.flash)}</div>` : '';
  return `<header class="top"><div class="bar"><a class="brand" href="/vault">${BRAND}<span>Vault</span></a><nav aria-label="Main">${links}</nav><span class="who" title="Signed in with GitHub"><span>${esc(user)}</span><i aria-hidden="true">${esc(user.slice(0, 1))}</i></span></div></header>${frozen}${flash}`;
}

// ---------- GitHub ----------

export type GithubResult = { id: number; login: string } | { error: string };

/** Exchange GitHub's one-time code for the user's id and login. Errors carry GitHub's error code, never secrets. */
export async function githubUser(env: Env, code: string, redirectUri: string): Promise<GithubResult> {
  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', 'User-Agent': 'secret-broker-remote' },
    body: new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: redirectUri }).toString(),
  });
  const tokenBody = (await tokenRes.json().catch(() => ({}))) as { access_token?: string; error?: string; error_description?: string };
  if (!tokenRes.ok || !tokenBody.access_token) {
    const error = `token exchange: ${tokenBody.error ?? `HTTP ${tokenRes.status}`}${tokenBody.error_description ? ` (${tokenBody.error_description})` : ''}`;
    console.error(JSON.stringify({ event: 'github_login_error', error }));
    return { error };
  }
  const userRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${tokenBody.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'secret-broker-remote' },
  });
  const user = (await userRes.json().catch(() => ({}))) as { id?: number; login?: string; message?: string };
  if (!userRes.ok || typeof user.id !== 'number' || !user.login) {
    const error = `user lookup: HTTP ${userRes.status}${user.message ? ` (${user.message})` : ''}`;
    console.error(JSON.stringify({ event: 'github_login_error', error }));
    return { error };
  }
  return { id: user.id, login: user.login };
}

// ---------- routes ----------

type App<B extends Env> = Hono<{ Bindings: B }>;

export interface WebDeps {
  grants?: (env: Env) => Grants;
  /** Overridable for tests. */
  github?: typeof githubUser;
}

function safeNext(next: string | null | undefined): string {
  // Same-origin paths only. Control characters are refused because browsers strip a tab or
  // newline from a Location header, which would turn "/<TAB>/evil" into "//evil". Anything
  // outside printable ASCII, or too long for the sign-in cookie that carries it, is refused too.
  return next && next.length <= 1500 && next.startsWith('/') && !next.startsWith('//') && !/[^\x21-\x7e]|\\/.test(next) ? next : '/approvals';
}

export function registerWebRoutes<B extends Env>(app: App<B>, deps: WebDeps = {}): void {
  const grants = deps.grants ?? ((env: Env) => vaultFor(env) as unknown as Grants);
  const github = deps.github ?? githubUser;


  app.get('/', (c) => c.redirect('/vault'));

  // Sign-in keeps no server state: the state and return path ride in a signed, short-lived cookie,
  // so a stranger opening /login cannot cause a storage write.
  app.get('/login', async (c) => {
    const state = crypto.randomUUID();
    const payload = btoa(JSON.stringify({ state, next: safeNext(c.req.query('next')), exp: Math.floor(Date.now() / 1000) + LOGIN_TTL_S })).replace(/=+$/, '');
    const cookie = `${payload}.${await hmacHex(c.env.COOKIE_ENCRYPTION_KEY, `weblogin:${payload}`)}`;
    const gh = new URL('https://github.com/login/oauth/authorize');
    gh.searchParams.set('client_id', c.env.GITHUB_CLIENT_ID);
    gh.searchParams.set('redirect_uri', new URL('/callback/web', c.req.url).href);
    gh.searchParams.set('scope', 'read:user');
    gh.searchParams.set('state', state);
    return new Response(null, {
      status: 302,
      headers: { Location: gh.href, 'Set-Cookie': `${LOGIN_COOKIE}=${cookie}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${LOGIN_TTL_S}` },
    });
  });

  /** The login cookie's payload when its signature and expiry hold, else null. */
  async function readLogin(secret: string, header: string | null): Promise<{ state: string; next: string } | null> {
    const [payload, sig] = (getCookie(header, LOGIN_COOKIE) ?? '').split('.');
    if (!payload || !sig || !safeEqual(sig, await hmacHex(secret, `weblogin:${payload}`))) return null;
    try {
      const l = JSON.parse(atob(payload)) as { state?: unknown; next?: unknown; exp?: unknown };
      return typeof l.state === 'string' && typeof l.next === 'string' && typeof l.exp === 'number' && l.exp * 1000 > Date.now() ? { state: l.state, next: l.next } : null;
    } catch {
      return null;
    }
  }

  app.get('/callback/web', async (c) => {
    const state = c.req.query('state') ?? '';
    const code = c.req.query('code') ?? '';
    const login = await readLogin(c.env.COOKIE_ENCRYPTION_KEY, c.req.header('Cookie') ?? null);
    if (!state || !code || !login || !safeEqual(login.state, state)) {
      return page('Sign-in failed', '<h1>Sign-in failed</h1><p>The sign-in link expired or was started in another browser. <a href="/vault">Sign in again</a>.</p>', 400);
    }
    const next = login.next;
    const user = await github(c.env, code, new URL('/callback/web', c.req.url).href);
    if ('error' in user) return page('Sign-in failed', `<h1>Sign-in failed</h1><p>GitHub said: <code>${esc(user.error)}</code></p>`, 502);
    if (!isAllowedUser(c.env, String(user.id))) {
      console.log(JSON.stringify({ event: 'web_login_refused', githubId: user.id, login: user.login }));
      return page('Not allowed', `<h1>Not allowed</h1><p>GitHub account ${esc(user.login)} cannot approve access here.</p>`, 403);
    }
    const session = await signSession(c.env.COOKIE_ENCRYPTION_KEY, {
      githubId: String(user.id),
      login: user.login,
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL_S,
    });
    const headers = new Headers({ Location: safeNext(next) });
    headers.append('Set-Cookie', `${SESSION_COOKIE}=${session}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${SESSION_TTL_S}`);
    headers.append('Set-Cookie', `${LOGIN_COOKIE}=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0`);
    return new Response(null, { status: 302, headers });
  });

  app.get('/approve/:id', async (c) => {
    const s = await requireSession(c.req.raw, c.env);
    if (s instanceof Response) return s;
    const req = await grants(c.env).getRequest(c.req.param('id'));
    const st = await navStatus(grants(c.env), c.req.url);
    if (!req) return page('Not found', `${nav('/approvals', s.login, st)}<h1>Request not found</h1><p>It was already approved, denied or has expired. <a href="/approvals">See all approvals</a></p>`, 404);
    const csrf = await csrfToken(c.env.COOKIE_ENCRYPTION_KEY, s, `approve:${req.id}`);
    const existing = await grants(c.env).getGrant(req.repo).catch(() => null);
    return page(`Approve ${req.repo}`, renderRequest(req, csrf, s.login, st, existing));
  });

  app.post('/approve/:id', async (c) => {
    const s = await requireSession(c.req.raw, c.env);
    if (s instanceof Response) return s;
    const id = c.req.param('id');
    const form = await c.req.raw.formData();
    const expected = await csrfToken(c.env.COOKIE_ENCRYPTION_KEY, s, `approve:${id}`);
    if (!safeEqual(String(form.get('csrf') ?? ''), expected))
      return page('Expired', `<h1>This form expired</h1><p>Nothing was approved. <a href="/approve/${esc(id)}">Open the request again</a> and choose once more.</p>`, 403);

    const store = grants(c.env);
    const req = await store.getRequest(id);
    if (!req) return page('Not found', '<h1>Request not found</h1><p>It was already approved, denied or has expired. <a href="/approvals">See all approvals</a></p>', 404);

    if (form.get('action') === 'deny') {
      await store.deny(id);
      console.log(JSON.stringify({ event: 'access_denied', repo: req.repo, by: s.login, handles: req.items.map((i) => i.handle) }));
      return page('Denied', `<h1>Denied</h1><p>Nothing was granted for <code>${esc(req.repo)}</code>. Claude will be told the request was denied.</p><p><a href="/approvals">See all approvals</a></p>`);
    }

    const selected = form.getAll('item').map((v) => Number(v));
    if (!selected.length)
      return page('Nothing ticked', `<h1>Nothing was ticked</h1><p>No secret was approved and the request is still open. <a href="/approve/${esc(id)}">Go back</a> and tick the secrets to allow, or use Deny all.</p>`, 400);
    const limits = parseLimits(form, req, selected);
    if (typeof limits === 'string') return page('Not approved', `<h1>Not approved</h1><p>${esc(limits)}</p><p><a href="/approve/${esc(id)}">Back to the request</a></p>`, 400);
    try {
      const grant = await store.approve(id, selected, s.login, limits);
      const approvedItems = selected.map((i) => req.items[i]).filter((x): x is NonNullable<typeof x> => Boolean(x));
      console.log(JSON.stringify({ event: 'access_approved', repo: req.repo, by: s.login, handles: approvedItems.map((i) => i.handle) }));
      return page(
        'Approved',
        `<h1 class="ok">Approved</h1><p>${approvedItems.length} secret${approvedItems.length === 1 ? '' : 's'} approved for <code>${esc(grant.repo)}</code>. Tell Claude to go ahead.</p>
${approvedItems.map((it) => `<div class="card"><code>${esc(it.handle)}</code>${tierTag(it.handle)}${itemDetail(it)}</div>`).join('')}
<p class="muted">Limits apply as chosen. <a href="/approvals">Review or revoke approvals</a></p>`,
      );
    } catch (err) {
      return page('Not approved', `<h1>Not approved</h1><p>${esc((err as Error).message)}</p><p><a href="/approve/${esc(id)}">Back to the request</a></p>`, 400);
    }
  });

  app.get('/approvals', async (c) => {
    const s = await requireSession(c.req.raw, c.env);
    if (s instanceof Response) return s;
    const store = grants(c.env);
    const withVaults = store as Grants & { listVaultRequests?: () => Promise<Array<{ id: string; slug: string; repo: string; reason: string }>> };
    const [g, p, vp] = await Promise.all([store.listGrants(), store.listRequests(), withVaults.listVaultRequests?.() ?? Promise.resolve([])]);
    const csrf = await csrfToken(c.env.COOKIE_ENCRYPTION_KEY, s, 'revoke');
    return page('Approvals', renderApprovals(g, p, csrf, s.login, vp, await navStatus(store, c.req.url)));
  });

  app.post('/approvals/revoke', async (c) => {
    const s = await requireSession(c.req.raw, c.env);
    if (s instanceof Response) return s;
    const form = await c.req.raw.formData();
    const expected = await csrfToken(c.env.COOKIE_ENCRYPTION_KEY, s, 'revoke');
    if (!safeEqual(String(form.get('csrf') ?? ''), expected))
      return page('Expired', '<h1>This form expired</h1><p>Nothing was revoked. <a href="/approvals">Open Approvals again</a> and try once more.</p>', 403);
    const repo = String(form.get('repo') ?? '');
    const indexRaw = form.get('index');
    const index = indexRaw === null ? undefined : Number(indexRaw);
    try {
      await grants(c.env).revoke(repo, index);
      console.log(JSON.stringify({ event: 'access_revoked', repo, index: index ?? 'all', by: s.login }));
    } catch (err) {
      return page('Error', `<h1>Could not revoke</h1><p>${esc((err as Error).message)}</p><p>Nothing was changed. <a href="/approvals">Back to Approvals</a></p>`, 400);
    }
    return new Response(null, { status: 303, headers: { Location: done('/approvals', 'revoked'), ...SECURITY_HEADERS } });
  });
}
