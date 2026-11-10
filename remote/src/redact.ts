import { toB64 } from './crypto';

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const enc = new TextEncoder();

/** The ways a value commonly comes back from an HTTP service. */
function variants(value: string): string[] {
  const out = new Set<string>([value]);
  out.add(encodeURIComponent(value));
  out.add(encodeURIComponent(value).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
  out.add(value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!));
  out.add(JSON.stringify(value).slice(1, -1));
  out.add([...enc.encode(value)].map((b) => b.toString(16).padStart(2, '0')).join(''));
  const b64 = toB64(enc.encode(value));
  out.add(b64);
  out.add(b64.replace(/=+$/, ''));
  out.add(b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  return [...out].filter((v) => v.length > 0);
}

export interface Redactor {
  (text: string): string;
}

/**
 * Best-effort scrub, the second layer of defence (the first is that the agent
 * never receives a value). Injected values are always scrubbed; other values
 * from the same tiers are scrubbed too when at least `minOtherLength` long,
 * so a short unrelated value like "true" does not shred the output.
 */
export function makeRedactor(
  injected: Map<string, string>,
  others: Map<string, string> = new Map(),
  extra: Map<string, string> = new Map(),
  minOtherLength = 6,
): Redactor {
  const pairs: Array<[string, string]> = [];
  const add = (handle: string, value: string) => {
    for (const v of variants(value)) pairs.push([v, handle]);
  };
  for (const [h, v] of injected) if (v) add(h, v);
  for (const [h, v] of extra) if (v) add(h, v);
  for (const [h, v] of others) if (v.length >= minOtherLength) add(h, v);
  // Longest first, so a value that contains another is replaced whole.
  pairs.sort((a, b) => b[0].length - a[0].length);
  if (pairs.length === 0) return (t) => t;
  const lookup = new Map(pairs);
  const re = new RegExp(pairs.map(([v]) => escapeRe(v)).join('|'), 'g');
  return (text) => text.replace(re, (m) => `[redacted:${lookup.get(m)}]`);
}
