function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Best-effort scrubbing of known secret values from child output.
 * This is the second layer of defence. The first is that the agent never
 * receives the value at all. A command that encodes a secret before
 * printing it will defeat this, by design of the threat model.
 */
export function redact(text: string, values: Map<string, string>): string {
  // Longest value first, so a secret that is a substring of another never leaves the longer
  // one half-scrubbed. Each value is also matched in the two encodings a CLI most often
  // prints it in (inside a URL, inside a JSON string).
  const entries = [...values].filter(([, v]) => v).sort((a, b) => b[1].length - a[1].length);
  let out = text;
  for (const [handle, value] of entries) {
    const forms = new Set([value, encodeURIComponent(value), JSON.stringify(value).slice(1, -1)]);
    for (const form of forms) out = out.replace(new RegExp(escapeRegExp(form), 'g'), `[redacted:${handle}]`);
  }
  return out;
}
