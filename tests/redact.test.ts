import { describe, it, expect } from 'vitest';
import { redact } from '../src/redact.js';

const values = new Map([
  ['secret://personal/token', 'sk-abc123'],
  ['secret://personal/other', 'pw-xyz'],
]);

describe('redact', () => {
  it('replaces a secret with its handle label', () => {
    expect(redact('using sk-abc123 now', values))
      .toBe('using [redacted:secret://personal/token] now');
  });

  it('replaces every occurrence', () => {
    expect(redact('sk-abc123 and sk-abc123', values))
      .toBe('[redacted:secret://personal/token] and [redacted:secret://personal/token]');
  });

  it('replaces multiple distinct secrets', () => {
    const out = redact('sk-abc123 then pw-xyz', values);
    expect(out).toBe('[redacted:secret://personal/token] then [redacted:secret://personal/other]');
  });

  it('leaves unrelated text untouched', () => {
    expect(redact('nothing to see', values)).toBe('nothing to see');
  });

  it('handles regex metacharacters in secret values', () => {
    const m = new Map([['secret://personal/re', 'a.*b($']]);
    expect(redact('x a.*b($ y', m)).toBe('x [redacted:secret://personal/re] y');
  });

  it('ignores empty values so it cannot blank the output', () => {
    const m = new Map([['secret://personal/empty', '']]);
    expect(redact('unchanged', m)).toBe('unchanged');
  });

  it('fully redacts a secret that is a substring of another', () => {
    const m = new Map([['secret://a/short', 'abc'], ['secret://a/long', 'abcdef123']]);
    const out = redact('x abcdef123 y abc', m);
    expect(out).toBe('x [redacted:secret://a/long] y [redacted:secret://a/short]');
    expect(out).not.toContain('def123');
  });

  it('redacts a value printed URL-encoded', () => {
    const m = new Map([['secret://a/pw', 'p@ss:w/rd']]);
    expect(redact(`https://h/?k=${encodeURIComponent('p@ss:w/rd')}`, m)).toBe('https://h/?k=[redacted:secret://a/pw]');
  });

  it('redacts a value printed JSON-escaped', () => {
    const m = new Map([['secret://a/q', 'a"b\c']]);
    expect(redact(JSON.stringify({ k: 'a"b\c' }), m)).toBe('{"k":"[redacted:secret://a/q]"}');
  });
});
