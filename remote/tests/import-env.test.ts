import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs script
import { parseEnv } from '../scripts/import-env.mjs';

describe('parseEnv', () => {
  it('handles the usual .env shapes', () => {
    const text = [
      '# comment',
      'export API_KEY=abc123',
      'PLAIN = value with spaces  # trailing comment',
      'URL=https://x.example/?a=1#frag',
      "SINGLE='it''s'",
      'DOUBLE="line1\\nline2 \\"quoted\\""',
      'MULTI="-----BEGIN KEY-----',
      'abc',
      '-----END KEY-----"',
      'EMPTY=',
      'NOEQUALS',
      'WIN=crlf\r',
    ].join('\n');
    expect(parseEnv(text)).toEqual([
      { key: 'API_KEY', value: 'abc123' },
      { key: 'PLAIN', value: 'value with spaces' },
      { key: 'URL', value: 'https://x.example/?a=1#frag' },
      { key: 'SINGLE', value: 'it' },
      { key: 'DOUBLE', value: 'line1\nline2 "quoted"' },
      { key: 'MULTI', value: '-----BEGIN KEY-----\nabc\n-----END KEY-----' },
      { key: 'EMPTY', value: '' },
      { key: 'WIN', value: 'crlf' },
    ]);
  });
});
