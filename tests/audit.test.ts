import { describe, it, expect } from 'vitest';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { appendAudit } from '../src/audit.js';
import type { AuditEntry } from '../src/audit.js';

const entry: AuditEntry = {
  ts: '2026-08-24T12:00:00.000Z',
  brokerId: 'abc',
  workspace: 'c:/work/globex',
  tier: 'client-work',
  handles: ['secret://client-work/globex-db-url'],
  command: 'npx prisma migrate deploy',
  outcome: 'allowed',
  exitCode: 0,
};

describe('appendAudit', () => {
  it('writes one JSON object per line', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'audit-'));
    const p = path.join(dir, 'audit.jsonl');
    await appendAudit(p, entry);
    await appendAudit(p, { ...entry, outcome: 'denied', reason: 'handle out of tier', exitCode: null });
    const lines = (await readFile(p, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).outcome).toBe('allowed');
    expect(JSON.parse(lines[1]).reason).toBe('handle out of tier');
  });

  it('creates the file and parent directory when absent', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'audit-'));
    const p = path.join(dir, 'nested', 'audit.jsonl');
    await appendAudit(p, entry);
    expect((await readFile(p, 'utf8')).trim()).toContain('client-work');
  });
});
