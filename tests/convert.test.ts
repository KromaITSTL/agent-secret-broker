import { describe, expect, it } from 'vitest';
import type { AuditEntry } from '../src/audit.js';
import { commandPattern, parseAudit, proposeRequests } from '../src/convert.js';

const entry = (o: Partial<AuditEntry>): AuditEntry => ({
  ts: '2026-10-01T10:00:00.000Z', brokerId: 'b', workspace: 'c:/work/site', tier: 'acme', handles: ['secret://acme/DB_URL'],
  command: 'supabase db push', outcome: 'allowed', exitCode: 0, ...o,
});

describe('commandPattern', () => {
  it('keeps a program with up to two subcommands, or an interpreter up to its script', () => {
    expect(commandPattern('supabase db push')).toBe('supabase db push');
    expect(commandPattern('supabase db push --linked')).toBe('supabase db push *');
    expect(commandPattern('vercel env pull a b c d e')).toBe('vercel env pull *');
    expect(commandPattern('node scripts/deploy.js')).toBe('node scripts/deploy.js');
    expect(commandPattern('node scripts/deploy.js --prod')).toBe('node scripts/deploy.js *');
    expect(commandPattern('node scripts/setup.mjs get TicketType/1 x')).toBe('node scripts/setup.mjs *');
    expect(commandPattern('node node_modules/tsx/dist/cli.mjs scripts/import.ts --dry')).toBe('node node_modules/tsx/dist/cli.mjs scripts/import.ts *');
    expect(commandPattern('node -e 1')).toBe('node *');
  });
});

describe('proposeRequests', () => {
  it('groups used secrets and their commands per repo, ignoring denied runs', () => {
    const repoOf = (w: string) => ({ 'c:/work/site': 'acme/site', 'c:/work/site/app': 'acme/site' } as Record<string, string>)[w] ?? null;
    const r = proposeRequests(
      [
        entry({}),
        entry({ workspace: 'c:/work/site/app', command: 'supabase db push --linked', ts: '2026-10-05T10:00:00.000Z' }),
        entry({ handles: ['secret://acme/SERVICE_KEY'], command: 'node scripts/seed.mjs' }),
        entry({ outcome: 'denied', handles: ['secret://acme/OTHER'] }),
        entry({ workspace: 'c:/work', handles: ['secret://personal/X'] }),
        entry({ handles: [] }),
      ],
      repoOf,
    );
    expect(r.proposals).toEqual([
      {
        repo: 'acme/site',
        workspaces: ['c:/work/site', 'c:/work/site/app'],
        items: [
          { handle: 'secret://acme/DB_URL', commands: ['supabase db push', 'supabase db push *'] },
          { handle: 'secret://acme/SERVICE_KEY', commands: ['node scripts/seed.mjs'] },
        ],
        firstUsed: '2026-10-01T10:00:00.000Z',
        lastUsed: '2026-10-05T10:00:00.000Z',
        runs: 3,
      },
    ]);
    expect(r.noRepo).toEqual(['c:/work']);
  });

  it('leaves out scratch-folder one-offs and patterns that could print the secret', () => {
    const r = proposeRequests(
      [
        entry({ command: 'node C:/Users/alice/AppData/Local/Temp/claude/x/scratchpad/probe.mjs read' }),
        entry({ command: 'node -e console.log(1)' }),
        entry({ command: 'node scripts/seed.mjs' }),
      ],
      () => 'acme/site',
    );
    expect(r.proposals[0]!.items).toEqual([{ handle: 'secret://acme/DB_URL', commands: ['node scripts/seed.mjs'] }]);
    expect(r.skipped.map((x) => x.why).sort()).toEqual(['could print the secret', 'one-off script in a temporary folder']);
  });

  it('parses audit lines and skips anything else', () => {
    const text = `${JSON.stringify(entry({}))}\nnot json\n{"other":1}\n\n`;
    expect(parseAudit(text)).toHaveLength(1);
  });
});
