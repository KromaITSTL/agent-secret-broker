import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
export interface AuditEntry {
  ts: string;
  brokerId: string;
  workspace: string;
  /** Tier label: 'personal', or 'personal+production' for a multi-tier grant. */
  tier: string | null;
  handles: string[];
  command: string;
  outcome: 'allowed' | 'denied';
  exitCode: number | null;
  reason?: string;
}

/** Append one audit record. Never receives or writes secret values. */
export async function appendAudit(logPath: string, entry: AuditEntry): Promise<void> {
  await mkdir(path.dirname(logPath), { recursive: true });
  await appendFile(logPath, `${JSON.stringify(entry)}\n`, 'utf8');
}
