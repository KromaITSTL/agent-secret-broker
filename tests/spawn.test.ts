import { describe, it, expect } from 'vitest';
import { realSpawn } from '../src/spawn.js';

describe('realSpawn', () => {
  it('captures stdout, injects env, and reports the exit code', async () => {
    const r = await realSpawn(process.execPath, ['-e', 'console.log("got:" + process.env.INJECTED)'], { INJECTED: 'v' });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('got:v');
  });

  it('reports a missing binary as a failed exit instead of crashing the process', async () => {
    const r = await realSpawn('definitely-not-a-real-binary-xyz', [], {});
    expect(r.code).not.toBe(0);
    expect(r.stderr).not.toBe('');
  });
});
