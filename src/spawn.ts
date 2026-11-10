import { spawn as nodeSpawn } from 'node:child_process';
import type { SpawnFn } from './server.js';

const WIN_CMD_HINT =
  'note: on Windows, npm/npx are .cmd shims that Node refuses to spawn ' +
  'without a shell (CVE-2024-27980), and this broker never uses a shell ' +
  'because that would defeat the command allowlist. Invoke the underlying ' +
  'tool directly, e.g. "node <path-to-cli.js>". See README.';

/**
 * Spawn without a shell, always resolving instead of throwing: a failed
 * spawn must become a failed tool result, never an uncaught exception that
 * kills the broker mid-session.
 */
export const realSpawn: SpawnFn = (cmd, args, env) =>
  new Promise((resolve) => {
    const fail = (err: unknown) => {
      const hint = process.platform === 'win32' ? `\n${WIN_CMD_HINT}` : '';
      resolve({ stdout: '', stderr: `${String(err)}${hint}\n`, code: 127 });
    };

    let child: ReturnType<typeof nodeSpawn>;
    try {
      // Node throws synchronously (EINVAL) for .cmd/.bat targets here.
      child = nodeSpawn(cmd, args, { env: { ...process.env, ...env }, shell: false });
    } catch (err) {
      fail(err);
      return;
    }

    let stdout = '';
    let stderr = '';
    // Decode as a stream, not per chunk: a multi-byte character split across chunks would
    // otherwise come back as U+FFFD and dodge redaction.
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (d) => { stdout += String(d); });
    child.stderr?.on('data', (d) => { stderr += String(d); });
    child.on('error', (err) => fail(err));
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 1 }));
  });
