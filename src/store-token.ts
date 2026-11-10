import { createInterface } from 'node:readline';
import { storeTierToken } from './keychain.js';
import { isTier } from './types.js';
import type { Tier } from './types.js';

/** Read one line without echoing it to the terminal. */
function promptHidden(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const out = process.stdout as NodeJS.WriteStream & { _writeToOutput?: unknown };
    process.stdout.write(question);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- readline hides input only via this private hook
    (rl as any)._writeToOutput = () => {};
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
    void out;
  });
}

async function main(): Promise<void> {
  const tier = process.argv[2] as Tier | undefined;
  if (!tier || !isTier(tier)) {
    process.stderr.write('usage: store-token <vault>   e.g. personal, production, acme-finance\n');
    process.exit(1);
  }

  const token = await promptHidden(`Paste the ${tier} machine token (input hidden): `);
  try {
    storeTierToken(tier, token);
  } catch (err: unknown) {
    process.stderr.write(`failed: ${String(err)}\n`);
    process.exit(1);
  }
  process.stdout.write(`stored ${tier} token in the OS keychain\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`store-token failed: ${String(err)}\n`);
  process.exit(1);
});
