import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const stub = (f: string) => fileURLToPath(new URL(`./tests/stubs/${f}`, import.meta.url));

export default defineConfig({
  // The Worker entry imports Workers-only modules; tests/entry.test.ts loads it against these stubs.
  resolve: { alias: { 'cloudflare:workers': stub('cloudflare-workers.ts'), 'agents/mcp/server': stub('agents-mcp-server.ts') } },
  test: { include: ['tests/**/*.test.ts'], server: { deps: { inline: [/workers-oauth-provider/] } } },
});
