// Stand-in for `agents/mcp/server`; the entry test never reaches the MCP endpoint.
export function createMcpHandler() {
  return async () => new Response('mcp stub');
}
