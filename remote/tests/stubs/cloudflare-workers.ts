// Stand-in for the `cloudflare:workers` runtime module so the Worker entry can load under Vitest.
export class WorkerEntrypoint {}
export class DurableObject {}
export class RpcTarget {}
export const env = {};
