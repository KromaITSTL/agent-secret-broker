import { InMemoryTransport, LATEST_PROTOCOL_VERSION } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import { DeniedError, type Broker } from '../src/broker';
import { buildServer } from '../src/mcp';

interface Reply {
  result?: { instructions?: string; tools?: Array<{ name: string }>; content?: Array<{ text: string }>; isError?: boolean };
}

async function connect(broker: Partial<Broker>) {
  const [client, server] = InMemoryTransport.createLinkedPair();
  const replies = new Map<number, Reply>();
  client.onmessage = (m) => { if ('id' in m) replies.set(Number(m.id), m as unknown as Reply); };
  await buildServer(broker as Broker).connect(server);
  await client.start();
  let id = 0;
  const call = async (method: string, params?: object): Promise<Reply> => {
    const n = ++id;
    await client.send({ jsonrpc: '2.0', id: n, method, params } as never);
    await vi.waitFor(() => expect(replies.has(n)).toBe(true));
    return replies.get(n)!;
  };
  const init = await call('initialize', { protocolVersion: LATEST_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  await client.send({ jsonrpc: '2.0', method: 'notifications/initialized' } as never);
  return { call, init };
}

const tool = (name: string, args: object) => ({ name, arguments: args });

describe('mcp server', () => {
  it('lists secret_reveal and explains logins in the instructions', async () => {
    const { call, init } = await connect({});
    expect(init.result!.instructions).toContain('secret_reveal');
    expect(init.result!.instructions).toMatch(/Prefer secret_fetch over secret_reveal/);
    expect(init.result!.instructions).not.toContain('never try to reveal');
    expect((await call('tools/list')).result!.tools!.map((t) => t.name)).toContain('secret_reveal');
  });

  it('passes secret_reveal to the broker and maps a denial', async () => {
    const seen: unknown[] = [];
    let deny = false;
    const { call } = await connect({
      reveal: async (a) => { seen.push(a); if (deny) throw new DeniedError('nope'); return { username: 'u', password: 'p' }; },
    });
    const ok = await call('tools/call', tool('secret_reveal', { repo: 'o/r', handle: 'secret://sites/PORTAL' }));
    expect(JSON.parse(ok.result!.content![0]!.text)).toEqual({ username: 'u', password: 'p' });
    expect(seen).toEqual([{ repo: 'o/r', handle: 'secret://sites/PORTAL' }]);
    deny = true;
    const no = await call('tools/call', tool('secret_reveal', { repo: 'o/r', handle: 'secret://sites/PORTAL' }));
    expect(no.result).toMatchObject({ isError: true, content: [{ text: 'Denied by secret-broker policy: nope' }] });
  });

  it('accepts reveal items without hosts in secret_request_access', async () => {
    const seen: Array<{ items: unknown[] }> = [];
    const { call } = await connect({ requestAccess: async (a) => { seen.push(a); return { approvalUrl: 'x', repo: 'o/r', requested: [], next: '' }; } });
    const r = await call('tools/call', tool('secret_request_access', { repo: 'o/r', reason: 'sign in', items: [{ handle: 'secret://sites/PORTAL', reveal: true }] }));
    expect(r.result!.isError).toBeFalsy();
    expect(seen[0]!.items).toEqual([{ handle: 'secret://sites/PORTAL', reveal: true }]);
  });

  it('rejects malformed secret_request_access items at the schema', async () => {
    const seen: unknown[] = [];
    const { call } = await connect({ requestAccess: async (a) => { seen.push(a); return { approvalUrl: 'x', repo: 'o/r', requested: [], next: '' }; } });
    const bad: Array<[Record<string, unknown>, RegExp]> = [
      [{ handle: 'secret://sites/PORTAL' }, /exactly one of hosts/],
      [{ handle: 'secret://sites/PORTAL', hosts: ['a.example.com'], reveal: true }, /exactly one of hosts/],
      [{ handle: 'secret://sites/PORTAL', reveal: true, methods: ['GET'] }, /reveal items take no methods or paths/],
    ];
    for (const [item, msg] of bad) {
      const r = await call('tools/call', tool('secret_request_access', { repo: 'o/r', reason: 'x', items: [item] }));
      expect(JSON.stringify(r)).toMatch(msg);
    }
    expect(seen).toEqual([]);
  });
});
