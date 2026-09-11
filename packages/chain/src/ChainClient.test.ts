import { describe, expect, it, vi } from 'vitest';
import { ChainClient } from './ChainClient.js';
import { ChainError } from './errors.js';
import type { NodeEndpoint } from './nodes.js';
import addressInfoFixture from './fixtures/address-info.json';

const NODE_A: NodeEndpoint = {
  name: 'A',
  url: 'https://a.test',
  protocol: 'esplora',
  network: 'mainnet',
  operator: 'Test',
  priority: 1,
};

const NODE_B: NodeEndpoint = {
  name: 'B',
  url: 'https://b.test',
  protocol: 'esplora',
  network: 'mainnet',
  operator: 'Test',
  priority: 2,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function text(body: string, status = 200): Response {
  return new Response(body, { status });
}

describe('ChainClient', () => {
  it('uses the primary endpoint when it succeeds', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(json(addressInfoFixture));
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A, NODE_B],
      transport: { fetchImpl, maxRetries: 0 },
    });
    await client.getAddressInfo('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    const calls = fetchImpl.mock.calls.map((c) => String(c[0]));
    expect(calls.every((u) => u.startsWith('https://a.test'))).toBe(true);
  });

  it('falls over to the next endpoint on 5xx', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockImplementation((url) => {
        const u = String(url);
        if (u.startsWith('https://a.test')) return Promise.resolve(text('boom', 503));
        if (u.startsWith('https://b.test')) return Promise.resolve(json(addressInfoFixture));
        return Promise.resolve(text('?', 404));
      });
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A, NODE_B],
      transport: { fetchImpl, maxRetries: 0 },
    });
    const info = await client.getAddressInfo('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    expect(info.address).toBe(addressInfoFixture.address);
    // Calls to A came first
    const calls = fetchImpl.mock.calls.map((c) => String(c[0]));
    expect(calls[0]?.startsWith('https://a.test')).toBe(true);
    expect(calls.some((u) => u.startsWith('https://b.test'))).toBe(true);
  });

  it('does NOT failover on 4xx', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(text('not found', 404));
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A, NODE_B],
      transport: { fetchImpl, maxRetries: 0 },
    });
    await expect(client.getAddressInfo('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU')).rejects.toMatchObject({
      code: 'http_4xx',
    });
    const calls = fetchImpl.mock.calls.map((c) => String(c[0]));
    // Only A was called, never B
    expect(calls.every((u) => u.startsWith('https://a.test'))).toBe(true);
  });

  it('throws when all endpoints fail with retryable errors', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(text('boom', 503));
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A, NODE_B],
      transport: { fetchImpl, maxRetries: 0 },
    });
    await expect(client.getAddressInfo('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU')).rejects.toMatchObject({
      code: 'http_5xx',
    });
  });

  it('broadcastTransaction uses only the primary endpoint', async () => {
    const validHex = 'a'.repeat(200);
    const validTxid = 'b'.repeat(64);
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockImplementation((url) => {
        const u = String(url);
        // A returns success, B should never be called
        if (u.startsWith('https://a.test')) return Promise.resolve(text(validTxid));
        throw new Error(`Should not call ${u}`);
      });
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A, NODE_B],
      transport: { fetchImpl, maxRetries: 0 },
    });
    const result = await client.broadcastTransaction(validHex);
    expect(result.txid).toBe(validTxid);
    expect(result.endpoint).toEqual(NODE_A);
  });

  it('broadcastTransaction does not failover when primary fails', async () => {
    const validHex = 'a'.repeat(200);
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockImplementation((url) => {
        const u = String(url);
        if (u.startsWith('https://a.test')) return Promise.resolve(text('', 500));
        // If we reach B we have a bug
        throw new Error(`Should not call ${u}`);
      });
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A, NODE_B],
      transport: { fetchImpl, maxRetries: 0 },
    });
    await expect(client.broadcastTransaction(validHex)).rejects.toMatchObject({
      code: 'broadcast_unavailable',
    });
  });

  // An empty endpoint list must NOT be a construction error — a wallet may
  // ship without public nodes (network not launched yet), and the app has
  // to boot so the user can add their own node in Settings. Requests fail
  // with a ChainError until then.
  it('constructs with zero endpoints and fails requests gracefully', async () => {
    const client = new ChainClient({ network: 'testnet', endpoints: [] });
    expect(client.endpoints).toEqual([]);
    await expect(client.getBlockchainInfo()).rejects.toMatchObject({
      name: 'ChainError',
      code: 'network',
    });
    await expect(client.broadcastTransaction('02000000')).rejects.toMatchObject({
      name: 'ChainError',
      code: 'broadcast_unavailable',
    });
  });

  it('exposes the network it was constructed with', () => {
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A],
    });
    expect(client.network).toBe('mainnet');
  });

  // sanity: ChainError still propagates
  it('re-throws ChainError unchanged for invalid_argument', async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const client = new ChainClient({
      network: 'mainnet',
      endpoints: [NODE_A],
      transport: { fetchImpl, maxRetries: 0 },
    });
    await expect(client.broadcastTransaction('not-hex')).rejects.toBeInstanceOf(
      ChainError,
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
