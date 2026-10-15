import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, it } from 'vitest';
import { ChainClient, MAX_BROADCAST_BYTES } from './index.js';

it('transports a complete 2 MiB native transaction as JSON over HTTP without retry', async () => {
  const hex = 'ab'.repeat(MAX_BROADCAST_BYTES);
  const txid = 'cd'.repeat(32);
  let count = 0, bytes = 0, path = '', contentType: string | undefined, receivedHex = '';
  const server = createServer((req, res) => {
    count++;
    path = req.url ?? '';
    contentType = req.headers['content-type'];
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => { bytes += chunk.length; chunks.push(chunk); });
    req.on('end', () => {
      receivedHex = JSON.parse(Buffer.concat(chunks).toString('utf8')).hex;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ txid }));
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const endpoint = { name: 'Local test', url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      protocol: 'esplora' as const, network: 'testnet' as const, operator: 'Test', priority: 1 };
    const client = new ChainClient({ network: 'testnet', endpoints: [endpoint], transport: { maxRetries: 0 } });
    expect((await client.broadcastTransaction(hex)).txid).toBe(txid);
    expect(count).toBe(1);
    expect(path).toBe('/api/tx');
    expect(contentType).toBe('application/json');
    expect(bytes).toBe(4_194_314);
    expect(receivedHex.length).toBe(4_194_304);
    expect(createHash('sha256').update(receivedHex).digest('hex')).toBe(createHash('sha256').update(hex).digest('hex'));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
