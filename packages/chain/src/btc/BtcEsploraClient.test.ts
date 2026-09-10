import { describe, expect, it, vi } from 'vitest';
import { ChainError } from '../errors';
import { BTC_ESPLORA_DEFAULTS, BTC_ESPLORA_TESTNET_DEFAULTS, btcEsploraDefaultsFor, BtcEsploraClient } from './BtcEsploraClient';

const BASE = 'https://btc.example.org/api';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function text(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain' } });
}

function client(fetchImpl: typeof fetch): BtcEsploraClient {
  return new BtcEsploraClient({ baseUrl: BASE, transport: { fetchImpl, maxRetries: 0 } });
}

describe('BtcEsploraClient', () => {
  it('ships sane public defaults', () => {
    expect(BTC_ESPLORA_DEFAULTS.length).toBeGreaterThan(0);
    for (const url of BTC_ESPLORA_DEFAULTS) expect(url).toMatch(/^https:\/\//);
  });

  it('selects the network default lists (testnet = testnet4 instances)', () => {
    expect(btcEsploraDefaultsFor('mainnet')).toBe(BTC_ESPLORA_DEFAULTS);
    expect(btcEsploraDefaultsFor('testnet')).toBe(BTC_ESPLORA_TESTNET_DEFAULTS);
    expect(BTC_ESPLORA_TESTNET_DEFAULTS.length).toBeGreaterThan(0);
    for (const url of BTC_ESPLORA_TESTNET_DEFAULTS) {
      expect(url).toMatch(/^https:\/\//);
      // The node's BTC side is testnet4 — a plain /testnet/ (testnet3) URL is a bug.
      expect(url).toContain('testnet4');
    }
  });

  it('tipHeight parses the plain-text number', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(text('850123\n'));
    await expect(client(fetchImpl).tipHeight()).resolves.toBe(850123);
    expect(fetchImpl.mock.calls[0]![0]).toBe(`${BASE}/blocks/tip/height`);
  });

  it('tipHeight rejects garbage', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(text('not a number'));
    await expect(client(fetchImpl).tipHeight()).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });

  it('addressUtxos parses confirmed and mempool entries', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      json([
        {
          txid: 'aa'.repeat(32),
          vout: 1,
          value: 5_000_000,
          status: { confirmed: true, block_height: 850_000 },
        },
        { txid: 'bb'.repeat(32), vout: 0, value: 250_000, status: { confirmed: false } },
      ]),
    );
    const utxos = await client(fetchImpl).addressUtxos('1TestAddr');
    expect(fetchImpl.mock.calls[0]![0]).toBe(`${BASE}/address/1TestAddr/utxo`);
    expect(utxos).toHaveLength(2);
    expect(utxos[0]).toEqual({
      txid: 'aa'.repeat(32),
      vout: 1,
      value: 5_000_000n,
      confirmed: true,
      blockHeight: 850_000,
    });
    expect(utxos[1]!.confirmed).toBe(false);
    expect(utxos[1]!.blockHeight).toBeUndefined();
    expect(utxos[1]!.value).toBe(250_000n);
  });

  it('addressUtxos rejects a non-array body', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(json({ nope: true }));
    await expect(client(fetchImpl).addressUtxos('1A')).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });

  it('addressTxs extracts outputs for episode reconstruction', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      json([
        {
          txid: 'cc'.repeat(32),
          status: { confirmed: true, block_height: 850_001 },
          vout: [
            {
              scriptpubkey: '76a91456ca8180ab9c6f4b9bb8a3d84cddd8567031940788ac',
              scriptpubkey_address: '18xkFDMwt6zjkyRk6BV1sqYAr3Lyz67FSj',
              value: 4_999_295,
            },
            { scriptpubkey: '6a20' + 'ee'.repeat(32), value: 0 },
          ],
        },
      ]),
    );
    const txs = await client(fetchImpl).addressTxs('1A');
    expect(txs).toHaveLength(1);
    expect(txs[0]!.status).toEqual({ confirmed: true, blockHeight: 850_001 });
    expect(txs[0]!.outputs[0]!.address).toBe('18xkFDMwt6zjkyRk6BV1sqYAr3Lyz67FSj');
    expect(txs[0]!.outputs[1]!.scriptPubKeyHex.startsWith('6a20')).toBe(true);
    expect(txs[0]!.outputs[1]!.address).toBeUndefined();
  });

  it('feeEstimates keeps integer targets with positive rates', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      json({ '1': 22.4, '6': 8.1, '144': 1.02, bogus: 5, '3': -1 }),
    );
    const fees = await client(fetchImpl).feeEstimates();
    expect(fees.get(1)).toBeCloseTo(22.4);
    expect(fees.get(6)).toBeCloseTo(8.1);
    expect(fees.get(144)).toBeCloseTo(1.02);
    expect(fees.has(3)).toBe(false);
  });

  it('feeEstimates with nothing usable is malformed', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(json({}));
    await expect(client(fetchImpl).feeEstimates()).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });

  it('txStatus maps the esplora shape', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(json({ confirmed: true, block_height: 850_010 }));
    await expect(client(fetchImpl).txStatus('dd'.repeat(32))).resolves.toEqual({
      confirmed: true,
      blockHeight: 850_010,
    });
    expect(fetchImpl.mock.calls[0]![0]).toBe(`${BASE}/tx/${'dd'.repeat(32)}/status`);
  });

  it('broadcast POSTs the raw hex and returns the trimmed txid', async () => {
    const txid = 'ab'.repeat(32);
    const fetchImpl = vi.fn().mockResolvedValue(text(`${txid}\n`));
    const raw = '0200000001abcdef';
    await expect(client(fetchImpl).broadcast(raw)).resolves.toBe(txid);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/tx`);
    expect(init.method).toBe('POST');
    expect(init.body).toBe(raw);
  });

  it('broadcast without a txid-shaped reply is malformed', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(text('sendrawtransaction RPC error: ...'));
    const err = await client(fetchImpl).broadcast('02000000').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ChainError);
    expect((err as ChainError).code).toBe('malformed_response');
  });

  it('trims trailing slashes from the base URL', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(text('1'));
    const c = new BtcEsploraClient({
      baseUrl: `${BASE}///`,
      transport: { fetchImpl, maxRetries: 0 },
    });
    await c.tipHeight();
    expect(fetchImpl.mock.calls[0]![0]).toBe(`${BASE}/blocks/tip/height`);
  });
});
