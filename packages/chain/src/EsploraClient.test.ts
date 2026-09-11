import { describe, expect, it, vi } from 'vitest';
import { ChainError } from './errors.js';
import { EsploraClient } from './EsploraClient.js';
import type { NodeEndpoint } from './nodes.js';
import addressInfoFixture from './fixtures/address-info.json';
import utxosFixture from './fixtures/utxos.json';
import txFixture from './fixtures/tx.json';
import feesFixture from './fixtures/fee-estimates.json';
import statusFixture from './fixtures/status.json';

const ENDPOINT: NodeEndpoint = {
  name: 'Test',
  url: 'https://test.local',
  protocol: 'esplora',
  network: 'mainnet',
  operator: 'Test',
  priority: 1,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain' } });
}

function makeClient(fetchImpl: typeof fetch): EsploraClient {
  return new EsploraClient(ENDPOINT, { fetchImpl, maxRetries: 0 });
}

describe('EsploraClient.constructor', () => {
  it('rejects non-esplora endpoints', () => {
    expect(
      () =>
        new EsploraClient({
          ...ENDPOINT,
          protocol: 'jsonrpc',
        }),
    ).toThrow(/esplora/);
  });
});

describe('EsploraClient.getBlockchainInfo', () => {
  it('parses tip height + hash from two plain-text endpoints', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockImplementation((url) => {
        const u = String(url);
        if (u.endsWith('/api/blocks/tip/height')) return Promise.resolve(textResponse('123456'));
        if (u.endsWith('/api/blocks/tip/hash')) return Promise.resolve(textResponse('abcdef'));
        return Promise.resolve(new Response('', { status: 404 }));
      });
    const client = makeClient(fetchImpl);
    const info = await client.getBlockchainInfo();
    expect(info).toEqual({
      tipHeight: 123456,
      tipHash: 'abcdef',
      network: 'mainnet',
    });
  });

  it('throws malformed_response on non-integer tip height', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockImplementation((url) => {
        const u = String(url);
        if (u.endsWith('/api/blocks/tip/height')) return Promise.resolve(textResponse('not-a-number'));
        if (u.endsWith('/api/blocks/tip/hash')) return Promise.resolve(textResponse('abcdef'));
        return Promise.resolve(new Response('', { status: 404 }));
      });
    const client = makeClient(fetchImpl);
    await expect(client.getBlockchainInfo()).rejects.toMatchObject({
      name: 'ChainError',
      code: 'malformed_response',
    });
  });
});

describe('EsploraClient.getAddressInfo', () => {
  it('parses the fixture into normalized AddressInfo', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(addressInfoFixture));
    const client = makeClient(fetchImpl);
    const info = await client.getAddressInfo(addressInfoFixture.address);
    expect(info.address).toBe(addressInfoFixture.address);
    expect(info.chain.fundedTxCount).toBe(3);
    expect(info.chain.fundedSum).toBe(500_000_000n);
    expect(info.chain.spentSum).toBe(100_000_000n);
    expect(info.mempool.fundedTxCount).toBe(0);
  });

  it('accepts numeric-string sums (node sends spent_txo_sum as a string)', async () => {
    const raw = {
      address: 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU',
      chain_stats: {
        funded_txo_count: 2,
        funded_txo_sum: 19999,
        spent_txo_count: 2,
        spent_txo_sum: '19999',
        tx_count: 3,
      },
      mempool_stats: {
        funded_txo_count: 0,
        funded_txo_sum: 0,
        spent_txo_count: 0,
        spent_txo_sum: 0,
        tx_count: 0,
      },
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const client = makeClient(fetchImpl);
    const info = await client.getAddressInfo('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    expect(info.chain.fundedSum).toBe(19999n);
    expect(info.chain.spentSum).toBe(19999n);
  });

  it('rejects empty address with invalid_argument', async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const client = makeClient(fetchImpl);
    await expect(client.getAddressInfo('')).rejects.toMatchObject({
      code: 'invalid_argument',
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('URL-encodes the address path segment', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(addressInfoFixture));
    const client = makeClient(fetchImpl);
    await client.getAddressInfo('weird/addr#fragment');
    const url = String(fetchImpl.mock.calls[0]?.[0]);
    expect(url).toContain('/api/address/weird%2Faddr%23fragment');
  });

  it('throws malformed_response when fund sum is missing', async () => {
    const bad = {
      address: 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU',
      chain_stats: {
        funded_txo_count: 1,
        spent_txo_count: 0,
        spent_txo_sum: 0,
        tx_count: 1,
        // funded_txo_sum missing
      },
      mempool_stats: addressInfoFixture.mempool_stats,
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(bad));
    const client = makeClient(fetchImpl);
    await expect(client.getAddressInfo('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU')).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });
});

describe('EsploraClient.listUnspent', () => {
  it('parses the fixture into normalized UTXOs', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(utxosFixture));
    const client = makeClient(fetchImpl);
    const utxos = await client.listUnspent('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    expect(utxos).toHaveLength(2);
    const first = utxos[0]!;
    expect(first.value).toBe(250_000_000n);
    expect(first.status.confirmed).toBe(true);
    expect(first.status.blockHeight).toBe(105432);
    const second = utxos[1]!;
    expect(second.status.confirmed).toBe(false);
    expect(second.status.blockHeight).toBeUndefined();
  });

  it('throws malformed_response when response is not an array', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ not: 'an array' }));
    const client = makeClient(fetchImpl);
    await expect(client.listUnspent('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU')).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });

  it('returns empty array for an unused address', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse([]));
    const client = makeClient(fetchImpl);
    const utxos = await client.listUnspent('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    expect(utxos).toEqual([]);
  });

  it('also accepts standard-Esplora object status (backward compat)', async () => {
    const raw = [
      {
        txid: 'aa',
        vout: 0,
        value: 5000,
        status: { confirmed: true, block_height: 9, block_hash: 'h', block_time: 1 },
      },
    ];
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const client = makeClient(fetchImpl);
    const utxos = await client.listUnspent('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    expect(utxos[0]!.status.confirmed).toBe(true);
    expect(utxos[0]!.status.blockHeight).toBe(9);
  });

  it('parses a token UTXO (token_id + token_amount, native value 0)', async () => {
    const raw = [
      {
        txid: 'ceca437f170e5e6e8f7f05fa4f0010ca0f1cc31c376fc2f29e4d23873cef6ca3',
        vout: 0,
        value: 0,
        status: 'confirmed',
        height: 1354179,
        token_id:
          '8b33404b9e184215e783081af45702e2d8911b08f656f2f0724d5dda73279ccd',
        token_amount: 56753706,
      },
    ];
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const utxo = (await makeClient(fetchImpl).listUnspent('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU'))[0]!;
    expect(utxo.value).toBe(0n);
    expect(utxo.tokenId).toBe(
      '8b33404b9e184215e783081af45702e2d8911b08f656f2f0724d5dda73279ccd',
    );
    expect(utxo.tokenAmount).toBe(56753706n);
  });

  it('treats a native change output tagged with token_id (no token_amount) as native coin', async () => {
    // The node tags every output of a token tx with the token id, including the
    // native-coin change. That change has a positive value and no token_amount, so it
    // must be an ordinary native coin — not a zero-amount token UTXO.
    const raw = [
      {
        txid: 'd5578c566b940138615149913cd2eca27c67403333cb0a9115e829601b6bb97e',
        vout: 2,
        value: 4967986,
        status: 'confirmed',
        height: 1462729,
        token_id: '8b33404b9e184215e783081af45702e2d8911b08f656f2f0724d5dda73279ccd',
      },
    ];
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const utxo = (await makeClient(fetchImpl).listUnspent('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU'))[0]!;
    expect(utxo.value).toBe(4967986n);
    expect(utxo.tokenId).toBeUndefined();
    expect(utxo.tokenAmount).toBeUndefined();
  });
});

describe('EsploraClient.getTransaction', () => {
  it('parses the fixture into normalized ChainTx', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(txFixture));
    const client = makeClient(fetchImpl);
    const tx = await client.getTransaction(txFixture.txid);
    expect(tx.txid).toBe(txFixture.txid);
    expect(tx.version).toBe(1);
    expect(tx.vin).toHaveLength(1);
    expect(tx.vout).toHaveLength(2);
    expect(tx.vout[0]!.value).toBe(250_000_000n);
    expect(tx.fee).toBe(1000n);
    expect(tx.vin[0]!.prevoutValue).toBe(300_000_000n);
  });
});

describe('EsploraClient.getAddressTransactions', () => {
  it('parses an array of transactions', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse([txFixture]));
    const client = makeClient(fetchImpl);
    const txs = await client.getAddressTransactions(addressInfoFixture.address);
    expect(txs).toHaveLength(1);
    expect(txs[0]!.txid).toBe(txFixture.txid);
    expect(txs[0]!.fee).toBe(1000n);
    const url = String(fetchImpl.mock.calls[0]?.[0]);
    expect(url).toContain('/api/address/');
    expect(url).toContain('/txs');
  });

  it('coerces vin.vout when the node sends it as a numeric string', async () => {
    // The live node sometimes serializes vin.vout as a string — the same
    // number/string inconsistency we already tolerate on sat sums. Regression
    // for "Field 'vin.vout' is not a non-negative integer: 1".
    const tx = {
      txid: 'aa',
      tx_type: 'standard',
      vin: [
        {
          txid: 'bb',
          vout: '1',
          prevout: { value: 500, scripthash_address: 'addr-source' },
        },
      ],
      vout: [{ scripthash: 'cc', scripthash_address: 'addr-out', value: 400 }],
      size: 200,
      fee: 1,
      status: { confirmed: true, block_time: 1700000000, block_height: 10 },
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse([tx]));
    const txs = await makeClient(fetchImpl).getAddressTransactions('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    expect(txs[0]!.vin[0]!.vout).toBe(1); // string "1" → number 1
    expect(txs[0]!.vin[0]!.prevoutValue).toBe(500n);
    expect(txs[0]!.vin[0]!.prevoutAddress).toBe('addr-source');
  });

  it('parses token outputs (token_id / amount / decimals)', async () => {
    const tx = {
      txid: 'tt',
      tx_type: 'tokens',
      vin: [{ txid: 'pp', vout: 0 }],
      vout: [
        {
          scripthash: 'sh',
          scripthash_address: 'addr-recipient',
          value: 0,
          token_id: 'deadbeef',
          token_amount: 23000000,
          token_decimals: 6,
        },
      ],
      size: 250,
      fee: 5,
      status: { confirmed: true, block_time: 1700000000 },
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse([tx]));
    const txs = await makeClient(fetchImpl).getAddressTransactions('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    expect(txs[0]!.version).toBe(4); // tx_type 'tokens' → 4
    const out = txs[0]!.vout[0]!;
    expect(out.tokenId).toBe('deadbeef');
    expect(out.tokenAmount).toBe(23000000n);
    expect(out.tokenDecimals).toBe(6);
    expect(out.value).toBe(0n);
  });

  it('parses token fields on a spent input (prevout)', async () => {
    const tx = {
      txid: 'tt',
      tx_type: 'tokens',
      vin: [
        {
          txid: 'pp',
          vout: 0,
          prevout: { value: 0, scripthash_address: 'addr-spent-token', token_id: 'deadbeef', token_amount: 15000000, token_decimals: 6 },
        },
      ],
      vout: [{ scripthash: 'sh', scripthash_address: 'addr-recipient', value: 0, token_id: 'deadbeef', token_amount: 5000000, token_decimals: 6 }],
      size: 250,
      fee: 5,
      status: { confirmed: true, block_time: 1700000000 },
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse([tx]));
    const txs = await makeClient(fetchImpl).getAddressTransactions('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU');
    const vin = txs[0]!.vin[0]!;
    expect(vin.prevoutAddress).toBe('addr-spent-token');
    expect(vin.prevoutTokenId).toBe('deadbeef');
    expect(vin.prevoutTokenAmount).toBe(15000000n);
    expect(vin.prevoutTokenDecimals).toBe(6);
  });

  it('returns [] for an address with no transactions', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse([]));
    const client = makeClient(fetchImpl);
    expect(await client.getAddressTransactions('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU')).toEqual([]);
  });

  it('throws malformed_response when the response is not an array', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ not: 'an array' }));
    const client = makeClient(fetchImpl);
    await expect(client.getAddressTransactions('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU')).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });
});

describe('EsploraClient.getAddressTransfers', () => {
  it('parses [txid, amount, blockHeight] tuples', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse([['d557', 10000000, 1462729]]));
    const transfers = await makeClient(fetchImpl).getAddressTransfers('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU', '8b33');
    expect(transfers).toEqual([{ txid: 'd557', amountAtomic: 10000000n, blockHeight: 1462729 }]);
  });

  it('leaves blockHeight undefined for an unconfirmed transfer (height 0)', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse([['pend', 7, 0]]));
    const [t] = await makeClient(fetchImpl).getAddressTransfers('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU', '8b33');
    expect(t).toEqual({ txid: 'pend', amountAtomic: 7n });
  });

  it('throws malformed_response when the response is not an array', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ not: 'array' }));
    await expect(makeClient(fetchImpl).getAddressTransfers('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU', '8b33')).rejects.toMatchObject({ code: 'malformed_response' });
  });
});

describe('EsploraClient.getFeeEstimates', () => {
  it('parses the fixture map', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(feesFixture));
    const client = makeClient(fetchImpl);
    const fees = await client.getFeeEstimates();
    expect(fees['1']).toBe(25.5);
    expect(fees['144']).toBe(1.0);
  });

  it('throws malformed_response when a value is not a number', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ '1': 'fast' }));
    const client = makeClient(fetchImpl);
    await expect(client.getFeeEstimates()).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });
});

describe('EsploraClient.broadcastTransaction', () => {
  const validHex = 'a'.repeat(200); // 100 bytes of "0a 0a 0a..."
  const validTxid = 'b'.repeat(64);

  it('POSTs JSON { hex } and parses the JSON { txid } success response', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ txid: validTxid }));
    const client = makeClient(fetchImpl);
    const txid = await client.broadcastTransaction(validHex);
    expect(txid).toBe(validTxid);
    const init = fetchImpl.mock.calls[0]?.[1];
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({ hex: validHex });
  });

  it('treats an empty 2xx body as success (txid is known locally)', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(textResponse(''));
    const client = makeClient(fetchImpl);
    expect(await client.broadcastTransaction(validHex)).toBe('');
  });

  it('strips whitespace from returned txid', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(textResponse(`${validTxid}\n`));
    const client = makeClient(fetchImpl);
    const txid = await client.broadcastTransaction(validHex);
    expect(txid).toBe(validTxid);
  });

  it('rejects non-hex input without calling fetch', async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const client = makeClient(fetchImpl);
    await expect(client.broadcastTransaction('not hex!!!')).rejects.toMatchObject({
      code: 'invalid_argument',
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('rejects empty hex', async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const client = makeClient(fetchImpl);
    await expect(client.broadcastTransaction('')).rejects.toMatchObject({
      code: 'invalid_argument',
    });
  });

  it('rejects hex larger than 100 KB', async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const client = makeClient(fetchImpl);
    const huge = 'a'.repeat(200_001);
    await expect(client.broadcastTransaction(huge)).rejects.toMatchObject({
      code: 'invalid_argument',
    });
  });

  it('maps 5xx to broadcast_unavailable (the current prod behavior)', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response('', { status: 500 }));
    const client = makeClient(fetchImpl);
    await expect(client.broadcastTransaction(validHex)).rejects.toMatchObject({
      name: 'ChainError',
      code: 'broadcast_unavailable',
      status: 500,
    });
  });

  it('maps 4xx to broadcast_rejected', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response('bad signature', { status: 422 }));
    const client = makeClient(fetchImpl);
    await expect(client.broadcastTransaction(validHex)).rejects.toMatchObject({
      name: 'ChainError',
      code: 'broadcast_rejected',
      status: 422,
    });
  });

  it('throws malformed_response if server returns non-txid text', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(textResponse('OK'));
    const client = makeClient(fetchImpl);
    await expect(client.broadcastTransaction(validHex)).rejects.toMatchObject({
      name: 'ChainError',
      code: 'malformed_response',
    });
  });

  it('does NOT retry on broadcast (single attempt)', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response('', { status: 503 }));
    const client = new EsploraClient(ENDPOINT, {
      fetchImpl,
      maxRetries: 5, // even if caller set retries high...
      backoffMs: 1,
    });
    await expect(
      client.broadcastTransaction(validHex),
    ).rejects.toMatchObject({ code: 'broadcast_unavailable' });
    // ...broadcast still only calls fetch once
    expect(fetchImpl).toHaveBeenCalledOnce();
  });
});

describe('ChainError', () => {
  it('preserves cause and endpoint via constructor', () => {
    const cause = new TypeError('boom');
    const err = new ChainError('network', 'msg', {
      cause,
      endpoint: 'https://x',
      status: 500,
    });
    expect(err.code).toBe('network');
    expect(err.cause).toBe(cause);
    expect(err.endpoint).toBe('https://x');
    expect(err.status).toBe(500);
  });
});

describe('EsploraClient.getNodeStatus', () => {
  it('parses sync state and the optional btc_synced flag', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({ chain: 'main', blocks: 123, initialblockdownload: false, btc_synced: false }),
      )
      .mockResolvedValueOnce(jsonResponse({ chain: 'main', blocks: 124, initialblockdownload: false }));
    const client = makeClient(fetchImpl as typeof fetch);
    // Upgrade-capable node: the flag comes through as a boolean…
    const withFlag = await client.getNodeStatus();
    expect(withFlag.blocks).toBe(123);
    expect(withFlag.btcSynced).toBe(false);
    // …a node without upgrade support simply doesn't report it, nor any of
    // the conversion-pool fields.
    const withoutFlag = await client.getNodeStatus();
    expect(withoutFlag.btcSynced).toBeUndefined();
    expect(withoutFlag.btcLockScriptHex).toBeUndefined();
    expect(withoutFlag.btcUpgraded).toBeUndefined();
    expect(withoutFlag.bestBlockHash).toBeUndefined();
  });

  it('parses the conversion pool, its running totals and the chain telemetry', async () => {
    const client = makeClient(vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(statusFixture)));
    const status = await client.getNodeStatus();
    expect(status.chain).toBe('testnet');
    expect(status.blocks).toBe(4321);
    expect(status.btcSynced).toBe(true);
    expect(status.btcHeaders).toBe(150_000);
    expect(status.btcScanned).toBe(149_990);
    expect(status.btcLockScriptHex).toBe('a914' + '11'.repeat(20) + '87');
    expect(status.btcUpgradeAddress).toBe('addr-pool');
    expect(status.btcUpgraded).toBe(900_000_000n);
    expect(status.btcDowngraded).toBe(40_000_000n);
    expect(status.minted).toBe(900_000_000n);
    expect(status.burned).toBe(40_000_000n);
    expect(status.totalCoins).toBe(860_000_000n);
    // The supply identity the node maintains.
    expect(status.minted! - status.burned!).toBe(status.totalCoins);
    expect(status.bestBlockHash).toBe('ab'.repeat(32));
    expect(status.bestBlockTime).toBe(1_700_000_000);
    expect(status.genesisTime).toBe(1_600_000_000);
    expect(status.mempoolSize).toBe(3);
    expect(status.mempoolBytes).toBe(640);
    // Fields without a documented unit stay out of the typed contract.
    expect(status).not.toHaveProperty('reward');
    expect(status).not.toHaveProperty('weight');
  });

  it('keeps running totals exact when the node serializes them as digit strings', async () => {
    // Beyond 2^53 the transport quotes the digits, so they arrive as
    // strings; the cumulative parser must keep every digit.
    const body = { ...statusFixture, btc_upgraded: '18446744073709551616', minted: '18446744073709551616' };
    const client = makeClient(vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(body)));
    const status = await client.getNodeStatus();
    expect(status.btcUpgraded).toBe(2n ** 64n);
    expect(status.minted).toBe(2n ** 64n);
  });

  it('lowercases the lock script so consumers can compare it byte for byte', async () => {
    const body = { ...statusFixture, btc_lock_script: 'A914' + 'AB'.repeat(20) + '87', bestblockhash: 'CD'.repeat(32) };
    const client = makeClient(vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(body)));
    const status = await client.getNodeStatus();
    expect(status.btcLockScriptHex).toBe('a914' + 'ab'.repeat(20) + '87');
    expect(status.bestBlockHash).toBe('cd'.repeat(32));
  });

  it.each([
    ['odd-length lock script', { btc_lock_script: 'a914' + '11'.repeat(20) + '8' }],
    ['non-hex lock script', { btc_lock_script: 'zz14' + '11'.repeat(20) + '87' }],
    ['empty lock script', { btc_lock_script: '' }],
    ['non-string pool address', { btc_upgrade_addr: 42 }],
    ['empty pool address', { btc_upgrade_addr: '' }],
    ['negative running total', { btc_upgraded: -1 }],
    ['non-numeric running total', { minted: 'abc' }],
    ['fractional running total', { burned: 1.5 }],
    ['short best block hash', { bestblockhash: 'ab'.repeat(31) }],
    ['non-integer mempool size', { mempool_size: 'many' }],
  ])('throws malformed_response on %s rather than dropping the field', async (_label, patch) => {
    const client = makeClient(vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ ...statusFixture, ...patch })));
    await expect(client.getNodeStatus()).rejects.toMatchObject({
      name: 'ChainError',
      code: 'malformed_response',
    });
  });
});

describe('EsploraClient — special transaction types', () => {
  const baseTx = {
    txid: 'aa'.repeat(32),
    vin: [{ txid: 'bb'.repeat(32), vout: 0, prevout: { value: 500_000, scripthash_address: 'addr-source' } }],
    vout: [{ scripthash: 'cc', scripthash_address: 'addr-out', value: 400_000 }],
    size: 200,
    fee: 100_000,
    status: { confirmed: true, block_time: 1_700_000_000, block_height: 10 },
  };

  it('maps slashing/burn/downgrade/upgrade_stop names to their ids', async () => {
    for (const [name, id] of [['slashing', 5], ['burn', 6], ['downgrade', 7], ['upgrade_stop', 8]] as const) {
      const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ ...baseTx, tx_type: name }));
      const tx = await makeClient(fetchImpl).getTransaction(baseTx.txid);
      expect(tx.version).toBe(id);
      expect(tx.txTypeName).toBe(name);
    }
  });

  it('does NOT fail on a tx_type this client has never heard of', async () => {
    // A new node type must degrade to "unknown", not break every history
    // fetch that touches such a transaction (slashing did exactly that).
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ ...baseTx, tx_type: 'wormhole' }));
    const tx = await makeClient(fetchImpl).getTransaction(baseTx.txid);
    expect(tx.version).toBe(0);
    expect(tx.txTypeName).toBe('wormhole');
  });

  it('parses the freeze form of downgrade_info', async () => {
    const raw = {
      ...baseTx,
      tx_type: 'downgrade',
      downgrade_info: {
        freeze_txid: 'dd'.repeat(32),
        freeze_vout: 1,
        btc_txid: 'ee'.repeat(32),
        btc_vout: 0,
        btc_value: 386_322,
        btc_scriptpubkey: '76a914' + '11'.repeat(20) + '88ac',
      },
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const tx = await makeClient(fetchImpl).getTransaction(baseTx.txid);
    expect(tx.downgradeInfo).toEqual({
      btcTxid: 'ee'.repeat(32),
      freezeTxid: 'dd'.repeat(32),
      freezeVout: 1,
      btcVout: 0,
      btcValueSat: 386_322n,
      btcScriptPubKey: '76a914' + '11'.repeat(20) + '88ac',
    });
  });

  it('parses the covenant annotation on a freeze output', async () => {
    // A freeze output (a STANDARD tx paying the covenant) carries a per-vout
    // `downgrade` object: the promised BTC address and the reclaim id.
    const raw = {
      ...baseTx,
      tx_type: 'standard',
      vout: [
        {
          scripthash: 'b7'.repeat(20),
          scripthash_address: 'btqFreeze',
          value: 40_000_000,
          downgrade: { btc_address: 'n1jP7jBBR9zxwBwz5X6JGH47W9btBfwZta', reclaim: '61EAFC'.padEnd(64, '0') },
        },
        { scripthash: 'cc', scripthash_address: 'addr-change', value: 100 },
      ],
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const tx = await makeClient(fetchImpl).getTransaction(baseTx.txid);
    expect(tx.vout[0]!.downgrade).toEqual({
      btcAddress: 'n1jP7jBBR9zxwBwz5X6JGH47W9btBfwZta',
      reclaimId: '61eafc'.padEnd(64, '0'),
    });
    expect(tx.vout[1]!.downgrade).toBeUndefined();
  });

  it('drops a non-hex reclaim placeholder but keeps the address', async () => {
    const raw = {
      ...baseTx,
      tx_type: 'standard',
      vout: [{ scripthash: 'b7'.repeat(20), value: 1, downgrade: { btc_address: 'n1jP…', reclaim: 'pending' } }],
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const tx = await makeClient(fetchImpl).getTransaction(baseTx.txid);
    expect(tx.vout[0]!.downgrade).toEqual({ btcAddress: 'n1jP…' });
    expect(tx.vout[0]!.downgrade!.reclaimId).toBeUndefined();
  });

  it('parses the burn form of downgrade_info', async () => {
    const raw = {
      ...baseTx,
      tx_type: 'burn',
      downgrade_info: { btc_txid: 'ee'.repeat(32), btc_block_hash: 'ff'.repeat(32) },
    };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    const tx = await makeClient(fetchImpl).getTransaction(baseTx.txid);
    expect(tx.downgradeInfo).toEqual({ btcTxid: 'ee'.repeat(32), btcBlockHash: 'ff'.repeat(32) });
  });

  it('keeps a uint64 token amount exact through the transport', async () => {
    // The node renders token_amount as a JSON NUMBER; above 2^53 only the
    // pre-parse quoting (jsonNumbers.ts) keeps the digits intact.
    const body = `{"txid":"${'aa'.repeat(32)}","tx_type":"tokens","size":200,"fee":1,` +
      `"status":{"confirmed":true,"block_height":10},` +
      `"vin":[{"txid":"${'bb'.repeat(32)}","vout":0,"prevout":{"value":1,"scripthash_address":"addr-s"}}],` +
      `"vout":[{"scripthash":"cc","scripthash_address":"addr-out","value":0,` +
      `"token_id":"${'8b'.repeat(32)}","token_amount":18446744073709551615}]}`;
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    const tx = await makeClient(fetchImpl).getTransaction('aa'.repeat(32));
    expect(tx.vout[0]!.tokenAmount).toBe(18446744073709551615n);
  });
});

describe('EsploraClient — cumulative sums beyond uint64', () => {
  it('accepts the float form a heavy staking address produces', async () => {
    // Real wire bytes from a foundation address with 750k+ transactions: the
    // node's own uint64 overflowed and it serialized the sums as doubles.
    const body = '{"tokens":{},"chain_stats":{"spent_txo_sum":1.5415907781994e+21,"tx_count":751820,' +
      '"funded_txo_sum":1.54159394334483e+21,"funded_txo_count":751820,"spent_txo_count":751819},' +
      '"mempool_stats":{"funded_txo_count":0,"tx_count":0,"spent_txo_sum":0,"funded_txo_sum":0,"spent_txo_count":0}}';
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    const info = await makeClient(fetchImpl).getAddressInfo('addr-whale');
    expect(info.chain.fundedSum).toBe(BigInt(1.54159394334483e21));
    expect(info.chain.fundedSum > 2n ** 64n).toBe(true);
    expect(info.chain.fundedSum - info.chain.spentSum > 0n).toBe(true);
  });

  it('still rejects a float where a transaction value must be exact', async () => {
    const raw = [{
      txid: 'a'.repeat(64), vout: 0, value: 0.5,
      status: 'confirmed', height: 10,
    }];
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(raw));
    await expect(makeClient(fetchImpl).listUnspent('addr-1')).rejects.toMatchObject({
      code: 'malformed_response',
    });
  });
});

describe('EsploraClient.getOutspend', () => {
  it('parses spent and unspent outspends', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ spent: true, txid: 'cd'.repeat(32) }))
      .mockResolvedValueOnce(jsonResponse({ spent: false }));
    const client = makeClient(fetchImpl);
    expect(await client.getOutspend('ab'.repeat(32), 0)).toEqual({ spent: true, txid: 'cd'.repeat(32) });
    expect(await client.getOutspend('ab'.repeat(32), 1)).toEqual({ spent: false });
    expect(String(fetchImpl.mock.calls[0]?.[0])).toContain(`/api/tx/${'ab'.repeat(32)}/outspend/0`);
  });
});
