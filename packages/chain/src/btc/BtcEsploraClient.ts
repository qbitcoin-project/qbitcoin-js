// Bitcoin Esplora client — the minimal read/broadcast surface the upgrade
// flow needs against a PLAIN Bitcoin esplora instance (blockstream.info,
// mempool.space, or self-hosted).
//
// Deliberately separate from EsploraClient.ts: that client speaks this
// project's node dialect (scripthash endpoints, JSON broadcast, string
// enums); Bitcoin esplora is the upstream vanilla API. Sharing parsers
// would couple two protocols that only look similar. The transport layer
// (timeout/retry/error mapping) is shared.

import { ChainError } from '../errors.js';
import { request, type TransportOptions } from '../transport.js';

/**
 * Public Bitcoin esplora instances used when the caller doesn't bring its
 * own. Order = priority. Self-hosting (an `esplora`/`electrs` instance)
 * avoids leaking addresses to a third party — the Settings screen offers
 * that the same way it does for the native node.
 */
export const BTC_ESPLORA_DEFAULTS: readonly string[] = [
  'https://blockstream.info/api',
  'https://mempool.space/api',
];

/**
 * Testnet counterpart. NOTE: the node's BTC side is **testnet4** (not
 * testnet3), so blockstream.info's `/testnet/api` (testnet3) is NOT
 * usable here — mempool.space is currently the only public instance.
 */
export const BTC_ESPLORA_TESTNET_DEFAULTS: readonly string[] = [
  'https://mempool.space/testnet4/api',
];

/** Default endpoint list for a Bitcoin network. */
export function btcEsploraDefaultsFor(network: 'mainnet' | 'testnet'): readonly string[] {
  return network === 'testnet' ? BTC_ESPLORA_TESTNET_DEFAULTS : BTC_ESPLORA_DEFAULTS;
}

export interface BtcUtxo {
  readonly txid: string;
  readonly vout: number;
  /** Value in satoshi. */
  readonly value: bigint;
  readonly confirmed: boolean;
  readonly blockHeight?: number;
}

export interface BtcTxStatus {
  readonly confirmed: boolean;
  readonly blockHeight?: number;
}

/** One output of a transaction in an address history — enough to
 *  reconstruct upgrade episodes from the chain (R1 in the design doc). */
export interface BtcHistoryOutput {
  readonly scriptPubKeyHex: string;
  readonly value: bigint;
  readonly address?: string;
}

export interface BtcHistoryTx {
  readonly txid: string;
  readonly status: BtcTxStatus;
  readonly outputs: readonly BtcHistoryOutput[];
}

export interface BtcEsploraConfig {
  /** Base URL without trailing slash, e.g. `https://blockstream.info/api`. */
  readonly baseUrl: string;
  readonly transport?: TransportOptions;
}

export class BtcEsploraClient {
  private readonly base: string;
  private readonly transport: TransportOptions;

  constructor(config: BtcEsploraConfig) {
    this.base = config.baseUrl.replace(/\/+$/, '');
    this.transport = config.transport ?? {};
  }

  /** Current chain tip height. */
  async tipHeight(): Promise<number> {
    const text = await request<string>(
      { url: `${this.base}/blocks/tip/height`, expect: 'text' },
      this.transport,
    );
    const height = Number(text.trim());
    if (!Number.isInteger(height) || height < 0) {
      throw this.malformed('/blocks/tip/height', `not a block height: ${text}`);
    }
    return height;
  }

  /** Unspent outputs of an address (confirmed and mempool). */
  async addressUtxos(address: string): Promise<BtcUtxo[]> {
    const raw = await request<unknown>(
      { url: `${this.base}/address/${address}/utxo`, expect: 'json' },
      this.transport,
    );
    if (!Array.isArray(raw)) throw this.malformed('/address/utxo', 'expected an array');
    return raw.map((u) => {
      const o = asObject(u, () => this.malformed('/address/utxo', 'utxo entry'));
      const status = asObject(o.status, () => this.malformed('/address/utxo', 'utxo status'));
      return {
        txid: asString(o.txid, () => this.malformed('/address/utxo', 'txid')),
        vout: asUint(o.vout, () => this.malformed('/address/utxo', 'vout')),
        value: BigInt(asUint(o.value, () => this.malformed('/address/utxo', 'value'))),
        confirmed: status.confirmed === true,
        ...(typeof status.block_height === 'number'
          ? { blockHeight: status.block_height }
          : {}),
      };
    });
  }

  /**
   * Address history (newest first, first page — esplora returns up to 50;
   * ample for a staging address that sees a handful of transactions).
   */
  async addressTxs(address: string): Promise<BtcHistoryTx[]> {
    const raw = await request<unknown>(
      { url: `${this.base}/address/${address}/txs`, expect: 'json' },
      this.transport,
    );
    if (!Array.isArray(raw)) throw this.malformed('/address/txs', 'expected an array');
    return raw.map((t) => {
      const o = asObject(t, () => this.malformed('/address/txs', 'tx entry'));
      const status = asObject(o.status, () => this.malformed('/address/txs', 'tx status'));
      const vout = Array.isArray(o.vout) ? o.vout : [];
      return {
        txid: asString(o.txid, () => this.malformed('/address/txs', 'txid')),
        status: {
          confirmed: status.confirmed === true,
          ...(typeof status.block_height === 'number'
            ? { blockHeight: status.block_height }
            : {}),
        },
        outputs: vout.map((v) => {
          const vo = asObject(v, () => this.malformed('/address/txs', 'vout entry'));
          return {
            scriptPubKeyHex: asString(vo.scriptpubkey, () => this.malformed('/address/txs', 'scriptpubkey')),
            value: BigInt(asUint(vo.value, () => this.malformed('/address/txs', 'vout value'))),
            ...(typeof vo.scriptpubkey_address === 'string'
              ? { address: vo.scriptpubkey_address }
              : {}),
          };
        }),
      };
    });
  }

  /** Fee estimates: confirmation target (blocks) → sat/vB (float). */
  async feeEstimates(): Promise<ReadonlyMap<number, number>> {
    const raw = await request<unknown>(
      { url: `${this.base}/fee-estimates`, expect: 'json' },
      this.transport,
    );
    const o = asObject(raw, () => this.malformed('/fee-estimates', 'expected an object'));
    const out = new Map<number, number>();
    for (const [k, v] of Object.entries(o)) {
      const target = Number(k);
      if (Number.isInteger(target) && typeof v === 'number' && v > 0) {
        out.set(target, v);
      }
    }
    if (out.size === 0) throw this.malformed('/fee-estimates', 'no usable entries');
    return out;
  }

  /** Confirmation status of a transaction. */
  async txStatus(txid: string): Promise<BtcTxStatus> {
    const raw = await request<unknown>(
      { url: `${this.base}/tx/${txid}/status`, expect: 'json' },
      this.transport,
    );
    const o = asObject(raw, () => this.malformed('/tx/status', 'expected an object'));
    return {
      confirmed: o.confirmed === true,
      ...(typeof o.block_height === 'number' ? { blockHeight: o.block_height } : {}),
    };
  }

  /**
   * Broadcast a raw transaction (hex). Returns the txid. Esplora takes the
   * hex as a text/plain body and answers with the txid as plain text.
   */
  async broadcast(rawTxHex: string): Promise<string> {
    const text = await request<string>(
      {
        url: `${this.base}/tx`,
        method: 'POST',
        body: rawTxHex,
        expect: 'text',
      },
      this.transport,
    );
    const txid = text.trim();
    if (!/^[0-9a-f]{64}$/.test(txid)) {
      throw this.malformed('/tx', `broadcast did not return a txid: ${text.slice(0, 120)}`);
    }
    return txid;
  }

  private malformed(endpoint: string, detail: string): ChainError {
    return new ChainError('malformed_response', `Bitcoin esplora ${endpoint}: ${detail}`, {
      endpoint: this.base + endpoint,
    });
  }
}

// ─── Tiny shape guards ─────────────────────────────────────────────────

function asObject(v: unknown, err: () => ChainError): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw err();
  return v as Record<string, unknown>;
}

function asString(v: unknown, err: () => ChainError): string {
  if (typeof v !== 'string' || v === '') throw err();
  return v;
}

function asUint(v: unknown, err: () => ChainError): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) throw err();
  return v;
}
