// Esplora REST client — talks to one node.
//
// The shape mirrors mempool.space's Esplora API (the de facto standard
// for Bitcoin-family chains served read-only over HTTPS). We document
// every endpoint we use, the response shape we expect, and the mapping
// to our domain types.
//
// References:
//   https://github.com/Blockstream/esplora/blob/master/API.md
//
// What this client DOES NOT do:
//   - Failover between endpoints (that's ChainClient's job)
//   - Caching
//   - WebSocket subscriptions

import type {
  AddressInfo,
  AddressStats,
  BlockchainInfo,
  ChainTx,
  ChainTxIn,
  ChainTxOut,
  CoinbaseInfo,
  DowngradeInfo,
  ConfirmationStatus,
  FeeEstimates,
  NodeStatus,
  Outspend,
  TokenInfo,
  TokenTransfer,
  Utxo,
} from './types';
import type { NodeEndpoint } from './nodes';
import { ChainError } from './errors';
import { request, type TransportOptions } from './transport';

// ─── Raw Esplora response shapes ─────────────────────────────────────
//
// These match the JSON the server returns. We do NOT export them — the
// outside world only sees our normalized domain types from ./types.ts.

interface RawAddressStats {
  readonly funded_txo_count: number;
  // Sums arrive inconsistently from the node: some as JSON numbers, others
  // (notably spent_txo_sum) as numeric strings. requireBigint handles both.
  readonly funded_txo_sum: number | string;
  readonly spent_txo_count: number;
  readonly spent_txo_sum: number | string;
  readonly tx_count: number;
}

interface RawAddressInfo {
  readonly address: string;
  readonly chain_stats: RawAddressStats;
  readonly mempool_stats: RawAddressStats;
  /** token_id (hex) → balance (number or numeric string). Absent when none. */
  readonly tokens?: Record<string, unknown>;
}

interface RawTokenInfo {
  readonly token_id?: string;
  readonly decimals?: number;
  readonly issuer?: string;
  readonly name?: string;
  readonly symbol?: string;
  readonly create_time?: number;
}

interface RawConfirmationStatus {
  readonly confirmed: boolean;
  readonly block_height?: number;
  readonly block_hash?: string;
  readonly block_time?: number;
  readonly block_pos?: number;
}

interface RawUtxo {
  readonly txid: string;
  readonly vout: number;
  readonly value: number | string;
  // The node's UTXO endpoint reports confirmation as a STRING ('confirmed')
  // with the block height at the top level — unlike tx endpoints, which use a
  // nested object. parseUtxoStatus handles both shapes.
  readonly status?: RawConfirmationStatus | string;
  readonly height?: number;
  readonly block_pos?: number;
  // Token UTXOs (TRANSFER outputs) carry these.
  readonly token_id?: string;
  readonly token_amount?: number | string;
}

interface RawTxIn {
  readonly txid: string;
  readonly vout: number;
  readonly prevout?: {
    readonly value: number;
    readonly scripthash?: string;
    // Live node: scripthash_address; standard Esplora: scriptpubkey_address.
    readonly scripthash_address?: string;
    readonly scriptpubkey_address?: string;
    // Token fields when the spent output carried a token.
    readonly token_id?: string;
    readonly token_amount?: number | string;
    readonly token_decimals?: number | string;
  };
  // Unlocking script + signature list (advanced view only; not used for signing).
  readonly redeem_script?: string;
  readonly siglist?: readonly string[];
}

interface RawTxOut {
  readonly value: number;
  readonly scripthash?: string;
  readonly scriptpubkey?: string;
  readonly scriptpubkey_address?: string;
  /** the node names this `scripthash_address`; standard Esplora
   *  uses `scriptpubkey_address`. We accept either. */
  readonly scripthash_address?: string;
  // Token outputs (tx_type 'tokens').
  readonly token_id?: string;
  readonly token_amount?: number | string;
  readonly token_decimals?: number | string;
  // Conversion covenant outputs (freeze/downgrade) carry the payout address
  // and the reclaim id; `reclaim` may be a non-hex placeholder.
  readonly downgrade?: { readonly btc_address?: unknown; readonly reclaim?: unknown };
}

interface RawTx {
  readonly txid: string;
  // the node sends a string `tx_type`; standard Esplora and our
  // synthetic fixtures use a numeric `version`. Accept both.
  readonly version?: number;
  readonly tx_type?: string;
  readonly vin: readonly RawTxIn[];
  readonly vout: readonly RawTxOut[];
  readonly size: number;
  readonly fee: number;
  readonly status: RawConfirmationStatus;
  readonly is_coinbase?: boolean;
}

// ─── Client ──────────────────────────────────────────────────────────

export class EsploraClient {
  constructor(
    readonly endpoint: NodeEndpoint,
    private readonly transportOpts: TransportOptions = {},
  ) {
    if (endpoint.protocol !== 'esplora') {
      throw new TypeError(
        `EsploraClient requires an esplora endpoint, got '${endpoint.protocol}'`,
      );
    }
  }

  // ─── Blockchain ────────────────────────────────────────────────────

  /**
   * Tip height + hash + network identifier (the network is taken from
   * the configured endpoint — Esplora itself doesn't expose it). Two
   * separate calls because Esplora doesn't have a combined endpoint;
   * we issue them in parallel.
   */
  async getBlockchainInfo(): Promise<BlockchainInfo> {
    const [tipHeight, tipHash] = await Promise.all([
      request<string>(
        { url: `${this.endpoint.url}/api/blocks/tip/height`, expect: 'text' },
        this.transportOpts,
      ),
      request<string>(
        { url: `${this.endpoint.url}/api/blocks/tip/hash`, expect: 'text' },
        this.transportOpts,
      ),
    ]);
    const height = Number.parseInt(tipHeight.trim(), 10);
    if (!Number.isFinite(height) || height < 0) {
      throw new ChainError(
        'malformed_response',
        `Invalid tip height: ${tipHeight}`,
        { endpoint: this.endpoint.url },
      );
    }
    return {
      tipHeight: height,
      tipHash: tipHash.trim(),
      network: this.endpoint.network,
    };
  }

  // ─── Addresses ─────────────────────────────────────────────────────

  /** `GET /api/address/<addr>` → balance + tx counts (confirmed + mempool). */
  async getAddressInfo(address: string): Promise<AddressInfo> {
    requireNonEmpty(address, 'address');
    const raw = await request<RawAddressInfo>(
      {
        url: `${this.endpoint.url}/api/address/${encodeURIComponent(address)}`,
        expect: 'json',
      },
      this.transportOpts,
    );
    return {
      address: raw.address,
      chain: parseAddressStats(raw.chain_stats),
      mempool: parseAddressStats(raw.mempool_stats),
      tokens: parseTokens(raw.tokens),
    };
  }

  /** `GET /api/tokens-info/<token_id>` → token metadata (symbol/decimals/…). */
  async getTokenInfo(id: string): Promise<TokenInfo> {
    requireNonEmpty(id, 'id');
    const raw = await request<RawTokenInfo>(
      {
        url: `${this.endpoint.url}/api/tokens-info/${encodeURIComponent(id)}`,
        expect: 'json',
      },
      this.transportOpts,
    );
    return parseTokenInfo(raw, id);
  }

  /** `GET /api/address/<addr>/utxo` → list of unspent outputs. */
  async listUnspent(address: string): Promise<Utxo[]> {
    requireNonEmpty(address, 'address');
    const raw = await request<readonly RawUtxo[]>(
      {
        url: `${this.endpoint.url}/api/address/${encodeURIComponent(address)}/utxo`,
        expect: 'json',
      },
      this.transportOpts,
    );
    if (!Array.isArray(raw)) {
      throw new ChainError(
        'malformed_response',
        'Expected UTXO list, got non-array',
        { endpoint: this.endpoint.url },
      );
    }
    return raw.map(parseUtxo);
  }

  // ─── Transactions ──────────────────────────────────────────────────

  /** `GET /api/tx/<txid>` → full transaction. */
  async getTransaction(txid: string): Promise<ChainTx> {
    requireNonEmpty(txid, 'txid');
    const raw = await request<RawTx>(
      { url: `${this.endpoint.url}/api/tx/${txid}`, expect: 'json' },
      this.transportOpts,
    );
    return parseTx(raw);
  }

  /** `GET /api/tx/<txid>/hex` → the raw serialized transaction as a hex string.
   *  Used by the advanced transaction view; fetched lazily, never for signing. */
  async getTransactionHex(txid: string): Promise<string> {
    requireNonEmpty(txid, 'txid');
    const hex = (
      await request<string>(
        { url: `${this.endpoint.url}/api/tx/${txid}/hex`, expect: 'text' },
        this.transportOpts,
      )
    ).trim();
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new ChainError(
        'malformed_response',
        `Expected hex transaction, got: ${hex.slice(0, 80)}`,
        { endpoint: this.endpoint.url },
      );
    }
    return hex;
  }

  /**
   * `GET /api/address/<addr>/txs` → recent transactions touching the address,
   * newest first: up to 25 mempool + the first 50 confirmed. For older pages
   * pass `afterTxid` (a confirmed txid) → `GET /txs/chain/<afterTxid>` returns
   * the next 50 confirmed.
   */
  async getAddressTransactions(
    address: string,
    afterTxid?: string,
  ): Promise<ChainTx[]> {
    requireNonEmpty(address, 'address');
    const base = `${this.endpoint.url}/api/address/${encodeURIComponent(address)}/txs`;
    const url = afterTxid ? `${base}/chain/${afterTxid}` : base;
    const raw = await request<readonly RawTx[]>(
      {
        url,
        expect: 'json',
      },
      this.transportOpts,
    );
    if (!Array.isArray(raw)) {
      throw new ChainError(
        'malformed_response',
        'Expected transaction list, got non-array',
        { endpoint: this.endpoint.url },
      );
    }
    return raw.map(parseTx);
  }

  /**
   * `GET /api/address/<addr>/transfers/<token_id>` → token transfers touching the
   * address, newest first, as compact `[txid, amount, blockHeight]` tuples. For
   * older pages pass `afterTxid` (a confirmed txid) →
   * `/transfers/<token_id>/chain/<afterTxid>`.
   */
  async getAddressTransfers(
    address: string,
    tokenId: string,
    afterTxid?: string,
  ): Promise<TokenTransfer[]> {
    requireNonEmpty(address, 'address');
    requireNonEmpty(tokenId, 'tokenId');
    const base = `${this.endpoint.url}/api/address/${encodeURIComponent(address)}/transfers/${encodeURIComponent(tokenId)}`;
    const url = afterTxid ? `${base}/chain/${afterTxid}` : base;
    const raw = await request<readonly unknown[]>(
      { url, expect: 'json' },
      this.transportOpts,
    );
    if (!Array.isArray(raw)) {
      throw new ChainError(
        'malformed_response',
        'Expected transfer list, got non-array',
        { endpoint: this.endpoint.url },
      );
    }
    return raw.map(parseTokenTransfer);
  }

  // ─── Status ────────────────────────────────────────────────────────

  /** `GET /api/status` → node sync state (chain, height, syncing) plus, on
   *  upgrade-capable nodes, the conversion pool's identity and running
   *  totals. The node exposes this on both the public and a self-hosted
   *  endpoint. */
  async getNodeStatus(): Promise<NodeStatus> {
    const raw = await request<Record<string, unknown>>(
      { url: `${this.endpoint.url}/api/status`, expect: 'json' },
      this.transportOpts,
    );
    return {
      chain: typeof raw.chain === 'string' ? raw.chain : 'main',
      blocks: typeof raw.blocks === 'number' && Number.isFinite(raw.blocks) ? raw.blocks : -1,
      initialBlockDownload: raw.initialblockdownload === true,
      // Total generated coins — the downgrade rate estimate derives the
      // upgrade level from it (display-only; the node fixes the real rate).
      ...(raw.total_coins !== undefined ? { totalCoins: parseCumulativeSat(raw.total_coins, 'total_coins') } : {}),
      // Only upgrade-capable nodes report it; absent = not applicable.
      ...(typeof raw.btc_synced === 'boolean' ? { btcSynced: raw.btc_synced } : {}),
      // Scan progress: credits require the FULL block to be scanned, which can
      // trail the headers by a lot — surface both so the UI can show the lag.
      ...(typeof raw.btc_headers === 'number' && Number.isFinite(raw.btc_headers) ? { btcHeaders: raw.btc_headers } : {}),
      ...(typeof raw.btc_scanned === 'number' && Number.isFinite(raw.btc_scanned) ? { btcScanned: raw.btc_scanned } : {}),
      // The conversion pool and its running totals. Absent on nodes without
      // upgrade support; when present they MUST parse — a node emitting
      // garbage in a consensus-relevant field is an error to surface, not a
      // field to drop (dropping would turn a consumer's lock-script check
      // into "nothing to compare").
      ...statusField(raw, 'btc_lock_script', 'btcLockScriptHex', requireHex),
      ...statusField(raw, 'btc_upgrade_addr', 'btcUpgradeAddress', requireNonEmptyString),
      ...statusField(raw, 'btc_upgraded', 'btcUpgraded', parseCumulativeSat),
      ...statusField(raw, 'btc_downgraded', 'btcDowngraded', parseCumulativeSat),
      ...statusField(raw, 'minted', 'minted', parseCumulativeSat),
      ...statusField(raw, 'burned', 'burned', parseCumulativeSat),
      // Chain and mempool telemetry.
      ...statusField(raw, 'bestblockhash', 'bestBlockHash', (v, f) => requireHex(v, f, 32)),
      ...statusField(raw, 'bestblocktime', 'bestBlockTime', requireInt),
      ...statusField(raw, 'genesistime', 'genesisTime', requireInt),
      ...statusField(raw, 'mempool_size', 'mempoolSize', requireInt),
      ...statusField(raw, 'mempool_bytes', 'mempoolBytes', requireInt),
    };
  }

  /**
   * `GET /api/tx/<txid>/outspend/<vout>` → whether (and by which transaction)
   * an output has been spent. The downgrade episode tracker walks the chain
   * freeze → downgrade → burn with this.
   */
  async getOutspend(txid: string, vout: number): Promise<Outspend> {
    const raw = await request<{ spent?: unknown; txid?: unknown }>(
      { url: `${this.endpoint.url}/api/tx/${encodeURIComponent(txid)}/outspend/${String(vout)}`, expect: 'json' },
      this.transportOpts,
    );
    const spent = raw.spent === true;
    return {
      spent,
      ...(spent && typeof raw.txid === 'string' && raw.txid.length > 0 ? { txid: raw.txid } : {}),
    };
  }

  // ─── Fees ──────────────────────────────────────────────────────────

  /** `GET /api/fee-estimates` → { target → atomic-unit/vbyte }. */
  async getFeeEstimates(): Promise<FeeEstimates> {
    const raw = await request<Record<string, unknown>>(
      { url: `${this.endpoint.url}/api/fee-estimates`, expect: 'json' },
      this.transportOpts,
    );
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw new ChainError(
        'malformed_response',
        'Expected fee-estimates object',
        { endpoint: this.endpoint.url },
      );
    }
    const out: Record<string, number> = {};
    for (const [k, v] of Object.entries(raw)) {
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
        throw new ChainError(
          'malformed_response',
          `Invalid fee rate at target ${k}: ${String(v)}`,
          { endpoint: this.endpoint.url },
        );
      }
      out[k] = v;
    }
    return out;
  }

  // ─── Broadcast ─────────────────────────────────────────────────────

  /**
   * `POST /api/tx` — body is hex (no 0x, no whitespace), response is
   * txid as plain text on success.
   *
   * NOTE: the prod endpoint
   * currently returns 500 on every input. We treat any non-2xx with
   * status >= 500 as 'broadcast_unavailable' (infra not wired), and any
   * 4xx as 'broadcast_rejected' (the tx itself was bad).
   */
  async broadcastTransaction(rawHex: string): Promise<string> {
    const hex = rawHex.trim().toLowerCase(); // node requires lowercase hex
    if (!/^[0-9a-f]+$/.test(hex)) {
      throw new ChainError(
        'invalid_argument',
        'broadcastTransaction expects hex (no 0x, no whitespace)',
      );
    }
    if (hex.length === 0) {
      throw new ChainError(
        'invalid_argument',
        'broadcastTransaction received empty hex',
      );
    }
    // Body 100 KB max = 200K hex chars.
    if (hex.length > 200_000) {
      throw new ChainError('invalid_argument', 'Transaction hex too large (>100 KB)');
    }

    try {
      // the node expects JSON `{ "hex": "..." }` (not Esplora's raw
      // text/plain body). No retry: re-sending
      // after a flaky success is risky.
      const body = (
        await request<string>(
          {
            url: `${this.endpoint.url}/api/tx`,
            method: 'POST',
            body: JSON.stringify({ hex }),
            contentType: 'application/json',
            expect: 'text',
          },
          { ...this.transportOpts, maxRetries: 0 },
        )
      ).trim();
      // Success. the node returns JSON `{ "txid": "..." }`; standard
      // Esplora returns the bare txid as text; some setups return an empty 2xx.
      // Accept all three — the caller also knows the txid (computed locally at
      // signing time), so an empty body is fine too.
      if (body === '') return '';
      let txid = '';
      if (/^[0-9a-f]{64}$/i.test(body)) {
        txid = body; // bare hex (Esplora convention)
      } else if (body.startsWith('{')) {
        try {
          const value = (JSON.parse(body) as { txid?: unknown }).txid;
          if (typeof value === 'string') txid = value.trim();
        } catch {
          // not JSON — falls through to the malformed_response below
        }
      }
      if (/^[0-9a-f]{64}$/i.test(txid)) return txid;
      throw new ChainError(
        'malformed_response',
        `Broadcast returned unexpected response: ${body.slice(0, 100)}`,
        { endpoint: this.endpoint.url },
      );
    } catch (e) {
      if (e instanceof ChainError) {
        // Re-map the generic HTTP codes to broadcast-specific codes so
        // the UI can show "node infra issue" vs "your transaction was
        // rejected".
        if (e.code === 'http_5xx') {
          throw new ChainError(
            'broadcast_unavailable',
            `Broadcast endpoint unavailable: ${e.message}`,
            { status: e.status, endpoint: e.endpoint, cause: e.cause },
          );
        }
        if (e.code === 'http_4xx') {
          throw new ChainError(
            'broadcast_rejected',
            `Broadcast rejected: ${e.message}`,
            { status: e.status, endpoint: e.endpoint, cause: e.cause },
          );
        }
      }
      throw e;
    }
  }
}

// ─── Parsers ─────────────────────────────────────────────────────────

function parseAddressStats(raw: RawAddressStats): AddressStats {
  return {
    fundedTxCount: requireInt(raw.funded_txo_count, 'funded_txo_count'),
    fundedSum: parseCumulativeSat(raw.funded_txo_sum, 'funded_txo_sum'),
    spentTxCount: requireInt(raw.spent_txo_count, 'spent_txo_count'),
    spentSum: parseCumulativeSat(raw.spent_txo_sum, 'spent_txo_sum'),
  };
}

function parseUtxo(raw: RawUtxo): Utxo {
  const utxo: {
    txid: string;
    vout: number;
    value: bigint;
    status: ConfirmationStatus;
    tokenId?: string;
    tokenAmount?: bigint;
  } = {
    txid: requireString(raw.txid, 'txid'),
    vout: requireInt(raw.vout, 'vout'),
    value: requireBigint(raw.value, 'value'),
    status: parseUtxoStatus(raw),
  };
  // Token TRANSFER UTXO — carries the token id and a positive token amount, with a
  // zero native value. The node also tags a token tx's *native change* output with
  // the token id (but without a token_amount); that is an ordinary native coin, so a
  // UTXO is only a token when a positive token amount is present.
  if (typeof raw.token_id === 'string' && raw.token_id && raw.token_amount !== undefined) {
    const amount = requireBigint(raw.token_amount, 'utxo.token_amount');
    if (amount > 0n) {
      utxo.tokenId = raw.token_id;
      utxo.tokenAmount = amount;
    }
  }
  return utxo;
}

/**
 * Confirmation status for a UTXO. the node reports it as a string
 * ('confirmed') plus a top-level `height`; standard Esplora uses a nested
 * object. Handle both.
 */
function parseUtxoStatus(raw: RawUtxo): ConfirmationStatus {
  if (typeof raw.status === 'string') {
    const confirmed = raw.status === 'confirmed';
    const result: { confirmed: boolean; blockHeight?: number } = { confirmed };
    if (confirmed && typeof raw.height === 'number') {
      result.blockHeight = raw.height;
    }
    return result;
  }
  if (raw.status != null) {
    return parseStatus(raw.status);
  }
  return { confirmed: false };
}

function parseTx(raw: RawTx): ChainTx {
  const vin: ChainTxIn[] = raw.vin.map((v) => {
    const result: {
      txid: string;
      vout: number;
      prevoutValue?: bigint;
      prevoutAddress?: string;
      prevoutTokenId?: string;
      prevoutTokenAmount?: bigint;
      prevoutTokenDecimals?: number;
      prevoutScripthash?: string;
      redeemScript?: string;
      siglist?: readonly string[];
    } = {
      txid: requireString(v.txid, 'vin.txid'),
      vout: requireInt(v.vout, 'vin.vout'),
    };
    if (typeof v.redeem_script === 'string' && v.redeem_script.length > 0) {
      result.redeemScript = v.redeem_script;
    }
    if (Array.isArray(v.siglist) && v.siglist.length > 0) {
      result.siglist = v.siglist.filter((s): s is string => typeof s === 'string');
    }
    if (v.prevout !== undefined) {
      result.prevoutValue = requireBigint(v.prevout.value, 'vin.prevout.value');
      const addr = v.prevout.scripthash_address ?? v.prevout.scriptpubkey_address;
      if (addr !== undefined) result.prevoutAddress = addr;
      if (typeof v.prevout.scripthash === 'string' && v.prevout.scripthash.length > 0) {
        result.prevoutScripthash = v.prevout.scripthash;
      }
      // A spent token TRANSFER output carries the token id + a positive amount; a
      // native change output tagged with the token id (no amount) is not a token input.
      if (typeof v.prevout.token_id === 'string' && v.prevout.token_id && v.prevout.token_amount !== undefined) {
        const amount = requireBigint(v.prevout.token_amount, 'vin.prevout.token_amount');
        if (amount > 0n) {
          result.prevoutTokenId = v.prevout.token_id;
          result.prevoutTokenAmount = amount;
          if (v.prevout.token_decimals !== undefined) {
            result.prevoutTokenDecimals = requireInt(v.prevout.token_decimals, 'vin.prevout.token_decimals');
          }
        }
      }
    }
    return result;
  });

  const vout: ChainTxOut[] = raw.vout.map((o) => {
    const result: {
      value: bigint;
      scripthash: string;
      address?: string;
      tokenId?: string;
      tokenAmount?: bigint;
      tokenDecimals?: number;
      downgrade?: { btcAddress?: string; reclaimId?: string };
    } = {
      value: requireBigint(o.value, 'vout.value'),
      scripthash: requireString(
        o.scripthash ?? o.scriptpubkey ?? '',
        'vout.scripthash',
      ),
    };
    // Live node uses `scripthash_address`; standard Esplora uses
    // `scriptpubkey_address`. Accept either.
    const outAddress = o.scriptpubkey_address ?? o.scripthash_address;
    if (outAddress !== undefined) {
      result.address = outAddress;
    }
    // A token TRANSFER output carries token_id + a positive token_amount (+ decimals)
    // and a zero native value. A token tx's native *change* output is tagged with the
    // token id but has no token_amount — that is a native coin output, not a transfer.
    if (typeof o.token_id === 'string' && o.token_id && o.token_amount !== undefined) {
      const amount = requireBigint(o.token_amount, 'vout.token_amount');
      if (amount > 0n) {
        result.tokenId = o.token_id;
        result.tokenAmount = amount;
        if (o.token_decimals !== undefined) {
          result.tokenDecimals = requireInt(o.token_decimals, 'vout.token_decimals');
        }
      }
    }
    // Conversion covenant outputs: the payout address plus the reclaim id
    // (hash256(pubkey), hex). `reclaim` non-hex (a placeholder) → id omitted.
    if (typeof o.downgrade === 'object' && o.downgrade !== null) {
      const info: { btcAddress?: string; reclaimId?: string } = {};
      if (typeof o.downgrade.btc_address === 'string' && o.downgrade.btc_address.length > 0) {
        info.btcAddress = o.downgrade.btc_address;
      }
      if (typeof o.downgrade.reclaim === 'string' && /^[0-9a-fA-F]{64}$/.test(o.downgrade.reclaim)) {
        info.reclaimId = o.downgrade.reclaim.toLowerCase();
      }
      if (info.btcAddress !== undefined || info.reclaimId !== undefined) {
        result.downgrade = info;
      }
    }
    return result;
  });

  const tx: {
    txid: string;
    version: number;
    vin: ChainTxIn[];
    vout: ChainTxOut[];
    size: number;
    fee: bigint;
    status: ConfirmationStatus;
    isCoinbase?: boolean;
    txTypeName?: string;
    coinbaseInfo?: CoinbaseInfo;
    downgradeInfo?: DowngradeInfo;
  } = {
    txid: requireString(raw.txid, 'txid'),
    version: parseTxVersion(raw),
    vin,
    vout,
    size: requireInt(raw.size, 'size'),
    fee: requireBigint(raw.fee, 'fee'),
    status: parseStatus(raw.status),
  };
  if (typeof raw.is_coinbase === 'boolean') tx.isCoinbase = raw.is_coinbase;
  if (typeof raw.tx_type === 'string') tx.txTypeName = raw.tx_type;
  // Upgrade coinbases carry their BTC provenance. The node reports tx_hash
  // in INTERNAL byte order; reverse it into the display order explorers use.
  const ci = (raw as { coinbase_info?: unknown }).coinbase_info;
  if (typeof ci === 'object' && ci !== null) {
    const o = ci as { block_height?: unknown; tx_hash?: unknown; out_num?: unknown; value?: unknown };
    if (typeof o.tx_hash === 'string' && typeof o.block_height === 'number' && typeof o.out_num === 'number') {
      tx.coinbaseInfo = {
        btcTxid: (o.tx_hash.match(/../g) ?? []).reverse().join(''),
        btcBlockHeight: o.block_height,
        btcOutNum: o.out_num,
        valueSat: typeof o.value === 'number' ? BigInt(o.value) : 0n,
      };
    }
  }
  // Downgrade/burn provenance. Unlike coinbase_info, the node sends these
  // txids/hashes already in display byte order — no reversal here.
  const di = (raw as { downgrade_info?: unknown }).downgrade_info;
  if (typeof di === 'object' && di !== null) {
    const o = di as {
      freeze_txid?: unknown;
      freeze_vout?: unknown;
      btc_txid?: unknown;
      btc_vout?: unknown;
      btc_value?: unknown;
      btc_scriptpubkey?: unknown;
      btc_block_hash?: unknown;
    };
    if (typeof o.btc_txid === 'string' && o.btc_txid.length > 0) {
      const info: {
        btcTxid: string;
        freezeTxid?: string;
        freezeVout?: number;
        btcVout?: number;
        btcValueSat?: bigint;
        btcScriptPubKey?: string;
        btcBlockHash?: string;
      } = { btcTxid: o.btc_txid };
      if (typeof o.freeze_txid === 'string' && o.freeze_txid.length > 0) info.freezeTxid = o.freeze_txid;
      if (o.freeze_vout !== undefined) info.freezeVout = requireInt(o.freeze_vout, 'downgrade_info.freeze_vout');
      if (o.btc_vout !== undefined) info.btcVout = requireInt(o.btc_vout, 'downgrade_info.btc_vout');
      if (o.btc_value !== undefined) info.btcValueSat = requireBigint(o.btc_value, 'downgrade_info.btc_value');
      if (typeof o.btc_scriptpubkey === 'string' && o.btc_scriptpubkey.length > 0) info.btcScriptPubKey = o.btc_scriptpubkey;
      if (typeof o.btc_block_hash === 'string' && o.btc_block_hash.length > 0) info.btcBlockHash = o.btc_block_hash;
      tx.downgradeInfo = info;
    }
  }
  return tx;
}

/** Parse one `[txid, amount, blockHeight]` transfer tuple. A non-positive height
 *  (unconfirmed / mempool) is left undefined. */
function parseTokenTransfer(entry: unknown): TokenTransfer {
  if (!Array.isArray(entry) || entry.length < 2) {
    throw new ChainError(
      'malformed_response',
      'Expected a [txid, amount, blockHeight] transfer tuple',
    );
  }
  const result: { txid: string; amountAtomic: bigint; blockHeight?: number } = {
    txid: requireString(entry[0], 'transfer.txid'),
    amountAtomic: requireBigint(entry[1], 'transfer.amount'),
  };
  const height = entry[2];
  if (typeof height === 'number' && Number.isFinite(height) && height > 0) {
    result.blockHeight = height;
  }
  return result;
}

/** The node's `tx_type` names → the numeric tx-type id the wallet uses
 *  (STANDARD=1, STAKE=2, COINBASE=3, TOKENS=4). */
const TX_TYPE_VERSION: Record<string, number> = {
  standard: 1,
  stake: 2,
  coinbase: 3,
  tokens: 4,
  slashing: 5,
  burn: 6,
  downgrade: 7,
  upgrade_stop: 8,
};

/**
 * Resolve ChainTx.version from either a numeric `version` (standard Esplora /
 * synthetic fixtures) or a string `tx_type`.
 */
function parseTxVersion(raw: RawTx): number {
  if (typeof raw.version === 'number') {
    return requireInt(raw.version, 'version');
  }
  if (typeof raw.tx_type === 'string') {
    // A name this map does not know yet resolves to 0 ("unknown") instead of
    // failing: a node that learns a new transaction type must not break
    // history for every address such a transaction touches (slashing did
    // exactly that before this map knew it). The raw name is kept on the tx.
    return TX_TYPE_VERSION[raw.tx_type] ?? 0;
  }
  throw new ChainError(
    'malformed_response',
    'Transaction missing both version and tx_type',
  );
}

function parseStatus(raw: RawConfirmationStatus): ConfirmationStatus {
  const result: {
    confirmed: boolean;
    blockHeight?: number;
    blockHash?: string;
    blockTime?: number;
    blockPos?: number;
  } = {
    confirmed: Boolean(raw.confirmed),
  };
  if (raw.block_height !== undefined) result.blockHeight = raw.block_height;
  if (raw.block_hash !== undefined) result.blockHash = raw.block_hash;
  if (raw.block_time !== undefined) result.blockTime = raw.block_time;
  if (raw.block_pos !== undefined) result.blockPos = raw.block_pos;
  return result;
}

// ─── Validators — throw ChainError('malformed_response') on bad shape ─

function requireString(v: unknown, field: string): string {
  if (typeof v !== 'string') {
    throw new ChainError(
      'malformed_response',
      `Field '${field}' is not a string: ${String(v)}`,
    );
  }
  return v;
}

function requireNonEmptyString(v: unknown, field: string): string {
  const s = requireString(v, field);
  if (s.length === 0) {
    throw new ChainError('malformed_response', `Field '${field}' is empty`);
  }
  return s;
}

/** Non-empty, even-length hex, returned lowercase (hex case carries no
 *  meaning, and consumers compare these values byte for byte against their
 *  own pins). `bytes` pins an exact length where the format has one. */
function requireHex(v: unknown, field: string, bytes?: number): string {
  const s = requireString(v, field);
  const lengthOk = bytes === undefined ? s.length > 0 && s.length % 2 === 0 : s.length === bytes * 2;
  if (!lengthOk || !/^[0-9a-fA-F]+$/.test(s)) {
    throw new ChainError(
      'malformed_response',
      `Field '${field}' is not ${bytes === undefined ? '' : `${bytes}-byte `}hex: ${s}`,
    );
  }
  return s.toLowerCase();
}

/** Optional `/api/status` field: absent → contributes nothing; present →
 *  parsed with the given parser, which throws on malformed input. */
function statusField<K extends string, T>(
  raw: Record<string, unknown>,
  key: string,
  out: K,
  parse: (v: unknown, field: string) => T,
): Partial<Record<K, T>> {
  const v = raw[key];
  return v === undefined ? {} : ({ [out]: parse(v, key) } as Record<K, T>);
}

function requireInt(v: unknown, field: string): number {
  // the node serializes some integer fields as numeric strings in
  // certain responses (observed: `vin.vout` in the address /txs listing) —
  // the same number/string inconsistency we already tolerate for sat sums in
  // requireBigint. Accept a clean integer string.
  const n = typeof v === 'string' && /^[0-9]+$/.test(v) ? Number(v) : v;
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 0) {
    throw new ChainError(
      'malformed_response',
      `Field '${field}' is not a non-negative integer: ${String(v)}`,
    );
  }
  return n;
}

/**
 * Parse a CUMULATIVE sat sum (funded_txo_sum / spent_txo_sum, token balance
 * totals). Unlike a transaction value — bounded by MAX_VALUE, far below
 * 2^53, where a float always means corruption — these sums grow without
 * bound: a staking address re-funds itself every block, and a busy one
 * overflows uint64 on the NODE side, which then serializes the running
 * total as a double ("1.54159394334483e+21"). The digits beyond double
 * precision are already lost at the source, so the exact-integer rule
 * cannot be enforced here; the double is converted exactly instead (its
 * error is a few source-side ULP — fractions of a coin at that magnitude).
 * Strings and safe integers stay exact.
 */
function parseCumulativeSat(v: unknown, field: string): bigint {
  if (typeof v === 'string') {
    if (!/^[0-9]+$/.test(v)) {
      throw new ChainError(
        'malformed_response',
        `Field '${field}' is not a non-negative integer: ${v}`,
      );
    }
    return BigInt(v);
  }
  if (typeof v !== 'number' || !Number.isFinite(v) || !Number.isInteger(v) || v < 0) {
    throw new ChainError(
      'malformed_response',
      `Field '${field}' is not a non-negative integer: ${String(v)}`,
    );
  }
  // Every finite double >= 2^53 is integer-valued, so BigInt() is exact on
  // the double itself; the rounding happened before it reached us.
  return BigInt(v);
}

const TOKEN_DEFAULT_DECIMALS = 6;

/** Parse the address-info `tokens` map: token_id (hex) → balance (bigint).
 *  Values arrive as numbers or numeric strings (like the sat sums); token
 *  balances are uint64 running totals, so they get the cumulative parser. */
function parseTokens(raw: unknown): Record<string, bigint> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return {};
  const out: Record<string, bigint> = {};
  for (const [id, v] of Object.entries(raw as Record<string, unknown>)) {
    out[id] = parseCumulativeSat(v, `tokens.${id}`);
  }
  return out;
}

function parseTokenInfo(raw: RawTokenInfo, fallbackId: string): TokenInfo {
  const decimals =
    typeof raw.decimals === 'number' &&
    Number.isInteger(raw.decimals) &&
    raw.decimals >= 0 &&
    raw.decimals <= 18
      ? raw.decimals
      : TOKEN_DEFAULT_DECIMALS;
  const info: {
    id: string;
    decimals: number;
    issuer?: string;
    name?: string;
    symbol?: string;
    createTime?: number;
  } = {
    id:
      typeof raw.token_id === 'string' && raw.token_id ? raw.token_id : fallbackId,
    decimals,
  };
  if (typeof raw.issuer === 'string') info.issuer = raw.issuer;
  if (typeof raw.name === 'string') info.name = raw.name;
  if (typeof raw.symbol === 'string') info.symbol = raw.symbol;
  if (typeof raw.create_time === 'number') info.createTime = raw.create_time;
  return info;
}

function requireBigint(v: unknown, field: string): bigint {
  // the node serializes sat sums inconsistently: some as JSON
  // numbers, some as numeric strings. Accept both. A string goes straight to
  // BigInt, which also avoids any precision loss on very large values.
  if (typeof v === 'string') {
    if (!/^[0-9]+$/.test(v)) {
      throw new ChainError(
        'malformed_response',
        `Field '${field}' is not a non-negative integer: ${v}`,
      );
    }
    return BigInt(v);
  }
  // Esplora returns JS numbers for sat values. They're safe up to
  // 2^53−1 = ~90 PBTC equivalent — well above any realistic balance,
  // but we still narrow to bigint at the boundary so internal math
  // never accidentally rounds.
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
    throw new ChainError(
      'malformed_response',
      `Field '${field}' is not a non-negative integer: ${String(v)}`,
    );
  }
  if (!Number.isSafeInteger(v)) {
    throw new ChainError(
      'malformed_response',
      `Field '${field}' exceeds safe integer range: ${v}`,
    );
  }
  return BigInt(v);
}

function requireNonEmpty(s: string, field: string): void {
  if (typeof s !== 'string' || s.length === 0) {
    throw new ChainError('invalid_argument', `${field} must be a non-empty string`);
  }
}
