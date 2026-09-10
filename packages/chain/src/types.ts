// Public domain types — the wallet's view of chain state.
//
// We mirror Esplora (mempool.space-style) response shapes where they
// already exist, but the types in THIS file are the abstraction the
// wallet code talks to. If we later add a JSON-RPC backend or swap
// nodes, these types stay stable — adapters do the mapping.
//
// Atomic units: balances and UTXO values are bigint, in atomic units
// UI converts to
// decimal for display; storage and math stay integer-safe.

import type { NodeEndpoint, Network } from './nodes';

// ─── Address-level state ─────────────────────────────────────────────

export interface AddressStats {
  /** Number of funded outputs that have landed in a confirmed block. */
  readonly fundedTxCount: number;
  /** Total sat (atomic units) received over all confirmed outputs. */
  readonly fundedSum: bigint;
  /** Number of spent outputs that have landed in a confirmed block. */
  readonly spentTxCount: number;
  /** Total sat sent out across all confirmed spends. */
  readonly spentSum: bigint;
}

export interface AddressInfo {
  readonly address: string;
  /** Confirmed (in-chain) statistics. */
  readonly chain: AddressStats;
  /** Pending (mempool) statistics — usually zero unless tx in flight. */
  readonly mempool: AddressStats;
  /** Token balances at this address: token_id (hex) → amount (atomic token
   *  units; divide by 10^decimals to display). Empty when none. */
  readonly tokens: Record<string, bigint>;
}

/** Token metadata from the token's creation tx (GET /api/tokens-info/:id). */
export interface TokenInfo {
  /** token_id hex (= the creation transaction's hash). */
  readonly id: string;
  /** Display decimals (≤18, default 6). */
  readonly decimals: number;
  readonly issuer?: string;
  readonly name?: string;
  readonly symbol?: string;
  /** Block time of the creation tx, Unix seconds. */
  readonly createTime?: number;
}

/** Net confirmed + mempool balance in atomic units. */
export function balanceOf(info: AddressInfo): bigint {
  const confirmed = info.chain.fundedSum - info.chain.spentSum;
  const pending = info.mempool.fundedSum - info.mempool.spentSum;
  const net = confirmed + pending;
  // The cumulative sums of a heavy staking address overflow uint64 on the
  // node and arrive as doubles; their rounding can push an emptied address
  // a few hundred thousand atomic units below zero. A real balance can't be
  // negative, so clamp the total (NOT the mempool term — a pending spend is
  // legitimately negative there).
  return net < 0n ? 0n : net;
}

/** Whether (and by which transaction) an output has been spent. */
export interface Outspend {
  readonly spent: boolean;
  /** Spending txid, present when `spent`. */
  readonly txid?: string;
}

// ─── UTXO ────────────────────────────────────────────────────────────

export interface Utxo {
  /** Source transaction hash, hex, little-endian (Bitcoin-style). */
  readonly txid: string;
  /** Output index in the source transaction. */
  readonly vout: number;
  /** Value in atomic units (0 for token UTXOs). */
  readonly value: bigint;
  /** Confirmation state. Undefined fields → still in mempool. */
  readonly status: ConfirmationStatus;
  /** Token id (hex) when this UTXO is a token TRANSFER output; native coin
   * UTXOs leave it undefined. */
  readonly tokenId?: string;
  /** Token amount in atomic token units, present iff `tokenId` is set. */
  readonly tokenAmount?: bigint;
}

export interface ConfirmationStatus {
  readonly confirmed: boolean;
  /** Block height containing this tx, if confirmed. */
  readonly blockHeight?: number;
  /** Block hash, hex, if confirmed. */
  readonly blockHash?: string;
  /** Block time, Unix seconds, if confirmed. */
  readonly blockTime?: number;
  /** Position of the tx within its block (0 = first), if the node reports it. */
  readonly blockPos?: number;
}

// ─── Transaction ─────────────────────────────────────────────────────

export interface ChainTx {
  readonly txid: string;
  /**
   * tx_type from the node — STANDARD=1, STAKE=2, COINBASE=3, TOKENS=4,
   * SLASHING=5, BURN=6, DOWNGRADE=7, UPGRADE_STOP=8; 0 for a name this
   * client does not know yet (see `txTypeName`).
   */
  readonly version: number;
  /** The node's raw tx_type name, kept so an unknown type stays displayable. */
  readonly txTypeName?: string;
  /** Inputs as seen by the node (for display, not signing). */
  readonly vin: readonly ChainTxIn[];
  /** Outputs as seen by the node. */
  readonly vout: readonly ChainTxOut[];
  /** Total size in bytes of the serialized transaction. */
  readonly size: number;
  /** Total fee in atomic units (sum of inputs − sum of outputs). */
  readonly fee: bigint;
  readonly status: ConfirmationStatus;
  /** True for the block's coinbase (block-reward) transaction. */
  readonly isCoinbase?: boolean;
  /** Upgrade-coinbase provenance: the source-chain payment this credit stems from. */
  readonly coinbaseInfo?: CoinbaseInfo;
  /** Downgrade/burn provenance (native → source-chain conversion). */
  readonly downgradeInfo?: DowngradeInfo;
}

/**
 * Where an upgrade coinbase came from: the BTC transaction output that paid
 * the chain's lock script. `btcTxid` is in DISPLAY byte order (explorers);
 * the node reports the internal order and the client reverses it.
 */
/**
 * Where a downgrade is headed / how it completed. Both forms share the field
 * name in the node's REST: a DOWNGRADE transaction carries the frozen outpoint
 * and the promised source-chain payout; a BURN transaction carries the
 * source-chain block that confirmed it. All txids/hashes arrive in DISPLAY
 * byte order (the node reverses them before sending — unlike coinbase_info).
 */
export interface DowngradeInfo {
  readonly btcTxid: string;
  // Downgrade (freeze) form:
  readonly freezeTxid?: string;
  readonly freezeVout?: number;
  readonly btcVout?: number;
  /** Satoshi promised on the source chain. */
  readonly btcValueSat?: bigint;
  readonly btcScriptPubKey?: string;
  // Burn form:
  readonly btcBlockHash?: string;
}

/**
 * The node's per-output view of a conversion covenant output (freeze or
 * downgrade): the decoded source-chain payout address and the reclaim id —
 * hash256 of the pubkey the covenant's ELSE branch lets reclaim the coins.
 */
export interface DowngradeOutputInfo {
  readonly btcAddress?: string;
  /** 32-byte hash256(pubkey), hex; absent when the node reports a non-hex
   *  placeholder instead. */
  readonly reclaimId?: string;
}

export interface CoinbaseInfo {
  readonly btcTxid: string;
  readonly btcBlockHeight: number;
  readonly btcOutNum: number;
  /** Satoshi locked on the BTC side (before the protocol fee). */
  readonly valueSat: bigint;
}

export interface ChainTxIn {
  readonly txid: string;
  readonly vout: number;
  /**
   * Previous-output value, if the node resolved it. Present on Esplora
   * because the node looks up the source output; absent on lightweight
   * backends.
   */
  readonly prevoutValue?: bigint;
  /**
   * Decoded address of the spent output, if the node resolved it. Lets the
   * wallet tell sent (we own an input) from received.
   */
  readonly prevoutAddress?: string;
  /** Token id on the spent output, if it carried a token. */
  readonly prevoutTokenId?: string;
  /** Token amount on the spent output, atomic units (present iff prevoutTokenId). */
  readonly prevoutTokenAmount?: bigint;
  /** Token decimals reported on the spent output (node default 6). */
  readonly prevoutTokenDecimals?: number;
  /** scripthash of the spent output, hex, if the node resolved it. */
  readonly prevoutScripthash?: string;
  /** Unlocking/redeem script for this input, hex, if the node provides it. */
  readonly redeemScript?: string;
  /**
   * Signature-list entries (hex), if present. Each entry is
   * `<sighash:1><algo:1><signature…>`; algo 1 = ECDSA, 129 = Falcon-512.
   * Carried for the advanced transaction view, not for signing.
   */
  readonly siglist?: readonly string[];
}

export interface ChainTxOut {
  readonly value: bigint;
  /** scripthash hex — the same value used to derive the address. */
  readonly scripthash: string;
  /** Decoded address, if the node could derive one from scripthash. */
  readonly address?: string;
  /** Covenant annotation the node attaches to conversion (freeze/downgrade)
   *  outputs: where the source-chain payout goes and who may reclaim. */
  readonly downgrade?: DowngradeOutputInfo;
  /** Token id (hex) when this output carries a token.
   *  Token outputs have a zero native `value`; the movement is `tokenAmount`. */
  readonly tokenId?: string;
  /** Token amount in atomic token units (divide by 10^tokenDecimals). */
  readonly tokenAmount?: bigint;
  /** Token decimals reported on the output (node default 6). */
  readonly tokenDecimals?: number;
}

/** One token transfer touching an address, from
 *  `GET /api/address/:addr/transfers/:token_id` (compact tuples). */
export interface TokenTransfer {
  /** Transaction hash that moved the token. */
  readonly txid: string;
  /** Token amount moved at this address, atomic token units. */
  readonly amountAtomic: bigint;
  /** Block height, when confirmed. */
  readonly blockHeight?: number;
}

// ─── Fee estimation ──────────────────────────────────────────────────

/**
 * Map of confirmation-target (in blocks) → fee rate (atomic units per
 * vbyte). Esplora returns this shape directly:
 *
 *   { "1": 12.5, "3": 9.0, "6": 4.2, "144": 1.0 }
 */
export type FeeEstimates = Readonly<Record<string, number>>;

// ─── Blockchain info ─────────────────────────────────────────────────

export interface BlockchainInfo {
  readonly tipHeight: number;
  readonly tipHash: string;
  /** Network the endpoint claims to serve. */
  readonly network: Network;
}

// Node sync/status from the node's `/api/status` endpoint — richer than the bare
// tip height: the chain name it serves, the current block height, and whether it is
// still doing its initial block download (i.e. not yet fully synced).
export interface NodeStatus {
  /** 'main' | 'testnet' | 'regtest'. */
  readonly chain: string;
  /** Best block height, or -1 when the node has no blocks yet. */
  readonly blocks: number;
  /** True while the node is still syncing (Esplora `initialblockdownload`). */
  readonly initialBlockDownload: boolean;
  /** Total generated coins in atomic units, when the node reports it. */
  readonly totalCoins?: bigint;
  /**
   * Whether the node has finished syncing the BITCOIN chain (upgrade-capable
   * nodes ignore upgrade txs until it has). Absent when the node doesn't
   * report it (no upgrade support).
   */
  readonly btcSynced?: boolean;
  /** Height of the last known BTC header (upgrade-capable nodes only). */
  readonly btcHeaders?: number;
  /** Height of the last fully SCANNED BTC block — credits require the scan. */
  readonly btcScanned?: number;
}

// ─── Broadcast result ────────────────────────────────────────────────

export interface BroadcastResult {
  readonly txid: string;
  /** Which endpoint accepted the broadcast — handy for logging. */
  readonly endpoint: NodeEndpoint;
}
