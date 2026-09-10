// Protocol-level constants.
//
// Everything here is fixed by the node protocol itself and identical for
// every chain running it. Values that differ per chain (address magic,
// WIF versions, derivation schemes, HKDF labels, message magic, upgrade
// parameters) are NOT constants of this package — consumers supply them
// via a `ChainProfile` (see profile.ts).

/** Which network an object lives on. */
export type Network = 'mainnet' | 'testnet';

/**
 * Signature algorithm. The protocol allows multiple algorithms per
 * address — the byte in the siglist tells the verifier which one to
 * use.
 */
export type Algorithm = 'ecdsa' | 'schnorr' | 'falcon512';

/**
 * Numeric algorithm IDs used in the byte that prefixes signatures inside
 * a siglist. Matches the `CRYPT_ALGO_*` constants in the node.
 */
export const ALGO_ID: Record<Algorithm, number> = {
  ecdsa: 1,
  schnorr: 2,
  falcon512: 129, // 0x80 (postquantum bit) | 1
};

/** Bit flag marking algorithms as post-quantum. */
export const ALGO_POSTQUANTUM_BIT = 0x80;

/** True if `algo` has the post-quantum bit set in its numeric ID. */
export function isPostQuantum(algo: Algorithm): boolean {
  return (ALGO_ID[algo] & ALGO_POSTQUANTUM_BIT) !== 0;
}

/** Atomic units per coin — `100_000_000` (1 coin = 10⁸ atomic, like satoshis). */
export const DENOMINATOR = 100_000_000;

/**
 * Parameters of the BTC→native upgrade path (the chain credits native
 * coins for BTC paid into its lock script). A chain that has no Bitcoin
 * upgrade sets `upgrade: null` in its profile; wallets keep the flow
 * dormant while it is null.
 */
export interface UpgradeChainConfig {
  /** Exact scriptPubKey (hex) of the chain's BTC lock/freeze output. */
  readonly lockScriptHex: string;
  /** Smallest convertible amount, in satoshi. */
  readonly minConvertValue: bigint;
  /** Below this, change folds into the fee instead of creating an output. */
  readonly dustLimit: bigint;
  /** Fee-estimate confirmation target, in blocks. */
  readonly feeTargetBlocks: number;
  /** sat/vB used when the fee oracle has no usable answer. */
  readonly fallbackFeeRate: number;
}

/**
 * Consensus parameters of the native→BTC downgrade (see downgrade.ts). A
 * chain without the downgrade flow sets `downgrade: null` in its profile.
 */
export interface DowngradeChainConfig {
  /** Falcon-512 pubkeys (hex) of the freeze federation — the freeze
   *  script's IF branch is their 2-of-3 CHECKMULTISIG. */
  readonly freezePubkeysHex: readonly string[];
  /** Seconds until the user may reclaim an unpicked freeze output. */
  readonly freezeSeconds: number;
  /** Seconds until the user may reclaim an unburned downgrade output. */
  readonly outputSeconds: number;
  /** The retired single-key covenant era, when the chain ever ran one: the
   *  conversion service no longer serves its outputs, but they stay
   *  user-reclaimable (and rescanned) forever. */
  readonly legacyLockPubkeyHex?: string;
}

/**
 * The token-id sighash fork predicate, pure for testability: does a
 * signature produced at `atSeconds` commit the token id under fork time
 * `fork`? Fork times are chain values (`profile.tokenSighashFork`): from
 * the fork moment the node appends the raw 32-byte token hash after the
 * outputs ("Add token_hash to transaction sign data") and rejects
 * token-transfer signatures that omit it; BEFORE the fork the same node
 * rejects signatures that append it — so the switch happens at the fork
 * time, not at a release. `0` = since genesis, `null` = never. The
 * network-aware form lives on the `bindProfile()` facade as
 * `sighashCommitsTokenId(network, atSeconds?)`.
 */
export function forkCommitsTokenId(fork: number | null, atSeconds: number): boolean {
  return fork !== null && atSeconds >= fork;
}

/**
 * SIGHASH types accepted by the protocol. The wallet only ever emits
 * `SIGHASH_ALL`. Other modes are listed for completeness so decoders /
 * verifiers can reject them explicitly.
 */
export const SIGHASH = {
  ALL: 1,
  NONE: 2,
  SINGLE: 3,
  ANYONECANPAY: 0x80, // flag, combined with one of the above
} as const;
