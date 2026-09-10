// BIP-32 hierarchical deterministic key derivation for secp256k1.
//
// Thin wrapper over @scure/bip32, plus the derivation-scheme MECHANICS.
//
// The scheme registry itself (which coin_types, which id is active) is a
// chain value: consumers declare their schemes in a `ChainProfile`
// (profile.ts) and either pass them to the pure helpers below or use the
// `bindProfile()` facade, which fixes the scheme list once.
//
// Why a scheme list instead of a single hardcoded path: SLIP-0044 (the
// industry coin_type list) may not have assigned a chain its number yet.
// Until it does, a chain uses a placeholder scheme; when the official
// number lands, a new active scheme is added alongside the legacy one and
// funds migrate.
//
// The Falcon-512 PQ branch derives BIP-32 leaves under purpose 512'
// (same coin_type, fully hardened) and stretches them into Falcon
// keygen seeds via HKDF — see `falconHd.ts`.

import { HDKey } from '@scure/bip32';
import type { Network } from './constants';

export { HDKey };

/**
 * Construct a BIP-32 master HD key from a 64-byte BIP-39 seed.
 *
 * `seed.length` must be in [16, 64] per BIP-32. In practice BIP-39 always
 * produces 64 bytes, so any other length is almost certainly a caller
 * bug — @scure/bip32 will throw.
 */
export function masterKeyFromSeed(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}

/**
 * Derive a child key from `parent` along `path`.
 *
 * Path syntax: BIP-32 conventional, "m/<index>[']/<index>['].../"
 *  - leading `m/` is optional
 *  - `'` (or `h`) after an index marks hardened derivation
 *
 * Throws on malformed paths or out-of-range indices.
 */
export function derivePath(parent: HDKey, path: string): HDKey {
  return parent.derive(path);
}

// ─── Derivation scheme mechanics ──────────────────────────────────────

/** Bit mask for hardened BIP-32 indices. Useful when constructing
 *  indices manually via `HDKey.deriveChild(n)`; with string paths the
 *  trailing `'` (or `h`) handles this for you. */
export const HARDENED = 0x80000000;

/**
 * A specific BIP-44 derivation scheme. A wallet may know about several
 * over its lifetime.
 *
 *  - `id` is a stable string identifier used in storage and APIs.
 *  - `coinType` is the BIP-44 coin_type number (unhardened — the `'`
 *    in the path string adds the hardened bit at parse time).
 *  - `status: 'active'` means new addresses are derived under this
 *    scheme. `'legacy'` means we still scan for funds here but don't
 *    create fresh addresses.
 *  - `pathTemplate` builds the BIP-44 path string for a given
 *    account/change/index triple.
 */
export interface DerivationScheme {
  readonly id: string;
  /**
   * BIP-44 coin_type. A plain number applies to every network; a record
   * follows the BIP-44 convention of a distinct testnet coin_type
   * (usually 1, "testnet, all coins") next to the chain's registered
   * mainnet number.
   */
  readonly coinType: number | Readonly<Record<Network, number>>;
  readonly label: string;
  readonly status: 'active' | 'legacy';
  readonly pathTemplate: (
    account: number,
    change: 0 | 1,
    index: number,
    network: Network,
  ) => string;
}

/** Resolve a scheme's coin_type for the given network. */
export function coinTypeFor(scheme: DerivationScheme, network: Network): number {
  return typeof scheme.coinType === 'number' ? scheme.coinType : scheme.coinType[network];
}

/**
 * Return the active derivation scheme of `schemes`. Throws if zero or
 * more than one scheme is marked active — both are configuration errors
 * (`bindProfile` rejects such profiles up front).
 */
export function activeScheme(schemes: readonly DerivationScheme[]): DerivationScheme {
  const actives = schemes.filter((s) => s.status === 'active');
  if (actives.length !== 1) {
    throw new Error(
      `Exactly one active derivation scheme required, found ${actives.length}`,
    );
  }
  return actives[0]!;
}

/** All legacy schemes of `schemes` — used for funds-discovery during seed import. */
export function legacySchemes(schemes: readonly DerivationScheme[]): readonly DerivationScheme[] {
  return schemes.filter((s) => s.status === 'legacy');
}

/** Look up a scheme by its stable id. Returns undefined if not found. */
export function schemeById(
  schemes: readonly DerivationScheme[],
  id: string,
): DerivationScheme | undefined {
  return schemes.find((s) => s.id === id);
}

/**
 * Look up a scheme by id, throwing on an unknown one. Use where an unknown
 * id is a data-integrity error (e.g. resolving the scheme of a UTXO about
 * to be signed) rather than an expected miss.
 */
export function requireScheme(
  schemes: readonly DerivationScheme[],
  id: string,
): DerivationScheme {
  const scheme = schemeById(schemes, id);
  if (scheme === undefined) {
    throw new Error(`Unknown derivation scheme '${id}'`);
  }
  return scheme;
}

// ─── Convenience aliases ──────────────────────────────────────────────

/**
 * Standard BIP-44 path for a classical (secp256k1) address under an
 * EXPLICIT scheme — the multi-scheme form used by discovery and signing,
 * where the address's own scheme (not necessarily the active one) decides
 * the path.
 *
 *   m / 44' / <coin_type for network>' / account' / change / index
 *
 * `change = 0` is the receive chain, `change = 1` is the change chain
 * (used internally to receive transaction change so it doesn't pile up
 * on the receive addresses). The network decides the coin_type level for
 * schemes that follow the BIP-44 testnet convention.
 *
 * The active-scheme convenience form lives on the `bindProfile()` facade
 * as `nativePath(account, index, network, change?)`.
 */
export function nativePathFor(
  scheme: DerivationScheme,
  account: number,
  index: number,
  network: Network,
  change: 0 | 1 = 0,
): string {
  return scheme.pathTemplate(account, change, index, network);
}
