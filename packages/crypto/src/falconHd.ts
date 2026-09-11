// HD → Falcon-512 derivation — the post-quantum address branch.
//
// Falcon has no BIP-32, so we bridge BIP-32 path structure to Falcon's
// seeded keygen. PQ keys are deterministic and recoverable from the same
// BIP-39 mnemonic as the classical branch:
//
//   child   = derivePath(master, m/512'/<coin_type>'/account'/change'/index')
//   ikm     = child.privateKey            // 32 B; never used as a secp256k1 key
//   seed48  = HKDF-SHA256(ikm, salt=∅, info=<chain's falconHdInfo>, L=48)
//   keypair = falcon512KeygenFromSeed(seed48)
//
// Design notes:
//  - The branch is separated from classical at the PURPOSE level (512' —
//    self-documenting for Falcon-512), not by a second coin_type:
//    SLIP-0044 assigns one number per coin, and both branches must
//    migrate together when the official coin_type lands.
//  - Every level is hardened. Watch-only xpub derivation is impossible
//    for Falcon anyway (keygen needs the private seed), so non-hardened
//    levels would buy nothing — hardening is free isolation. Even an
//    adversary holding revealed classical keys cannot reach this subtree.
//  - The BIP-32 leaf private key is used ONLY as HKDF input keying
//    material; the info label domain-separates it from the app-data key
//    and from any future PQ scheme. The label is a CHAIN VALUE supplied
//    by the consumer's profile (`profile.falconHdInfo`) — versioned, and
//    once a chain has shipped, its label must never change (existing PQ
//    funds would become unrecoverable).
//
// CONSENSUS-FOR-RECOVERABILITY: this mapping must stay byte-stable
// forever — changing any stage (path, info label, HKDF, keygen) strands
// existing PQ funds. Golden vectors in falconHd.test.ts freeze the
// mechanics; each consumer's pin tests freeze its own label and paths.

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

import {
  coinTypeFor,
  derivePath,
  type DerivationScheme,
  type HDKey,
} from './bip32.js';
import type { Network } from './constants.js';
import {
  FALCON512_SEED_BYTES,
  falcon512KeygenFromSeed,
  type Falcon512Keypair,
} from './falcon512.js';

/** BIP-43 purpose for the Falcon-512 branch. Project-defined (there is
 *  no BIP for PQ derivation); 512 is self-documenting. The classical
 *  branch stays on purpose 44'. */
export const PURPOSE_FALCON512 = 512;

/**
 * BIP-32 path of a Falcon-512 leaf under an EXPLICIT scheme:
 *
 *   m / 512' / <scheme's coin_type>' / account' / change' / index'
 *
 * Mirrors `nativePathFor` (same argument order, same `(account, change,
 * index)` space, same receive/change rotation semantics) but is fully
 * hardened and lives under purpose 512'. The coin_type is shared with
 * the classical branch — both migrate together through the scheme list
 * when the official SLIP-0044 number lands. Within a scheme, the network
 * may select the BIP-44 testnet coin_type.
 *
 * The active-scheme convenience form lives on the `bindProfile()` facade
 * as `nativePqPath(account, index, network, change?)`.
 */
export function nativePqPathFor(
  scheme: DerivationScheme,
  account: number,
  index: number,
  network: Network,
  change: 0 | 1 = 0,
): string {
  return `m/${PURPOSE_FALCON512}'/${coinTypeFor(scheme, network)}'/${account}'/${change}'/${index}'`;
}

/**
 * Derive the Falcon-512 keypair at `(account, change, index)` from a
 * BIP-32 master key.
 *
 * The BIP-32 leaf at {@link nativePqPathFor} provides 32 bytes of input
 * keying material; HKDF-SHA256 stretches it to Falcon's 48-byte keygen
 * seed under the `hkdfInfo` label; keygen is then fully deterministic.
 * The leaf key and the seed are wiped before returning.
 *
 * `scheme` selects the coin_type level of the leaf path. `hkdfInfo` is
 * the chain's Falcon HKDF label (`profile.falconHdInfo`) — the same for
 * every scheme of a chain (versioned separately; see the header notes).
 * The `bindProfile()` facade supplies both from the profile and defaults
 * `scheme` to the active one.
 *
 * Returns `{ publicKey (897 B), privateKey (1281 B) }`.
 */
export async function deriveFalconKeypair(
  master: HDKey,
  account: number,
  change: 0 | 1,
  index: number,
  network: Network,
  scheme: DerivationScheme,
  hkdfInfo: string,
): Promise<Falcon512Keypair> {
  const child = derivePath(master, nativePqPathFor(scheme, account, index, network, change));
  const ikm = child.privateKey;
  if (ikm === null) {
    // Unreachable from a seed-built master (hardened derivation already
    // requires a private key), but guards the public-key-only case.
    throw new Error('Falcon derivation requires a private BIP-32 master key');
  }
  const seed = hkdf(sha256, ikm, undefined, hkdfInfo, FALCON512_SEED_BYTES);
  child.wipePrivateData(); // zeroes ikm — already consumed by HKDF
  try {
    return await falcon512KeygenFromSeed(seed);
  } finally {
    seed.fill(0);
  }
}
