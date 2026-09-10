// Hash primitives used throughout the protocol.
//
// All inputs and outputs are byte arrays (`Uint8Array`). Higher-level
// modules (address, signing) compose these into the protocol's actual
// constructions like `scripthash = hash160(p2pk_script)`.
//

import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { ripemd160 as nobleRipemd160 } from '@noble/hashes/ripemd160';

/** SHA-256 of `data`. 32-byte output. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** RIPEMD-160 of `data`. 20-byte output. */
export function ripemd160(data: Uint8Array): Uint8Array {
  return nobleRipemd160(data);
}

/**
 * HASH160 = RIPEMD-160(SHA-256(data)). 20-byte output.
 *
 * Used as the scripthash for classical (secp256k1) addresses
 * — matches Bitcoin's HASH160.
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/**
 * HASH256 = SHA-256(SHA-256(data)). 32-byte output.
 *
 * Used in two places in the protocol:
 *  1. The scripthash for post-quantum (Falcon-512) addresses.
 *  2. The transaction hash (`txid`) — applied to the full serialized tx.
 *  3. The sighash that's signed — applied to `sign_data`.
 *
 * Identical to Bitcoin's double-SHA256.
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * Base58Check checksum: first 4 bytes of HASH256(data).
 *
 * Used as the trailing checksum on both addresses and WIF private keys.
 */
export function checksum32(data: Uint8Array): Uint8Array {
  return hash256(data).slice(0, 4);
}
