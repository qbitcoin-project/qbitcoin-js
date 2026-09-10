// secp256k1 ECDSA primitives.
//
// Thin wrapper over @noble/curves/secp256k1. We expose only what the
// wallet actually uses: get public key from private, sign a 32-byte
// digest, verify a signature, and validate keys.
//
// Two important format decisions for node compatibility:
//
//  1. Public keys are **compressed** (33 bytes, 0x02 / 0x03 prefix).
//     The node's `is_valid_pubkey` accepts both 33 (compressed) and 65
//     (uncompressed) for ECDSA, but P2PK redeem scripts in the mempool
//     use compressed — and we already proved this from a real tx
//     (`21 03... ac`).
//
//  2. Signatures are **DER-encoded**. The mempool dump confirmed
//     siglist entries start with `30 45 02 21 ...` — DER SEQUENCE.
//     `@noble/curves` produces low-S DER by default, which matches what
//     mainline Bitcoin Core and the node emit.

import { secp256k1 } from '@noble/curves/secp256k1';

/** Length of a secp256k1 private key in bytes. */
export const PRIVATE_KEY_BYTES = 32;

/** Length of a compressed secp256k1 public key in bytes. */
export const COMPRESSED_PUBLIC_KEY_BYTES = 33;

/** Length of an uncompressed secp256k1 public key in bytes. */
export const UNCOMPRESSED_PUBLIC_KEY_BYTES = 65;

/** True if `key` is a valid secp256k1 scalar (32 bytes, 0 < k < n). */
export function isValidPrivateKey(key: Uint8Array): boolean {
  if (key.length !== PRIVATE_KEY_BYTES) return false;
  return secp256k1.utils.isValidPrivateKey(key);
}

/**
 * True if `pubkey` decodes as a valid point on the curve.
 *
 * Accepts both 33-byte compressed (`02`/`03` prefix) and 65-byte
 * uncompressed (`04` prefix) encodings.
 */
export function isValidPublicKey(pubkey: Uint8Array): boolean {
  if (
    pubkey.length !== COMPRESSED_PUBLIC_KEY_BYTES &&
    pubkey.length !== UNCOMPRESSED_PUBLIC_KEY_BYTES
  ) {
    return false;
  }
  try {
    secp256k1.ProjectivePoint.fromHex(pubkey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Derive the compressed public key from a private key.
 *
 * Pass `compressed: false` for the legacy 65-byte form — only useful for
 * Bitcoin-imported keys that originated as uncompressed.
 */
export function getPublicKey(
  privateKey: Uint8Array,
  compressed = true,
): Uint8Array {
  return secp256k1.getPublicKey(privateKey, compressed);
}

/**
 * Sign a 32-byte digest with a private key. Returns DER-encoded signature.
 *
 * `msgHash` MUST already be 32 bytes — typically the output of
 * `hash256(sign_data)`. Passing a raw message
 * (not its hash) would silently produce a wrong signature; the type
 * makes this hard to mistake.
 *
 * The signature is **low-S normalized** (canonical form) — Bitcoin and
 * the node both reject high-S signatures, this is the safe default.
 */
export function sign(msgHash: Uint8Array, privateKey: Uint8Array): Uint8Array {
  if (msgHash.length !== 32) {
    throw new RangeError(`secp256k1 sign requires 32-byte digest, got ${msgHash.length}`);
  }
  const sig = secp256k1.sign(msgHash, privateKey, { lowS: true });
  return sig.toDERRawBytes();
}

/**
 * Verify a DER-encoded signature against a digest and public key.
 *
 * Returns `false` on any parse error or invalid signature, never throws
 * — useful when validating incoming network data.
 */
export function verify(
  signature: Uint8Array,
  msgHash: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (msgHash.length !== 32) return false;
  try {
    return secp256k1.verify(signature, msgHash, publicKey, { lowS: true });
  } catch {
    return false;
  }
}
