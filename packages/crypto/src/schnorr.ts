// Schnorr signatures (BIP-340) over secp256k1.
//
// Thin wrapper over @noble/curves — same shape as secp256k1.ts (ECDSA).
//
// Node parity (its Schnorr layer wraps CPAN Crypt::PK::ECC::Schnorr,
// documented as "Compatible with Bitcoin taproot softfork (BIP-340)"):
//
//   - Public keys are 32-byte **x-only**. The node normalizes the keypair
//     to even y at import (negating d when needed) and strips the parity
//     byte; BIP-340 signing handles parity internally, so we do NOT need
//     to negate anything — same signatures, same x-only pubkey either way.
//   - Signatures are 64 bytes (R.x ‖ s), verified with lift_x semantics —
//     the node literally re-imports "\x02" + pubkey to verify.
//   - The signed message is `hash256(sign_data)`, a 32-byte digest.
//
// Signing is feature-gated at the dispatch layer (see features.ts);
// the primitives here are always available for tests and verification.

import { schnorr, secp256k1 } from '@noble/curves/secp256k1';

/** Length of an x-only Schnorr public key in bytes (BIP-340). */
export const SCHNORR_PUBLIC_KEY_BYTES = 32;

/** Length of a Schnorr signature in bytes (BIP-340). */
export const SCHNORR_SIGNATURE_BYTES = 64;

/**
 * Derive the 32-byte x-only public key from a private key.
 *
 * The x coordinate is unaffected by point negation, so this equals the
 * compressed ECDSA pubkey minus its parity byte — which is exactly how
 * the node produces it (`substr(public_compressed, 1)`).
 */
export function schnorrGetPublicKey(privateKey: Uint8Array): Uint8Array {
  return schnorr.getPublicKey(privateKey);
}

/**
 * True if `pubkey` is 32 bytes and lifts to a curve point (BIP-340
 * lift_x). Mirrors the node's check: import `0x02 ‖ x` as a compressed
 * point and see if it decodes.
 */
export function isValidSchnorrPublicKey(pubkey: Uint8Array): boolean {
  if (pubkey.length !== SCHNORR_PUBLIC_KEY_BYTES) return false;
  const compressed = new Uint8Array(1 + SCHNORR_PUBLIC_KEY_BYTES);
  compressed[0] = 0x02;
  compressed.set(pubkey, 1);
  try {
    secp256k1.ProjectivePoint.fromHex(compressed);
    return true;
  } catch {
    return false;
  }
}

/**
 * Sign a 32-byte digest (BIP-340). Returns a 64-byte signature.
 *
 * Like the ECDSA path, the digest MUST already be 32 bytes — the chain's
 * convention is `hash256(sign_data)`. `auxRand` (32 bytes) is the BIP-340
 * auxiliary randomness: omit for a fresh random value (recommended); pass
 * it explicitly only for deterministic test vectors.
 */
export function schnorrSign(
  digest: Uint8Array,
  privateKey: Uint8Array,
  auxRand?: Uint8Array,
): Uint8Array {
  if (digest.length !== 32) {
    throw new RangeError(
      `schnorr sign requires 32-byte digest, got ${digest.length}`,
    );
  }
  return schnorr.sign(digest, privateKey, auxRand);
}

/**
 * Verify a 64-byte Schnorr signature against a message and an x-only
 * public key. Accepts any message length (BIP-340 does; adversarial
 * network data decides what we get). Returns `false` on any parse error
 * or invalid signature — never throws.
 */
export function schnorrVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return schnorr.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
