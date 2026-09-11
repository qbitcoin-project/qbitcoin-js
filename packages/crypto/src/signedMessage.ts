// Canonical signed-message format.
//
// The node has no `signmessage`/`verifymessage`, so we DEFINE the format and
// ship it here — canonical, tested, and verifiable by dApps from the
// returned pubkey.
//
//   preimage = varstr(MAGIC) || varstr(utf8(message))
//   digest   = hash256(preimage)                    // double-SHA256
//   sig      = sign(digest, key, algo)              // secp256k1 / Falcon-512
//
// The magic prefix is a CHAIN VALUE (`profile.messageMagic`): signatures
// made under one chain's magic don't verify under another's — deliberate
// domain separation between chains. Every function below takes it as an
// explicit parameter; the `bindProfile()` facade supplies it.
//
// Domain separation from transactions: varstr(MAGIC) begins with
// varint(len(MAGIC)), and any magic of 5+ bytes is not a valid tx_type
// (1..4), so a signed message can never be mistaken for (or collide with)
// a transaction sighash. `bindProfile()` enforces the 5-byte minimum.

import type { Algorithm } from './constants.js';
import { encodeVarstr } from './encoding/varstr.js';
import { falcon512Verify } from './falcon512.js';
import { hash256 } from './hashes.js';
import { verify as secp256k1Verify } from './secp256k1.js';
import { signWithAlgorithm } from './signing.js';

const utf8 = new TextEncoder();

/** The bytes that get hashed: `varstr(magic) || varstr(utf8(message))`. */
export function signedMessagePreimage(message: string, magic: string): Uint8Array {
  const magicVarstr = encodeVarstr(utf8.encode(magic));
  const body = encodeVarstr(utf8.encode(message));
  const out = new Uint8Array(magicVarstr.length + body.length);
  out.set(magicVarstr, 0);
  out.set(body, magicVarstr.length);
  return out;
}

/** Domain-separated digest for a signed message. */
export function signedMessageDigest(message: string, magic: string): Uint8Array {
  return hash256(signedMessagePreimage(message, magic));
}

/** Sign a UTF-8 message → raw signature bytes for `algo` (DER for ECDSA). */
export async function signMessage(
  message: string,
  privateKey: Uint8Array,
  algo: Algorithm,
  magic: string,
): Promise<Uint8Array> {
  return signWithAlgorithm(signedMessageDigest(message, magic), privateKey, algo);
}

/** Verify a message signature against `publicKey`. Never throws — callers may
 *  pass adversarial input. */
export async function verifyMessage(
  message: string,
  signature: Uint8Array,
  publicKey: Uint8Array,
  algo: Algorithm,
  magic: string,
): Promise<boolean> {
  try {
    const digest = signedMessageDigest(message, magic);
    if (algo === 'ecdsa') return secp256k1Verify(signature, digest, publicKey);
    if (algo === 'falcon512') return await falcon512Verify(signature, digest, publicKey);
    return false; // schnorr / unknown not supported for messages
  } catch {
    return false;
  }
}
