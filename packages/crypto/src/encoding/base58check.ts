// Base58Check encoding with configurable version prefix length.
//
// The chain uses a **2-byte version prefix** (ADDR_MAGIC) for addresses,
// while Bitcoin and the WIF private-key format use a **1-byte prefix**.
// We support both via the `versionLen` parameter.
//
// Layout:
//
//     version (versionLen bytes) || payload || checksum (4 bytes)
//
// where checksum = first 4 bytes of HASH256(version || payload).
//
// The whole thing is encoded in Base58 with Bitcoin's alphabet.

import { base58 } from '@scure/base';
import { checksum32 } from '../hashes.js';

/**
 * Encode `version || payload` with an appended Base58Check checksum.
 *
 * `versionLen` is informational — the function works regardless. We keep
 * it for symmetry with `decodeBase58Check`.
 */
export function encodeBase58Check(
  version: Uint8Array,
  payload: Uint8Array,
): string {
  const data = new Uint8Array(version.length + payload.length);
  data.set(version, 0);
  data.set(payload, version.length);
  const check = checksum32(data);

  const out = new Uint8Array(data.length + check.length);
  out.set(data, 0);
  out.set(check, data.length);
  return base58.encode(out);
}

export interface Base58CheckDecodeResult {
  /** The version prefix (length determined by `versionLen` argument). */
  version: Uint8Array;
  /** Everything between the version and the trailing checksum. */
  payload: Uint8Array;
}

/**
 * Decode a Base58Check string into `{ version, payload }`. The caller
 * passes `versionLen` so we know where the version ends and the payload
 * begins.
 *
 * Throws `Error` if the input is not valid Base58, if its decoded length
 * is too short to hold a version + checksum, or if the trailing
 * checksum doesn't match.
 */
export function decodeBase58Check(
  input: string,
  versionLen: number,
): Base58CheckDecodeResult {
  if (!Number.isInteger(versionLen) || versionLen < 1) {
    throw new RangeError(`versionLen must be a positive integer, got ${versionLen}`);
  }

  let raw: Uint8Array;
  try {
    raw = base58.decode(input);
  } catch (e) {
    throw new Error(`Invalid Base58: ${(e as Error).message}`);
  }

  const minLen = versionLen + 4; // version + 4-byte checksum
  if (raw.length < minLen) {
    throw new Error(
      `Base58Check payload too short: ${raw.length} bytes, need at least ${minLen}`,
    );
  }

  const payloadEnd = raw.length - 4;
  const expectedChecksum = raw.slice(payloadEnd);
  const computedChecksum = checksum32(raw.slice(0, payloadEnd));

  // Constant-time comparison would be ideal but checksum mismatch on
  // address decode isn't a side-channel risk — addresses are public.
  for (let i = 0; i < 4; i++) {
    if (expectedChecksum[i] !== computedChecksum[i]) {
      throw new Error('Base58Check checksum mismatch');
    }
  }

  return {
    version: raw.slice(0, versionLen),
    payload: raw.slice(versionLen, payloadEnd),
  };
}
