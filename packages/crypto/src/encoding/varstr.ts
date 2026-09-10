// Length-prefixed byte string (`varstr` in the node's Perl).
//
// Encoding:  varint(length) || raw bytes
//
// Used everywhere in tx serialization: scripthash, redeem_script, data,
// siglist entries.

import { decodeVarint, encodeVarint } from './varint';

/** Encode `bytes` as varstr = varint(length) || bytes. */
export function encodeVarstr(bytes: Uint8Array): Uint8Array {
  const lenPrefix = encodeVarint(bytes.length);
  const out = new Uint8Array(lenPrefix.length + bytes.length);
  out.set(lenPrefix, 0);
  out.set(bytes, lenPrefix.length);
  return out;
}

export interface VarstrDecodeResult {
  /** The string's payload bytes (NOT including the length prefix). */
  bytes: Uint8Array;
  /** Number of bytes consumed from the input, including the length prefix. */
  bytesRead: number;
}

/**
 * Decode a varstr starting at `offset` in `data`.
 *
 * Throws `RangeError` if the encoded length would read past the end of
 * the input, or if the length itself exceeds `Number.MAX_SAFE_INTEGER`
 * (which would be a malformed message anyway — no real tx is that big).
 */
export function decodeVarstr(
  data: Uint8Array,
  offset = 0,
): VarstrDecodeResult {
  const { value: lenBig, bytesRead: lenBytes } = decodeVarint(data, offset);
  if (lenBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`varstr length ${lenBig} exceeds safe integer range`);
  }
  const len = Number(lenBig);
  const start = offset + lenBytes;
  const end = start + len;
  if (end > data.length) {
    throw new RangeError(
      `varstr truncated: need ${len} bytes at offset ${start}, only ${data.length - start} available`,
    );
  }
  return {
    bytes: data.slice(start, end),
    bytesRead: lenBytes + len,
  };
}
