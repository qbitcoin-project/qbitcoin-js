// Hex encoding helpers.
//
// We use a tiny in-house implementation to avoid coupling tests and
// non-crypto code to `@noble/hashes/utils` — keeping the dependency tree
// narrow.

/**
 * Decode a hex string (lowercase or uppercase, no `0x` prefix) into bytes.
 * Throws `TypeError` if the input has odd length or contains non-hex
 * characters.
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new TypeError(`Hex string must have even length, got ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new TypeError(`Invalid hex character at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

/** Encode bytes as a lowercase hex string (no `0x` prefix). */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}
