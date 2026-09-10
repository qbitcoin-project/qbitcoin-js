// Bitcoin-style variable-length integer encoding.
//
// Used to encode counts of inputs/outputs/siglist items in transactions
// and lengths in `varstr`. Same format as Bitcoin Core's `CompactSize`.
//
//
// | Value range          | Encoding                  |
// |----------------------|---------------------------|
// | 0 ≤ n < 0xFD         | one byte: n               |
// | 0xFD ≤ n ≤ 0xFFFF    | 0xFD || n as 2 bytes LE   |
// | 0x10000 ≤ n ≤ 0xFFFFFFFF | 0xFE || n as 4 bytes LE |
// | n ≥ 0x100000000      | 0xFF || n as 8 bytes LE   |

const MAX_U8 = 0xfd;
const MAX_U16 = 0xffff;
const MAX_U32 = 0xffffffff;

/**
 * Encode a non-negative integer as a Bitcoin varint.
 *
 * Accepts both `number` (for values up to 2^53) and `bigint` (for the
 * full uint64 range).
 *
 * Throws `RangeError` on negative inputs or non-integer numbers.
 */
export function encodeVarint(value: number | bigint): Uint8Array {
  const n = typeof value === 'bigint' ? value : BigInt(value);
  if (typeof value === 'number' && !Number.isInteger(value)) {
    throw new RangeError(`varint requires an integer, got ${value}`);
  }
  if (n < 0n) {
    throw new RangeError(`varint cannot be negative, got ${n}`);
  }

  if (n < BigInt(MAX_U8)) {
    return new Uint8Array([Number(n)]);
  }
  if (n <= BigInt(MAX_U16)) {
    const out = new Uint8Array(3);
    out[0] = 0xfd;
    new DataView(out.buffer).setUint16(1, Number(n), true /* little-endian */);
    return out;
  }
  if (n <= BigInt(MAX_U32)) {
    const out = new Uint8Array(5);
    out[0] = 0xfe;
    new DataView(out.buffer).setUint32(1, Number(n), true);
    return out;
  }
  if (n <= 0xffffffffffffffffn) {
    const out = new Uint8Array(9);
    out[0] = 0xff;
    new DataView(out.buffer).setBigUint64(1, n, true);
    return out;
  }
  throw new RangeError(`varint overflow: ${n} exceeds uint64 max`);
}

export interface VarintDecodeResult {
  /** The decoded integer. Always returned as bigint for uniform handling. */
  value: bigint;
  /** Number of bytes consumed from the input. */
  bytesRead: number;
}

/**
 * Decode a Bitcoin varint starting at `offset` in `data`.
 *
 * Returns `{ value, bytesRead }`. Throws `RangeError` if there aren't
 * enough bytes left or if the encoding is malformed.
 */
export function decodeVarint(
  data: Uint8Array,
  offset = 0,
): VarintDecodeResult {
  if (offset < 0 || offset >= data.length) {
    throw new RangeError(`varint offset ${offset} out of bounds (length ${data.length})`);
  }

  const tag = data[offset]!;
  if (tag < 0xfd) {
    return { value: BigInt(tag), bytesRead: 1 };
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (tag === 0xfd) {
    if (offset + 3 > data.length) {
      throw new RangeError('varint truncated (need 3 bytes for 0xfd prefix)');
    }
    return { value: BigInt(view.getUint16(offset + 1, true)), bytesRead: 3 };
  }
  if (tag === 0xfe) {
    if (offset + 5 > data.length) {
      throw new RangeError('varint truncated (need 5 bytes for 0xfe prefix)');
    }
    return { value: BigInt(view.getUint32(offset + 1, true)), bytesRead: 5 };
  }
  // tag === 0xff
  if (offset + 9 > data.length) {
    throw new RangeError('varint truncated (need 9 bytes for 0xff prefix)');
  }
  return { value: view.getBigUint64(offset + 1, true), bytesRead: 9 };
}
