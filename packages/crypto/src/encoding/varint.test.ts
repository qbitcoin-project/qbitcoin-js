import { describe, expect, it } from 'vitest';
import { decodeVarint, encodeVarint } from './varint.js';
import { fromHex, toHex } from './hex.js';

// Test vectors from Bitcoin Core's `serialize.h` and `compactsize.h` docs.
// Cover all four ranges plus the boundary values.

describe('encodeVarint — boundaries', () => {
  it('encodes 0 as 0x00', () => {
    expect(toHex(encodeVarint(0))).toBe('00');
  });

  it('encodes 252 (0xFC) as one byte', () => {
    expect(toHex(encodeVarint(0xfc))).toBe('fc');
  });

  it('encodes 253 (0xFD) with 0xFD prefix', () => {
    expect(toHex(encodeVarint(0xfd))).toBe('fdfd00');
  });

  it('encodes 0xFFFF with 0xFD prefix', () => {
    expect(toHex(encodeVarint(0xffff))).toBe('fdffff');
  });

  it('encodes 0x10000 with 0xFE prefix', () => {
    expect(toHex(encodeVarint(0x10000))).toBe('fe00000100');
  });

  it('encodes 0xFFFFFFFF with 0xFE prefix', () => {
    expect(toHex(encodeVarint(0xffffffff))).toBe('feffffffff');
  });

  it('encodes 0x100000000 with 0xFF prefix (bigint)', () => {
    expect(toHex(encodeVarint(0x100000000n))).toBe('ff0000000001000000');
  });

  it('encodes uint64 max', () => {
    expect(toHex(encodeVarint(0xffffffffffffffffn))).toBe('ffffffffffffffffff');
  });
});

describe('encodeVarint — input validation', () => {
  it('rejects negative numbers', () => {
    expect(() => encodeVarint(-1)).toThrow(RangeError);
  });

  it('rejects negative bigints', () => {
    expect(() => encodeVarint(-1n)).toThrow(RangeError);
  });

  it('rejects non-integers', () => {
    expect(() => encodeVarint(1.5)).toThrow(RangeError);
  });

  it('rejects beyond uint64 max', () => {
    expect(() => encodeVarint(0x10000000000000000n)).toThrow(RangeError);
  });
});

describe('decodeVarint', () => {
  it('decodes one-byte form', () => {
    expect(decodeVarint(fromHex('00'))).toEqual({ value: 0n, bytesRead: 1 });
    expect(decodeVarint(fromHex('fc'))).toEqual({ value: 0xfcn, bytesRead: 1 });
  });

  it('decodes 0xFD form', () => {
    expect(decodeVarint(fromHex('fdfd00'))).toEqual({
      value: 0xfdn,
      bytesRead: 3,
    });
    expect(decodeVarint(fromHex('fdffff'))).toEqual({
      value: 0xffffn,
      bytesRead: 3,
    });
  });

  it('decodes 0xFE form', () => {
    expect(decodeVarint(fromHex('fe00000100'))).toEqual({
      value: 0x10000n,
      bytesRead: 5,
    });
    expect(decodeVarint(fromHex('feffffffff'))).toEqual({
      value: 0xffffffffn,
      bytesRead: 5,
    });
  });

  it('decodes 0xFF form', () => {
    expect(decodeVarint(fromHex('ff0000000001000000'))).toEqual({
      value: 0x100000000n,
      bytesRead: 9,
    });
    expect(decodeVarint(fromHex('ffffffffffffffffff'))).toEqual({
      value: 0xffffffffffffffffn,
      bytesRead: 9,
    });
  });

  it('respects offset', () => {
    // Two varints packed: 0x05, then 0xFD with 0xFFFF.
    const buf = fromHex('05fdffff');
    expect(decodeVarint(buf, 0)).toEqual({ value: 5n, bytesRead: 1 });
    expect(decodeVarint(buf, 1)).toEqual({ value: 0xffffn, bytesRead: 3 });
  });

  it('rejects truncated 0xFD', () => {
    expect(() => decodeVarint(fromHex('fd'))).toThrow(RangeError);
    expect(() => decodeVarint(fromHex('fdff'))).toThrow(RangeError);
  });

  it('rejects truncated 0xFE', () => {
    expect(() => decodeVarint(fromHex('feffff'))).toThrow(RangeError);
  });

  it('rejects truncated 0xFF', () => {
    expect(() => decodeVarint(fromHex('ffff'))).toThrow(RangeError);
  });

  it('rejects offset out of bounds', () => {
    expect(() => decodeVarint(fromHex('00'), 1)).toThrow(RangeError);
    expect(() => decodeVarint(fromHex(''))).toThrow(RangeError);
    expect(() => decodeVarint(fromHex('00'), -1)).toThrow(RangeError);
  });
});

describe('encode → decode roundtrip', () => {
  const values: bigint[] = [
    0n,
    1n,
    0xfcn,
    0xfdn,
    0xfen,
    0xffn,
    0x100n,
    0xffffn,
    0x10000n,
    0xffffffffn,
    0x100000000n,
    0xffffffffffffffffn,
  ];

  it.each(values)('roundtrips %s', (v) => {
    const enc = encodeVarint(v);
    const dec = decodeVarint(enc);
    expect(dec.value).toBe(v);
    expect(dec.bytesRead).toBe(enc.length);
  });
});
