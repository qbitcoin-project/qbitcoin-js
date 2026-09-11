import { describe, expect, it } from 'vitest';
import { decodeVarstr, encodeVarstr } from './varstr.js';
import { fromHex, toHex } from './hex.js';

describe('encodeVarstr', () => {
  it('encodes empty string', () => {
    expect(toHex(encodeVarstr(new Uint8Array(0)))).toBe('00');
  });

  it('encodes short string', () => {
    expect(toHex(encodeVarstr(fromHex('deadbeef')))).toBe('04deadbeef');
  });

  it('encodes 0xFC-byte string (one-byte length)', () => {
    const payload = new Uint8Array(0xfc).fill(0xaa);
    const enc = encodeVarstr(payload);
    expect(enc[0]).toBe(0xfc);
    expect(enc.length).toBe(0xfc + 1);
  });

  it('encodes 0xFD-byte string (three-byte length)', () => {
    const payload = new Uint8Array(0xfd).fill(0xaa);
    const enc = encodeVarstr(payload);
    expect(enc[0]).toBe(0xfd);
    expect(enc[1]).toBe(0xfd);
    expect(enc[2]).toBe(0x00);
    expect(enc.length).toBe(0xfd + 3);
  });
});

describe('decodeVarstr', () => {
  it('decodes empty', () => {
    expect(decodeVarstr(fromHex('00'))).toEqual({
      bytes: new Uint8Array(0),
      bytesRead: 1,
    });
  });

  it('decodes short string', () => {
    const result = decodeVarstr(fromHex('04deadbeef'));
    expect(toHex(result.bytes)).toBe('deadbeef');
    expect(result.bytesRead).toBe(5);
  });

  it('respects offset', () => {
    // 0x02 0xaa 0xaa  (3-byte varstr "aaaa")
    // 0x01 0xbb       (2-byte varstr "bb")
    const buf = fromHex('02aaaa01bb');
    const first = decodeVarstr(buf, 0);
    expect(toHex(first.bytes)).toBe('aaaa');
    expect(first.bytesRead).toBe(3);

    const second = decodeVarstr(buf, 3);
    expect(toHex(second.bytes)).toBe('bb');
    expect(second.bytesRead).toBe(2);
  });

  it('rejects truncated payload', () => {
    // Says 4 bytes follow, only gives 2.
    expect(() => decodeVarstr(fromHex('04dead'))).toThrow(RangeError);
  });

  it('rejects unrealistic lengths', () => {
    // 0xFF prefix with bigint length beyond MAX_SAFE_INTEGER.
    // Bytes: ff (prefix) || 00...01 (LE bigint > 2^53)
    expect(() => decodeVarstr(fromHex('ff0000000000000020'))).toThrow(RangeError);
  });
});

describe('encode → decode roundtrip', () => {
  it.each([
    new Uint8Array(0),
    fromHex('00'),
    fromHex('aabbccdd'),
    new Uint8Array(0xfc).fill(0x42),
    new Uint8Array(0xfd).fill(0x42),
    new Uint8Array(1000).fill(0x42),
  ])('roundtrips length %#', (payload) => {
    const enc = encodeVarstr(payload);
    const dec = decodeVarstr(enc);
    expect(dec.bytes).toEqual(payload);
    expect(dec.bytesRead).toBe(enc.length);
  });
});
