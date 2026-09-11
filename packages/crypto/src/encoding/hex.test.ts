import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from './hex.js';

describe('toHex', () => {
  it('encodes empty', () => {
    expect(toHex(new Uint8Array(0))).toBe('');
  });

  it('encodes single byte with leading zero', () => {
    expect(toHex(new Uint8Array([0x0a]))).toBe('0a');
  });

  it('encodes multiple bytes', () => {
    expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef');
  });

  it('encodes 0xff', () => {
    expect(toHex(new Uint8Array([0xff]))).toBe('ff');
  });
});

describe('fromHex', () => {
  it('decodes empty', () => {
    expect(fromHex('')).toEqual(new Uint8Array(0));
  });

  it('decodes lowercase', () => {
    expect(fromHex('deadbeef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('decodes uppercase', () => {
    expect(fromHex('DEADBEEF')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('rejects odd length', () => {
    expect(() => fromHex('a')).toThrow(TypeError);
    expect(() => fromHex('abc')).toThrow(TypeError);
  });

  it('rejects non-hex characters', () => {
    expect(() => fromHex('gg')).toThrow(TypeError);
    expect(() => fromHex('zz')).toThrow(TypeError);
  });

  it('roundtrips', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]);
    expect(fromHex(toHex(bytes))).toEqual(bytes);
  });
});
