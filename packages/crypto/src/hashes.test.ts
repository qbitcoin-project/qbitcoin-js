import { describe, expect, it } from 'vitest';
import { checksum32, hash160, hash256, ripemd160, sha256 } from './hashes.js';

// Test vectors from RFC 6234 (SHA-256), RFC 3174 (RIPEMD-160 NESSIE
// vectors), and Bitcoin Core's test suite.

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

describe('sha256', () => {
  it('empty input', () => {
    expect(toHex(sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('abc', () => {
    expect(toHex(sha256(new TextEncoder().encode('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('ripemd160', () => {
  it('empty input', () => {
    expect(toHex(ripemd160(new Uint8Array(0)))).toBe(
      '9c1185a5c5e9fc54612808977ee8f548b2258d31',
    );
  });

  it('abc', () => {
    expect(toHex(ripemd160(new TextEncoder().encode('abc')))).toBe(
      '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc',
    );
  });
});

describe('hash160', () => {
  // From Bitcoin: HASH160 of a compressed public key is the standard
  // P2PKH address derivation step.
  it('matches a known compressed pubkey → hash160', () => {
    // Compressed pubkey from Bitcoin test vectors.
    const pubkey = hex(
      '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352',
    );
    expect(toHex(hash160(pubkey))).toBe('f54a5851e9372b87810a8e60cdd2e7cfd80b6e31');
  });
});

describe('hash256', () => {
  // From Bitcoin test vectors — double-SHA256 of "hello".
  it('"hello"', () => {
    expect(toHex(hash256(new TextEncoder().encode('hello')))).toBe(
      '9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50',
    );
  });

  it('empty input', () => {
    // SHA-256 of empty: e3b0...b855
    // SHA-256 of that: 5df6e0e2... (precomputed)
    expect(toHex(hash256(new Uint8Array(0)))).toBe(
      '5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456',
    );
  });
});

describe('checksum32', () => {
  it('is first 4 bytes of hash256', () => {
    const data = new TextEncoder().encode('hello');
    expect(toHex(checksum32(data))).toBe('9595c9df');
    expect(toHex(checksum32(data))).toBe(toHex(hash256(data).slice(0, 4)));
  });
});
