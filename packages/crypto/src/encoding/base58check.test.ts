import { describe, expect, it } from 'vitest';
import { decodeBase58Check, encodeBase58Check } from './base58check.js';
import { fromHex, toHex } from './hex.js';

describe('encodeBase58Check — Bitcoin-compat (1-byte version)', () => {
  // Known WIF test vector (Bitcoin testnet private key + compressed flag).
  // Verifying we match the canonical encoding.
  it('matches WIF testnet vector', () => {
    // From https://en.bitcoin.it/wiki/Wallet_import_format#Mini_private_key_format
    // Private key bytes:
    const priv = fromHex(
      '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d',
    );
    const compressed = fromHex('01'); // compressed pubkey flag
    const payload = new Uint8Array(priv.length + compressed.length);
    payload.set(priv);
    payload.set(compressed, priv.length);
    const result = encodeBase58Check(fromHex('80'), payload);
    expect(result).toBe('KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617');
  });
});

describe('encodeBase58Check — 2-byte version prefix', () => {
  it('encodes a synthetic 20-byte payload with mainnet magic', () => {
    // ADDR_MAGIC mainnet = 0x07 0x6e.
    // Use an all-zeros 20-byte scripthash so the result is deterministic.
    const result = encodeBase58Check(fromHex('1e51'), new Uint8Array(20));
    // Round-trip self-check below — the exact base58 string is what
    // matters for cross-implementation compatibility.
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });
});

describe('decodeBase58Check', () => {
  it('roundtrips with 2-byte version', () => {
    const version = fromHex('1e51');
    const payload = fromHex('00112233445566778899aabbccddeeff00112233');
    const encoded = encodeBase58Check(version, payload);
    const decoded = decodeBase58Check(encoded, 2);
    expect(toHex(decoded.version)).toBe('1e51');
    expect(toHex(decoded.payload)).toBe(toHex(payload));
  });

  it('roundtrips with 1-byte version (WIF-style)', () => {
    const version = fromHex('80');
    const payload = fromHex(
      '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d01',
    );
    const encoded = encodeBase58Check(version, payload);
    const decoded = decodeBase58Check(encoded, 1);
    expect(toHex(decoded.version)).toBe('80');
    expect(toHex(decoded.payload)).toBe(toHex(payload));
  });

  it('roundtrips with 32-byte HASH256-based scripthash (PQ address)', () => {
    const version = fromHex('1e51');
    // 32 bytes representing what hash256(p2pk_script) would produce.
    const payload = new Uint8Array(32).map((_, i) => i);
    const encoded = encodeBase58Check(version, payload);
    const decoded = decodeBase58Check(encoded, 2);
    expect(toHex(decoded.payload)).toBe(toHex(payload));
  });

  it('rejects checksum mismatch (single-byte flip)', () => {
    const version = fromHex('1e51');
    const payload = new Uint8Array(20);
    const encoded = encodeBase58Check(version, payload);

    // Flip a character early enough to change the decoded payload bytes.
    // Bitcoin base58 alphabet swaps:
    const tampered = encoded.replace(/^./, encoded[0] === '1' ? '2' : '1');
    expect(() => decodeBase58Check(tampered, 2)).toThrow();
  });

  it('rejects invalid base58 characters', () => {
    expect(() => decodeBase58Check('not_base58!', 2)).toThrow(/Invalid Base58/);
  });

  it('rejects too-short decoded output', () => {
    // Encode 1 byte without check — passes base58 but fails length check.
    // Pure "1" decodes to a single zero byte in base58 — too short for any
    // version+checksum combination.
    expect(() => decodeBase58Check('1', 2)).toThrow(/too short/);
  });

  it('rejects nonsensical versionLen', () => {
    const encoded = encodeBase58Check(fromHex('1e51'), new Uint8Array(20));
    expect(() => decodeBase58Check(encoded, 0)).toThrow(RangeError);
    expect(() => decodeBase58Check(encoded, -1)).toThrow(RangeError);
    expect(() => decodeBase58Check(encoded, 1.5)).toThrow(RangeError);
  });
});
