import { describe, expect, it } from 'vitest';
import {
  COMPRESSED_PUBLIC_KEY_BYTES,
  UNCOMPRESSED_PUBLIC_KEY_BYTES,
  getPublicKey,
  isValidPrivateKey,
  isValidPublicKey,
  sign,
  verify,
} from './secp256k1';
import { fromHex, toHex } from './encoding/hex';
import { hash256 } from './hashes';

// Well-known Bitcoin test private key — used in WIF examples on the
// Bitcoin Wiki. Its corresponding pubkey is widely known and so make a
// good interop check.
const PRIV = fromHex(
  '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d',
);

describe('isValidPrivateKey', () => {
  it('accepts well-known key', () => {
    expect(isValidPrivateKey(PRIV)).toBe(true);
  });

  it('rejects all-zeros', () => {
    expect(isValidPrivateKey(new Uint8Array(32))).toBe(false);
  });

  it('rejects keys ≥ curve order n', () => {
    // n for secp256k1: fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    expect(
      isValidPrivateKey(
        fromHex(
          'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
        ),
      ),
    ).toBe(false);
  });

  it('rejects wrong length', () => {
    expect(isValidPrivateKey(new Uint8Array(31))).toBe(false);
    expect(isValidPrivateKey(new Uint8Array(33))).toBe(false);
  });
});

describe('getPublicKey', () => {
  it('produces 33-byte compressed by default', () => {
    const pk = getPublicKey(PRIV);
    expect(pk.length).toBe(COMPRESSED_PUBLIC_KEY_BYTES);
    // Compressed pubkeys start with 0x02 (even y) or 0x03 (odd y).
    expect([0x02, 0x03]).toContain(pk[0]);
  });

  it('produces 65-byte uncompressed on request', () => {
    const pk = getPublicKey(PRIV, false);
    expect(pk.length).toBe(UNCOMPRESSED_PUBLIC_KEY_BYTES);
    expect(pk[0]).toBe(0x04);
  });

  it('compressed and uncompressed encode the same point', () => {
    // The 32-byte x-coordinate must match in both encodings.
    const compressed = getPublicKey(PRIV, true);
    const uncompressed = getPublicKey(PRIV, false);
    expect(toHex(compressed.slice(1, 33))).toBe(
      toHex(uncompressed.slice(1, 33)),
    );
  });
});

describe('isValidPublicKey', () => {
  it('accepts compressed pubkey from known privkey', () => {
    expect(isValidPublicKey(getPublicKey(PRIV))).toBe(true);
  });

  it('accepts uncompressed pubkey from known privkey', () => {
    expect(isValidPublicKey(getPublicKey(PRIV, false))).toBe(true);
  });

  it('rejects wrong length', () => {
    expect(isValidPublicKey(new Uint8Array(32))).toBe(false);
    expect(isValidPublicKey(new Uint8Array(34))).toBe(false);
  });

  it('rejects garbage of the right length', () => {
    // 33 bytes starting with 0x02 but the x-coord isn't a valid point.
    const fake = new Uint8Array(33);
    fake[0] = 0x02;
    fake.fill(0xff, 1);
    expect(isValidPublicKey(fake)).toBe(false);
  });
});

describe('sign + verify roundtrip', () => {
  it('signs and verifies a digest', () => {
    const msg = new TextEncoder().encode('hello, chain');
    const digest = hash256(msg);
    const sig = sign(digest, PRIV);
    const pub = getPublicKey(PRIV);
    expect(verify(sig, digest, pub)).toBe(true);
  });

  it('signature is DER (starts with 0x30)', () => {
    const digest = hash256(new TextEncoder().encode('x'));
    const sig = sign(digest, PRIV);
    expect(sig[0]).toBe(0x30);
  });

  it('verify rejects wrong public key', () => {
    const digest = hash256(new TextEncoder().encode('x'));
    const sig = sign(digest, PRIV);
    // Different private key → different public key
    const wrongPriv = fromHex(
      '1111111111111111111111111111111111111111111111111111111111111111',
    );
    expect(verify(sig, digest, getPublicKey(wrongPriv))).toBe(false);
  });

  it('verify rejects tampered digest', () => {
    const digest = hash256(new TextEncoder().encode('x'));
    const sig = sign(digest, PRIV);
    const tampered = new Uint8Array(digest);
    tampered[0] = (tampered[0]! ^ 1) & 0xff;
    expect(verify(sig, tampered, getPublicKey(PRIV))).toBe(false);
  });

  it('verify rejects garbage signature without throwing', () => {
    const digest = hash256(new TextEncoder().encode('x'));
    expect(verify(new Uint8Array([0xff, 0xff]), digest, getPublicKey(PRIV))).toBe(false);
    expect(verify(new Uint8Array(0), digest, getPublicKey(PRIV))).toBe(false);
  });

  it('sign rejects non-32-byte digest', () => {
    expect(() => sign(new Uint8Array(31), PRIV)).toThrow(RangeError);
    expect(() => sign(new Uint8Array(33), PRIV)).toThrow(RangeError);
  });

  it('verify rejects non-32-byte digest', () => {
    const sig = sign(hash256(new TextEncoder().encode('x')), PRIV);
    expect(verify(sig, new Uint8Array(31), getPublicKey(PRIV))).toBe(false);
  });
});

