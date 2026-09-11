import { afterEach, describe, expect, it } from 'vitest';
import { addressFromPubkey, validateAddress } from './address.js';
import { TEST_PROFILE } from './profile.fixtures.js';
import {
  SchnorrDisabledError,
  isSchnorrEnabled,
  setSchnorrEnabled,
} from './features.js';
import { fromHex, toHex } from './encoding/hex.js';
import {
  SCHNORR_PUBLIC_KEY_BYTES,
  SCHNORR_SIGNATURE_BYTES,
  isValidSchnorrPublicKey,
  schnorrGetPublicKey,
  schnorrSign,
  schnorrVerify,
} from './schnorr.js';
import { BIP340_VECTORS_CSV } from './schnorr.vectors.js';
import { getPublicKey as ecdsaGetPublicKey } from './secp256k1.js';
import {
  SIGHASH,
  encodeSiglistEntry,
  signWithAlgorithm,
  verifySiglistEntry,
} from './index.js';

interface Bip340Vector {
  readonly index: number;
  readonly secretKey: Uint8Array | null;
  readonly publicKey: Uint8Array;
  readonly auxRand: Uint8Array | null;
  readonly message: Uint8Array;
  readonly signature: Uint8Array;
  readonly result: boolean;
  readonly comment: string;
}

// The comment column may contain commas — split only the first 6 fields.
function parseVectors(csv: string): Bip340Vector[] {
  return csv
    .trim()
    .split('\n')
    .slice(1)
    .map((line) => {
      const cols = line.split(',');
      const [index, secret, pub, aux, msg, sig, result] = cols;
      return {
        index: Number(index),
        secretKey: secret === '' ? null : fromHex(secret ?? ''),
        publicKey: fromHex(pub ?? ''),
        auxRand: aux === '' ? null : fromHex(aux ?? ''),
        message: fromHex(msg ?? ''),
        signature: fromHex(sig ?? ''),
        result: result === 'TRUE',
        comment: cols.slice(7).join(','),
      };
    });
}

const VECTORS = parseVectors(BIP340_VECTORS_CSV);

describe('BIP-340 official vectors', () => {
  it('parses the full upstream set', () => {
    expect(VECTORS).toHaveLength(19);
  });

  it('derives every vector public key from its secret key', () => {
    for (const v of VECTORS) {
      if (v.secretKey === null) continue;
      expect(toHex(schnorrGetPublicKey(v.secretKey)), `vector ${v.index}`).toBe(
        toHex(v.publicKey),
      );
    }
  });

  it('reproduces every signing vector bit-for-bit (32-byte messages)', () => {
    for (const v of VECTORS) {
      if (v.secretKey === null || v.auxRand === null) continue;
      if (v.message.length !== 32) continue; // sign path enforces digests
      const sig = schnorrSign(v.message, v.secretKey, v.auxRand);
      expect(toHex(sig), `vector ${v.index}`).toBe(toHex(v.signature));
      expect(sig).toHaveLength(SCHNORR_SIGNATURE_BYTES);
    }
  });

  it('matches every verification result, including all failure modes', () => {
    for (const v of VECTORS) {
      expect(
        schnorrVerify(v.signature, v.message, v.publicKey),
        `vector ${v.index}: ${v.comment}`,
      ).toBe(v.result);
    }
  });
});

describe('schnorrSign — input validation', () => {
  const SK = fromHex(
    'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef',
  );

  it('rejects non-32-byte digests', () => {
    expect(() => schnorrSign(new Uint8Array(31), SK)).toThrow(RangeError);
    expect(() => schnorrSign(new Uint8Array(0), SK)).toThrow(RangeError);
  });

  it('produces a randomized but always-valid signature by default', () => {
    const digest = new Uint8Array(32).fill(0x5a);
    const a = schnorrSign(digest, SK);
    const b = schnorrSign(digest, SK);
    // Fresh aux randomness → different signatures for the same message…
    expect(toHex(a)).not.toBe(toHex(b));
    // …but both verify.
    const pub = schnorrGetPublicKey(SK);
    expect(schnorrVerify(a, digest, pub)).toBe(true);
    expect(schnorrVerify(b, digest, pub)).toBe(true);
    // And a flipped digest byte does not.
    const wrong = digest.slice();
    wrong[0] ^= 0xff;
    expect(schnorrVerify(a, wrong, pub)).toBe(false);
  });
});

describe('isValidSchnorrPublicKey', () => {
  it('accepts a vector pubkey and rejects known-bad ones', () => {
    const good = VECTORS[0]!.publicKey;
    expect(isValidSchnorrPublicKey(good)).toBe(true);

    // Vector 5: x-only key not on the curve.
    expect(isValidSchnorrPublicKey(VECTORS[5]!.publicKey)).toBe(false);
    // Vector 14: x exceeds the field size.
    expect(isValidSchnorrPublicKey(VECTORS[14]!.publicKey)).toBe(false);
    // Wrong lengths.
    expect(isValidSchnorrPublicKey(new Uint8Array(33))).toBe(false);
    expect(isValidSchnorrPublicKey(new Uint8Array(0))).toBe(false);
  });
});

describe('node parity', () => {
  const SK = fromHex(
    'c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9',
  );

  it('x-only pubkey equals the compressed ECDSA point minus its parity byte', () => {
    // This is literally how the node builds it: substr(public_compressed, 1).
    const compressed = ecdsaGetPublicKey(SK);
    expect(toHex(schnorrGetPublicKey(SK))).toBe(toHex(compressed.slice(1)));
    expect(schnorrGetPublicKey(SK)).toHaveLength(SCHNORR_PUBLIC_KEY_BYTES);
  });

  it('schnorr and ecdsa addresses differ for the same private key', () => {
    // Mirrors the node's schnorr.t test 11 — the P2PK script pushes a
    // 32-byte key instead of a 33-byte one, so the hash differs.
    const schnorrAddr = addressFromPubkey(
      schnorrGetPublicKey(SK),
      'schnorr',
      'mainnet',
      TEST_PROFILE.addrMagic,
    );
    const ecdsaAddr = addressFromPubkey(ecdsaGetPublicKey(SK), 'ecdsa', 'mainnet', TEST_PROFILE.addrMagic);
    expect(schnorrAddr).not.toBe(ecdsaAddr);
    // Both are classical (HASH160) mainnet addresses.
    expect(validateAddress(schnorrAddr, 'mainnet', TEST_PROFILE.addrMagic, TEST_PROFILE.addressRegex)).toBe(true);
    expect(TEST_PROFILE.addressRegex.mainnet.test(schnorrAddr)).toBe(true);
  });
});

describe('feature gate — signing off by default, verification always on', () => {
  const SK = fromHex(
    'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef',
  );
  const DIGEST = new Uint8Array(32).fill(0x42);

  afterEach(() => {
    setSchnorrEnabled(false);
  });

  it('is disabled by default', () => {
    expect(isSchnorrEnabled()).toBe(false);
  });

  it('signWithAlgorithm refuses schnorr while the flag is off', async () => {
    await expect(signWithAlgorithm(DIGEST, SK, 'schnorr')).rejects.toThrow(
      SchnorrDisabledError,
    );
  });

  it('signWithAlgorithm signs schnorr once enabled', async () => {
    setSchnorrEnabled(true);
    const sig = await signWithAlgorithm(DIGEST, SK, 'schnorr');
    expect(sig).toHaveLength(SCHNORR_SIGNATURE_BYTES);
    expect(schnorrVerify(sig, DIGEST, schnorrGetPublicKey(SK))).toBe(true);
  });

  it('verifySiglistEntry verifies a schnorr envelope even with the flag off', async () => {
    // Produce the envelope while enabled…
    setSchnorrEnabled(true);
    const rawSig = await signWithAlgorithm(DIGEST, SK, 'schnorr');
    const entry = encodeSiglistEntry(SIGHASH.ALL, 'schnorr', rawSig);
    // …then verify with the flag off: network data doesn't wait for us.
    setSchnorrEnabled(false);
    const pub = schnorrGetPublicKey(SK);
    expect(await verifySiglistEntry(entry, DIGEST, pub)).toBe(true);

    // Tampered envelope fails.
    const bad = entry.slice();
    bad[10] ^= 0xff;
    expect(await verifySiglistEntry(bad, DIGEST, pub)).toBe(false);
  });
});
