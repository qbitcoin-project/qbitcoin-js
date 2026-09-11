import { describe, expect, it } from 'vitest';
import {
  coinTypeFor,
  activeScheme,
  derivePath,
  nativePathFor,
  legacySchemes,
  masterKeyFromSeed,
  requireScheme,
  schemeById,
  type DerivationScheme,
} from './bip32.js';
import { fromHex, toHex } from './encoding/hex.js';
import { TEST_PROFILE, TEST_SCHEME_V1, TEST_SCHEME_V2 } from './profile.fixtures.js';

// BIP-32 official test vectors from the spec:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
//
// Test Vector 1 — seed and chain master key.

const TV1_SEED = fromHex('000102030405060708090a0b0c0d0e0f');

// Expected master private-key bytes (32 bytes) and chain code (32 bytes)
// per BIP-32 spec Test Vector 1, derived from the seed above.
const TV1_MASTER_PRIV =
  'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35';
const TV1_MASTER_CC =
  '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508';

// m/0' — first hardened child.
const TV1_0H_PRIV =
  'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea';

describe('masterKeyFromSeed — BIP-32 Test Vector 1', () => {
  it('produces correct master private key', () => {
    const m = masterKeyFromSeed(TV1_SEED);
    expect(toHex(m.privateKey!)).toBe(TV1_MASTER_PRIV);
  });

  it('produces correct master chain code', () => {
    const m = masterKeyFromSeed(TV1_SEED);
    expect(toHex(m.chainCode!)).toBe(TV1_MASTER_CC);
  });

  it('has 33-byte compressed public key', () => {
    const m = masterKeyFromSeed(TV1_SEED);
    expect(m.publicKey!.length).toBe(33);
  });
});

describe('derivePath — BIP-32 Test Vector 1', () => {
  it("matches expected key at m/0'", () => {
    const m = masterKeyFromSeed(TV1_SEED);
    const child = derivePath(m, "m/0'");
    expect(toHex(child.privateKey!)).toBe(TV1_0H_PRIV);
  });

  it('derives along a longer path without throwing', () => {
    const m = masterKeyFromSeed(TV1_SEED);
    const child = derivePath(m, "m/0'/1/2'/2/1000000000");
    expect(child.privateKey!.length).toBe(32);
    expect(child.chainCode!.length).toBe(32);
  });

  it('produces deterministic outputs for the same path', () => {
    const m1 = masterKeyFromSeed(TV1_SEED);
    const m2 = masterKeyFromSeed(TV1_SEED);
    expect(toHex(derivePath(m1, "m/0'/0/0").privateKey!)).toBe(
      toHex(derivePath(m2, "m/0'/0/0").privateKey!),
    );
  });
});

// Scheme mechanics run against the test fixture's scheme list — the
// package has no scheme registry of its own; consumers declare theirs in
// a ChainProfile.
const SCHEMES = TEST_PROFILE.schemes;

describe('derivation scheme mechanics', () => {
  it('activeScheme returns the single active scheme', () => {
    expect(activeScheme(SCHEMES)).toBe(TEST_SCHEME_V2);
  });

  it('activeScheme throws on zero or several active schemes', () => {
    expect(() => activeScheme([TEST_SCHEME_V1])).toThrow(/Exactly one active/);
    expect(() =>
      activeScheme([TEST_SCHEME_V2, { ...TEST_SCHEME_V1, status: 'active' }]),
    ).toThrow(/found 2/);
  });

  it('legacySchemes filters by status', () => {
    expect(legacySchemes(SCHEMES)).toEqual([TEST_SCHEME_V1]);
    expect(legacySchemes([TEST_SCHEME_V2])).toEqual([]);
  });

  it('schemeById finds schemes and misses unknown ids', () => {
    expect(schemeById(SCHEMES, 'test-v1')).toBe(TEST_SCHEME_V1);
    expect(schemeById(SCHEMES, 'unknown')).toBeUndefined();
  });

  it('requireScheme returns known schemes and throws on unknown ids', () => {
    expect(requireScheme(SCHEMES, 'test-v2-dual')).toBe(TEST_SCHEME_V2);
    expect(() => requireScheme(SCHEMES, 'nope')).toThrow(/Unknown derivation scheme/);
  });
});

describe('nativePathFor', () => {
  it('builds the path from the scheme template', () => {
    expect(nativePathFor(TEST_SCHEME_V1, 0, 3, 'mainnet', 1)).toBe("m/44'/7777'/0'/1/3");
    expect(nativePathFor(TEST_SCHEME_V2, 0, 0, 'mainnet')).toBe("m/44'/8888'/0'/0/0");
  });

  it('defaults to the receive chain (change=0)', () => {
    expect(nativePathFor(TEST_SCHEME_V1, 2, 7, 'mainnet')).toBe("m/44'/7777'/2'/0/7");
  });

  it('can be passed to derivePath', () => {
    const m = masterKeyFromSeed(TV1_SEED);
    const child = derivePath(m, nativePathFor(TEST_SCHEME_V2, 0, 0, 'mainnet'));
    expect(child.privateKey).toBeDefined();
    expect(child.privateKey!.length).toBe(32);
  });

  it('different indices give different keys', () => {
    const m = masterKeyFromSeed(TV1_SEED);
    const a = derivePath(m, nativePathFor(TEST_SCHEME_V2, 0, 0, 'mainnet'));
    const b = derivePath(m, nativePathFor(TEST_SCHEME_V2, 0, 1, 'mainnet'));
    expect(toHex(a.privateKey!)).not.toBe(toHex(b.privateKey!));
  });
});

describe('coinTypeFor — per-network coin_type', () => {
  it('a plain number applies to every network', () => {
    expect(coinTypeFor(TEST_SCHEME_V1, 'mainnet')).toBe(7777);
    expect(coinTypeFor(TEST_SCHEME_V1, 'testnet')).toBe(7777);
  });

  it('a record resolves per network, and the path follows it', () => {
    expect(coinTypeFor(TEST_SCHEME_V2, 'mainnet')).toBe(8888);
    expect(coinTypeFor(TEST_SCHEME_V2, 'testnet')).toBe(1);
    expect(nativePathFor(TEST_SCHEME_V2, 0, 0, 'mainnet')).toBe("m/44'/8888'/0'/0/0");
    expect(nativePathFor(TEST_SCHEME_V2, 0, 0, 'testnet')).toBe("m/44'/1'/0'/0/0");
    expect(nativePathFor(TEST_SCHEME_V2, 1, 3, 'mainnet', 1)).toBe("m/44'/8888'/1'/1/3");
  });

  it('same cell, different networks → different keys when coin_type differs', () => {
    const m = masterKeyFromSeed(TV1_SEED);
    const onMain = derivePath(m, nativePathFor(TEST_SCHEME_V2, 0, 0, 'mainnet'));
    const onTest = derivePath(m, nativePathFor(TEST_SCHEME_V2, 0, 0, 'testnet'));
    expect(toHex(onMain.privateKey!)).not.toBe(toHex(onTest.privateKey!));
  });

  it('a custom scheme shape works with the same mechanics', () => {
    const custom: DerivationScheme = {
      id: 'custom',
      coinType: 4242,
      label: 'custom',
      status: 'legacy',
      pathTemplate: (account, change, index, _network) =>
        `m/44'/4242'/${account}'/${change}/${index}`,
    };
    expect(coinTypeFor(custom, 'mainnet')).toBe(4242);
    expect(nativePathFor(custom, 0, 1, 'testnet', 1)).toBe("m/44'/4242'/0'/1/1");
  });
});
