// Tests for the HD → Falcon-512 derivation (PQ branch).
//
// The mapping mnemonic → PQ address is consensus-for-recoverability: if
// any stage changes (path template, purpose, HKDF info label, seed
// length, keygen), existing PQ funds become unrecoverable from their
// mnemonic. The pins below freeze the MECHANICS against the test
// fixture's profile; every consumer additionally pins FULL mnemonic →
// pubkey/address golden vectors for its own frozen chain values in its
// own repo.

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';

import { addressFromPubkey, decodeAddress } from './address.js';
import { derivePath, masterKeyFromSeed } from './bip32.js';
import { mnemonicToSeed } from './bip39.js';
import { toHex } from './encoding/hex.js';
import {
  FALCON512_PRIVATE_KEY_BYTES,
  FALCON512_PUBLIC_KEY_BYTES,
  falcon512Sign,
  falcon512Verify,
} from './falcon512.js';
import {
  PURPOSE_FALCON512,
  deriveFalconKeypair,
  nativePqPathFor,
} from './falconHd.js';
import { sha256 } from './hashes.js';
import { TEST_PROFILE, TEST_SCHEME_V1, TEST_SCHEME_V2 } from './profile.fixtures.js';

/** The standard BIP-39 test mnemonic (same one bip39.test.ts uses). */
const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function master() {
  return masterKeyFromSeed(mnemonicToSeed(MNEMONIC));
}

const INFO = TEST_PROFILE.falconHdInfo;

describe('nativePqPathFor', () => {
  it('builds the fully-hardened purpose-512 path on the scheme coin_type', () => {
    expect(PURPOSE_FALCON512).toBe(512);
    expect(nativePqPathFor(TEST_SCHEME_V2, 0, 0, 'mainnet')).toBe("m/512'/8888'/0'/0'/0'");
    expect(nativePqPathFor(TEST_SCHEME_V2, 0, 0, 'mainnet', 1)).toBe("m/512'/8888'/0'/1'/0'");
    expect(nativePqPathFor(TEST_SCHEME_V1, 1, 2, 'mainnet', 1)).toBe("m/512'/7777'/1'/1'/2'");
  });

  it('the PQ branch follows the per-network coin_type too', () => {
    expect(nativePqPathFor(TEST_SCHEME_V2, 0, 0, 'testnet')).toBe("m/512'/1'/0'/0'/0'");
  });
});

describe('deriveFalconKeypair — HKDF stage (test profile)', () => {
  // Pins path + info label + HKDF independently of the WASM keygen.
  // Golden seeds were generated with an INDEPENDENT implementation
  // (@scure/bip32 + @noble/hkdf directly, fixture values inlined).
  it('mainnet leaf(0,0,0) stretches to the pinned 48-byte seed (ct=8888)', () => {
    const child = derivePath(master(), nativePqPathFor(TEST_SCHEME_V2, 0, 0, 'mainnet', 0));
    const seed48 = hkdf(nobleSha256, child.privateKey!, undefined, INFO, 48);
    expect(toHex(seed48)).toBe(
      'aa2fcc689d3428991678198f073d53aba8d5dd868538f3094276a5457769d5db' +
        '4490f9bd551466b89633ee05e8bcf68a',
    );
  });

  it('testnet leaf(0,0,0) stretches to its own pinned seed (ct=1)', () => {
    const child = derivePath(master(), nativePqPathFor(TEST_SCHEME_V2, 0, 0, 'testnet', 0));
    const seed48 = hkdf(nobleSha256, child.privateKey!, undefined, INFO, 48);
    expect(toHex(seed48)).toBe(
      '74e7e1f00d182051754f5b43b55c6ff2d1a65c24b5e7ba4dc02041f35dde75dd' +
        '4dac1150a335453b81e8aa9f53ed1e54',
    );
  });

  it('derived keys have the Falcon-512 shape', async () => {
    const kp = await deriveFalconKeypair(master(), 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    expect(kp.publicKey.length).toBe(FALCON512_PUBLIC_KEY_BYTES);
    expect(kp.privateKey.length).toBe(FALCON512_PRIVATE_KEY_BYTES);
    expect(kp.publicKey[0]).toBe(0x09); // Falcon-512 version byte
    expect(toHex(sha256(kp.publicKey))).toHaveLength(64);
  });

  it('derived addresses decode as the 32-byte PQ form', async () => {
    const kp = await deriveFalconKeypair(master(), 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    const decoded = decodeAddress(
      addressFromPubkey(kp.publicKey, 'falcon512', 'mainnet', TEST_PROFILE.addrMagic),
      TEST_PROFILE.addrMagic,
      TEST_PROFILE.addressRegex,
    );
    expect(decoded.type).toBe('pq');
    expect(decoded.scripthash.length).toBe(32);
    expect(decoded.network).toBe('mainnet');
  });
});

describe('deriveFalconKeypair — properties', () => {
  it('is deterministic: same cell twice → identical keypair', async () => {
    const a = await deriveFalconKeypair(master(), 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    const b = await deriveFalconKeypair(master(), 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    expect(toHex(a.publicKey)).toBe(toHex(b.publicKey));
    expect(toHex(a.privateKey)).toBe(toHex(b.privateKey));
  });

  it('neighbouring cells (account/change/index) all differ', async () => {
    const m = master();
    const cells: Array<[number, 0 | 1, number]> = [
      [0, 0, 0],
      [0, 0, 1],
      [0, 1, 0],
      [1, 0, 0],
    ];
    const pks = new Set<string>();
    for (const [a, c, i] of cells) {
      pks.add(toHex((await deriveFalconKeypair(m, a, c, i, 'mainnet', TEST_SCHEME_V2, INFO)).publicKey));
    }
    expect(pks.size).toBe(cells.length);
  });

  it('an explicit legacy scheme derives its own branch', async () => {
    const m = master();
    const active = await deriveFalconKeypair(m, 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    const legacy = await deriveFalconKeypair(m, 0, 0, 0, 'mainnet', TEST_SCHEME_V1, INFO);
    expect(toHex(legacy.publicKey)).not.toBe(toHex(active.publicKey));
    // …and is deterministic on its own path.
    const again = await deriveFalconKeypair(m, 0, 0, 0, 'mainnet', TEST_SCHEME_V1, INFO);
    expect(toHex(again.publicKey)).toBe(toHex(legacy.publicKey));
  });

  it('the HKDF info label changes the keypair (domain separation)', async () => {
    const m = master();
    const a = await deriveFalconKeypair(m, 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    const b = await deriveFalconKeypair(m, 0, 0, 0, 'mainnet', TEST_SCHEME_V2, 'other/label/v1');
    expect(toHex(a.publicKey)).not.toBe(toHex(b.publicKey));
  });

  it('same cell, different networks → different keypairs when coin_type differs', async () => {
    const m = master();
    const onMain = await deriveFalconKeypair(m, 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    const onTest = await deriveFalconKeypair(m, 0, 0, 0, 'testnet', TEST_SCHEME_V2, INFO);
    expect(toHex(onMain.publicKey)).not.toBe(toHex(onTest.publicKey));
  });

  it('the derived keypair signs and verifies', async () => {
    const kp = await deriveFalconKeypair(master(), 0, 0, 0, 'mainnet', TEST_SCHEME_V2, INFO);
    const msg = new TextEncoder().encode('pq phase-a');
    const sig = await falcon512Sign(msg, kp.privateKey);
    expect(sig.length).toBeGreaterThan(0);
    expect(await falcon512Verify(sig, msg, kp.publicKey)).toBe(true);
    // Wrong message must not verify.
    expect(
      await falcon512Verify(sig, new TextEncoder().encode('tampered'), kp.publicKey),
    ).toBe(false);
  });
});
