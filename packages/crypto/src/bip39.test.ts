import { describe, expect, it } from 'vitest';
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from './bip39';
import { toHex } from './encoding/hex';

// Test vectors from Trezor's BIP-39 canonical test suite (passphrase = "TREZOR").
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//
// These are the most-cited interop test vectors in the ecosystem; if our
// `mnemonicToSeed` matches them, we're compatible with every BIP-39 wallet.
const TREZOR_VECTORS: Array<{
  mnemonic: string;
  passphrase: string;
  seed: string;
}> = [
  {
    mnemonic:
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    passphrase: 'TREZOR',
    seed: 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
  },
  {
    mnemonic:
      'legal winner thank year wave sausage worth useful legal winner thank yellow',
    passphrase: 'TREZOR',
    seed: '2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607',
  },
  {
    mnemonic:
      'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
    passphrase: 'TREZOR',
    seed: 'd71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8',
  },
];

describe('generateMnemonic', () => {
  it('produces 12 words by default', () => {
    const m = generateMnemonic();
    expect(m.split(' ').length).toBe(12);
  });

  it.each([12, 15, 18, 21, 24] as const)('produces %i words on request', (n) => {
    const m = generateMnemonic(n);
    expect(m.split(' ').length).toBe(n);
    expect(validateMnemonic(m)).toBe(true);
  });

  it('produces a different mnemonic every call', () => {
    const a = generateMnemonic();
    const b = generateMnemonic();
    expect(a).not.toBe(b);
  });
});

describe('validateMnemonic', () => {
  it('accepts Trezor test vectors', () => {
    for (const v of TREZOR_VECTORS) {
      expect(validateMnemonic(v.mnemonic)).toBe(true);
    }
  });

  it('rejects too-few words', () => {
    expect(validateMnemonic('abandon abandon abandon')).toBe(false);
  });

  it('rejects non-wordlist words', () => {
    // 12 words, last one is bogus — checksum can't pass.
    expect(
      validateMnemonic(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzzz',
      ),
    ).toBe(false);
  });

  it('rejects empty string', () => {
    expect(validateMnemonic('')).toBe(false);
  });

  it('rejects valid wordlist words with bad checksum', () => {
    // Replace last word "about" (checksum-valid) with another wordlist word.
    expect(
      validateMnemonic(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
      ),
    ).toBe(false);
  });

  it('trims leading/trailing whitespace', () => {
    const { mnemonic } = TREZOR_VECTORS[0]!;
    expect(validateMnemonic(`  ${mnemonic}  `)).toBe(true);
  });
});

describe('mnemonicToSeed — Trezor interop', () => {
  it.each(TREZOR_VECTORS)(
    'matches seed for "$mnemonic"',
    ({ mnemonic, passphrase, seed }) => {
      expect(toHex(mnemonicToSeed(mnemonic, passphrase))).toBe(seed);
    },
  );

  it('produces 64-byte seed', () => {
    const seed = mnemonicToSeed(TREZOR_VECTORS[0]!.mnemonic);
    expect(seed.length).toBe(64);
  });

  it('differs with/without passphrase', () => {
    const m = TREZOR_VECTORS[0]!.mnemonic;
    const noPass = mnemonicToSeed(m);
    const withPass = mnemonicToSeed(m, 'TREZOR');
    expect(toHex(noPass)).not.toBe(toHex(withPass));
  });
});
