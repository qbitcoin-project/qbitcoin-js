import { describe, expect, it } from 'vitest';
import { addressFromPubkey } from './address';
import { derivePath, nativePathFor, masterKeyFromSeed } from './bip32';
import type { Network } from './constants';
import { bindProfile } from './profile';
import { TEST_PROFILE, TEST_SCHEME_V1, TEST_SCHEME_V2 } from './profile.fixtures';
import { addressFromXpub, exportAccountXpubFor, isValidAccountXpub, parseAccountXpub } from './xpub';

const chain = bindProfile(TEST_PROFILE);
const MAGIC = TEST_PROFILE.addrMagic;

// A fixed (non-secret) seed — deterministic so the vectors below are stable.
const master = masterKeyFromSeed(Uint8Array.from({ length: 64 }, (_, i) => (i * 7 + 3) & 0xff));

// The seed-derived address at a leaf, for cross-checking the xpub-derived one.
function seedAddress(chainIdx: 0 | 1, index: number, network: Network): string {
  const node = derivePath(master, nativePathFor(TEST_SCHEME_V2, 0, index, network, chainIdx));
  if (node.publicKey === null) throw new Error('derived node has no public key');
  return addressFromPubkey(node.publicKey, 'ecdsa', network, MAGIC);
}

describe('account xpub (classical watch-only)', () => {
  it('derives the same addresses as the seed, across both chains and indices', () => {
    const account = parseAccountXpub(chain.exportAccountXpub(master, 'mainnet', 0));
    for (const chainIdx of [0, 1] as const) {
      for (const index of [0, 1, 2, 7, 20]) {
        expect(addressFromXpub(account, chainIdx, index, 'mainnet', MAGIC)).toBe(
          seedAddress(chainIdx, index, 'mainnet'),
        );
      }
    }
  });

  it('matches the seed on a testnet account too (its own coin_type branch)', () => {
    // The network selects the account BRANCH on export as well as the address
    // encoding, so a testnet watch descriptor must be built from a testnet
    // xpub — pairing a mainnet xpub with testnet leaves derives a different
    // key entirely (that mismatch is what a schemes-aware descriptor prevents).
    const account = parseAccountXpub(chain.exportAccountXpub(master, 'testnet'));
    expect(addressFromXpub(account, 0, 0, 'testnet', MAGIC)).toBe(seedAddress(0, 0, 'testnet'));
  });

  it('renders one account key under either network prefix', () => {
    // Encoding-only: the same account node, two networks, two address forms.
    const account = parseAccountXpub(chain.exportAccountXpub(master, 'mainnet'));
    expect(addressFromXpub(account, 0, 0, 'testnet', MAGIC)).not.toBe(
      addressFromXpub(account, 0, 0, 'mainnet', MAGIC),
    );
    expect(addressFromXpub(account, 0, 0, 'mainnet', MAGIC)).toBe(seedAddress(0, 0, 'mainnet'));
  });

  it('accepts a freshly exported account xpub', () => {
    expect(isValidAccountXpub(chain.exportAccountXpub(master, 'mainnet', 0))).toBe(true);
    expect(isValidAccountXpub(chain.exportAccountXpub(master, 'mainnet', 5))).toBe(true);
  });

  it('exportAccountXpubFor: active scheme matches the facade export, another scheme differs but derives its own leaves', () => {
    expect(exportAccountXpubFor(master, TEST_SCHEME_V2, 'mainnet', 0)).toBe(
      chain.exportAccountXpub(master, 'mainnet', 0),
    );
    const legacyXpub = exportAccountXpubFor(master, TEST_SCHEME_V1, 'mainnet', 0);
    expect(legacyXpub).not.toBe(chain.exportAccountXpub(master, 'mainnet', 0));
    expect(isValidAccountXpub(legacyXpub)).toBe(true);
    // Public CKD from the scheme's account node reproduces the scheme's seed leaves.
    const node = derivePath(master, nativePathFor(TEST_SCHEME_V1, 0, 3, 'mainnet', 1));
    expect(addressFromXpub(parseAccountXpub(legacyXpub), 1, 3, 'mainnet', MAGIC)).toBe(
      addressFromPubkey(node.publicKey!, 'ecdsa', 'mainnet', MAGIC),
    );
  });

  it('rejects junk, a master-depth xpub, and a private extended key', () => {
    expect(isValidAccountXpub('not an xpub')).toBe(false);
    expect(isValidAccountXpub('')).toBe(false);
    // The master's own xpub is depth 0 — not an account key.
    expect(isValidAccountXpub(master.publicExtendedKey)).toBe(false);
    // A private extended key at account depth must still be rejected.
    const accountPath = nativePathFor(TEST_SCHEME_V2, 0, 0, 'mainnet', 0).split('/').slice(0, 4).join('/');
    expect(isValidAccountXpub(derivePath(master, accountPath).privateExtendedKey)).toBe(false);
  });
});
