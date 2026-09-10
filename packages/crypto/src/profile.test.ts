import { describe, expect, it } from 'vitest';

import { addressFromScripthash, validateAddress } from './address';
import { nativePathFor } from './bip32';
import type { DowngradeChainConfig, UpgradeChainConfig } from './constants';
import { federationFreezeScript } from './downgrade';
import { deriveAppDataKey } from './appData';
import { masterKeyFromSeed } from './bip32';
import { fromHex, toHex } from './encoding/hex';
import { deriveFalconKeypair } from './falconHd';
import { bindProfile, validateProfile, type ChainProfile } from './profile';
import { TEST_PROFILE, TEST_SCHEME_V1, TEST_SCHEME_V2 } from './profile.fixtures';
import { getPublicKey } from './secp256k1';
import { signedMessageDigest } from './signedMessage';
import { decodeWif, encodeWif } from './wif';
import { exportAccountXpubFor, parseAccountXpub } from './xpub';

const chain = bindProfile(TEST_PROFILE);

// A deterministic 64-byte "seed" for derivation-equivalence checks.
const SEED = Uint8Array.from({ length: 64 }, (_, i) => (i * 7 + 3) & 0xff);

describe('validateProfile', () => {
  const bad = (patch: Partial<ChainProfile>): ChainProfile => ({ ...TEST_PROFILE, ...patch });

  it('accepts the test profile', () => {
    expect(() => validateProfile(TEST_PROFILE)).not.toThrow();
  });

  it('rejects zero or two active schemes', () => {
    expect(() => validateProfile(bad({ schemes: [TEST_SCHEME_V1] }))).toThrow(/active/);
    expect(() =>
      validateProfile(bad({ schemes: [TEST_SCHEME_V2, { ...TEST_SCHEME_V1, status: 'active' }] })),
    ).toThrow(/active/);
  });

  it('rejects duplicate scheme ids', () => {
    expect(() =>
      validateProfile(bad({ schemes: [TEST_SCHEME_V2, { ...TEST_SCHEME_V1, id: TEST_SCHEME_V2.id }] })),
    ).toThrow(/unique/);
  });

  it('rejects a metaV1SchemeId that is not one of the schemes', () => {
    expect(() => validateProfile(bad({ metaV1SchemeId: 'nope' }))).toThrow(/metaV1SchemeId/);
  });

  it('rejects empty address magic', () => {
    expect(() =>
      validateProfile(bad({ addrMagic: { ...TEST_PROFILE.addrMagic, testnet: new Uint8Array(0) } })),
    ).toThrow(/magic/);
  });

  it('rejects out-of-range and colliding WIF versions', () => {
    expect(() =>
      validateProfile(bad({ wifVersion: { mainnet: 256, testnet: 0xef } })),
    ).toThrow(/WIF version/);
    expect(() =>
      validateProfile(bad({ wifVersion: { mainnet: 0x80, testnet: 0x80 } })),
    ).toThrow(/must differ/);
  });

  it('rejects empty or colliding HKDF info labels', () => {
    expect(() => validateProfile(bad({ falconHdInfo: '' }))).toThrow(/info labels/);
    expect(() =>
      validateProfile(bad({ appDataInfo: TEST_PROFILE.falconHdInfo })),
    ).toThrow(/domain-separate/);
  });

  it('rejects a message magic shorter than 5 bytes', () => {
    expect(() => validateProfile(bad({ messageMagic: 'abcd' }))).toThrow(/messageMagic/);
  });
});

describe('TEST_PROFILE address regexes (property check)', () => {
  // The fixture's regexes were derived from its fake magic the way real
  // chains derive theirs from node constants. Sample the whole payload
  // space: every encoded address must satisfy the shape pre-filter,
  // otherwise validateAddress would reject real addresses.
  it('every encoded address passes the shape pre-filter', () => {
    for (const network of ['mainnet', 'testnet'] as const) {
      for (const len of [20, 32]) {
        for (let i = 0; i < 500; i++) {
          const payload = new Uint8Array(len);
          crypto.getRandomValues(payload);
          const addr = addressFromScripthash(payload, network, TEST_PROFILE.addrMagic);
          expect(TEST_PROFILE.addressRegex[network].test(addr)).toBe(true);
          expect(chain.validateAddress(addr, network)).toBe(true);
        }
      }
    }
  });

  it('rejects first chars outside the reachable ranges', () => {
    const tail = '1'.repeat(49);
    expect(TEST_PROFILE.addressRegex.mainnet.test(`5V6${tail}`)).toBe(false);
    expect(TEST_PROFILE.addressRegex.mainnet.test(`5VA${tail}`)).toBe(false);
    expect(TEST_PROFILE.addressRegex.testnet.test(`36Xt${tail.slice(1)}`)).toBe(false);
  });
});

describe('bindProfile — facade equivalence with the pure functions', () => {
  it('exposes the profile and validates at bind time', () => {
    expect(chain.profile).toBe(TEST_PROFILE);
    expect(() => bindProfile({ ...TEST_PROFILE, metaV1SchemeId: 'nope' })).toThrow();
  });

  it('scheme lookups resolve against the profile schemes', () => {
    expect(chain.activeScheme()).toBe(TEST_SCHEME_V2);
    expect(chain.legacySchemes()).toEqual([TEST_SCHEME_V1]);
    expect(chain.schemeById('test-v1')).toBe(TEST_SCHEME_V1);
    expect(chain.schemeById('nope')).toBeUndefined();
    expect(chain.requireScheme('test-v2-dual')).toBe(TEST_SCHEME_V2);
    expect(() => chain.requireScheme('nope')).toThrow(/Unknown derivation scheme/);
    expect(chain.metaV1SchemeId).toBe('test-v1');
  });

  it('nativePath / nativePqPath default to the active scheme', () => {
    expect(chain.nativePath(0, 3, 'mainnet', 1)).toBe(
      nativePathFor(TEST_SCHEME_V2, 0, 3, 'mainnet', 1),
    );
    expect(chain.nativePath(0, 0, 'testnet')).toBe("m/44'/1'/0'/0/0");
    expect(chain.nativePqPath(1, 2, 'mainnet', 1)).toBe("m/512'/8888'/1'/1'/2'");
    expect(chain.nativePqPath(0, 0, 'testnet')).toBe("m/512'/1'/0'/0'/0'");
  });

  it('deriveFalconKeypair defaults the scheme and injects the HKDF label', async () => {
    const master = masterKeyFromSeed(SEED);
    const viaFacade = await chain.deriveFalconKeypair(master, 0, 0, 0, 'mainnet');
    const viaPure = await deriveFalconKeypair(
      master, 0, 0, 0, 'mainnet', TEST_SCHEME_V2, TEST_PROFILE.falconHdInfo,
    );
    expect(toHex(viaFacade.publicKey)).toBe(toHex(viaPure.publicKey));
  });

  it('exportAccountXpub matches the explicit-scheme form on the active scheme', () => {
    const master = masterKeyFromSeed(SEED);
    expect(chain.exportAccountXpub(master, 'mainnet', 0)).toBe(
      exportAccountXpubFor(master, TEST_SCHEME_V2, 'mainnet', 0),
    );
  });

  it('address facade round-trips against the pure functions', () => {
    const scripthash = new Uint8Array(20).fill(7);
    const addr = chain.addressFromScripthash(scripthash, 'mainnet');
    expect(addr).toBe(addressFromScripthash(scripthash, 'mainnet', TEST_PROFILE.addrMagic));
    expect(chain.validateAddress(addr, 'mainnet')).toBe(
      validateAddress(addr, 'mainnet', TEST_PROFILE.addrMagic, TEST_PROFILE.addressRegex),
    );
    const decoded = chain.decodeAddress(addr);
    expect(decoded.network).toBe('mainnet');
    expect(toHex(decoded.scripthash)).toBe(toHex(scripthash));
  });

  it('addressFromPubkey and addressFromXpub agree on the same leaf', () => {
    const master = masterKeyFromSeed(SEED);
    const account = parseAccountXpub(chain.exportAccountXpub(master, 'mainnet', 0));
    const child = account.deriveChild(0).deriveChild(4);
    expect(chain.addressFromXpub(account, 0, 4, 'mainnet')).toBe(
      chain.addressFromPubkey(child.publicKey!, 'ecdsa', 'mainnet'),
    );
  });

  it('WIF facade round-trips and injects the version map', () => {
    const key = new Uint8Array(32).fill(1);
    const wif = chain.encodeWif(key, 'testnet');
    expect(wif).toBe(encodeWif(key, 'testnet', TEST_PROFILE.wifVersion));
    expect(toHex(chain.decodeWif(wif, 'testnet').payload)).toBe(toHex(key));
    expect(toHex(decodeWif(wif, 'testnet', TEST_PROFILE.wifVersion).payload)).toBe(toHex(key));
  });

  it('deriveAppDataKey injects the app-data label (differs from the Falcon label)', () => {
    expect(toHex(chain.deriveAppDataKey(SEED))).toBe(
      toHex(deriveAppDataKey(SEED, TEST_PROFILE.appDataInfo)),
    );
    expect(toHex(chain.deriveAppDataKey(SEED))).not.toBe(
      toHex(deriveAppDataKey(SEED, TEST_PROFILE.falconHdInfo)),
    );
  });

  it('signed-message facade injects the magic', async () => {
    expect(toHex(chain.signedMessageDigest('hi'))).toBe(
      toHex(signedMessageDigest('hi', TEST_PROFILE.messageMagic)),
    );
    // The preimage starts with varint(len(magic)) — 21 for the fixture.
    expect(chain.signedMessagePreimage('hi')[0]).toBe(0x15);
    const priv = new Uint8Array(32);
    priv[31] = 5;
    const sig = await chain.signMessage('hi', priv, 'ecdsa');
    expect(await chain.verifyMessage('hi', sig, getPublicKey(priv), 'ecdsa')).toBe(true);
    expect(await chain.verifyMessage('other', sig, getPublicKey(priv), 'ecdsa')).toBe(false);
  });

  it('passes upgrade parameters through (null and non-null)', () => {
    expect(chain.upgrade).toBeNull();
    const cfg: UpgradeChainConfig = {
      lockScriptHex: '76a914' + '00'.repeat(20) + '88ac',
      minConvertValue: 10_000n,
      dustLimit: 546n,
      feeTargetBlocks: 6,
      fallbackFeeRate: 2,
    };
    const withUpgrade = bindProfile({
      ...TEST_PROFILE,
      upgrade: { mainnet: cfg, testnet: cfg },
    });
    expect(withUpgrade.upgrade?.mainnet.minConvertValue).toBe(10_000n);
  });
});

describe('validateProfile — downgrade and token-sighash fork', () => {
  const bad = (patch: Partial<ChainProfile>): ChainProfile => ({ ...TEST_PROFILE, ...patch });
  const dg = TEST_PROFILE.downgrade!;
  const withMainnet = (patch: Partial<DowngradeChainConfig>): ChainProfile =>
    bad({ downgrade: { ...dg, mainnet: { ...dg.mainnet, ...patch } } });
  const twoKeys = dg.mainnet.freezePubkeysHex.slice(0, 2);

  it('accepts a chain without the downgrade flow', () => {
    expect(() => validateProfile(bad({ downgrade: null }))).not.toThrow();
  });

  it('requires exactly three Falcon-512 freeze pubkeys', () => {
    expect(() => validateProfile(withMainnet({ freezePubkeysHex: [] }))).toThrow(/2-of-3/);
    expect(() => validateProfile(withMainnet({ freezePubkeysHex: twoKeys }))).toThrow(/2-of-3/);
    expect(() =>
      validateProfile(withMainnet({ freezePubkeysHex: [...twoKeys, 'zz'.repeat(897)] })),
    ).toThrow(/Falcon-512/);
    expect(() =>
      validateProfile(withMainnet({ freezePubkeysHex: [...twoKeys, '09'.repeat(896)] })),
    ).toThrow(/Falcon-512/);
  });

  it('rejects non-positive reclaim windows and a malformed legacy key', () => {
    expect(() => validateProfile(withMainnet({ freezeSeconds: 0 }))).toThrow(/windows/);
    expect(() => validateProfile(withMainnet({ outputSeconds: -1 }))).toThrow(/windows/);
    expect(() => validateProfile(withMainnet({ legacyLockPubkeyHex: '02ab' }))).toThrow(/33-byte/);
  });

  it('rejects a negative or fractional fork time, accepts null and 0', () => {
    expect(() =>
      validateProfile(bad({ tokenSighashFork: { mainnet: -1, testnet: null } })),
    ).toThrow(/tokenSighashFork/);
    expect(() =>
      validateProfile(bad({ tokenSighashFork: { mainnet: 1.5, testnet: null } })),
    ).toThrow(/tokenSighashFork/);
    expect(() =>
      validateProfile(bad({ tokenSighashFork: { mainnet: 0, testnet: null } })),
    ).not.toThrow();
  });
});

describe('bindProfile — token-sighash fork and downgrade pass-through', () => {
  it('sighashCommitsTokenId follows the profile fork times', () => {
    const fork = TEST_PROFILE.tokenSighashFork.mainnet!;
    expect(chain.sighashCommitsTokenId('mainnet', fork - 1)).toBe(false);
    expect(chain.sighashCommitsTokenId('mainnet', fork)).toBe(true);
    expect(chain.sighashCommitsTokenId('mainnet')).toBe(true); // now is past the fixture fork
    expect(chain.sighashCommitsTokenId('testnet', 0)).toBe(false); // null = never
    expect(chain.sighashCommitsTokenId('testnet')).toBe(false);
  });

  it('passes downgrade parameters through', () => {
    expect(chain.downgrade).toBe(TEST_PROFILE.downgrade);
    expect(bindProfile({ ...TEST_PROFILE, downgrade: null }).downgrade).toBeNull();
  });

  it('the fixture federation keys build the freeze covenant', () => {
    const keys = TEST_PROFILE.downgrade!.mainnet.freezePubkeysHex.map(fromHex);
    const script = federationFreezeScript(keys, TEST_PROFILE.downgrade!.mainnet.freezeSeconds);
    expect(script.length).toBeGreaterThan(3 * 897);
  });
});
