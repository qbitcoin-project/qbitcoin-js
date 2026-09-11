// Test-only ChainProfile fixture. Every value is FAKE — the package's own
// suite runs against this profile so that no real chain's constants ever
// live in this repo. Consumers pin their real profiles in their own repos.
//
// The address regexes were derived for the fake magic the same way real
// chains derive theirs from the node constants: numeric base58 bounds over
// all payloads (magic‖00…00‖0000… to magic‖ff…ff‖ffff…), sampled for
// length constancy. profile.test.ts re-verifies them property-style.

import type { DerivationScheme } from './bip32.js';
import { coinTypeFor } from './bip32.js';
import type { ChainProfile } from './profile.js';

/** Legacy scheme: single-number coin_type (the pre-SLIP-0044 shape). */
export const TEST_SCHEME_V1: DerivationScheme = {
  id: 'test-v1',
  coinType: 7777,
  label: 'Test v1 (legacy)',
  status: 'legacy',
  pathTemplate: (account, change, index, _network) =>
    `m/44'/7777'/${account}'/${change}/${index}`,
};

/** Active scheme: per-network coin_type (the BIP-44 testnet convention). */
export const TEST_SCHEME_V2: DerivationScheme = {
  id: 'test-v2-dual',
  coinType: { mainnet: 8888, testnet: 1 },
  label: 'Test v2 (active)',
  status: 'active',
  pathTemplate: (account, change, index, network) =>
    `m/44'/${coinTypeFor(TEST_SCHEME_V2, network)}'/${account}'/${change}/${index}`,
};

export const TEST_PROFILE: ChainProfile = {
  name: 'testchain',
  addrMagic: {
    mainnet: Uint8Array.of(0x1e, 0x51),
    testnet: Uint8Array.of(0x03, 0x35, 0x91), // three bytes — lengths differ on purpose
  },
  addressRegex: {
    mainnet:
      /^(?:vq[s-z][1-9A-HJ-NP-Za-km-z]{32}|vr[1-9A-G][1-9A-HJ-NP-Za-km-z]{32}|5V[7-9][1-9A-HJ-NP-Za-km-z]{49})$/,
    testnet:
      /^(?:SA[78][1-9A-HJ-NP-Za-km-z]{33}|36X[u-w][1-9A-HJ-NP-Za-km-z]{49})$/,
  },
  wifVersion: { mainnet: 0x80, testnet: 0xef },
  schemes: [TEST_SCHEME_V2, TEST_SCHEME_V1],
  metaV1SchemeId: 'test-v1',
  falconHdInfo: 'test/pq/falcon512/v1',
  appDataInfo: 'test/app-data/v1',
  messageMagic: 'Test Signed Message:\n',
  upgrade: null,
  downgrade: {
    mainnet: {
      freezePubkeysHex: [fakeFalconPubkeyHex(0xa1), fakeFalconPubkeyHex(0xb2), fakeFalconPubkeyHex(0xc3)],
      freezeSeconds: 48 * 3600,
      outputSeconds: 7 * 24 * 3600,
    },
    testnet: {
      freezePubkeysHex: [fakeFalconPubkeyHex(0xd4), fakeFalconPubkeyHex(0xe5), fakeFalconPubkeyHex(0xf6)],
      freezeSeconds: 48 * 3600,
      outputSeconds: 7 * 24 * 3600,
      legacyLockPubkeyHex: '02' + 'ab'.repeat(32), // a retired single-key era
    },
  },
  // mainnet forks at a fixed past moment, testnet never — both predicate
  // branches are exercised.
  tokenSighashFork: { mainnet: 1_700_000_000, testnet: null },
};

/** A fake 897-byte Falcon-512 public key: version byte 0x09 + a fill byte. */
export function fakeFalconPubkeyHex(fill: number): string {
  return '09' + fill.toString(16).padStart(2, '0').repeat(896);
}
