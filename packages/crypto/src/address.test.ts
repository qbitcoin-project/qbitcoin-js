import { describe, expect, it } from 'vitest';
import {
  addressFromPubkey,
  addressFromScripthash,
  decodeAddress,
  scripthashFromPubkey,
  validateAddress,
} from './address';
import { fromHex, toHex } from './encoding/hex';
import { hash256 } from './hashes';
import { TEST_PROFILE } from './profile.fixtures';
import { scriptP2PK } from './script';

const MAGIC = TEST_PROFILE.addrMagic;
const REGEX = TEST_PROFILE.addressRegex;

// Scripthash values originally sampled from a live node's mempool (they
// exercise realistic byte distributions); the address strings are
// base58check(TEST magic ‖ scripthash) — computed with an INDEPENDENT
// implementation (@scure/base + @noble/hashes directly), so these are
// encoding-level goldens for the fixture profile.

interface PubkeyVector {
  pubkey: string;
  scripthash: string;
  address: string;
}

const MAINNET_PUBKEY_VECTORS: PubkeyVector[] = [
  {
    pubkey:
      '039b66566d3acb6bd203a0a61f4e0105b84f12e107aaf27f30466807121197d10c',
    scripthash: 'a63aa6b72ec7668ee5529a2d4706b7ac8239a4a2',
    address: 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU',
  },
  {
    pubkey:
      '02b17362c10f06ff75a7039798de7301991fc371aeccf1aba3c8849a2f3f06322c',
    scripthash: '38a3a70af85baab9455c148fa2ce83657d9a484c',
    address: 'vqxGncGPbx1YSQmg5pTJCjNE5DnY8RJo5Ae',
  },
];

// scripthash ↔ address pairs (no pubkey known — used only for the
// scripthash→address direction).
const MAINNET_SCRIPTHASH_PAIRS: Array<{ scripthash: string; address: string }> = [
  { scripthash: 'de4bde2de43a35b7538e9992b94f2c29bec01e8b', address: 'vrDNhcj9NaZkWpnjQkg9vtXB98kLh33P3Jc' },
  { scripthash: 'ad5ef5738c9b3e8de242e75d3f99c5b92a49a25a', address: 'vr8v1NncPxXWTL2q8DXv9bqRG6mAMsWZwhD' },
  { scripthash: 'b9aeee3da2449c03ab85eaa772754459292b1e40', address: 'vrA37HdU9DnbyoWgNYYXBn3eSS7LD2PL2DU' },
  { scripthash: 'cd5e217bbc2e368a398ba6130aba5187ea689ca2', address: 'vrBqC1Pt792gJXsv5xnf6mcjY3r4p9oq8uP' },
  { scripthash: '827ea2d412a1c9e1f859d9a8daadc4921a0237c4', address: 'vr51JGWgx1WGpGG4R5HM1MQkwAoWs77Txz9' },
  { scripthash: '3795a4207eed2182225da6866b45edfddb095e5c', address: 'vqxBD9YcXiS9N8p74rvQbZrj8HDPApcumif' },
];

// The first scripthash above, encoded under the (3-byte) testnet magic.
const TESTNET_ADDRESS = 'SA82h3yDi7H36GQPok3FTDSdKcrzuMB7eXd4';

describe('scripthashFromPubkey', () => {
  it.each(MAINNET_PUBKEY_VECTORS)(
    'matches scripthash for $address',
    ({ pubkey, scripthash }) => {
      const computed = scripthashFromPubkey(fromHex(pubkey), 'ecdsa');
      expect(toHex(computed)).toBe(scripthash);
    },
  );
});

describe('addressFromPubkey', () => {
  it.each(MAINNET_PUBKEY_VECTORS)(
    'derives $address from its pubkey',
    ({ pubkey, address }) => {
      expect(addressFromPubkey(fromHex(pubkey), 'ecdsa', 'mainnet', MAGIC)).toBe(address);
    },
  );
});

describe('addressFromScripthash', () => {
  it.each(MAINNET_SCRIPTHASH_PAIRS)(
    'encodes $address',
    ({ scripthash, address }) => {
      expect(addressFromScripthash(fromHex(scripthash), 'mainnet', MAGIC)).toBe(address);
    },
  );

  it('uses the per-network magic (3-byte testnet prefix)', () => {
    expect(
      addressFromScripthash(fromHex(MAINNET_SCRIPTHASH_PAIRS[0]!.scripthash), 'testnet', MAGIC),
    ).not.toBe(MAINNET_SCRIPTHASH_PAIRS[0]!.address);
    expect(
      addressFromScripthash(fromHex('a63aa6b72ec7668ee5529a2d4706b7ac8239a4a2'), 'testnet', MAGIC),
    ).toBe(TESTNET_ADDRESS);
  });

  it('rejects scripthash with unexpected length', () => {
    expect(() => addressFromScripthash(new Uint8Array(19), 'mainnet', MAGIC)).toThrow(RangeError);
    expect(() => addressFromScripthash(new Uint8Array(21), 'mainnet', MAGIC)).toThrow(RangeError);
    expect(() => addressFromScripthash(new Uint8Array(31), 'mainnet', MAGIC)).toThrow(RangeError);
  });

  it('accepts both 20-byte and 32-byte scripthashes', () => {
    expect(() => addressFromScripthash(new Uint8Array(20), 'mainnet', MAGIC)).not.toThrow();
    expect(() => addressFromScripthash(new Uint8Array(32), 'mainnet', MAGIC)).not.toThrow();
  });
});

describe('validateAddress', () => {
  it.each(MAINNET_SCRIPTHASH_PAIRS)('accepts mainnet address $address', ({ address }) => {
    expect(validateAddress(address, 'mainnet', MAGIC, REGEX)).toBe(true);
  });

  it('accepts the testnet vector on testnet only', () => {
    expect(validateAddress(TESTNET_ADDRESS, 'testnet', MAGIC, REGEX)).toBe(true);
    expect(validateAddress(TESTNET_ADDRESS, 'mainnet', MAGIC, REGEX)).toBe(false);
  });

  it('rejects mainnet address on testnet network', () => {
    expect(validateAddress('vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU', 'testnet', MAGIC, REGEX)).toBe(false);
  });

  it('rejects addresses with bad checksum', () => {
    // Flip one character in a valid address — checksum will fail.
    const real = 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU';
    const tampered = real.slice(0, -1) + (real.at(-1) === '1' ? '2' : '1');
    expect(validateAddress(tampered, 'mainnet', MAGIC, REGEX)).toBe(false);
  });

  it('rejects empty / gibberish', () => {
    expect(validateAddress('', 'mainnet', MAGIC, REGEX)).toBe(false);
    expect(validateAddress('not an address at all', 'mainnet', MAGIC, REGEX)).toBe(false);
  });
});

// ─── Post-quantum (Falcon-512) addresses ──────────────────────────────
//
// Synthetic deterministic 897-byte pubkey (0x09 version byte + pattern).
// The scripthash is magic-independent (hash256 of the P2PK script) and
// was FROZEN before the profile split; the addresses are its encoding
// under the fixture magic, generated independently like the vectors above.

function syntheticFalconPubkey(): Uint8Array {
  const pk = new Uint8Array(897);
  pk[0] = 0x09;
  for (let i = 1; i < pk.length; i++) pk[i] = i % 256;
  return pk;
}

const PQ_SCRIPTHASH =
  'a996d29978cadc7100f8ee23fc408bbcbadc4500564ba02989e55b772494f280';
const PQ_MAINNET_ADDRESS =
  '5V8f94NcKtRRNWWDiUsJXA1puLNPKRqdYB2uH8p4kpSSAHyZZz69';
const PQ_TESTNET_ADDRESS =
  '36Xvq31Etr2LTeTV2JSBRBsNTKdanc3PaLygXn4SyWwWrhi9qjjWk';

describe('post-quantum (falcon512) address encoding', () => {
  it('scripthash = hash256(scriptP2PK(pubkey)), 32 bytes', () => {
    const pk = syntheticFalconPubkey();
    const sh = scripthashFromPubkey(pk, 'falcon512');
    expect(sh.length).toBe(32);
    expect(toHex(sh)).toBe(PQ_SCRIPTHASH);
    // Cross-check the construction explicitly: hash256 over the P2PK script.
    expect(toHex(sh)).toBe(toHex(hash256(scriptP2PK(pk))));
  });

  it('encodes the frozen mainnet/testnet PQ addresses', () => {
    const pk = syntheticFalconPubkey();
    expect(addressFromPubkey(pk, 'falcon512', 'mainnet', MAGIC)).toBe(
      PQ_MAINNET_ADDRESS,
    );
    expect(addressFromPubkey(pk, 'falcon512', 'testnet', MAGIC)).toBe(
      PQ_TESTNET_ADDRESS,
    );
  });

  it('PQ addresses match the network regex and validate', () => {
    expect(REGEX.mainnet.test(PQ_MAINNET_ADDRESS)).toBe(true);
    expect(REGEX.testnet.test(PQ_TESTNET_ADDRESS)).toBe(true);
    expect(validateAddress(PQ_MAINNET_ADDRESS, 'mainnet', MAGIC, REGEX)).toBe(true);
    expect(validateAddress(PQ_TESTNET_ADDRESS, 'testnet', MAGIC, REGEX)).toBe(true);
    expect(validateAddress(PQ_MAINNET_ADDRESS, 'testnet', MAGIC, REGEX)).toBe(false);
  });

  it('decodes round-trip as type pq', () => {
    const dec = decodeAddress(PQ_MAINNET_ADDRESS, MAGIC, REGEX);
    expect(dec.type).toBe('pq');
    expect(dec.network).toBe('mainnet');
    expect(toHex(dec.scripthash)).toBe(PQ_SCRIPTHASH);
    expect(addressFromScripthash(dec.scripthash, 'mainnet', MAGIC)).toBe(
      PQ_MAINNET_ADDRESS,
    );
  });
});

describe('decodeAddress', () => {
  it.each(MAINNET_SCRIPTHASH_PAIRS)('decodes $address', ({ scripthash, address }) => {
    const dec = decodeAddress(address, MAGIC, REGEX);
    expect(dec.network).toBe('mainnet');
    expect(dec.type).toBe('classical');
    expect(toHex(dec.scripthash)).toBe(scripthash);
  });

  it('infers testnet from the string', () => {
    const dec = decodeAddress(TESTNET_ADDRESS, MAGIC, REGEX);
    expect(dec.network).toBe('testnet');
    expect(dec.type).toBe('classical');
  });

  it('round-trips via addressFromScripthash', () => {
    const original = 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU';
    const dec = decodeAddress(original, MAGIC, REGEX);
    expect(addressFromScripthash(dec.scripthash, dec.network, MAGIC)).toBe(original);
  });

  it('throws on garbage', () => {
    expect(() => decodeAddress('garbage', MAGIC, REGEX)).toThrow();
  });

  it('throws on tampered checksum', () => {
    const real = 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU';
    const tampered = real.slice(0, -1) + (real.at(-1) === '1' ? '2' : '1');
    expect(() => decodeAddress(tampered, MAGIC, REGEX)).toThrow();
  });
});
