import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../encoding/hex.js';
import { hash160, sha256 } from '../hashes.js';
import { getPublicKey } from '../secp256k1.js';
import { decodeBtcAddress } from './address.js';
import { btcP2shP2wshMultisig } from './multisig.js';

// Three real compressed pubkeys (synthetic private keys) — handed to the
// builder in a deliberately unsorted order everywhere below.
const PK_A = getPublicKey(fromHex('11'.repeat(32)));
const PK_B = getPublicKey(fromHex('22'.repeat(32)));
const PK_C = getPublicKey(fromHex('33'.repeat(32)));
const KEYS = [PK_A, PK_B, PK_C];

const sortedHex = KEYS.map(toHex).sort();

describe('btcP2shP2wshMultisig', () => {
  it('assembles the witnessScript byte-exactly: OP_2 <pk×3, BIP67 order> OP_3 OP_CHECKMULTISIG', () => {
    const { witnessScript } = btcP2shP2wshMultisig(2, [PK_C, PK_A, PK_B], 'mainnet');
    const expected = '52' + sortedHex.map((pk) => '21' + pk).join('') + '53' + 'ae';
    expect(toHex(witnessScript)).toBe(expected);
  });

  it('derives redeemScript and scriptPubKey by the P2SH-P2WSH construction', () => {
    const lock = btcP2shP2wshMultisig(2, KEYS, 'mainnet');
    // redeem = OP_0 <32: sha256(witnessScript)> — the P2WSH witness program.
    expect(toHex(lock.redeemScript)).toBe('0020' + toHex(sha256(lock.witnessScript)));
    // spk = OP_HASH160 <20: hash160(redeem)> OP_EQUAL.
    expect(toHex(lock.scriptPubKey)).toBe('a914' + toHex(hash160(lock.redeemScript)) + '87');
  });

  it('the address decodes back to the same scriptPubKey on both networks', () => {
    for (const network of ['mainnet', 'testnet'] as const) {
      const lock = btcP2shP2wshMultisig(2, KEYS, network);
      const decoded = decodeBtcAddress(lock.address, network);
      expect(decoded.kind).toBe('p2sh');
      expect(toHex(decoded.scriptPubKey)).toBe(toHex(lock.scriptPubKey));
    }
  });

  it('is key-order independent (BIP67: one set, one address)', () => {
    const a = btcP2shP2wshMultisig(2, [PK_A, PK_B, PK_C], 'mainnet');
    const b = btcP2shP2wshMultisig(2, [PK_C, PK_B, PK_A], 'mainnet');
    expect(a.address).toBe(b.address);
    expect(toHex(a.witnessScript)).toBe(toHex(b.witnessScript));
  });

  it('mainnet and testnet addresses differ for the same keys', () => {
    expect(btcP2shP2wshMultisig(2, KEYS, 'mainnet').address).not.toBe(
      btcP2shP2wshMultisig(2, KEYS, 'testnet').address,
    );
  });

  it('rejects malformed shapes and keys', () => {
    expect(() => btcP2shP2wshMultisig(4, KEYS, 'mainnet')).toThrow(/invalid multisig shape/);
    expect(() => btcP2shP2wshMultisig(0, KEYS, 'mainnet')).toThrow(/invalid multisig shape/);
    expect(() => btcP2shP2wshMultisig(2, [PK_A, PK_B, new Uint8Array(32)], 'mainnet')).toThrow(/33 bytes/);
  });
});
