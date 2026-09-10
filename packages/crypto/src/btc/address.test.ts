import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../encoding/hex';
import {
  bech32Encode,
  btcAddressFromScriptPubKey,
  btcP2pkhAddress,
  btcP2pkhAddressForPubkey,
  decodeBtcAddress,
  toWords,
} from './address';

// The BIP-173 reference program (hash160 of the famous uncompressed G pubkey).
const WPROG20 = fromHex('751e76e8199196d454941c45d1b3a323f1433bd6');

describe('btcP2pkhAddress', () => {
  it('encodes the classic version-0x00 form', () => {
    // hash160 pinned by the staging-derivation golden in the app tests.
    expect(btcP2pkhAddress(fromHex('d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa'), 'mainnet')).toBe(
      '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA',
    );
  });

  it('testnet uses version 0x6f', () => {
    const addr = btcP2pkhAddress(WPROG20, 'testnet');
    expect(addr.startsWith('m') || addr.startsWith('n')).toBe(true);
  });

  it('rejects a wrong-length hash', () => {
    expect(() => btcP2pkhAddress(new Uint8Array(19), 'mainnet')).toThrow(/20 bytes/);
  });
});

describe('decodeBtcAddress — legacy', () => {
  it('P2PKH round-trips to the canonical script', () => {
    const addr = btcP2pkhAddress(WPROG20, 'mainnet');
    const decoded = decodeBtcAddress(addr, 'mainnet');
    expect(decoded.kind).toBe('p2pkh');
    expect(toHex(decoded.scriptPubKey)).toBe(`76a914${toHex(WPROG20)}88ac`);
  });

  it('P2SH decodes to a hash-script form', () => {
    // 3… mainnet address for the same 20 bytes (built via our own encoder path).
    const decoded = decodeBtcAddress('3P14159f73E4gFr7JterCCQh9QjiTjiZrG', 'mainnet');
    expect(decoded.kind).toBe('p2sh');
    expect(decoded.scriptPubKey[0]).toBe(0xa9);
    expect(decoded.scriptPubKey.length).toBe(23);
    expect(decoded.scriptPubKey[22]).toBe(0x87);
  });

  it('rejects a mainnet address on testnet', () => {
    const addr = btcP2pkhAddress(WPROG20, 'mainnet');
    expect(() => decodeBtcAddress(addr, 'testnet')).toThrow(/version/);
  });

  it('rejects garbage', () => {
    expect(() => decodeBtcAddress('definitely-not-an-address', 'mainnet')).toThrow(/Not a valid/);
  });
});

describe('decodeBtcAddress — segwit', () => {
  it('decodes the BIP-173 v0 P2WPKH reference address', () => {
    const decoded = decodeBtcAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'mainnet');
    expect(decoded.kind).toBe('v0_p2wpkh');
    expect(toHex(decoded.scriptPubKey)).toBe(`0014${toHex(WPROG20)}`);
  });

  it('is case-insensitive but rejects mixed case', () => {
    const upper = 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4';
    expect(decodeBtcAddress(upper, 'mainnet').kind).toBe('v0_p2wpkh');
    expect(() => decodeBtcAddress('bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'mainnet')).toThrow(/Mixed-case/);
  });

  it('round-trips a v0 P2WSH program', () => {
    const prog = new Uint8Array(32).fill(7);
    const addr = bech32Encode('bc', [0, ...toWords(prog)], 'bech32');
    const decoded = decodeBtcAddress(addr, 'mainnet');
    expect(decoded.kind).toBe('v0_p2wsh');
    expect(toHex(decoded.scriptPubKey)).toBe(`0020${toHex(prog)}`);
  });

  it('round-trips a v1 taproot output under bech32m', () => {
    const prog = new Uint8Array(32).fill(9);
    const addr = bech32Encode('bc', [1, ...toWords(prog)], 'bech32m');
    const decoded = decodeBtcAddress(addr, 'mainnet');
    expect(decoded.kind).toBe('v1_p2tr');
    expect(toHex(decoded.scriptPubKey)).toBe(`5120${toHex(prog)}`);
  });

  it('rejects v1 encoded as plain bech32 (and v0 as bech32m)', () => {
    const prog32 = new Uint8Array(32).fill(9);
    const v1AsBech32 = bech32Encode('bc', [1, ...toWords(prog32)], 'bech32');
    expect(() => decodeBtcAddress(v1AsBech32, 'mainnet')).toThrow(/bech32m/);
    const v0AsBech32m = bech32Encode('bc', [0, ...toWords(WPROG20)], 'bech32m');
    expect(() => decodeBtcAddress(v0AsBech32m, 'mainnet')).toThrow(/bech32 /);
  });

  it('rejects the wrong network hrp', () => {
    expect(() => decodeBtcAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'testnet')).toThrow(/different network/);
  });

  it('rejects a corrupted checksum', () => {
    expect(() => decodeBtcAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5', 'mainnet')).toThrow(/checksum/);
  });
});

describe('btcP2pkhAddressForPubkey', () => {
  it('hashes a compressed pubkey through hash160', () => {
    const pubkey = fromHex('03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e');
    expect(btcP2pkhAddressForPubkey(pubkey, 'mainnet')).toBe('1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');
  });
});

describe('btcAddressFromScriptPubKey', () => {
  // Every standard template must round-trip: decode an address to its
  // scriptPubKey, then recover the same address from the script.
  const roundtrip = (address: string, network: 'mainnet' | 'testnet' = 'mainnet'): void => {
    const { scriptPubKey } = decodeBtcAddress(address, network);
    expect(btcAddressFromScriptPubKey(scriptPubKey, network)).toBe(address);
  };

  it('recovers P2PKH addresses', () => {
    roundtrip('1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');
  });

  it('recovers P2SH addresses', () => {
    roundtrip('3P14159f73E4gFr7JterCCQh9QjiTjiZrG');
  });

  it('recovers segwit v0 addresses', () => {
    roundtrip('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  });

  it('encodes per network', () => {
    const { scriptPubKey } = decodeBtcAddress('1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA', 'mainnet');
    const testnetAddr = btcAddressFromScriptPubKey(scriptPubKey, 'testnet');
    expect(testnetAddr !== undefined && (testnetAddr.startsWith('m') || testnetAddr.startsWith('n'))).toBe(true);
  });

  it('returns undefined for a nonstandard script', () => {
    expect(btcAddressFromScriptPubKey(fromHex('6a20aabb'), 'mainnet')).toBeUndefined();
    expect(btcAddressFromScriptPubKey(new Uint8Array(0), 'mainnet')).toBeUndefined();
  });
});
