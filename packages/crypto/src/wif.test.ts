import { describe, expect, it } from 'vitest';
import { encodeBase58Check } from './encoding/base58check';
import { fromHex, toHex } from './encoding/hex';
import {
  FALCON512_PRIVATE_KEY_BYTES,
  FALCON512_PUBLIC_KEY_BYTES,
  falcon512Verify,
} from './falcon512';
import { hash256 } from './hashes';
import {
  FALCON512_KEYPAIR_BYTES,
  WifError,
  WifNetworkError,
  decodeWif,
  encodeWif,
  falconKeypairFromWifPayload,
} from './wif';
import { NODE_FALCON_SIG_HEX, NODE_FALCON_WIF } from './wif.vectors';
import { TEST_PROFILE } from './profile.fixtures';

const V = TEST_PROFILE.wifVersion; // 0x80 / 0xEF — Bitcoin-compatible bytes

// The canonical Bitcoin wiki WIF vector (https://en.bitcoin.it/wiki/Wallet_import_format).
// The mainnet WIF is byte-compatible with Bitcoin's (version 0x80, no
// compression flag), so this doubles as a cross-implementation check.
const BTC_KEY_HEX =
  '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d';
const BTC_WIF = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ';

describe('encodeWif / decodeWif — classical (32-byte) keys', () => {
  it('matches the canonical Bitcoin mainnet vector', () => {
    expect(encodeWif(fromHex(BTC_KEY_HEX), 'mainnet', V)).toBe(BTC_WIF);
  });

  it('decodes the canonical vector back to the same key', () => {
    const { payload, candidates } = decodeWif(BTC_WIF, 'mainnet', V);
    expect(toHex(payload)).toBe(BTC_KEY_HEX);
    expect(candidates).toEqual(['ecdsa', 'schnorr']);
  });

  it('round-trips on testnet with the 0xEF version byte', () => {
    const key = new Uint8Array(32).fill(7);
    const wif = encodeWif(key, 'testnet', V);
    const { payload, candidates } = decodeWif(wif, 'testnet', V);
    expect(toHex(payload)).toBe(toHex(key));
    expect(candidates).toEqual(['ecdsa', 'schnorr']);
  });

  it('tolerates surrounding whitespace', () => {
    const { payload } = decodeWif(`  ${BTC_WIF}\n`, 'mainnet', V);
    expect(toHex(payload)).toBe(BTC_KEY_HEX);
  });
});

describe('decodeWif — rejection paths', () => {
  it('reports the DETECTED network on a cross-network key', () => {
    const key = new Uint8Array(32).fill(7);
    const testnetWif = encodeWif(key, 'testnet', V);
    let caught: unknown;
    try {
      decodeWif(testnetWif, 'mainnet', V);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(WifNetworkError);
    expect((caught as WifNetworkError).detected).toBe('testnet');
    expect((caught as WifNetworkError).expected).toBe('mainnet');

    // And the mirror case.
    expect(() => decodeWif(BTC_WIF, 'testnet', V)).toThrow(WifNetworkError);
  });

  it('rejects a corrupted checksum', () => {
    const last = BTC_WIF.at(-1);
    const tampered = BTC_WIF.slice(0, -1) + (last === 'x' ? 'y' : 'x');
    expect(() => decodeWif(tampered, 'mainnet', V)).toThrow(WifError);
    expect(() => decodeWif(tampered, 'mainnet', V)).toThrow(/checksum/i);
  });

  it('rejects non-Base58 input', () => {
    expect(() => decodeWif('not a wif 0OIl', 'mainnet', V)).toThrow(WifError);
  });

  it('rejects an unknown version byte', () => {
    const wif = encodeBase58Check(Uint8Array.of(0x42), new Uint8Array(32).fill(1));
    expect(() => decodeWif(wif, 'mainnet', V)).toThrow(/version byte 0x42/);
  });

  it('rejects a Bitcoin compressed-key WIF with an explanatory message', () => {
    const payload = new Uint8Array(33).fill(7);
    payload[32] = 0x01; // Bitcoin's compression flag
    const wif = encodeBase58Check(Uint8Array.of(0x80), payload);
    expect(() => decodeWif(wif, 'mainnet', V)).toThrow(/compressed-key WIF/);
  });

  it('rejects unsupported payload lengths', () => {
    const wif = encodeBase58Check(Uint8Array.of(0x80), new Uint8Array(31).fill(1));
    expect(() => decodeWif(wif, 'mainnet', V)).toThrow(/31 bytes/);
  });

  it('rejects an out-of-range secp256k1 scalar', () => {
    // Zero and the curve order n are both invalid scalars.
    const zero = encodeWif(new Uint8Array(32), 'mainnet', V);
    expect(() => decodeWif(zero, 'mainnet', V)).toThrow(/secp256k1/);

    const n = fromHex(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    );
    expect(() => decodeWif(encodeWif(n, 'mainnet', V), 'mainnet', V)).toThrow(
      /secp256k1/,
    );
  });
});

describe('encodeWif — input validation', () => {
  it('rejects payloads that are neither 32 nor 2178 bytes', () => {
    expect(() => encodeWif(new Uint8Array(33), 'mainnet', V)).toThrow(RangeError);
    expect(() => encodeWif(new Uint8Array(0), 'mainnet', V)).toThrow(RangeError);
  });
});

// ─── Falcon-512 — cross-checked against the node's own test vector ────
//
// test/falcon.t in the node repo pins a WIF plus a signature made with that
// key. If our decoder, Base58 handling, keypair split, and Falcon verify all
// agree with the node, that whole pipeline is interoperable.

const NODE_SIGN_DATA = (() => {
  // The node's sign_data: "\x55\xaa" x 700.
  const data = new Uint8Array(1400);
  for (let i = 0; i < data.length; i += 2) {
    data[i] = 0x55;
    data[i + 1] = 0xaa;
  }
  return data;
})();

describe('Falcon-512 WIF — node vector', () => {
  it('decodes as a mainnet Falcon payload', () => {
    const { payload, candidates } = decodeWif(NODE_FALCON_WIF, 'mainnet', V);
    expect(candidates).toEqual(['falcon512']);
    expect(payload.length).toBe(FALCON512_KEYPAIR_BYTES);
  });

  it('re-encodes to the exact node WIF string (2178-byte Base58 roundtrip)', () => {
    const { payload } = decodeWif(NODE_FALCON_WIF, 'mainnet', V);
    expect(encodeWif(payload, 'mainnet', V)).toBe(NODE_FALCON_WIF);
  });

  it('splits into a consistent keypair (sign/verify self-check passes)', async () => {
    const { payload } = decodeWif(NODE_FALCON_WIF, 'mainnet', V);
    const kp = await falconKeypairFromWifPayload(payload);
    expect(kp.privateKey.length).toBe(FALCON512_PRIVATE_KEY_BYTES);
    expect(kp.publicKey.length).toBe(FALCON512_PUBLIC_KEY_BYTES);
    // Independent copies — wiping the payload must not touch the keypair.
    payload.fill(0);
    expect(kp.privateKey.some((b) => b !== 0)).toBe(true);
  });

  it("verifies the node's signature with the embedded public key", async () => {
    const { payload } = decodeWif(NODE_FALCON_WIF, 'mainnet', V);
    const { publicKey } = await falconKeypairFromWifPayload(payload);

    const envelope = fromHex(NODE_FALCON_SIG_HEX);
    // check_sig's envelope: algo byte first (0x81 = Falcon-512), then the
    // raw signature, verified over hash256(sign_data).
    expect(envelope[0]).toBe(0x81);
    const rawSig = envelope.slice(1);
    const digest = hash256(NODE_SIGN_DATA);

    expect(await falcon512Verify(rawSig, digest, publicKey)).toBe(true);

    // Sanity: a flipped digest byte must not verify.
    const wrong = digest.slice();
    wrong[0] ^= 0xff;
    expect(await falcon512Verify(rawSig, wrong, publicKey)).toBe(false);
  });

  it('rejects a mismatched private/public pair', async () => {
    const { payload } = decodeWif(NODE_FALCON_WIF, 'mainnet', V);
    // Corrupt the public half — checksum already passed, so only the pair
    // self-check can catch this.
    payload[FALCON512_PRIVATE_KEY_BYTES + 100] ^= 0xff;
    await expect(falconKeypairFromWifPayload(payload)).rejects.toThrow(
      /does not match/,
    );
  });

  it('rejects a wrong-length payload', async () => {
    await expect(falconKeypairFromWifPayload(new Uint8Array(100))).rejects.toThrow(
      /2178/,
    );
  });
});
