import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from './encoding/hex.js';
import { TEST_PROFILE } from './profile.fixtures.js';
import { getPublicKey } from './secp256k1.js';
import {
  signMessage,
  signedMessageDigest,
  signedMessagePreimage,
  verifyMessage,
} from './signedMessage.js';

// Fixed test key: private bytes 0x01..0x20 (deterministic ECDSA → stable sig).
const PRIV = (() => {
  const k = new Uint8Array(32);
  for (let i = 0; i < 32; i++) k[i] = i + 1;
  return k;
})();
const PUB = getPublicKey(PRIV);
const MSG = 'Hello, chain!';
const MAGIC = TEST_PROFILE.messageMagic; // 'Test Signed Message:\n', 21 bytes

describe('signed message format', () => {
  it('domain-separates from transactions (preimage starts with the magic varint)', () => {
    // The 21-byte magic → varint(21) = 0x15, which is not a valid tx_type
    // (1..4), so a message preimage can never be a transaction sighash
    // preimage. bindProfile enforces the 5-byte minimum on every profile.
    expect(MAGIC.length).toBe(21);
    expect(signedMessagePreimage(MSG, MAGIC)[0]).toBe(0x15);
  });

  it('digest is the golden double-SHA256 of the preimage', () => {
    // Goldens computed with an independent implementation (varstr framing
    // + double-SHA256 via @noble/hashes directly).
    expect(toHex(signedMessageDigest(MSG, MAGIC))).toBe(
      '97eba9b294db47c526ab7f8a6a9dc3deb3f9f287995c63bb64f790c5cb2a6135',
    );
    expect(toHex(signedMessageDigest('', MAGIC))).toBe(
      '329cf7cf82b5081ca95ef8dd8257dbf04852b881b120cb1519a3af910b9d860e',
    );
  });

  it('a different magic produces a different digest (chain domain separation)', () => {
    expect(toHex(signedMessageDigest(MSG, 'Other Signed Message:\n'))).not.toBe(
      toHex(signedMessageDigest(MSG, MAGIC)),
    );
  });

  it('signs deterministically and round-trips', async () => {
    const sig = await signMessage(MSG, PRIV, 'ecdsa', MAGIC);
    const again = await signMessage(MSG, PRIV, 'ecdsa', MAGIC);
    expect(toHex(sig)).toBe(toHex(again));
    expect(await verifyMessage(MSG, sig, PUB, 'ecdsa', MAGIC)).toBe(true);
  });

  it('a signature does not verify under another chain magic', async () => {
    const sig = await signMessage(MSG, PRIV, 'ecdsa', MAGIC);
    expect(await verifyMessage(MSG, sig, PUB, 'ecdsa', 'Other Signed Message:\n')).toBe(false);
  });

  it('rejects a tampered message, wrong key, bad sig, unsupported algo', async () => {
    const sig = await signMessage(MSG, PRIV, 'ecdsa', MAGIC);
    expect(await verifyMessage(`${MSG}!`, sig, PUB, 'ecdsa', MAGIC)).toBe(false);
    const otherPriv = new Uint8Array(32);
    otherPriv[31] = 9;
    expect(await verifyMessage(MSG, sig, getPublicKey(otherPriv), 'ecdsa', MAGIC)).toBe(false);
    expect(await verifyMessage(MSG, fromHex('deadbeef'), PUB, 'ecdsa', MAGIC)).toBe(false);
    expect(await verifyMessage(MSG, sig, PUB, 'schnorr', MAGIC)).toBe(false);
  });
});
