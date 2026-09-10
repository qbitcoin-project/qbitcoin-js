import { describe, expect, it } from 'vitest';
import {
  AppDataError,
  deriveAppDataKey,
  openAppData,
  sealAppData,
} from './appData';

const seed = new Uint8Array(64).fill(7);
const INFO = 'test/app-data/v1';
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => new TextDecoder().decode(b);

describe('deriveAppDataKey', () => {
  it('is deterministic and 32 bytes', () => {
    const a = deriveAppDataKey(seed, INFO);
    const b = deriveAppDataKey(seed, INFO);
    expect(a).toHaveLength(32);
    expect([...a]).toEqual([...b]);
  });

  it('differs for a different info label (domain separation)', () => {
    const a = deriveAppDataKey(seed, INFO);
    const b = deriveAppDataKey(seed, 'other/app-data/v1');
    expect([...a]).not.toEqual([...b]);
  });

  it('differs for a different seed', () => {
    const a = deriveAppDataKey(seed, INFO);
    const b = deriveAppDataKey(new Uint8Array(64).fill(9), INFO);
    expect([...a]).not.toEqual([...b]);
  });
});

describe('sealAppData / openAppData', () => {
  it('round-trips plaintext', async () => {
    const key = deriveAppDataKey(seed, INFO);
    const blob = await sealAppData(key, enc('[{"address":"addr-1","label":"Alice"}]'));
    expect(dec(await openAppData(key, blob))).toBe('[{"address":"addr-1","label":"Alice"}]');
  });

  it('produces a different IV/ciphertext each call', async () => {
    const key = deriveAppDataKey(seed, INFO);
    const a = await sealAppData(key, enc('same'));
    const b = await sealAppData(key, enc('same'));
    expect(a).not.toBe(b); // random IV ⇒ different blob
  });

  it('rejects the wrong key', async () => {
    const blob = await sealAppData(deriveAppDataKey(seed, INFO), enc('secret'));
    const wrong = deriveAppDataKey(new Uint8Array(64).fill(1), INFO);
    await expect(openAppData(wrong, blob)).rejects.toBeInstanceOf(AppDataError);
  });

  it('rejects tampered ciphertext', async () => {
    const key = deriveAppDataKey(seed, INFO);
    const blob = JSON.parse(await sealAppData(key, enc('secret'))) as {
      v: 1;
      iv: string;
      ct: string;
    };
    const tampered = JSON.stringify({ ...blob, ct: base64Flip(blob.ct) });
    await expect(openAppData(key, tampered)).rejects.toBeInstanceOf(AppDataError);
  });

  it('rejects a malformed blob', async () => {
    const key = deriveAppDataKey(seed, INFO);
    await expect(openAppData(key, 'not json')).rejects.toBeInstanceOf(AppDataError);
    await expect(openAppData(key, '{"v":2}')).rejects.toBeInstanceOf(AppDataError);
  });
});

/** Flip a character in the base64 ciphertext to simulate tampering. */
function base64Flip(b64: string): string {
  const i = Math.floor(b64.length / 2);
  const ch = b64[i] === 'A' ? 'B' : 'A';
  return b64.slice(0, i) + ch + b64.slice(i + 1);
}
