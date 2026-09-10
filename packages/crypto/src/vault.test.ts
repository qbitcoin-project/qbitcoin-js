import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ARGON2ID_PARAMS,
  IV_BYTES,
  SALT_BYTES,
  VaultAuthError,
  VaultFormatError,
  deriveKey,
  sealVault,
  unsealVault,
  type VaultBlob,
} from './vault';
import { fromHex, toHex } from './encoding/hex';

// Fast KDF parameters for tests — production is ~0.5s per derivation; tests use
// tiny costs (~ms). Same algorithms, same plumbing, just less work.
const FAST_SCRYPT = { N: 1024, r: 8, p: 1, dkLen: 32 };
const FAST_ARGON = { m: 64, t: 1, p: 1, dkLen: 32 };

const PASSWORD = 'correct horse battery staple';
const SEED = fromHex(
  'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
);

describe('deriveKey (scrypt — legacy/explicit)', () => {
  it('produces 32-byte key', async () => {
    const key = await deriveKey(PASSWORD, new Uint8Array(16), FAST_SCRYPT);
    expect(key.length).toBe(32);
  });

  it('is deterministic for same inputs', async () => {
    const salt = new Uint8Array(16).fill(0xaa);
    const a = await deriveKey(PASSWORD, salt, FAST_SCRYPT);
    const b = await deriveKey(PASSWORD, salt, FAST_SCRYPT);
    expect(toHex(a)).toBe(toHex(b));
  });

  it('differs for different salts and passwords', async () => {
    const a = await deriveKey(PASSWORD, new Uint8Array(16), FAST_SCRYPT);
    const b = await deriveKey(PASSWORD, new Uint8Array(16).fill(1), FAST_SCRYPT);
    const c = await deriveKey('omega', new Uint8Array(16), FAST_SCRYPT);
    expect(toHex(a)).not.toBe(toHex(b));
    expect(toHex(a)).not.toBe(toHex(c));
  });
});

describe('sealVault + unsealVault — round-trip (Argon2id, the default)', () => {
  it('roundtrips a seed', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    expect(blob.kdf).toBe('argon2id');
    expect(toHex(await unsealVault(blob, PASSWORD))).toBe(toHex(SEED));
  });

  it('roundtrips empty and long plaintext', async () => {
    const empty = await sealVault(new Uint8Array(0), PASSWORD, { params: FAST_ARGON });
    expect((await unsealVault(empty, PASSWORD)).length).toBe(0);

    const data = new Uint8Array(4096);
    for (let i = 0; i < data.length; i++) data[i] = i & 0xff;
    const blob = await sealVault(data, PASSWORD, { params: FAST_ARGON });
    expect(toHex(await unsealVault(blob, PASSWORD))).toBe(toHex(data));
  });

  it('two seals of the same plaintext give different blobs', async () => {
    const a = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    const b = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(toHex(await unsealVault(a, PASSWORD))).toBe(
      toHex(await unsealVault(b, PASSWORD)),
    );
  });
});

describe('sealVault — output format', () => {
  it('emits version 1 + argon2id by default, embedding its params', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    expect(blob.v).toBe(1);
    expect(blob.kdf).toBe('argon2id');
    expect(blob.kdfParams).toEqual(FAST_ARGON);
  });

  it('uses OWASP-strength Argon2id params by default', () => {
    // Don't run it (slow) — just check the constant.
    expect(DEFAULT_ARGON2ID_PARAMS.m).toBe(19456); // 19 MiB
    expect(DEFAULT_ARGON2ID_PARAMS.t).toBe(2);
    expect(DEFAULT_ARGON2ID_PARAMS.dkLen).toBe(32);
  });

  it('serializes to JSON cleanly', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    const parsed = JSON.parse(JSON.stringify(blob)) as VaultBlob;
    expect(toHex(await unsealVault(parsed, PASSWORD))).toBe(toHex(SEED));
  });
});

describe('backward compatibility — legacy scrypt vaults still open', () => {
  it('seals + unseals with kdf: scrypt', async () => {
    const blob = await sealVault(SEED, PASSWORD, { kdf: 'scrypt', params: FAST_SCRYPT });
    expect(blob.kdf).toBe('scrypt');
    expect(blob.kdfParams).toEqual(FAST_SCRYPT);
    expect(toHex(await unsealVault(blob, PASSWORD))).toBe(toHex(SEED));
  });

  it('wrong password on a scrypt blob throws VaultAuthError', async () => {
    const blob = await sealVault(SEED, PASSWORD, { kdf: 'scrypt', params: FAST_SCRYPT });
    await expect(unsealVault(blob, 'wrong')).rejects.toThrow(VaultAuthError);
  });
});

describe('unsealVault — failure modes', () => {
  it('throws VaultAuthError on wrong password', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    await expect(unsealVault(blob, 'wrong password')).rejects.toThrow(VaultAuthError);
  });

  it('throws VaultAuthError on tampered ciphertext', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    // Flip the FIRST base64 char (well clear of the trailing padding group):
    // it stays valid base64 but decodes to different bytes, so AEAD auth fails
    // (VaultAuthError). Tampering near the end could instead corrupt the base64
    // padding bits and trip the decoder first (VaultFormatError) — flaky.
    const tampered = {
      ...blob,
      ciphertext:
        (blob.ciphertext[0] === 'A' ? 'B' : 'A') + blob.ciphertext.slice(1),
    } as VaultBlob;
    await expect(unsealVault(tampered, PASSWORD)).rejects.toThrow(VaultAuthError);
  });

  it('throws VaultFormatError on unknown version', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    const bad = { ...blob, v: 99 } as unknown as VaultBlob;
    await expect(unsealVault(bad, PASSWORD)).rejects.toThrow(VaultFormatError);
  });

  it('throws VaultFormatError on an unknown KDF', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    const bad = { ...blob, kdf: 'pbkdf2' } as unknown as VaultBlob;
    await expect(unsealVault(bad, PASSWORD)).rejects.toThrow(VaultFormatError);
  });

  it('throws VaultFormatError on malformed base64', async () => {
    const blob = await sealVault(SEED, PASSWORD, { params: FAST_ARGON });
    const bad = { ...blob, salt: 'not!valid!base64!' } as VaultBlob;
    await expect(unsealVault(bad, PASSWORD)).rejects.toThrow(VaultFormatError);
  });
});

describe('vault layout constants', () => {
  it('salt is 16 bytes; IV is 12 bytes (Web Crypto standard)', () => {
    expect(SALT_BYTES).toBe(16);
    expect(IV_BYTES).toBe(12);
  });
});
