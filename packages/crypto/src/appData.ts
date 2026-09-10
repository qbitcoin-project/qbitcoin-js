// App-data encryption — at-rest protection for NON-key local data (e.g. the
// address book) using a key derived from the wallet master seed.
//
// Why a separate key (not the password-vault seal):
//   - The vault seal (vault.ts) protects the SEED with the user's password
//     (scrypt). App-data is encrypted with a key the wallet already holds while
//     unlocked, so the user doesn't re-enter a password to read their contacts.
//   - HKDF-SHA256 with a fixed `info` label domain-separates this key from any
//     other use of the seed. Holding/leaking the app-data key never exposes the
//     seed (HKDF is one-way) and can't be reused as a signing key.
//
// The derived key lives only in the background (the one place with the seed);
// callers pass it straight into seal/open and wipe it after.

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { base64 } from '@scure/base';

/** AES-256 key length in bytes. */
const KEY_BYTES = 32;

/** AES-GCM IV size — 96 bits, the Web Crypto standard. */
const IV_BYTES = 12;

/** Sealed app-data blob (JSON-serialized into storage). */
export interface AppDataBlob {
  readonly v: 1;
  /** Random AES-GCM IV, base64. */
  readonly iv: string;
  /** Ciphertext incl. the 16-byte GCM tag, base64. */
  readonly ct: string;
}

/** Thrown when opening fails — wrong key, tampered ciphertext, or bad format.
 *  Like VaultAuthError, we don't distinguish the cases. */
export class AppDataError extends Error {
  override readonly name = 'AppDataError';
}

/**
 * Derive the 32-byte AES-256 app-data key from the wallet master seed.
 * Pure HKDF-SHA256; deterministic for a given seed, domain-separated by
 * `info` — the chain's app-data HKDF label (`profile.appDataInfo`; the
 * `bindProfile()` facade supplies it). The label is baked into the
 * on-disk encryption KDF — a shipped chain must never change it (existing
 * app data would stop decrypting); bump its version suffix only with a
 * migration. No salt — the seed is already high-entropy and the info
 * label fixes the purpose.
 */
export function deriveAppDataKey(masterSeed: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, masterSeed, undefined, info, KEY_BYTES);
}

/** Encrypt `plaintext` under `key` (AES-256-GCM). Fresh random IV each call;
 *  returns a JSON-serialized {@link AppDataBlob} string. */
export async function sealAppData(key: Uint8Array, plaintext: Uint8Array): Promise<string> {
  const iv = randomBytes(IV_BYTES);
  const cryptoKey = await importAesKey(key);
  const ct = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: asAB(iv) },
    cryptoKey,
    asAB(plaintext),
  );
  const blob: AppDataBlob = {
    v: 1,
    iv: base64.encode(iv),
    ct: base64.encode(new Uint8Array(ct)),
  };
  return JSON.stringify(blob);
}

/** Decrypt a JSON-serialized {@link AppDataBlob} under `key`. Throws
 *  {@link AppDataError} on a bad format, wrong key, or tampered ciphertext. */
export async function openAppData(key: Uint8Array, serialized: string): Promise<Uint8Array> {
  let blob: AppDataBlob;
  try {
    blob = JSON.parse(serialized) as AppDataBlob;
  } catch {
    throw new AppDataError('app-data blob is not valid JSON');
  }
  if (blob.v !== 1 || typeof blob.iv !== 'string' || typeof blob.ct !== 'string') {
    throw new AppDataError('app-data blob is malformed');
  }

  let iv: Uint8Array;
  let ct: Uint8Array;
  try {
    iv = base64.decode(blob.iv);
    ct = base64.decode(blob.ct);
  } catch {
    throw new AppDataError('app-data blob has invalid base64');
  }

  const cryptoKey = await importAesKey(key);
  try {
    const buffer = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: asAB(iv) },
      cryptoKey,
      asAB(ct),
    );
    return new Uint8Array(buffer);
  } catch {
    throw new AppDataError('app-data decryption failed: wrong key or tampered');
  }
}

// ─── Helpers (mirror vault.ts; kept local so this module is self-contained) ──

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    asAB(rawKey),
    { name: 'AES-GCM' },
    false /* not extractable */,
    ['encrypt', 'decrypt'],
  );
}

function asAB(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  return u8 as Uint8Array<ArrayBuffer>;
}
