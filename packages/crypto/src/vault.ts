// Encrypted vault — primitive layer.
//
// Wraps a password-protected blob using a memory-hard KDF + AES-256-GCM
// (authenticated encryption). Pure primitives: no storage, no lock timer, no
// UI. Those higher-level concerns live in `packages/vault`.
//
// KDF: new vaults use **Argon2id**.
// Old vaults sealed with **scrypt** still open — `unsealVault` dispatches on the
// blob's `kdf` field, and `packages/vault` re-seals them to Argon2id on unlock.
// The blob carries `kdf` + `kdfParams`, so parameters can be raised later
// without breaking existing vaults.
//
// Security model:
//   - Password is the ONLY secret protecting the seed.
//   - Brute-force is expected; the memory-hard KDF makes it expensive.
//   - The blob can be exfiltrated (e.g. via cloud sync of chrome.storage)
//     without compromising funds, ASSUMING the password is strong.
//   - AES-GCM tag covers ciphertext; tampering yields a clear error.
//   - Salt is random per-vault; IV is random per-encryption (96-bit).

import { argon2id } from '@noble/hashes/argon2';
import { scryptAsync } from '@noble/hashes/scrypt';
import { base64 } from '@scure/base';

// ─── Parameters ──────────────────────────────────────────────────────

/**
 * Argon2id cost parameters — OWASP "first recommended option"
 * (m = 19 MiB, t = 2, p = 1). ~0.4–0.6 s in pure JS. The default for NEW
 * vaults. `m` is memory in KiB; raise it (with a re-seal) as devices get
 * faster — each vault embeds its own params, so old blobs keep opening.
 */
export const DEFAULT_ARGON2ID_PARAMS: Argon2idParams = {
  m: 19456, // 19 MiB
  t: 2, // iterations (time cost)
  p: 1, // parallelism
  dkLen: 32, // 256-bit key for AES-256
};

export interface Argon2idParams {
  /** Memory cost in KiB. */
  m: number;
  /** Time cost (iterations). */
  t: number;
  /** Parallelism. */
  p: number;
  /** Derived key length in bytes. */
  dkLen: number;
}

/**
 * scrypt cost parameters. Retained for LEGACY vaults (sealed before the
 * Argon2id switch) and for selecting scrypt explicitly. Each vault embeds its
 * own parameters so future changes don't invalidate existing vaults.
 */
export const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 131072, // 2^17
  r: 8,
  p: 1,
  dkLen: 32,
};

export interface ScryptParams {
  /** CPU/memory cost — power of two, ≥ 2^14. */
  N: number;
  /** Block size. */
  r: number;
  /** Parallelization. */
  p: number;
  /** Derived key length in bytes. */
  dkLen: number;
}

/** Number of bytes in the random salt. 16 bytes = 128 bits of entropy. */
export const SALT_BYTES = 16;

/** AES-GCM IV size in bytes — 96 bits is the Web Crypto standard. */
export const IV_BYTES = 12;

// ─── Vault blob format ───────────────────────────────────────────────

/**
 * Serialized vault blob, stored as JSON. Discriminated by `kdf`: `argon2id`
 * for new vaults, `scrypt` for legacy ones. `v` is the structural version.
 */
interface VaultBlobCommon {
  /** Format version. Increment on incompatible structural changes. */
  v: 1;
  /** Random salt for the KDF, base64-encoded. */
  salt: string;
  /** Random IV for AES-GCM, base64-encoded. */
  iv: string;
  /** Ciphertext including the 16-byte GCM auth tag, base64-encoded. */
  ciphertext: string;
}

export type VaultBlob =
  | (VaultBlobCommon & { kdf: 'argon2id'; kdfParams: Argon2idParams })
  | (VaultBlobCommon & { kdf: 'scrypt'; kdfParams: ScryptParams });

/** KDF used for newly-sealed vaults. `packages/vault` upgrades anything else to
 *  this on unlock. */
export const CURRENT_KDF = 'argon2id';

// ─── Errors ──────────────────────────────────────────────────────────

/**
 * Thrown by `unsealVault` when authentication fails — either the password is
 * wrong, or the ciphertext has been tampered with. We deliberately don't
 * distinguish the two: an attacker shouldn't learn whether they guessed a valid
 * password without also having an unmodified blob.
 */
export class VaultAuthError extends Error {
  override readonly name = 'VaultAuthError';
  constructor() {
    super('Vault decryption failed: wrong password or tampered ciphertext');
  }
}

/** Thrown by `unsealVault` when the blob's format / version / KDF is unrecognised. */
export class VaultFormatError extends Error {
  override readonly name = 'VaultFormatError';
  constructor(reason: string) {
    super(`Vault blob is malformed: ${reason}`);
  }
}

// ─── KDF ─────────────────────────────────────────────────────────────

/**
 * Derive a 32-byte AES key from a password using scrypt. Exported for legacy /
 * explicit use; new vaults use Argon2id (see `sealVault`).
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
): Promise<Uint8Array> {
  const pwBytes = new TextEncoder().encode(password.normalize('NFKC'));
  return scryptAsync(pwBytes, salt, {
    N: params.N,
    r: params.r,
    p: params.p,
    dkLen: params.dkLen,
  });
}

/** Derive a 32-byte AES key from a password using Argon2id (synchronous in
 *  @noble/hashes). Passwords are NFKC-normalized, same as the scrypt path. */
function deriveArgon2idKey(
  password: string,
  salt: Uint8Array,
  params: Argon2idParams,
): Uint8Array {
  const pwBytes = new TextEncoder().encode(password.normalize('NFKC'));
  return argon2id(pwBytes, salt, {
    m: params.m,
    t: params.t,
    p: params.p,
    dkLen: params.dkLen,
  });
}

// ─── Core API ────────────────────────────────────────────────────────

/** Options for {@link sealVault}. Defaults to Argon2id with
 *  {@link DEFAULT_ARGON2ID_PARAMS}; pass `kdf: 'scrypt'` for the legacy KDF. */
export type SealOptions =
  | { readonly kdf?: 'argon2id'; readonly params?: Argon2idParams }
  | { readonly kdf: 'scrypt'; readonly params?: ScryptParams };

/**
 * Encrypt `plaintext` with `password`. Returns a self-contained blob suitable
 * for JSON-serialization and storage. New vaults use Argon2id by default; pass
 * `{ kdf: 'scrypt' }` only for legacy/compat scenarios.
 *
 * Fresh random salt and IV every call — two encrypts of the same data with the
 * same password produce different blobs.
 */
export async function sealVault(
  plaintext: Uint8Array,
  password: string,
  opts: SealOptions = {},
): Promise<VaultBlob> {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);

  if (opts.kdf === 'scrypt') {
    const params = opts.params ?? DEFAULT_SCRYPT_PARAMS;
    const key = await deriveKey(password, salt, params);
    const ciphertext = await aesGcmEncrypt(key, iv, plaintext);
    return {
      v: 1,
      kdf: 'scrypt',
      kdfParams: params,
      salt: base64.encode(salt),
      iv: base64.encode(iv),
      ciphertext: base64.encode(ciphertext),
    };
  }

  const params = opts.params ?? DEFAULT_ARGON2ID_PARAMS;
  const key = deriveArgon2idKey(password, salt, params);
  const ciphertext = await aesGcmEncrypt(key, iv, plaintext);
  return {
    v: 1,
    kdf: 'argon2id',
    kdfParams: params,
    salt: base64.encode(salt),
    iv: base64.encode(iv),
    ciphertext: base64.encode(ciphertext),
  };
}

/**
 * Decrypt a vault blob with `password`. Returns the original plaintext.
 * Dispatches on the blob's `kdf` so both Argon2id (new) and scrypt (legacy)
 * vaults open.
 *
 * Throws `VaultAuthError` on wrong password or tampered ciphertext, and
 * `VaultFormatError` on a malformed blob / unknown version or KDF.
 */
export async function unsealVault(
  blob: VaultBlob,
  password: string,
): Promise<Uint8Array> {
  if (blob.v !== 1) {
    throw new VaultFormatError(`Unsupported version: ${blob.v}`);
  }

  let salt: Uint8Array;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    salt = base64.decode(blob.salt);
    iv = base64.decode(blob.iv);
    ciphertext = base64.decode(blob.ciphertext);
  } catch (e) {
    throw new VaultFormatError(`Invalid base64: ${(e as Error).message}`);
  }

  let key: Uint8Array;
  if (blob.kdf === 'argon2id') {
    key = deriveArgon2idKey(password, salt, blob.kdfParams);
  } else if (blob.kdf === 'scrypt') {
    key = await deriveKey(password, salt, blob.kdfParams);
  } else {
    throw new VaultFormatError(
      `Unsupported KDF: ${String((blob as { kdf?: unknown }).kdf)}`,
    );
  }

  try {
    return await aesGcmDecrypt(key, iv, ciphertext);
  } catch {
    // Web Crypto throws a generic OperationError on auth failure — could be
    // wrong password or tampered ciphertext. We don't distinguish.
    throw new VaultAuthError();
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────

async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key);
  const buffer = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: asAB(iv) },
    cryptoKey,
    asAB(plaintext),
  );
  return new Uint8Array(buffer);
}

async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key);
  const buffer = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: asAB(iv) },
    cryptoKey,
    asAB(ciphertext),
  );
  return new Uint8Array(buffer);
}

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

/**
 * Cast a `Uint8Array` to one backed by `ArrayBuffer` (not `SharedArrayBuffer`).
 * TS 5.7+ requires this for Web Crypto inputs; our buffers are always plain
 * ArrayBuffer since we allocate them locally.
 */
function asAB(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  return u8 as Uint8Array<ArrayBuffer>;
}
