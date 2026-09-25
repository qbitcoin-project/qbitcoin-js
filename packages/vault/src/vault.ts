// Vault — stateful seed storage with autolock.
//
// Holds the encrypted mnemonic in host-supplied storage and keeps only its
// derived seed resident while unlocked. The host owns derived keys, storage
// adapters, user activity signals and platform lifecycle integration.

import {
  CURRENT_KDF,
  deriveAppDataKey,
  HDKey,
  masterKeyFromSeed,
  mnemonicToSeed,
  openAppData,
  sealAppData,
  sealVault,
  unsealVault,
  validateMnemonic,
  VaultAuthError,
  VaultFormatError,
  type VaultBlob,
} from '@qbtc/crypto';
import {
  InvalidMnemonicError,
  InvalidPasswordError,
  UnlockThrottledError,
  VaultEmptyError,
  VaultExistsError,
  WalletLockedError,
} from './errors.js';
import type { VaultStorage } from './storage.js';

// ─── Configuration ───────────────────────────────────────────────────

/** Default autolock — 5 minutes of inactivity. */
const DEFAULT_AUTO_LOCK_MS = 5 * 60 * 1000;

// Password throttle (defence-in-depth on top of the Argon2id KDF). The first few
// wrong passwords are free — fat-fingering a strong password is normal — after
// which a mandatory cooldown grows per failure, capped. In-memory only: it resets
// on app restart, so the KDF cost stays the real brute-force barrier; this just
// blunts repeated guessing across unlock, reveal and password changes.
const PASSWORD_FREE_ATTEMPTS = 3;
const PASSWORD_BACKOFF_BASE_MS = 1000;
const PASSWORD_BACKOFF_MAX_MS = 30_000;

export interface VaultConfig {
  /**
   * Autolock the vault after this many milliseconds of inactivity.
   * "Activity" is an explicit {@link Vault.noteActivity} call, driven by real
   * user interaction in the UI — NOT internal key access or background reads, so
   * a polling renderer can't hold the wallet open while the user is away. Pass
   * `0` when the host enforces autolock itself (e.g. extension alarms).
   *
   * Default: 5 minutes.
   */
  readonly autoLockMs?: number;
  /**
   * HKDF `info` label of the app-data encryption key ({@link Vault.sealData}).
   * A chain value the host takes from its chain profile (the profile's
   * `appDataInfo`) — the vault carries no chain constants of its own.
   * Frozen once shipped: data sealed under one label is unreadable under
   * another.
   */
  readonly appDataInfo: string;
}

// ─── State + events ──────────────────────────────────────────────────

/** Vault state — derived from storage contents + in-memory key. */
export type VaultStatus = 'empty' | 'locked' | 'unlocked';

/** Reason for a lock event. */
export type LockReason = 'manual' | 'timeout';

/** Events emitted as the vault transitions between states. */
export type VaultEvent =
  | { readonly type: 'created' }
  | { readonly type: 'unlocked' }
  | { readonly type: 'locked'; readonly reason: LockReason }
  | { readonly type: 'destroyed' };

/** Callback signature for `vault.on(...)`. */
export type VaultListener = (event: VaultEvent) => void;

// ─── The class ───────────────────────────────────────────────────────

export class Vault {
  private masterSeed: Uint8Array | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly listeners: Set<VaultListener> = new Set();
  private readonly autoLockMs: number;
  private readonly appDataInfo: string;
  // Shared password-throttle state (in-memory): consecutive authentication
  // failures and the timestamp until which password checks are refused.
  private failedPasswordAttempts = 0;
  private passwordBlockedUntil = 0;
  private generation = 0;
  private pending: Promise<void> = Promise.resolve();

  constructor(
    private readonly store: VaultStorage,
    config: VaultConfig,
  ) {
    this.autoLockMs = config.autoLockMs ?? DEFAULT_AUTO_LOCK_MS;
    if (!Number.isFinite(this.autoLockMs) || this.autoLockMs < 0 || this.autoLockMs > 2 ** 31 - 1) {
      throw new RangeError(`autoLockMs must be between 0 and 2147483647, got ${this.autoLockMs}`);
    }
    if (typeof config.appDataInfo !== 'string' || config.appDataInfo.length === 0) {
      throw new RangeError('appDataInfo must not be empty');
    }
    this.appDataInfo = config.appDataInfo;
  }

  // ─── State inspection ──────────────────────────────────────────────

  /** Current status. Reads storage to distinguish empty from locked. */
  async getStatus(): Promise<VaultStatus> {
    if (this.masterSeed !== null) return 'unlocked';
    const blob = await this.store.read();
    return blob !== null ? 'locked' : 'empty';
  }

  /** True if the vault is unlocked (master key available). */
  isUnlocked(): boolean {
    return this.masterSeed !== null;
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────

  /**
   * Create a new vault from a BIP-39 mnemonic and a password. Leaves
   * the vault in the `unlocked` state — UX-wise, the user typically
   * just finished writing down their seed phrase and would expect to
   * land in the wallet immediately.
   *
   * Throws `VaultExistsError` if a vault is already in storage. The UI
   * should make destroying an existing vault an explicit step.
   */
  async create(mnemonic: string, password: string): Promise<void> {
    return this.inSession(async (check) => {
      const existing = await this.store.read();
      check();
      if (existing !== null) throw new VaultExistsError();
      const normalized = mnemonic.trim();
      if (!validateMnemonic(normalized)) throw new InvalidMnemonicError();

      const mnemonicBytes = new TextEncoder().encode(normalized);
      try {
        const blob = await sealVault(mnemonicBytes, password);
        check();
        await this.store.write(serializeBlob(blob));
        check();
        this.masterSeed = mnemonicToSeed(normalized);
        this.startAutoLockTimer();
        this.emit({ type: 'created' });
        check();
        this.emit({ type: 'unlocked' });
      } finally {
        mnemonicBytes.fill(0);
      }
    });
  }

  /**
   * Unlock an existing vault with `password`. Idempotent: calling
   * `unlock` while already unlocked just refreshes the autolock timer
   * (handy for "user is active" pings).
   *
   * Throws `VaultEmptyError` if there's no vault, `InvalidPasswordError`
   * on wrong password or tampered ciphertext, `UnlockThrottledError` during
   * the shared password cooldown. An already-unlocked call does not check
   * the password and does not reset the throttle.
   */
  async unlock(password: string): Promise<void> {
    return this.inSession(async (check) => {
      if (this.isUnlocked()) {
        this.refreshTimer();
        return;
      }
      const stored = await this.store.read();
      check();
      if (stored === null) throw new VaultEmptyError();
      const blob = parseBlob(stored);
      const decrypted = await this.decryptMnemonic(blob, password);
      try {
        check();
        this.resetPasswordThrottle();
        // Keep legacy data readable if its best-effort upgrade cannot be saved.
        if (blob.kdf !== CURRENT_KDF) {
          try {
            const upgraded = await sealVault(decrypted, password);
            check();
            await this.store.write(serializeBlob(upgraded));
          } catch {
            // Storage must leave the previous blob intact when a write fails.
          }
          check();
        }
        const mnemonic = new TextDecoder().decode(decrypted);
        if (!validateMnemonic(mnemonic)) throw new InvalidMnemonicError();
        this.masterSeed = mnemonicToSeed(mnemonic);
        this.startAutoLockTimer();
        this.emit({ type: 'unlocked' });
      } finally {
        decrypted.fill(0);
      }
    });
  }

  /**
   * Lock the vault immediately. Wipes the master seed from memory and
   * stops the autolock timer. Idempotent.
   */
  lock(reason: LockReason = 'manual'): void {
    this.generation += 1;
    const wasUnlocked = this.isUnlocked();
    this.stopTimer();
    this.wipeSecrets();
    if (wasUnlocked) this.emit({ type: 'locked', reason });
  }

  /**
   * Permanently delete the vault — clears storage AND in-memory secrets.
   * After this returns the vault is back in `empty` state.
   *
   * UI should require explicit confirmation: this is unrecoverable
   * unless the user backed up their seed phrase.
   */
  async destroy(): Promise<void> {
    // Cancel earlier work immediately; clear after any already-started write.
    this.generation += 1;
    this.stopTimer();
    this.wipeSecrets();
    return this.enqueue(async () => {
      await this.store.clear();
      // Reset only after deletion succeeds and earlier checks have settled.
      // A failed clear must not reopen guesses against the existing blob.
      this.resetPasswordThrottle();
      this.emit({ type: 'destroyed' });
    });
  }

  // ─── Authorized operations (require unlocked) ──────────────────────

  /**
   * Signal genuine user activity (pointer/keyboard in the UI), resetting the
   * idle-autolock countdown. This is the ONLY thing that extends the unlock
   * window: internal key access and background reads deliberately do not, so a
   * polling UI can't keep the wallet unlocked while the user is away. No-op when
   * locked/empty or when autolock is disabled.
   */
  noteActivity(): void {
    if (this.masterSeed === null) return;
    this.refreshTimer();
  }

  /**
   * Return the BIP-32 master HD key. Does NOT touch the autolock timer:
   * derivation/signing is routinely driven by background work (discovery,
   * balance polling), so treating it as activity would defeat idle-autolock.
   * Real activity is signalled via {@link noteActivity}. Throws
   * `WalletLockedError` if locked.
   */
  getMasterKey(): HDKey {
    if (this.masterSeed === null) throw new WalletLockedError();
    return masterKeyFromSeed(this.masterSeed);
  }

  /**
   * Reveal the recovery mnemonic for display in Settings. Requires a FRESH
   * password — the wallet never keeps the mnemonic resident (an immutable JS
   * string can't be zeroed), so we re-decrypt the stored blob on demand. Only
   * the seed is held in memory, and it's wiped on lock.
   *
   * Must be unlocked AND given the correct password — defence-in-depth against
   * shoulder-surfing a momentarily unattended unlocked wallet. Does NOT touch
   * the autolock timer (the UI signals activity via {@link noteActivity}). The
   * returned string is transient: the UI shows it and drops it; it is never
   * stored here.
   *
   * Throws `WalletLockedError` if locked, `VaultEmptyError` if there's no
   * vault, `InvalidPasswordError` on a wrong password, or
   * `UnlockThrottledError` during the shared password cooldown.
   */
  async revealMnemonic(password: string): Promise<string> {
    if (this.masterSeed === null) throw new WalletLockedError();
    return this.inSession(async (check) => {
      const stored = await this.store.read();
      check();
      if (stored === null) throw new VaultEmptyError();
      const decrypted = await this.decryptMnemonic(parseBlob(stored), password);
      try {
        check();
        this.resetPasswordThrottle();
        return new TextDecoder().decode(decrypted);
      } finally {
        decrypted.fill(0);
      }
    });
  }

  /**
   * Encrypt non-key local data (e.g. the address book) at rest with a key
   * derived from the seed (HKDF; see @qbtc/crypto appData). Available only
   * when unlocked; the derived key never leaves the background and is wiped
   * after use. Does NOT reset the autolock timer — reading the address book
   * shouldn't extend the unlock window.
   */
  async sealData(plaintext: string): Promise<string> {
    if (this.masterSeed === null) throw new WalletLockedError();
    const key = deriveAppDataKey(this.masterSeed, this.appDataInfo);
    const bytes = new TextEncoder().encode(plaintext);
    try {
      // No cancellation after the await: the result is ciphertext, which
      // holds no secret, and discarding it on a concurrent lock would only
      // lose the host's data (openData, which returns plaintext, does check).
      return await sealAppData(key, bytes);
    } finally {
      key.fill(0);
      bytes.fill(0);
    }
  }

  /**
   * Decrypt data sealed by {@link sealData}. Throws `WalletLockedError` if
   * locked; the crypto layer throws `AppDataError` on a malformed or foreign
   * blob (wrong key / tampered).
   */
  async openData(blob: string): Promise<string> {
    if (this.masterSeed === null) throw new WalletLockedError();
    const generation = this.generation;
    const key = deriveAppDataKey(this.masterSeed, this.appDataInfo);
    let plaintext: Uint8Array | undefined;
    try {
      plaintext = await openAppData(key, blob);
      this.checkGeneration(generation);
      return new TextDecoder().decode(plaintext);
    } finally {
      key.fill(0);
      plaintext?.fill(0);
    }
  }

  /**
   * Change the password without re-deriving keys. Vault must be locked
   * or unlocked (not empty). Works whether or not the vault is
   * currently unlocked — the unlocked state is preserved.
   *
   * Throws `InvalidPasswordError` on wrong old password, or
   * `UnlockThrottledError` during the shared password cooldown.
   */
  async changePassword(
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    return this.inSession(async (check) => {
      const stored = await this.store.read();
      check();
      if (stored === null) throw new VaultEmptyError();
      const decrypted = await this.decryptMnemonic(parseBlob(stored), oldPassword);
      try {
        check();
        this.resetPasswordThrottle();
        const newBlob = await sealVault(decrypted, newPassword);
        check();
        await this.store.write(serializeBlob(newBlob));
        check();
      } finally {
        decrypted.fill(0);
      }
    });
  }

  // ─── Events ────────────────────────────────────────────────────────

  /**
   * Register a listener for state events. Returns an unsubscribe
   * function. Listeners are called synchronously in registration order.
   */
  on(listener: VaultListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private emit(event: VaultEvent): void {
    for (const listener of this.listeners) {
      listener(event);
    }
  }

  // ─── Internals ─────────────────────────────────────────────────────

  // Serialize password/storage operations for this instance. Rejections must
  // not poison the queue. Hosts must use one Vault per storage location.
  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.pending.then(operation);
    this.pending = result.then(() => {}, () => {});
    return result;
  }

  private inSession<T>(operation: (check: () => void) => Promise<T>): Promise<T> {
    const generation = this.generation;
    return this.enqueue(() => {
      const check = () => this.checkGeneration(generation);
      check();
      return operation(check);
    });
  }

  private checkGeneration(generation: number): void {
    if (generation !== this.generation) throw new WalletLockedError();
  }

  // Called only inside the serialized session queue. Check the shared
  // cooldown immediately before the KDF, not when the request is enqueued.
  // Callers own the returned buffer and reset the throttle only after their
  // generation check succeeds; a cancelled success must not clear failures.
  private async decryptMnemonic(blob: VaultBlob, password: string): Promise<Uint8Array> {
    const wait = this.passwordBlockedUntil - Date.now();
    if (wait > 0) throw new UnlockThrottledError(wait);
    try {
      return await unsealVault(blob, password);
    } catch (e) {
      // Count an authentication failure even if lock() cancelled its session.
      // Otherwise interleaving locks with password checks could evade backoff.
      if (e instanceof VaultAuthError) {
        this.registerFailedPassword();
        throw new InvalidPasswordError();
      }
      throw e;
    }
  }

  // Count a wrong-password attempt and, past the free allowance, open a cooldown
  // window that grows per failure (capped). See the PASSWORD_* constants.
  private registerFailedPassword(): void {
    this.failedPasswordAttempts += 1;
    if (this.failedPasswordAttempts > PASSWORD_FREE_ATTEMPTS) {
      const over = this.failedPasswordAttempts - PASSWORD_FREE_ATTEMPTS; // 1, 2, 3, …
      const backoff = Math.min(PASSWORD_BACKOFF_BASE_MS * 2 ** (over - 1), PASSWORD_BACKOFF_MAX_MS);
      this.passwordBlockedUntil = Date.now() + backoff;
    }
  }

  private resetPasswordThrottle(): void {
    this.failedPasswordAttempts = 0;
    this.passwordBlockedUntil = 0;
  }

  private wipeSecrets(): void {
    if (this.masterSeed !== null) {
      this.masterSeed.fill(0);
      this.masterSeed = null;
    }
  }

  private startAutoLockTimer(): void {
    if (this.autoLockMs > 0) this.refreshTimer();
  }

  private refreshTimer(): void {
    if (this.autoLockMs <= 0) return;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      this.lock('timeout');
    }, this.autoLockMs);
  }

  private stopTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}

// ─── Blob serialization helpers ──────────────────────────────────────

function serializeBlob(blob: VaultBlob): string {
  return JSON.stringify(blob);
}

function parseBlob(serialized: string): VaultBlob {
  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new VaultFormatError('Invalid JSON');
  }
  if (typeof value !== 'object' || value === null) {
    throw new VaultFormatError('Expected an object');
  }
  const blob = value as Record<string, unknown>;
  if (blob.v !== 1 || (blob.kdf !== 'argon2id' && blob.kdf !== 'scrypt')) {
    throw new VaultFormatError('Unsupported version or KDF');
  }
  if (typeof blob.salt !== 'string' || typeof blob.iv !== 'string' || typeof blob.ciphertext !== 'string') {
    throw new VaultFormatError('Expected encoded salt, IV and ciphertext');
  }
  if (typeof blob.kdfParams !== 'object' || blob.kdfParams === null) {
    throw new VaultFormatError('Missing KDF parameters');
  }
  const params = blob.kdfParams as Record<string, unknown>;
  const fields = blob.kdf === 'argon2id' ? ['m', 't', 'p', 'dkLen'] : ['N', 'r', 'p', 'dkLen'];
  for (const field of fields) {
    const n = params[field];
    if (typeof n !== 'number' || !Number.isSafeInteger(n) || n <= 0) {
      throw new VaultFormatError(`Invalid KDF parameter: ${field}`);
    }
  }
  return value as VaultBlob;
}
