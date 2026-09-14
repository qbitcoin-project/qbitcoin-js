// Error types for the vault package.
//
// All errors are distinguishable subclasses so callers (background SW,
// UI) can render specific messages and decide whether to retry.

/** Raised when an operation requires an unlocked vault but it's locked. */
export class WalletLockedError extends Error {
  override readonly name = 'WalletLockedError';
  constructor() {
    super('Wallet is locked. Unlock with your password first.');
  }
}

/** Raised when `unlock(password)` or `changePassword(old, _)` is called
 *  with the wrong password. Deliberately indistinguishable from a
 *  ciphertext-tampered case to avoid leaking timing info. */
export class InvalidPasswordError extends Error {
  override readonly name = 'InvalidPasswordError';
  constructor() {
    super('Incorrect password.');
  }
}

/** Raised when `create()` receives a mnemonic that doesn't pass BIP-39
 *  checksum/wordlist validation. */
export class InvalidMnemonicError extends Error {
  override readonly name = 'InvalidMnemonicError';
  constructor() {
    super('Invalid recovery phrase — words or checksum do not match BIP-39.');
  }
}

/** Raised when `create()` is called but a vault already exists. The UX
 *  should make destroying an existing vault an explicit action — never
 *  silently overwrite. */
export class VaultExistsError extends Error {
  override readonly name = 'VaultExistsError';
  constructor() {
    super('A vault already exists in this storage. Destroy it first to create a new one.');
  }
}

/** Raised when `unlock()`, `revealMnemonic()`, etc. are called but
 *  there's no vault in storage. The UI should detect `empty` state
 *  before attempting these. */
export class VaultEmptyError extends Error {
  override readonly name = 'VaultEmptyError';
  constructor() {
    super('No vault exists in this storage. Create one first.');
  }
}

/** Raised when unlock attempts are temporarily throttled after repeated wrong
 *  passwords (defence-in-depth on top of the KDF cost). `retryAfterMs` is how
 *  long the caller should wait before trying again. */
export class UnlockThrottledError extends Error {
  override readonly name = 'UnlockThrottledError';
  readonly retryAfterMs: number;
  constructor(retryAfterMs: number) {
    const seconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
    super(`Too many attempts. Try again in ${seconds} second${seconds === 1 ? '' : 's'}.`);
    this.retryAfterMs = retryAfterMs;
  }
}
