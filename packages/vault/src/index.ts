export {
  Vault,
  type LockReason,
  type VaultConfig,
  type VaultEvent,
  type VaultListener,
  type VaultStatus,
} from './vault.js';

export {
  InMemoryVaultStorage,
  type VaultStorage,
} from './storage.js';

export {
  InvalidMnemonicError,
  InvalidPasswordError,
  UnlockThrottledError,
  VaultEmptyError,
  VaultExistsError,
  WalletLockedError,
} from './errors.js';
