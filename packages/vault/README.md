# @qbtc/vault

Password-protected BIP-39 seed storage for wallets. Owns the in-memory seed,
lock state, password changes and lifecycle events. The application supplies
storage and its frozen application-data encryption label.

Uses `@qbtc/crypto` for Argon2id, AES-GCM, BIP-39/32 and application-data
encryption. No filesystem, browser-extension, Electron or chain-client
dependencies. Ships compiled ESM, TypeScript declarations and sources.

## Install

```sh
pnpm add @qbtc/vault @qbtc/crypto
```

`@qbtc/crypto` is a peer dependency (`^1.1.0`): the vault uses the copy your
application already has, so the `HDKey` it returns and the crypto errors it
propagates are the same classes you import yourself. Pin both packages to
exact versions.

Node 22+ or a runtime with Web Crypto, TextEncoder and TextDecoder is
required. In a browser, use a secure context and bundle the package.

## Usage

```ts
import { Vault, type VaultStorage } from '@qbtc/vault';

// Implement these operations using your application's persistence layer.
// Writes must be atomic: a rejected write must preserve the previous blob.
declare const storage: VaultStorage;
declare const mnemonic: string;
declare const password: string;

const vault = new Vault(storage, {
  // Use the existing profile.appDataInfo for an established application.
  appDataInfo: 'mychain/app-data/v1',
  autoLockMs: 5 * 60 * 1000,
});

const unsubscribe = vault.on((event) => {
  if (event.type === 'locked' || event.type === 'destroyed') {
    // Drop derived keys, sensitive UI state and application caches here.
  }
});

await vault.create(mnemonic, password); // persists and unlocks
vault.noteActivity(); // call on real user interaction
const encrypted = await vault.sealData('private application data');
vault.lock();
await vault.unlock(password);
const plaintext = await vault.openData(encrypted);
vault.lock();
unsubscribe();
```

Use `InMemoryVaultStorage` in tests and demos. Persistent storage adapters
belong to the host: files, IndexedDB and browser.storage.local all fit the
same interface. The package has no default storage key or file path.

## API

| Method | Behavior |
|---|---|
| `getStatus()` | Resolves to `empty`, `locked` or `unlocked`. |
| `isUnlocked()` | Synchronously reports whether this instance holds a seed. |
| `create(mnemonic, password)` | Validates a BIP-39 phrase, refuses to overwrite storage, then persists and unlocks. |
| `unlock(password)` | Opens an existing vault. When already unlocked, refreshes the timer without checking the password again. |
| `lock(reason?)` | Immediately wipes the resident seed and cancels earlier session operations. Reason is `manual` (default) or `timeout`. |
| `destroy()` | Immediately wipes the seed, cancels earlier session work and queues deletion of the stored blob. |
| `changePassword(oldPassword, newPassword)` | Re-encrypts the mnemonic; works locked or unlocked and preserves that state unless a lock occurs. |
| `revealMnemonic(password)` | Requires an unlocked vault and a fresh correct password. |
| `getMasterKey()` | Returns a new secret BIP-32 HDKey; the caller owns its lifetime. |
| `sealData(plaintext)` / `openData(blob)` | Encrypt/decrypt strings using a key derived from the primary seed and appDataInfo. Require unlock. A lock during `sealData` does not discard the finished ciphertext; a lock during `openData` withholds the plaintext. |
| `noteActivity()` | Refreshes the internal timer when unlocked. |
| `on(listener)` | Synchronous event subscription; returns an unsubscribe function. Listeners should not throw. |

Events: `created`, `unlocked`, `locked` (with `reason`), `destroyed`.
Destroy emits `destroyed`, not a separate `locked` event. Repeated lock
does not emit another event; repeated unlock does not emit `unlocked`.

Exported errors: `WalletLockedError`, `InvalidPasswordError`,
`InvalidMnemonicError`, `VaultExistsError`, `VaultEmptyError`,
`UnlockThrottledError` (with `retryAfterMs`). Malformed blobs and application
data may also raise `VaultFormatError` or `AppDataError` from `@qbtc/crypto`.
Storage errors propagate unchanged, except for a best-effort KDF upgrade.

## Autolock and platform integration

The internal timer defaults to five minutes. Only explicit activity and
successful create/unlock refresh it; key derivation and app-data reads do
not extend the session. Timeouts must be finite, nonnegative and at most
2147483647 milliseconds.

An extension that enforces idle locking with browser alarms should pass
`autoLockMs: 0`, track activity in its background service and call
`vault.lock('timeout')` when due. Keep-alive, service-worker restarts and
OS lifecycle events belong to the application. A new Vault instance always
starts without an in-memory seed.

## Concurrency and storage

Use one Vault instance per storage location. Password and storage
operations are serialized within that instance. Multiple processes or
instances writing the same location require coordination in the host.

`lock()` and `destroy()` immediately invalidate earlier queued/in-flight
session operations. Those operations reject with `WalletLockedError` at
their next checkpoint and cannot restore an unlocked state or return
decrypted data after that lock. A new explicit unlock issued after a lock
is a new request and is allowed.

An already-started storage write cannot be cancelled: a create or password
change can finish writing while its caller receives `WalletLockedError`.
The host must treat this as an interrupted operation, not proof that the
write was rolled back. Destroy waits for earlier writes before clearing
the blob. Do not perform automatic destructive recovery on an error.

## Existing data

Preserves the v1 JSON blob used by the crypto package: `v`, `kdf`,
`kdfParams`, `salt`, `iv`, `ciphertext`. Password normalization is NFKC.
New vaults use Argon2id; legacy scrypt vaults remain readable and are
re-encrypted with Argon2id on successful unlock. A failed upgrade write
does not prevent unlocking the original data.

When replacing an existing implementation, keep its exact storage
location and `appDataInfo`. Changing the label makes existing app-data
unreadable. Changing the password preserves the app-data key because that
key derives from the seed. Replacing the primary seed changes the key.

The vault stores one primary mnemonic without a BIP-39 passphrase.
Additional wallets, imported private keys and watch-only sources belong
to the application's wallet model.

## Security boundaries

- Keep the instance in the trusted process that performs signing. It is
  not a sandbox for its callers: `getMasterKey()` exposes a secret HDKey.
- Lock wipes the seed owned by this instance. Derived keys, returned
  strings and host caches cannot be revoked or reliably zeroed by it.
- Mnemonic and app-data byte buffers owned by this layer are wiped on
  completion and failure. JavaScript strings and runtime-internal copies
  cannot be guaranteed erased.
- Throttling applies to failed `unlock` attempts in the current instance:
  after the fourth failure, cooldown starts at one second and increases
  to thirty seconds. It resets on successful unlock or destruction. It
  does not cover reveal/change-password requests or offline guessing.
- Password-strength requirements and request authorization belong to the
  host. This package does not enforce a password minimum.
- The storage adapter is a trusted persistence boundary, not an arbitrary
  file-import API. Stored KDF parameters control work and memory cost;
  this package checks their shape but imposes no new cost ceiling on
  existing blobs. A host accepting untrusted imports must bound resource
  usage before opening them.

## License

[MIT](LICENSE).
