import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  InvalidMnemonicError,
  InvalidPasswordError,
  UnlockThrottledError,
  VaultEmptyError,
  VaultExistsError,
  WalletLockedError,
} from './errors.js';
import { AppDataError, sealVault } from '@qbtc/crypto';
import { InMemoryVaultStorage } from './storage.js';
import { Vault, type VaultConfig, type VaultEvent } from './vault.js';

// A valid 12-word BIP-39 phrase from Trezor's canonical test vectors.
const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'correct horse battery staple';
/** The HKDF label a host takes from its chain profile. */
const APP_DATA_INFO = 'test/app-data/v1';
const cfg = (autoLockMs: number): VaultConfig => ({ autoLockMs, appDataInfo: APP_DATA_INFO });

describe('Vault — lifecycle (empty → unlocked)', () => {
  it('starts in empty state when storage is empty', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    expect(await v.getStatus()).toBe('empty');
    expect(v.isUnlocked()).toBe(false);
  });

  it('create() leaves vault in unlocked state', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    expect(await v.getStatus()).toBe('unlocked');
    expect(v.isUnlocked()).toBe(true);
  });

  it('create() writes the encrypted blob to storage', async () => {
    const storage = new InMemoryVaultStorage();
    const v = new Vault(storage, cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    const blob = await storage.read();
    expect(blob).not.toBeNull();
    // The stored blob is JSON with our scheme; new vaults default to Argon2id.
    expect(JSON.parse(blob!).v).toBe(1);
    expect(JSON.parse(blob!).kdf).toBe('argon2id');
  });

  it('create() rejects invalid mnemonic', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await expect(v.create('not a real mnemonic', PASSWORD)).rejects.toThrow(
      InvalidMnemonicError,
    );
  });

  it('create() trims whitespace', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(`  ${MNEMONIC}\n`, PASSWORD);
    expect(await v.revealMnemonic(PASSWORD)).toBe(MNEMONIC);
  });

  it('create() refuses to overwrite an existing vault', async () => {
    const storage = new InMemoryVaultStorage();
    const v = new Vault(storage, cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();

    const v2 = new Vault(storage, cfg(0));
    await expect(v2.create(MNEMONIC, PASSWORD)).rejects.toThrow(
      VaultExistsError,
    );
  });
}, 30_000);

describe('Vault — lock + unlock', () => {
  it('lock() takes unlocked vault to locked state', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    expect(await v.getStatus()).toBe('locked');
    expect(v.isUnlocked()).toBe(false);
  });

  it('unlock() with correct password restores access', async () => {
    const storage = new InMemoryVaultStorage();
    const v = new Vault(storage, cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();

    // Use a fresh Vault instance to simulate SW restart.
    const v2 = new Vault(storage, cfg(0));
    expect(await v2.getStatus()).toBe('locked');
    await v2.unlock(PASSWORD);
    expect(v2.isUnlocked()).toBe(true);
    expect(await v2.revealMnemonic(PASSWORD)).toBe(MNEMONIC);
  });

  it('unlock() rejects wrong password with InvalidPasswordError', async () => {
    const storage = new InMemoryVaultStorage();
    const v = new Vault(storage, cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    await expect(v.unlock('wrong password')).rejects.toThrow(
      InvalidPasswordError,
    );
  });

  it('unlock() on empty storage throws VaultEmptyError', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await expect(v.unlock(PASSWORD)).rejects.toThrow(VaultEmptyError);
  });

  it('unlock() is idempotent when already unlocked', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    // Second unlock should not throw.
    await v.unlock(PASSWORD);
    expect(v.isUnlocked()).toBe(true);
  });

  it('lock() is idempotent', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    v.lock();
    expect(await v.getStatus()).toBe('locked');
  });
}, 30_000);

describe('Vault — getMasterKey + revealMnemonic', () => {
  it('returns a master key when unlocked', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    const key = v.getMasterKey();
    expect(key.privateKey).toBeDefined();
    expect(key.publicKey?.length).toBe(33);
  });

  it('returns the same key across calls (same seed)', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    const a = v.getMasterKey().privateKey!;
    const b = v.getMasterKey().privateKey!;
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it('getMasterKey() throws WalletLockedError when locked', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    expect(() => v.getMasterKey()).toThrow(WalletLockedError);
  });

  it('revealMnemonic() returns the mnemonic when unlocked + correct password', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    // The mnemonic is NOT cached — reveal re-decrypts the blob.
    expect(await v.revealMnemonic(PASSWORD)).toBe(MNEMONIC);
  });

  it('revealMnemonic() rejects a wrong password with InvalidPasswordError', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    await expect(v.revealMnemonic('wrong password')).rejects.toThrow(
      InvalidPasswordError,
    );
  });

  it('revealMnemonic() throws WalletLockedError when locked', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    await expect(v.revealMnemonic(PASSWORD)).rejects.toThrow(WalletLockedError);
  });
}, 30_000);

describe('Vault — destroy + changePassword', () => {
  it('destroy() removes blob and resets state to empty', async () => {
    const storage = new InMemoryVaultStorage();
    const v = new Vault(storage, cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    await v.destroy();
    expect(await v.getStatus()).toBe('empty');
    expect(await storage.read()).toBeNull();
  });

  it('changePassword() lets the new password unlock the vault', async () => {
    const storage = new InMemoryVaultStorage();
    const v = new Vault(storage, cfg(0));
    await v.create(MNEMONIC, PASSWORD);

    await v.changePassword(PASSWORD, 'new password');
    v.lock();

    await expect(v.unlock(PASSWORD)).rejects.toThrow(InvalidPasswordError);
    await v.unlock('new password');
    expect(await v.revealMnemonic('new password')).toBe(MNEMONIC);
  });

  it('changePassword() preserves the unlocked state', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    await v.changePassword(PASSWORD, 'new password');
    expect(v.isUnlocked()).toBe(true);
  });

  it('changePassword() rejects wrong old password', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    await expect(v.changePassword('wrong', 'new password')).rejects.toThrow(
      InvalidPasswordError,
    );
  });

  it('changePassword() on empty storage throws VaultEmptyError', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await expect(v.changePassword(PASSWORD, 'new')).rejects.toThrow(
      VaultEmptyError,
    );
  });
}, 30_000);

describe('Vault — KDF migration', () => {
  it('upgrades a legacy scrypt vault to Argon2id on unlock', async () => {
    const storage = new InMemoryVaultStorage();
    // Seed a legacy scrypt vault directly (fast scrypt params for the test).
    const legacy = await sealVault(new TextEncoder().encode(MNEMONIC), PASSWORD, {
      kdf: 'scrypt',
      params: { N: 1024, r: 8, p: 1, dkLen: 32 },
    });
    await storage.write(JSON.stringify(legacy));
    expect(JSON.parse((await storage.read())!).kdf).toBe('scrypt');

    const v = new Vault(storage, cfg(0));
    await v.unlock(PASSWORD);
    expect(v.isUnlocked()).toBe(true);
    expect(await v.revealMnemonic(PASSWORD)).toBe(MNEMONIC);

    // Re-sealed to Argon2id at rest, and still unlockable afterwards.
    expect(JSON.parse((await storage.read())!).kdf).toBe('argon2id');
    const v2 = new Vault(storage, cfg(0));
    await v2.unlock(PASSWORD);
    expect(v2.isUnlocked()).toBe(true);
  });
}, 30_000);

describe('Vault — events', () => {
  it('emits "created" + "unlocked" on create()', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    const events: VaultEvent[] = [];
    v.on((e) => events.push(e));
    await v.create(MNEMONIC, PASSWORD);
    expect(events.map((e) => e.type)).toEqual(['created', 'unlocked']);
  });

  it('emits "locked" on lock()', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    const events: VaultEvent[] = [];
    v.on((e) => events.push(e));
    v.lock();
    expect(events).toEqual([{ type: 'locked', reason: 'manual' }]);
  });

  it('does NOT emit "locked" when calling lock() on already-locked vault', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    const events: VaultEvent[] = [];
    v.on((e) => events.push(e));
    v.lock(); // already locked
    expect(events).toEqual([]);
  });

  it('emits "unlocked" on unlock() (but not on idempotent re-unlock)', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    const events: VaultEvent[] = [];
    v.on((e) => events.push(e));
    await v.unlock(PASSWORD);
    await v.unlock(PASSWORD); // idempotent — no new event
    expect(events.map((e) => e.type)).toEqual(['unlocked']);
  });

  it('emits "destroyed" on destroy()', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    const events: VaultEvent[] = [];
    v.on((e) => events.push(e));
    await v.destroy();
    // destroy on an unlocked vault implicitly clears in-memory state but
    // doesn't itself emit 'locked' — that's bundled into 'destroyed'.
    expect(events.map((e) => e.type)).toEqual(['destroyed']);
  });

  it('unsubscribe stops further events', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    const events: VaultEvent[] = [];
    const off = v.on((e) => events.push(e));
    await v.create(MNEMONIC, PASSWORD);
    off();
    v.lock();
    expect(events.map((e) => e.type)).toEqual(['created', 'unlocked']);
  });
}, 30_000);

describe('Vault — autolock timer', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('autolocks after configured timeout', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(1000));
    await v.create(MNEMONIC, PASSWORD);
    expect(v.isUnlocked()).toBe(true);
    vi.advanceTimersByTime(1000);
    expect(v.isUnlocked()).toBe(false);
  });

  it('emits locked with reason="timeout" on autolock', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(1000));
    const events: VaultEvent[] = [];
    v.on((e) => events.push(e));
    await v.create(MNEMONIC, PASSWORD);
    vi.advanceTimersByTime(1000);
    const lockEvent = events.find((e) => e.type === 'locked');
    expect(lockEvent).toEqual({ type: 'locked', reason: 'timeout' });
  });

  it('getMasterKey() does NOT reset the timer (background work must not hold the wallet open)', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(1000));
    await v.create(MNEMONIC, PASSWORD);
    vi.advanceTimersByTime(800);
    v.getMasterKey(); // must NOT reset — derivation is often background-driven
    vi.advanceTimersByTime(300); // 1100ms since create → past the timeout
    expect(v.isUnlocked()).toBe(false);
  });

  it('noteActivity() resets the timer', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(1000));
    await v.create(MNEMONIC, PASSWORD);
    vi.advanceTimersByTime(800);
    v.noteActivity(); // genuine user activity resets the countdown
    vi.advanceTimersByTime(800);
    expect(v.isUnlocked()).toBe(true);
    vi.advanceTimersByTime(300);
    expect(v.isUnlocked()).toBe(false);
  });

  it('noteActivity() is a no-op when locked (does not resurrect or throw)', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(1000));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    expect(() => v.noteActivity()).not.toThrow();
    expect(v.isUnlocked()).toBe(false);
  });

  it('autoLockMs=0 disables the timer', async () => {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    vi.advanceTimersByTime(1_000_000);
    expect(v.isUnlocked()).toBe(true);
  });

  it('rejects negative autoLockMs', () => {
    expect(() => new Vault(new InMemoryVaultStorage(), cfg(-1))).toThrow(
      RangeError,
    );
  });
}, 30_000);

describe('Vault — unlock throttle', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  async function lockedVault(): Promise<Vault> {
    const v = new Vault(new InMemoryVaultStorage(), cfg(0));
    await v.create(MNEMONIC, PASSWORD);
    v.lock();
    return v;
  }

  it('lets the first few wrong attempts through without a cooldown', async () => {
    const v = await lockedVault();
    for (let i = 0; i < 3; i++) {
      await expect(v.unlock('wrong password')).rejects.toThrow(InvalidPasswordError);
    }
    // Still no cooldown — the correct password unlocks right away.
    await v.unlock(PASSWORD);
    expect(v.isUnlocked()).toBe(true);
  });

  it('throttles once the free attempts are exhausted, then recovers after the cooldown', async () => {
    const v = await lockedVault();
    for (let i = 0; i < 4; i++) {
      await expect(v.unlock('wrong password')).rejects.toThrow(InvalidPasswordError);
    }
    // Inside the cooldown window: even the right password is refused fast.
    await expect(v.unlock(PASSWORD)).rejects.toThrow(UnlockThrottledError);
    // After the cooldown elapses it works again.
    vi.advanceTimersByTime(30_000);
    await v.unlock(PASSWORD);
    expect(v.isUnlocked()).toBe(true);
  });

  it('resets the failure counter after a successful unlock', async () => {
    const v = await lockedVault();
    for (let i = 0; i < 3; i++) {
      await expect(v.unlock('wrong password')).rejects.toThrow(InvalidPasswordError);
    }
    await v.unlock(PASSWORD); // success → counter reset
    v.lock();
    // Counter is back to zero, so three more wrong attempts stay "free".
    for (let i = 0; i < 3; i++) {
      await expect(v.unlock('wrong password')).rejects.toThrow(InvalidPasswordError);
    }
    await v.unlock(PASSWORD);
    expect(v.isUnlocked()).toBe(true);
  });
}, 30_000);

describe('Vault — app-data label binding', () => {
  it('binds the app-data key to the configured HKDF label', async () => {
    const storage = new InMemoryVaultStorage();
    const a = new Vault(storage, cfg(0));
    await a.create(MNEMONIC, PASSWORD);
    const blob = await a.sealData('address book');
    expect(await a.openData(blob)).toBe('address book');
    // The same seed under another label derives a different key.
    const b = new Vault(storage, { autoLockMs: 0, appDataInfo: 'other/app-data/v1' });
    await b.unlock(PASSWORD);
    await expect(b.openData(blob)).rejects.toThrow(AppDataError);
  });

  it('rejects an empty label', () => {
    expect(() => new Vault(new InMemoryVaultStorage(), { autoLockMs: 0, appDataInfo: '' })).toThrow(RangeError);
  });
});
