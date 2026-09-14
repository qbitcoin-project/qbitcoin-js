import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as crypto from '@qbtc/crypto';
import { InMemoryVaultStorage, InvalidPasswordError, UnlockThrottledError, Vault, VaultExistsError, WalletLockedError } from './index.js';
import { LEGACY } from './legacy.fixtures.js';

// Exercise asynchronous lifecycle behavior with real encryption at a small
// test-only cost. The original lifecycle suite uses production defaults.
vi.mock('@qbtc/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof crypto>();
  return {
    ...actual,
    sealVault: vi.fn((plaintext: Uint8Array, password: string) => actual.sealVault(plaintext, password, {
      params: { m: 32, t: 1, p: 1, dkLen: 32 },
    })),
    unsealVault: vi.fn(actual.unsealVault),
    sealAppData: vi.fn(actual.sealAppData),
    openAppData: vi.fn(actual.openAppData),
  };
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

const instances: Vault[] = [];
function makeVault(storage = new InMemoryVaultStorage()) {
  const vault = new Vault(storage, { autoLockMs: 0, appDataInfo: LEGACY.appDataInfo });
  instances.push(vault);
  return { vault, storage };
}

async function createdVault() {
  const result = makeVault();
  await result.vault.create(LEGACY.mnemonic, LEGACY.password);
  return result;
}

beforeEach(() => vi.clearAllMocks());
afterEach(() => {
  instances.splice(0).forEach((vault) => vault.lock());
  vi.restoreAllMocks();
});

describe('concurrent lifecycle operations', () => {
  it('never overwrites a vault when create requests arrive together', async () => {
    const { vault } = makeVault();
    const first = vault.create(LEGACY.mnemonic, LEGACY.password);
    const second = vault.create(LEGACY.mnemonic, 'other password');
    await expect(first).resolves.toBeUndefined();
    await expect(second).rejects.toThrow(VaultExistsError);
    expect(await vault.revealMnemonic(LEGACY.password)).toBe(LEGACY.mnemonic);
  });

  it('lock cancels both in-flight and queued unlocks', async () => {
    const { vault } = await createdVault();
    vault.lock();
    const entered = deferred<void>();
    const decrypted = deferred<Uint8Array>();
    vi.mocked(crypto.unsealVault).mockImplementationOnce(() => {
      entered.resolve();
      return decrypted.promise;
    });
    const first = vault.unlock(LEGACY.password);
    const second = vault.unlock(LEGACY.password);
    const assertions = Promise.all([
      expect(first).rejects.toThrow(WalletLockedError),
      expect(second).rejects.toThrow(WalletLockedError),
    ]);
    await entered.promise;
    vault.lock();
    const bytes = new TextEncoder().encode(LEGACY.mnemonic);
    decrypted.resolve(bytes);
    await assertions;
    expect(bytes.every((n) => n === 0)).toBe(true);
    expect(vault.isUnlocked()).toBe(false);
    // Cancellation must not poison the queue for a later explicit unlock.
    await vault.unlock(LEGACY.password);
    expect(vault.isUnlocked()).toBe(true);
  });

  it('destroy waits for a started write and leaves no resurrected blob', async () => {
    const { vault, storage } = makeVault();
    const entered = deferred<void>();
    const release = deferred<void>();
    const write = storage.write.bind(storage);
    vi.spyOn(storage, 'write').mockImplementationOnce(async (blob) => {
      entered.resolve();
      await release.promise;
      await write(blob);
    });
    const creation = vault.create(LEGACY.mnemonic, LEGACY.password);
    const assertion = expect(creation).rejects.toThrow(WalletLockedError);
    await entered.promise;
    const destruction = vault.destroy();
    expect(vault.isUnlocked()).toBe(false);
    release.resolve();
    await assertion;
    await destruction;
    expect(await storage.read()).toBeNull();
    expect(await vault.getStatus()).toBe('empty');
  });

  it('serializes password changes so the second sees the first password', async () => {
    const { vault } = await createdVault();
    await Promise.all([
      vault.changePassword(LEGACY.password, 'second'),
      vault.changePassword('second', 'third'),
    ]);
    expect(await vault.revealMnemonic('third')).toBe(LEGACY.mnemonic);
    await expect(vault.revealMnemonic('second')).rejects.toThrow(InvalidPasswordError);
  });

  it('does not return a mnemonic after the vault is locked during decryption', async () => {
    const { vault } = await createdVault();
    const entered = deferred<void>();
    const decrypted = deferred<Uint8Array>();
    vi.mocked(crypto.unsealVault).mockImplementationOnce(() => {
      entered.resolve();
      return decrypted.promise;
    });
    const reveal = vault.revealMnemonic(LEGACY.password);
    const assertion = expect(reveal).rejects.toThrow(WalletLockedError);
    await entered.promise;
    vault.lock();
    const bytes = new TextEncoder().encode(LEGACY.mnemonic);
    decrypted.resolve(bytes);
    await assertion;
    expect(bytes.every((n) => n === 0)).toBe(true);
  });

  it('counts a wrong password toward the throttle even when a lock lands mid-attempt', async () => {
    const { vault } = await createdVault();
    vault.lock();
    // Three free attempts, then the cooldown — each attempt interleaved with
    // a lock() while the KDF is running, the way a UI closing on error would.
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const entered = deferred<void>();
      let fail!: (reason: unknown) => void;
      vi.mocked(crypto.unsealVault).mockImplementationOnce(() => {
        entered.resolve();
        return new Promise<Uint8Array>((_, reject) => { fail = reject; });
      });
      const unlocking = vault.unlock('wrong password');
      const assertion = expect(unlocking).rejects.toThrow(InvalidPasswordError);
      await entered.promise;
      vault.lock();
      fail(new crypto.VaultAuthError());
      await assertion;
    }
    await expect(vault.unlock(LEGACY.password)).rejects.toThrow(UnlockThrottledError);
  });

  it('returns ciphertext sealed before a lock instead of discarding it', async () => {
    const { vault } = await createdVault();
    const actual = await vi.importActual<typeof crypto>('@qbtc/crypto');
    const release = deferred<void>();
    vi.mocked(crypto.sealAppData).mockImplementationOnce(async (key, bytes) => {
      const blob = await actual.sealAppData(key, bytes);
      await release.promise;
      return blob;
    });
    const sealing = vault.sealData('address book');
    vault.lock();
    release.resolve();
    const blob = await sealing;
    await vault.unlock(LEGACY.password);
    expect(await vault.openData(blob)).toBe('address book');
  });

  it('does not return app data after a lock and wipes the decrypted buffer', async () => {
    const { vault } = await createdVault();
    const decrypted = deferred<Uint8Array>();
    vi.mocked(crypto.openAppData).mockReturnValueOnce(decrypted.promise);
    const opening = vault.openData('pending encrypted data');
    const assertion = expect(opening).rejects.toThrow(WalletLockedError);
    vault.lock();
    const bytes = new TextEncoder().encode('private metadata');
    decrypted.resolve(bytes);
    await assertion;
    expect(bytes.every((n) => n === 0)).toBe(true);
  });
});

describe('failure handling', () => {
  it('wipes the mnemonic buffer when storage rejects creation and permits a retry', async () => {
    const { vault, storage } = makeVault();
    vi.spyOn(storage, 'write').mockRejectedValueOnce(new Error('disk full'));
    await expect(vault.create(LEGACY.mnemonic, LEGACY.password)).rejects.toThrow('disk full');
    const bytes = vi.mocked(crypto.sealVault).mock.calls[0][0];
    expect(bytes.every((n) => n === 0)).toBe(true);
    expect(vault.isUnlocked()).toBe(false);
    await vault.create(LEGACY.mnemonic, LEGACY.password);
    expect(vault.isUnlocked()).toBe(true);
  });

  it('wipes the decrypted mnemonic if password re-encryption fails', async () => {
    const { vault } = await createdVault();
    vi.mocked(crypto.sealVault).mockRejectedValueOnce(new Error('encryption failed'));
    await expect(vault.changePassword(LEGACY.password, 'next')).rejects.toThrow('encryption failed');
    const bytes = vi.mocked(crypto.sealVault).mock.calls.at(-1)![0];
    expect(bytes.every((n) => n === 0)).toBe(true);
    expect(await vault.revealMnemonic(LEGACY.password)).toBe(LEGACY.mnemonic);
  });

  it('still opens a legacy vault when the KDF upgrade cannot be stored', async () => {
    const { vault, storage } = makeVault();
    const original = JSON.stringify(LEGACY.rows[0].scrypt);
    await storage.write(original);
    vi.spyOn(storage, 'write').mockRejectedValueOnce(new Error('disk full'));
    await vault.unlock(LEGACY.password);
    expect(vault.isUnlocked()).toBe(true);
    expect(await storage.read()).toBe(original);
  });

  it.each(['null', '[]', '{}', 'not JSON', '{"v":1,"kdf":"argon2id","salt":"","iv":"","ciphertext":"","kdfParams":{"m":-1}}'])('rejects malformed storage before calling the KDF: %s', async (blob) => {
    const { vault, storage } = makeVault();
    await storage.write(blob);
    await expect(vault.unlock(LEGACY.password)).rejects.toThrow(crypto.VaultFormatError);
    expect(crypto.unsealVault).not.toHaveBeenCalled();
  });

  it.each([NaN, Infinity, -Infinity, 2 ** 31])('rejects an invalid timeout: %s', (autoLockMs) => {
    expect(() => new Vault(new InMemoryVaultStorage(), { autoLockMs, appDataInfo: LEGACY.appDataInfo })).toThrow(RangeError);
  });
});
