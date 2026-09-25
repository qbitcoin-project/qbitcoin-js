import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as crypto from '@qbtc/crypto';
import { InMemoryVaultStorage, InvalidPasswordError, UnlockThrottledError, Vault, WalletLockedError } from './index.js';
import { LEGACY } from './legacy.fixtures.js';

// Keep the KDF real at a small test-only cost. Existing lifecycle and
// compatibility suites exercise production parameters and historical blobs.
vi.mock('@qbtc/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof crypto>();
  return {
    ...actual,
    sealVault: vi.fn((plaintext: Uint8Array, password: string) => actual.sealVault(plaintext, password, {
      params: { m: 32, t: 1, p: 1, dkLen: 32 },
    })),
    unsealVault: vi.fn(actual.unsealVault),
  };
});

type Method = 'unlock' | 'revealMnemonic' | 'changePassword';
const METHODS: Method[] = ['unlock', 'revealMnemonic', 'changePassword'];
const CASES = [
  { method: 'unlock', locked: true },
  { method: 'revealMnemonic', locked: false },
  { method: 'changePassword', locked: false },
  { method: 'changePassword', locked: true },
] as const;
const NEXT_PASSWORD = 'another test password';
const instances: Vault[] = [];

function attempt(vault: Vault, method: Method, password: string): Promise<unknown> {
  return method === 'changePassword'
    ? vault.changePassword(password, NEXT_PASSWORD)
    : vault[method](password);
}

async function createdVault(locked = false) {
  const storage = new InMemoryVaultStorage();
  const vault = new Vault(storage, { autoLockMs: 0, appDataInfo: LEGACY.appDataInfo });
  instances.push(vault);
  await vault.create(LEGACY.mnemonic, LEGACY.password);
  if (locked) vault.lock();
  return { vault, storage };
}

async function wrongAttempts(vault: Vault, method: Method, count = 3) {
  for (let i = 0; i < count; i += 1) {
    await expect(attempt(vault, method, 'wrong password')).rejects.toThrow(InvalidPasswordError);
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
});
afterEach(() => {
  instances.splice(0).forEach((vault) => vault.lock());
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('shared password throttle', () => {
  it.each(CASES)('$method (locked=$locked) enforces exponential cooldowns before decryption', async ({ method, locked }) => {
    const { vault } = await createdVault(locked);
    await wrongAttempts(vault, method);
    for (const delay of [1000, 2000, 4000, 8000, 16_000, 30_000, 30_000]) {
      await wrongAttempts(vault, method, 1);
      const decryptions = vi.mocked(crypto.unsealVault).mock.calls.length;
      await expect(attempt(vault, method, LEGACY.password)).rejects.toMatchObject({
        name: 'UnlockThrottledError', retryAfterMs: delay,
      });
      vi.advanceTimersByTime(delay - 1);
      await expect(attempt(vault, method, 'wrong password')).rejects.toMatchObject({
        name: 'UnlockThrottledError', retryAfterMs: 1,
        message: 'Too many attempts. Try again in 1 second.',
      });
      expect(crypto.unsealVault).toHaveBeenCalledTimes(decryptions);
      vi.advanceTimersByTime(1);
    }
    await expect(attempt(vault, method, LEGACY.password)).resolves.toBe(
      method === 'revealMnemonic' ? LEGACY.mnemonic : undefined,
    );
  });

  it('shares failures and cooldowns across methods and lock transitions', async () => {
    const { vault } = await createdVault();
    await wrongAttempts(vault, 'revealMnemonic', 1);
    await wrongAttempts(vault, 'changePassword', 1);
    await wrongAttempts(vault, 'revealMnemonic', 1);
    vault.lock();
    await wrongAttempts(vault, 'unlock', 1);
    const decryptions = vi.mocked(crypto.unsealVault).mock.calls.length;
    await expect(vault.changePassword(LEGACY.password, NEXT_PASSWORD)).rejects.toThrow(UnlockThrottledError);
    await expect(vault.unlock(LEGACY.password)).rejects.toThrow(UnlockThrottledError);
    expect(crypto.unsealVault).toHaveBeenCalledTimes(decryptions);
    vi.advanceTimersByTime(1000);
    await vault.changePassword(LEGACY.password, NEXT_PASSWORD);
    expect(vault.isUnlocked()).toBe(false);
    await vault.unlock(NEXT_PASSWORD);
    expect(await vault.revealMnemonic(NEXT_PASSWORD)).toBe(LEGACY.mnemonic);
  });

  it('an already-unlocked unlock and activity do not reset failures or cooldowns', async () => {
    const { vault } = await createdVault();
    await wrongAttempts(vault, 'revealMnemonic');
    await vault.unlock(LEGACY.password);
    await wrongAttempts(vault, 'changePassword', 1);
    await vault.unlock('not checked while unlocked');
    vault.noteActivity();
    await expect(vault.revealMnemonic(LEGACY.password)).rejects.toMatchObject({ retryAfterMs: 1000 });
    vault.lock();
    vault.lock();
    await expect(vault.unlock(LEGACY.password)).rejects.toThrow(UnlockThrottledError);
  });

  it.each(CASES)('$method (locked=$locked) resets failures after an actual successful password check', async ({ method, locked }) => {
    const { vault } = await createdVault(locked);
    await wrongAttempts(vault, method);
    await attempt(vault, method, LEGACY.password);
    const password = method === 'changePassword' ? NEXT_PASSWORD : LEGACY.password;
    await wrongAttempts(vault, 'changePassword');
    await expect(vault.changePassword(password, NEXT_PASSWORD)).resolves.toBeUndefined();
  });

  it('queued mixed requests recheck the cooldown before starting another KDF', async () => {
    const { vault } = await createdVault();
    const results = await Promise.allSettled(Array.from({ length: 8 }, (_, i) =>
      attempt(vault, i % 2 === 0 ? 'revealMnemonic' : 'changePassword', 'wrong password'),
    ));
    for (const [i, result] of results.entries()) {
      expect(result.status).toBe('rejected');
      if (result.status === 'rejected') {
        expect(result.reason).toBeInstanceOf(i < 4 ? InvalidPasswordError : UnlockThrottledError);
      }
    }
    expect(crypto.unsealVault).toHaveBeenCalledTimes(4);
    await expect(vault.revealMnemonic(LEGACY.password)).rejects.toMatchObject({ retryAfterMs: 1000 });
  });

  it.each(METHODS)('%s counts a failed in-flight check even if a lock cancels its session', async (method) => {
    const { vault } = await createdVault();
    await wrongAttempts(vault, 'changePassword');
    if (method === 'unlock') vault.lock();
    const entered = deferred<void>();
    const result = deferred<Uint8Array>();
    vi.mocked(crypto.unsealVault).mockImplementationOnce(() => {
      entered.resolve();
      return result.promise;
    });
    const pending = expect(attempt(vault, method, 'wrong password')).rejects.toThrow(InvalidPasswordError);
    await entered.promise;
    vault.lock();
    result.reject(new crypto.VaultAuthError());
    await pending;
    await expect(vault.changePassword(LEGACY.password, NEXT_PASSWORD)).rejects.toMatchObject({ retryAfterMs: 1000 });
  });

  it.each(METHODS)('%s withholds and wipes a cancelled success without resetting failures', async (method) => {
    const { vault } = await createdVault();
    await wrongAttempts(vault, 'changePassword');
    if (method === 'unlock') vault.lock();
    const entered = deferred<void>();
    const result = deferred<Uint8Array>();
    vi.mocked(crypto.unsealVault).mockImplementationOnce(() => {
      entered.resolve();
      return result.promise;
    });
    const pending = expect(attempt(vault, method, LEGACY.password)).rejects.toThrow(WalletLockedError);
    await entered.promise;
    const queued = expect(vault.changePassword('wrong password', NEXT_PASSWORD)).rejects.toThrow(WalletLockedError);
    vault.lock();
    const bytes = new TextEncoder().encode(LEGACY.mnemonic);
    result.resolve(bytes);
    await Promise.all([pending, queued]);
    expect(bytes.every((byte) => byte === 0)).toBe(true);
    expect(crypto.unsealVault).toHaveBeenCalledTimes(4);
    await wrongAttempts(vault, 'changePassword', 1);
    await expect(vault.unlock(LEGACY.password)).rejects.toMatchObject({ retryAfterMs: 1000 });
  });

  it.each(METHODS)('%s does not count or reset failures for an unrelated decryption error', async (method) => {
    const { vault } = await createdVault(method === 'unlock');
    await wrongAttempts(vault, 'changePassword');
    const error = new Error('crypto unavailable');
    vi.mocked(crypto.unsealVault).mockRejectedValueOnce(error);
    await expect(attempt(vault, method, LEGACY.password)).rejects.toBe(error);
    await wrongAttempts(vault, 'changePassword', 1);
    await expect(vault.changePassword(LEGACY.password, NEXT_PASSWORD)).rejects.toMatchObject({ retryAfterMs: 1000 });
  });

  it('does not count or reset failures for storage and format errors', async () => {
    const { vault, storage } = await createdVault();
    await wrongAttempts(vault, 'revealMnemonic');
    const error = new Error('storage unavailable');
    vi.spyOn(storage, 'read').mockRejectedValueOnce(error);
    await expect(vault.changePassword(LEGACY.password, NEXT_PASSWORD)).rejects.toBe(error);
    vi.spyOn(storage, 'read').mockResolvedValueOnce('not JSON');
    await expect(vault.revealMnemonic(LEGACY.password)).rejects.toThrow(crypto.VaultFormatError);
    expect(crypto.unsealVault).toHaveBeenCalledTimes(3);
    await wrongAttempts(vault, 'changePassword', 1);
    await expect(vault.revealMnemonic(LEGACY.password)).rejects.toMatchObject({ retryAfterMs: 1000 });
  });

  it('resets after a verified password even if saving the new password fails', async () => {
    const { vault, storage } = await createdVault();
    await wrongAttempts(vault, 'revealMnemonic');
    vi.spyOn(storage, 'write').mockRejectedValueOnce(new Error('disk full'));
    await expect(vault.changePassword(LEGACY.password, NEXT_PASSWORD)).rejects.toThrow('disk full');
    await wrongAttempts(vault, 'changePassword');
    expect(await vault.revealMnemonic(LEGACY.password)).toBe(LEGACY.mnemonic);
  });

  it('does not reset the throttle when destruction fails to clear storage', async () => {
    const { vault, storage } = await createdVault(true);
    await wrongAttempts(vault, 'unlock', 4);
    vi.spyOn(storage, 'clear').mockRejectedValueOnce(new Error('storage unavailable'));
    await expect(vault.destroy()).rejects.toThrow('storage unavailable');
    await expect(vault.unlock(LEGACY.password)).rejects.toMatchObject({ retryAfterMs: 1000 });
  });

  it('resets after successful destruction, including failures from earlier in-flight checks', async () => {
    const { vault } = await createdVault(true);
    const entered = deferred<void>();
    const result = deferred<Uint8Array>();
    vi.mocked(crypto.unsealVault).mockImplementationOnce(() => {
      entered.resolve();
      return result.promise;
    });
    const pending = expect(vault.unlock('wrong password')).rejects.toThrow(InvalidPasswordError);
    await entered.promise;
    const destruction = vault.destroy();
    result.reject(new crypto.VaultAuthError());
    await pending;
    await destruction;
    await vault.create(LEGACY.mnemonic, LEGACY.password);
    vault.lock();
    await wrongAttempts(vault, 'unlock');
    await expect(vault.unlock(LEGACY.password)).resolves.toBeUndefined();
  });
});
