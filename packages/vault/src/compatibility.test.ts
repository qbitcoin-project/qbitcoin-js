import { describe, expect, it } from 'vitest';
import { unsealVault, type VaultBlob } from '@qbtc/crypto';
import { InMemoryVaultStorage, UnlockThrottledError, Vault } from './index.js';
import { LEGACY } from './legacy.fixtures.js';

describe.each(LEGACY.rows)('existing $producer data', (fixture) => {
  it.each(['argon2id', 'scrypt'] as const)('opens %s data and preserves the seed and application data', async (kdf) => {
    const storage = new InMemoryVaultStorage();
    await storage.write(JSON.stringify(fixture[kdf]));
    const vault = new Vault(storage, { autoLockMs: 0, appDataInfo: LEGACY.appDataInfo });
    // The fixture uses the Angstrom sign; the reader uses its NFKC equivalent.
    const password = LEGACY.password.normalize('NFKC');
    await vault.unlock(password);
    try {
      expect(await vault.revealMnemonic(password)).toBe(LEGACY.mnemonic);
      expect(Buffer.from(vault.getMasterKey().privateKey!).toString('hex')).toBe(fixture.masterPrivateKey);
      expect(await vault.openData(fixture.appData)).toBe(LEGACY.plaintext);
      expect(JSON.parse((await storage.read())!).kdf).toBe('argon2id');
      await vault.changePassword(password, 'replacement password');
      const blob = JSON.parse((await storage.read())!) as VaultBlob;
      const plaintext = await unsealVault(blob, 'replacement password');
      expect(new TextDecoder().decode(plaintext)).toBe(LEGACY.mnemonic);
      plaintext.fill(0);
      expect(await vault.openData(fixture.appData)).toBe(LEGACY.plaintext);
    } finally {
      vault.lock();
    }
  });
});

it('exports the throttle error through the package entry point', () => {
  expect(new UnlockThrottledError(1000).retryAfterMs).toBe(1000);
});
