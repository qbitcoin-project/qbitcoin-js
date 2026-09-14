import { describe, expect, it } from 'vitest';
import { InMemoryVaultStorage } from './storage.js';

describe('InMemoryVaultStorage', () => {
  it('starts empty', async () => {
    const s = new InMemoryVaultStorage();
    expect(await s.read()).toBeNull();
  });

  it('reads back what it wrote', async () => {
    const s = new InMemoryVaultStorage();
    await s.write('hello');
    expect(await s.read()).toBe('hello');
  });

  it('overwrites on second write', async () => {
    const s = new InMemoryVaultStorage();
    await s.write('first');
    await s.write('second');
    expect(await s.read()).toBe('second');
  });

  it('clear() makes it empty', async () => {
    const s = new InMemoryVaultStorage();
    await s.write('something');
    await s.clear();
    expect(await s.read()).toBeNull();
  });

  it('clear() on empty is a no-op', async () => {
    const s = new InMemoryVaultStorage();
    await s.clear();
    expect(await s.read()).toBeNull();
  });
});

