/**
 * The persistence boundary. Implementations decide where the encrypted
 * blob actually lives. One Vault instance must own each storage location;
 * concurrent writers across instances or processes require host coordination.
 */
export interface VaultStorage {
  /** Return the stored blob, or `null` if nothing is stored. */
  read(): Promise<string | null>;

  /** Atomically replace the stored blob; on failure, preserve the old value. */
  write(blob: string): Promise<void>;

  /** Remove the stored blob if any (idempotent — `clear()` on empty is OK). */
  clear(): Promise<void>;
}

// ─── InMemoryVaultStorage — for tests ────────────────────────────────

/**
 * A storage backend that lives entirely in JS memory. Useful in tests
 * and in unusual environments where no persistent storage is available.
 * Not suitable for production — the data is lost when the JS context
 * is torn down.
 */
export class InMemoryVaultStorage implements VaultStorage {
  private blob: string | null = null;

  async read(): Promise<string | null> {
    return this.blob;
  }

  async write(blob: string): Promise<void> {
    this.blob = blob;
  }

  async clear(): Promise<void> {
    this.blob = null;
  }
}
