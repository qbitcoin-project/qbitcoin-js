// Pin of the shipped Falcon-512 WASM binary.
//
// The binary is committed (and published in the npm tarball) rather than
// rebuilt on install; this pin guarantees that what ships is exactly the
// artifact produced by the reproducible build in tools/falcon512-wasm
// (see its README for the toolchain versions). If the binary is ever
// rebuilt, verify the rebuild reproduces THIS hash before updating it —
// a hash change without a deliberate toolchain bump means the artifact
// was tampered with or corrupted.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { toHex } from './encoding/hex.js';
import { sha256 } from './hashes.js';

const WASM_SHA256 =
  '38031dca9ffc1e0d814f2a67a8c544c02fab6b7d3cfa419c4a06fafa877fbac1';

describe('falcon512.wasm artifact', () => {
  it('matches the pinned SHA-256', async () => {
    const path = fileURLToPath(new URL('../wasm/falcon512.wasm', import.meta.url));
    const bytes = await readFile(path);
    expect(toHex(sha256(bytes))).toBe(WASM_SHA256);
  });
});
