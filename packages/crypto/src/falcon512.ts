// Falcon-512 — TypeScript wrapper around the WASM module built in
// `tools/falcon512-wasm/`.
//
// Memory model: every call allocates ad-hoc with Module._malloc, copies
// bytes in/out via HEAPU8, and frees in a `finally`. The WASM linear
// memory is shared across calls but each call is isolated — no global
// state survives between calls.
//
// Concurrency note: WASM module is single-threaded. Concurrent callers
// take turns; if you sign two transactions in parallel, the second
// awaits the first. For the wallet's load this is fine — sign/verify
// take milliseconds.
//

/** Length of a Falcon-512 private key in bytes. */
export const FALCON512_PRIVATE_KEY_BYTES = 1281;

/** Length of a Falcon-512 public key in bytes. */
export const FALCON512_PUBLIC_KEY_BYTES = 897;

/** Maximum length of a Falcon-512 signature in bytes. Actual signatures
 *  are usually 600–666 bytes; allocate this much and slice down. */
export const FALCON512_SIG_MAX_BYTES = 666;

/** Length of the keygen seed in bytes (PQClean's inner_shake256 seed). */
export const FALCON512_SEED_BYTES = 48;

/** A Falcon-512 keypair. Held as raw bytes; no leaky in-memory state. */
export interface Falcon512Keypair {
  /** 897-byte public key. */
  readonly publicKey: Uint8Array;
  /** 1281-byte private key. */
  readonly privateKey: Uint8Array;
}

/**
 * Raised when the WASM module fails to load — for example because the
 * `.wasm` file is missing from `packages/crypto/wasm/`. Build it by
 * running `tools/falcon512-wasm/build.sh`.
 */
export class Falcon512NotBuiltError extends Error {
  override readonly name = 'Falcon512NotBuiltError';
  constructor(cause?: unknown) {
    super(
      'Falcon-512 WASM module failed to load. Run tools/falcon512-wasm/build.sh ' +
        'and commit packages/crypto/wasm/falcon512.{wasm,mjs}.',
      cause !== undefined ? { cause } : undefined,
    );
  }
}

// ─── WASM module loading ─────────────────────────────────────────────

/**
 * Minimal type for the Emscripten-generated module. We declare only what
 * we use — Emscripten's default output has dozens of fields, most
 * unused.
 */
interface FalconModule {
  HEAPU8: Uint8Array;
  _malloc(size: number): number;
  _free(ptr: number): void;
  _wallet_falcon512_keygen_from_seed(
    seedPtr: number,
    seedLen: number,
    pkPtr: number,
    skPtr: number,
  ): number;
  _wallet_falcon512_sign_detached(
    msgPtr: number,
    msgLen: number,
    skPtr: number,
    sigOutPtr: number,
    sigLenOutPtr: number,
  ): number;
  _wallet_falcon512_verify(
    sigPtr: number,
    sigLen: number,
    msgPtr: number,
    msgLen: number,
    pkPtr: number,
  ): number;
}

let modulePromise: Promise<FalconModule> | null = null;

/** Supplies the raw `.wasm` bytes. */
export type Falcon512WasmSource = () => Promise<Uint8Array>;

let wasmSource: Falcon512WasmSource | null = null;

/**
 * Override how the Falcon-512 `.wasm` bytes are obtained.
 *
 * The default loader fetches the `.wasm` relative to this module (works for
 * Node tests and simple bundles), but bundled browser extensions place assets
 * unpredictably — a packaged extension must point the loader at its own
 * resource URL (e.g. `browser.runtime.getURL('falcon512.wasm')`) so the WASM
 * loads in the background service worker too. Call this once at startup,
 * before any sign/verify/keygen. Resets the cached module so a prior failed
 * load is retried with the new source.
 */
export function setFalcon512WasmSource(source: Falcon512WasmSource): void {
  wasmSource = source;
  modulePromise = null;
}

async function loadModule(): Promise<FalconModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      try {
        // Dynamic import so vitest and bundlers can resolve the .mjs
        // glue file. The generated Emscripten glue is an async factory
        // that returns a Promise<Module>.
        const mod: {
          default: (config?: {
            wasmBinary?: Uint8Array;
          }) => Promise<FalconModule>;
          // @ts-expect-error — Emscripten-generated .mjs has no .d.ts
        } = await import('../wasm/falcon512.mjs');

        // The Emscripten glue (ENVIRONMENT='web,worker') auto-locates the
        // .wasm via `new URL("falcon512.wasm", import.meta.url)` relative to
        // the GLUE file and fetches it. In a bundled MV3 service worker that
        // URL doesn't resolve to the emitted asset, so the fetch fails and
        // keygen never runs. We instead resolve the .wasm from THIS module
        // with `new URL('../wasm/falcon512.wasm', import.meta.url)` — a
        // pattern the bundler rewrites to the correct hashed asset URL in
        // every context (popup, content script, service worker) — fetch the
        // bytes ourselves, and hand them in as `wasmBinary` so Emscripten
        // never has to locate or fetch anything. Node test runners use
        // `file://` URLs that `fetch` can't read, so there we read the file.
        const config: { wasmBinary?: Uint8Array } = {};
        const isNode =
          typeof process !== 'undefined' &&
          process.versions != null &&
          process.versions.node != null;
        if (wasmSource) {
          // Caller-supplied source (e.g. the extension points us at its own
          // packaged resource URL — the only reliable location in a bundled
          // service worker).
          config.wasmBinary = await wasmSource();
        } else if (isNode) {
          // Specifiers are built at runtime: browser bundlers resolve literal
          // dynamic imports, and this branch is Node-only.
          const nodeFs = 'node:fs/promises';
          const nodeUrl = 'node:url';
          const [fs, url] = await Promise.all([
            import(/* @vite-ignore */ nodeFs) as Promise<typeof import('node:fs/promises')>,
            import(/* @vite-ignore */ nodeUrl) as Promise<typeof import('node:url')>,
          ]);
          const wasmUrl = new URL('../wasm/falcon512.wasm', import.meta.url);
          config.wasmBinary = new Uint8Array(
            await fs.readFile(url.fileURLToPath(wasmUrl)),
          );
        } else {
          // Default browser fallback: fetch relative to this module. Works in
          // simple bundles; bundled extensions should call
          // setFalcon512WasmSource() instead (see above).
          const wasmUrl = new URL('../wasm/falcon512.wasm', import.meta.url);
          const resp = await fetch(wasmUrl);
          if (!resp.ok) {
            throw new Error(
              `Falcon-512 .wasm fetch failed: ${resp.status} ${resp.url}`,
            );
          }
          config.wasmBinary = new Uint8Array(await resp.arrayBuffer());
        }

        return await mod.default(config);
      } catch (e) {
        // Reset so a retry can be attempted (e.g., after the .wasm file
        // is finally built).
        modulePromise = null;
        throw new Falcon512NotBuiltError(e);
      }
    })();
  }
  return modulePromise;
}

// ─── Public API ──────────────────────────────────────────────────────

/**
 * Deterministically derive a Falcon-512 keypair from a 48-byte seed.
 *
 * The seed comes from our HKDF-based PQ-derivation scheme. PQClean's internal SHAKE256 PRNG is
 * initialized with this seed, after which keygen is fully deterministic.
 *
 * Returns the same `(pk, sk)` for the same input.
 */
export async function falcon512KeygenFromSeed(
  seed: Uint8Array,
): Promise<Falcon512Keypair> {
  if (seed.length !== FALCON512_SEED_BYTES) {
    throw new RangeError(
      `Falcon-512 seed must be ${FALCON512_SEED_BYTES} bytes, got ${seed.length}`,
    );
  }
  const M = await loadModule();

  const seedPtr = M._malloc(seed.length);
  const pkPtr = M._malloc(FALCON512_PUBLIC_KEY_BYTES);
  const skPtr = M._malloc(FALCON512_PRIVATE_KEY_BYTES);
  try {
    M.HEAPU8.set(seed, seedPtr);
    const rc = M._wallet_falcon512_keygen_from_seed(
      seedPtr,
      seed.length,
      pkPtr,
      skPtr,
    );
    if (rc !== 0) {
      throw new Error(`Falcon-512 keygen failed with code ${rc}`);
    }
    return {
      publicKey: M.HEAPU8.slice(pkPtr, pkPtr + FALCON512_PUBLIC_KEY_BYTES),
      privateKey: M.HEAPU8.slice(skPtr, skPtr + FALCON512_PRIVATE_KEY_BYTES),
    };
  } finally {
    M._free(seedPtr);
    M._free(pkPtr);
    M._free(skPtr);
  }
}

/**
 * Produce a detached Falcon-512 signature for `message` using
 * `privateKey`.
 *
 * Falcon signing is intrinsically randomized — two signatures of the
 * same message under the same key WILL differ. Both verify against the
 * same public key. This is by design (cryptographic property of the
 * algorithm); don't try to make it deterministic.
 */
export async function falcon512Sign(
  message: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  if (privateKey.length !== FALCON512_PRIVATE_KEY_BYTES) {
    throw new RangeError(
      `Falcon-512 private key must be ${FALCON512_PRIVATE_KEY_BYTES} bytes, got ${privateKey.length}`,
    );
  }
  const M = await loadModule();

  const msgPtr = M._malloc(message.length || 1);
  const skPtr = M._malloc(privateKey.length);
  const sigPtr = M._malloc(FALCON512_SIG_MAX_BYTES);
  const sigLenPtr = M._malloc(4); // size_t = uint32 on wasm32
  try {
    if (message.length > 0) {
      M.HEAPU8.set(message, msgPtr);
    }
    M.HEAPU8.set(privateKey, skPtr);
    const rc = M._wallet_falcon512_sign_detached(
      msgPtr,
      message.length,
      skPtr,
      sigPtr,
      sigLenPtr,
    );
    if (rc !== 0) {
      throw new Error(`Falcon-512 sign failed with code ${rc}`);
    }
    // Read the actual signature length (Falcon signatures vary 600-666 B).
    const sigLen = new DataView(
      M.HEAPU8.buffer,
      M.HEAPU8.byteOffset,
      M.HEAPU8.byteLength,
    ).getUint32(sigLenPtr, true);
    return M.HEAPU8.slice(sigPtr, sigPtr + sigLen);
  } finally {
    M._free(msgPtr);
    M._free(skPtr);
    M._free(sigPtr);
    M._free(sigLenPtr);
  }
}

/**
 * Verify a Falcon-512 signature.
 *
 * Returns `true` iff `signature` is a valid Falcon-512 signature of
 * `message` under `publicKey`. Never throws — safe to call on
 * adversarial input. Wrong-sized arguments simply return `false`.
 */
export async function falcon512Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== FALCON512_PUBLIC_KEY_BYTES) return false;
  if (signature.length === 0 || signature.length > FALCON512_SIG_MAX_BYTES) {
    return false;
  }

  let M: FalconModule;
  try {
    M = await loadModule();
  } catch {
    return false;
  }

  const sigPtr = M._malloc(signature.length);
  const msgPtr = M._malloc(message.length || 1);
  const pkPtr = M._malloc(publicKey.length);
  try {
    M.HEAPU8.set(signature, sigPtr);
    if (message.length > 0) {
      M.HEAPU8.set(message, msgPtr);
    }
    M.HEAPU8.set(publicKey, pkPtr);
    const rc = M._wallet_falcon512_verify(
      sigPtr,
      signature.length,
      msgPtr,
      message.length,
      pkPtr,
    );
    return rc === 0;
  } finally {
    M._free(sigPtr);
    M._free(msgPtr);
    M._free(pkPtr);
  }
}

/** True if the WASM module has been loaded and is ready for use. */
export function falcon512IsReady(): boolean {
  return modulePromise !== null;
}
