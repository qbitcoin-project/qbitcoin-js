import { describe, expect, it } from 'vitest';
import {
  FALCON512_PRIVATE_KEY_BYTES,
  FALCON512_PUBLIC_KEY_BYTES,
  FALCON512_SEED_BYTES,
  FALCON512_SIG_MAX_BYTES,
  falcon512IsReady,
  falcon512KeygenFromSeed,
  falcon512Sign,
  falcon512Verify,
} from './falcon512';
import { decodeBase58Check } from './encoding/base58check';
import { fromHex, toHex } from './encoding/hex';
import { hash256 } from './hashes';

describe('Falcon-512 constants — match PQClean sizes', () => {
  it('public key is 897 bytes', () => {
    expect(FALCON512_PUBLIC_KEY_BYTES).toBe(897);
  });

  it('private key is 1281 bytes', () => {
    expect(FALCON512_PRIVATE_KEY_BYTES).toBe(1281);
  });

  it('max signature is 666 bytes', () => {
    expect(FALCON512_SIG_MAX_BYTES).toBe(666);
  });

  it('seed is 48 bytes', () => {
    expect(FALCON512_SEED_BYTES).toBe(48);
  });
});

// ─── End-to-end self-tests against our own WASM module ──────────────

describe('falcon512KeygenFromSeed', () => {
  const ZERO_SEED = new Uint8Array(FALCON512_SEED_BYTES);
  const SEED_A = new Uint8Array(FALCON512_SEED_BYTES).fill(0xaa);
  const SEED_B = new Uint8Array(FALCON512_SEED_BYTES).fill(0xbb);

  it('produces keys of the right size', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(ZERO_SEED);
    expect(publicKey.length).toBe(FALCON512_PUBLIC_KEY_BYTES);
    expect(privateKey.length).toBe(FALCON512_PRIVATE_KEY_BYTES);
  });

  it('is deterministic — same seed gives same keys', async () => {
    const a = await falcon512KeygenFromSeed(SEED_A);
    const b = await falcon512KeygenFromSeed(SEED_A);
    expect(toHex(a.publicKey)).toBe(toHex(b.publicKey));
    expect(toHex(a.privateKey)).toBe(toHex(b.privateKey));
  });

  it('different seeds give different keys', async () => {
    const a = await falcon512KeygenFromSeed(SEED_A);
    const b = await falcon512KeygenFromSeed(SEED_B);
    expect(toHex(a.publicKey)).not.toBe(toHex(b.publicKey));
    expect(toHex(a.privateKey)).not.toBe(toHex(b.privateKey));
  });

  it('rejects wrong-sized seed', async () => {
    await expect(
      falcon512KeygenFromSeed(new Uint8Array(47)),
    ).rejects.toThrow(RangeError);
    await expect(
      falcon512KeygenFromSeed(new Uint8Array(49)),
    ).rejects.toThrow(RangeError);
  });
});

describe('falcon512Sign + falcon512Verify roundtrip', () => {
  it('signs and verifies a short message', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0x11),
    );
    const msg = new TextEncoder().encode('hello falcon');
    const sig = await falcon512Sign(msg, privateKey);
    expect(sig.length).toBeGreaterThan(40);
    expect(sig.length).toBeLessThanOrEqual(FALCON512_SIG_MAX_BYTES);
    expect(await falcon512Verify(sig, msg, publicKey)).toBe(true);
  });

  it('signs and verifies a large message', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0x22),
    );
    const msg = new Uint8Array(10_000).map((_, i) => i & 0xff);
    const sig = await falcon512Sign(msg, privateKey);
    expect(await falcon512Verify(sig, msg, publicKey)).toBe(true);
  });

  it('signs and verifies an empty message', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0x33),
    );
    const sig = await falcon512Sign(new Uint8Array(0), privateKey);
    expect(await falcon512Verify(sig, new Uint8Array(0), publicKey)).toBe(true);
  });

  it('two signatures of the same message differ (Falcon is randomized)', async () => {
    const { privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0x44),
    );
    const msg = new TextEncoder().encode('x');
    const a = await falcon512Sign(msg, privateKey);
    const b = await falcon512Sign(msg, privateKey);
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('falcon512Verify — failure modes', () => {
  it('rejects wrong public key', async () => {
    const alice = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0xa1),
    );
    const bob = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0xb2),
    );
    const msg = new TextEncoder().encode('msg');
    const sig = await falcon512Sign(msg, alice.privateKey);
    expect(await falcon512Verify(sig, msg, bob.publicKey)).toBe(false);
  });

  it('rejects tampered message', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0x55),
    );
    const sig = await falcon512Sign(new TextEncoder().encode('a'), privateKey);
    expect(
      await falcon512Verify(sig, new TextEncoder().encode('b'), publicKey),
    ).toBe(false);
  });

  it('rejects tampered signature', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0x66),
    );
    const msg = new TextEncoder().encode('m');
    const sig = await falcon512Sign(msg, privateKey);
    const tampered = new Uint8Array(sig);
    tampered[10] = (tampered[10]! ^ 1) & 0xff;
    expect(await falcon512Verify(tampered, msg, publicKey)).toBe(false);
  });

  it('returns false on wrong-sized pubkey without throwing', async () => {
    expect(
      await falcon512Verify(
        new Uint8Array(666),
        new Uint8Array(0),
        new Uint8Array(100),
      ),
    ).toBe(false);
  });

  it('returns false on empty signature without throwing', async () => {
    expect(
      await falcon512Verify(
        new Uint8Array(0),
        new Uint8Array(0),
        new Uint8Array(FALCON512_PUBLIC_KEY_BYTES),
      ),
    ).toBe(false);
  });

  it('returns false on oversized signature without throwing', async () => {
    expect(
      await falcon512Verify(
        new Uint8Array(FALCON512_SIG_MAX_BYTES + 1),
        new Uint8Array(0),
        new Uint8Array(FALCON512_PUBLIC_KEY_BYTES),
      ),
    ).toBe(false);
  });
});

// ─── Cross-implementation compatibility check ────────────────────────
//
// Test vector from the node's Falcon test suite — a WIF-encoded
// Falcon-512 private key, fixed sign_data, and the hex of a signature
// produced by the node's Falcon signing + the protocol's signature()
// wrapper.
//
// If our WASM verifies this signature against the public key derived
// from the WIF private key, we are byte-for-byte protocol-compatible
// with the node's Falcon implementation. This is the
// strongest possible cross-impl check.

describe('Falcon-512 — node compatibility', () => {
  // sign_data = "\x55\xaa" x 700  (1400 bytes total)
  const SIGN_DATA = new Uint8Array(1400);
  for (let i = 0; i < SIGN_DATA.length; i += 2) {
    SIGN_DATA[i] = 0x55;
    SIGN_DATA[i + 1] = 0xaa;
  }

  // WIF-encoded Falcon-512 private key from the node's test vector. Decoded layout is
  // version(1) || sk(1281) || pk(897) || checksum(4). We use mainnet
  // WIF version 0x80 here because the test runs with default config
  // (testnet=0).
  const WIF =
    '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';

  // Signature hex from the node's test vector.
  // Layout: [algo_id=0x81] [PQClean raw sig].
  // the node's signature check strips the leading algo_id, then PQClean's
  // verify gets the raw sig starting with its own header (0x39 for
  // Falcon-512).
  const SIG_WITH_ALGO_HEX =
    '813961c32c0fcc6132c89b74f34894091d4d598c53d284597e7fcf2bace22a41460fb99436f82c151b73836a237a164acde34ff0080eee10be36bcc8545168c22d99deca8d0e25c8e7732f51c419679e05c19670c8497a9760670e3b07f88ad2f850abe77243c0d495f5bf9265a5d887af8da8705712417adee252d1911aebae398f42e9059e7deaec77c87f6648400e2e0115c3891bd71da1c18c1acdcafc5f6b52a6cd929e191546cea1dc22383f44f22b45da68323e8912d994e1c3f2aa4d0dae68358eb1e773f7a99d8babc6954bd1fa03a7d1475fae6542dff0efeedf4fb481706ae35f328b44435b6e124de7d510cb6dcb8ca9e8130712171021e959a542d6a44b759643a8ccc3f32a6a6b1da9aaf4bf5e5a7625b877b208da9c7915aa4f70cff19e475a1e8edc546464ab12f8eeb509b0996c72f1173d8fdebb6102294d833d3cfa3e0bac1378c68cb5271492c85f47cf6e61312ad73c468d013172312771509dd3a26a0511f0b56b86f35a92b950de779525b7b96b1105fec1f35f0cbd362708fcd9b273578530483632c98936939954e6c3f0a0ece0ac7af99b814ec838ffd0464348a05a71e536778358555cb9ba444d32fd3a711a64417080fedbc3facad575c4ca81b3a7a755ea74579977b3d454adf7e0d0d577b11edd6f5aae3105c7796f5418febf4a1692bea6a4678e62af16ce9bc8a118adaa6b52c68ee5513b00c6b2f0620133346ccd85387cf32fbf5ea9a449684645d9dfe65a59732465081045f2736e1bc9b9f5fa06a095676d26cd706ce4ee8fb6dedab308be4b8f6651137728c6e439fb8359c0d2a1397cb24cc899fd5532b3a5b8bf792890b2a1426bffd13a113d3989db5be80a3fd7b4c234031ecfd112ae556682d9cc696cc3a8a3956419ae991bb40aa8aba7fbe7659b92c0';

  it('verifies the node test signature against the WIF-decoded pubkey', async () => {
    // Decode WIF: 1-byte version + 2178 bytes (sk||pk) + 4-byte checksum.
    const { payload } = decodeBase58Check(WIF, 1);
    expect(payload.length).toBe(
      FALCON512_PRIVATE_KEY_BYTES + FALCON512_PUBLIC_KEY_BYTES,
    );

    // The node's Falcon pubkey serialization concatenates sk||pk;
    // the pubkey is the trailing 897 bytes.
    const publicKey = payload.slice(FALCON512_PRIVATE_KEY_BYTES);
    expect(publicKey.length).toBe(FALCON512_PUBLIC_KEY_BYTES);

    // Strip the leading algo_id byte (0x81 = CRYPT_ALGO_FALCON).
    const sigWithAlgo = fromHex(SIG_WITH_ALGO_HEX);
    expect(sigWithAlgo[0]).toBe(0x81);
    const rawSig = sigWithAlgo.slice(1);

    // The node's signature check hashes the data through `hash256`
    // before passing to verify_signature. We replicate that protocol
    // step here — `signing.ts::signWithAlgorithm` will do the same when
    // building real transactions.
    const digest = hash256(SIGN_DATA);

    // Cross-implementation moment of truth: if our WASM verifies a
    // signature produced by the node's Falcon signer, the byte formats
    // are compatible.
    const ok = await falcon512Verify(rawSig, digest, publicKey);
    expect(ok).toBe(true);
  });

  it('extracted privkey can sign and self-verify (node convention — over hash256)', async () => {
    const { payload } = decodeBase58Check(WIF, 1);
    const privateKey = payload.slice(0, FALCON512_PRIVATE_KEY_BYTES);
    const publicKey = payload.slice(FALCON512_PRIVATE_KEY_BYTES);
    // Match the node's convention: sign hash256(data), not data directly.
    const digest = hash256(SIGN_DATA);
    const ourSig = await falcon512Sign(digest, privateKey);
    expect(await falcon512Verify(ourSig, digest, publicKey)).toBe(true);
  });
});

describe('falcon512IsReady', () => {
  it('reports true after any successful call has loaded the module', async () => {
    // Force a real load by doing a keygen — short-circuiting `verify`
    // paths return early without touching WASM.
    await falcon512KeygenFromSeed(new Uint8Array(FALCON512_SEED_BYTES));
    expect(falcon512IsReady()).toBe(true);
  });
});
