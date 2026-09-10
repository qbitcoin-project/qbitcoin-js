# Falcon-512 WASM build pipeline

Builds a deterministic, browser-loadable WebAssembly module that wraps
[PQClean](https://github.com/PQClean/PQClean)'s Falcon-512 reference
implementation. Output goes to `packages/crypto/wasm/falcon512.{wasm,mjs}`
which is then vendored in the repository.

The wallet uses three functions from this module:

| Function | Purpose |
|--|--|
| `wallet_falcon512_keygen_from_seed(seed[48], pk, sk)` | Deterministic keygen from a 48-byte HKDF-derived seed |
| `wallet_falcon512_sign_detached(msg, msg_len, sk, sig_out, sig_len_out)` | Produce a detached signature for `msg` under secret key `sk` |
| `wallet_falcon512_verify(sig, sig_len, msg, msg_len, pk)` | Verify a detached signature |

## Why this exists

The Perl node uses `Crypt::PQClean::Sign` (CPAN, version 0.04.1 as of
Jan 2025) which bundles PQClean Falcon-512. Browser extensions can't run
Perl, can't load native modules, and can't fetch raw TCP. So we compile
the same PQClean C source to WebAssembly and ship it inside the
extension.

Falcon-512 has been stable in PQClean since 2021 — no encoding changes —
so any modern PQClean release should produce byte-compatible output
with the node. We verify this against the node's own Falcon-512 test
vector.

## Prerequisites

You only need this if you're (re-)building the WASM. End users and
day-to-day extension developers DON'T need any of this — they just use
the committed `falcon512.wasm` file.

Either:

**Option A — Docker (recommended).** Reproducible, no host pollution.

```bash
docker --version    # any modern Docker or Podman works
```

**Option B — Local Emscripten.** Faster iteration during development.

```bash
emcc --version      # must be 3.1.50 or newer
```

## Build

From this directory:

```bash
# Option A — Docker (one command):
./build.sh

# Option B — local emcc (faster, less hermetic):
./fetch-pqclean.sh
make
```

Both end with:

```
packages/crypto/wasm/falcon512.wasm   # ~120 KB
packages/crypto/wasm/falcon512.mjs    # ~15 KB JS glue
```

## Verify the build

After building, run the smoke test:

```bash
cd ../..
pnpm --filter @qbtc/crypto test falcon512
```

This checks two things:

1. The pubkey produced from the known test seed has the right structure
   (897 bytes, leading version byte 0x09).
2. A known-good signature from the node's test suite verifies against
   the pubkey derived from that test's WIF private key. **This is our
   ground-truth cross-implementation compatibility check.**

If both pass, the WASM is byte-compatible with the node.

## Reproducibility

The build is fully reproducible — the same git checkout produces a
byte-identical `falcon512.wasm` across machines:

```bash
sha256sum ../../packages/crypto/wasm/falcon512.wasm
# Should match the hash in CI artifacts and README.
```

This is what makes auditing meaningful: anyone with our git tag, this
script, and Docker can rebuild and verify our binary corresponds to the
checked-in source.

## Layout

```
tools/falcon512-wasm/
├── README.md          # you are here
├── Dockerfile         # Emscripten 3.1.61 + Make
├── Makefile           # the actual emcc invocation
├── build.sh           # convenience: docker build && docker run make
├── fetch-pqclean.sh   # downloads PQClean source at a pinned commit
├── shim.c             # our C wrapper exposing the wallet_* API
├── shim.h             # signatures of the wallet_* functions
└── .gitignore         # ignores build output and pqclean-src/
```

`pqclean-src/` is fetched on demand — not committed. The pinned commit
is in `fetch-pqclean.sh`. Update it consciously.

## Updating PQClean

1. Bump the commit hash in `fetch-pqclean.sh`.
2. Rebuild with `./build.sh`.
3. Run the smoke test — if it passes, encoding hasn't drifted.
4. If it fails, investigate before committing the new `.wasm`.
5. Open a PR — include the falcon.t vector check result in the PR body.

Anything beyond a routine PQClean bump (e.g., algorithm changes,
parameter changes) requires a security review.
