# @qbtc/crypto

Cryptographic core for wallets and tools built on the QBitcoin protocol.
Pure TypeScript on audited primitives (@noble, @scure) — runs in Node, in
Electron main processes, in browser pages, and in extension service
workers.

The package knows **no chain constants**. Everything that makes a chain
itself — derivation schemes, address magic, WIF versions, HKDF labels,
message magic, upgrade parameters — is injected by the consumer as a
`ChainProfile`:

```ts
import { bindProfile, type ChainProfile } from '@qbtc/crypto';

// Your chain's values live in YOUR repo (one file, pin-tested there).
const PROFILE: ChainProfile = {
  name: 'mychain',
  addrMagic: { mainnet: Uint8Array.of(/*…*/), testnet: Uint8Array.of(/*…*/) },
  addressRegex: { mainnet: /^…$/, testnet: /^…$/ },
  wifVersion: { mainnet: 0x80, testnet: 0xef },
  schemes: [/* DerivationScheme[] — exactly one 'active' */],
  metaV1SchemeId: '…',
  falconHdInfo: 'mychain/pq/falcon512/v1',
  appDataInfo: 'mychain/app-data/v1',
  messageMagic: 'MyChain Signed Message:\n',
  upgrade: null,        // BTC→native conversion parameters, or null
  downgrade: null,      // native→BTC downgrade federation, or null
  tokenSighashFork: { mainnet: 0, testnet: 0 }, // token-id sighash fork times
};

export const chain = bindProfile(PROFILE); // validated once, no globals
// chain.nativePath(0, 0, 'mainnet'), chain.decodeAddress(…), chain.encodeWif(…), …
```

Every underlying function is also exported in a pure form that takes the
chain values as explicit parameters — the facade is convenience, not a
requirement. There is no global state: profiles for two chains can
coexist in one process.

**Frozen-value warning.** A shipped chain must never change its profile's
schemes, magic, HKDF labels, or WIF versions — user funds and stored data
depend on them byte-exactly. Keep pin tests for your profile in your own
repo; this package's suite runs only against a fake test profile.

## Layout

```
src/
├─ encoding/
│  ├─ varint.ts          Bitcoin variable-length integers
│  ├─ varstr.ts          length-prefixed byte strings
│  ├─ base58check.ts     Base58Check (version + 4-byte checksum)
│  └─ hex.ts             hex ↔ bytes helpers
├─ hashes.ts             sha256, ripemd160, hash160, hash256, checksum32
├─ script.ts             P2PK redeem-script construction
├─ address.ts            encode / decode / validate addresses
├─ bip39.ts              mnemonic ↔ seed
├─ bip32.ts              HD derivation (secp256k1) + scheme mechanics
├─ xpub.ts               account xpub export / watch-only derivation
├─ secp256k1.ts          ECDSA sign / verify
├─ schnorr.ts            Schnorr (BIP-340) + feature gate (features.ts)
├─ falcon512.ts          Falcon-512 (post-quantum) via the bundled WASM
├─ falconHd.ts           HD → Falcon-512 keygen-seed derivation
├─ transaction.ts        tx model, serialization + sighash
├─ signing.ts            per-input signing (algorithm dispatch)
├─ signedMessage.ts      canonical signed-message format
├─ wif.ts                WIF private-key envelope (classical + Falcon)
├─ downgrade.ts          native→BTC downgrade covenants (freeze / reclaim)
├─ vault.ts              seed sealing — Argon2id KDF + AES-256-GCM
├─ appData.ts            HKDF data-encryption key + AES-GCM (e.g. address book)
├─ btc/                  Bitcoin tx builder, addresses, P2SH-P2WSH multisig lock
├─ profile.ts            ChainProfile, validateProfile, bindProfile
└─ index.ts              public API
```

## Principles

- **Test vectors first.** Each primitive is written against known
  inputs/outputs from a canonical source (BIP specs, Bitcoin test vectors, the
  node's own test suite) before it's implemented. Profile-dependent goldens
  are generated with independent implementations against the fake test
  profile; real chain values are pinned in each consumer's repo.
- **No browser globals.** Must run in Node; apps import it like any
  normal library.
- **No runtime CDN / remote code.** Only published, lockfile-pinned npm
  dependencies.

## Dependencies

| Package | Why |
|--|--|
| `@noble/hashes` | SHA-256, RIPEMD-160, Argon2id — audited, zero-dep, constant-time |
| `@noble/curves` | secp256k1 ECDSA + Schnorr |
| `@scure/base` | Base58Check encoding |
| `@scure/bip39` | Mnemonic phrases |
| `@scure/bip32` | HD derivation |

Falcon-512 is provided by a WebAssembly module compiled from
[PQClean](https://github.com/PQClean/PQClean) (built by the repo's
`tools/falcon512-wasm`, vendored at `wasm/falcon512.{wasm,mjs}` and
shipped in the npm tarball with a pinned SHA-256). Hosts that can't
`fetch` a package asset can override loading via
`setFalcon512WasmSource()`.

## Browser bundling

The package is plain ESM and declares `"sideEffects": false`, so bundlers
drop whatever a consumer does not import: a page that only needs
addresses, WIF and Bitcoin transactions ends up with ~45 KB minified and
no Falcon code at all. The Falcon-512 WASM glue is loaded through a
dynamic `import()` inside the loader, so it only reaches a bundle that
actually calls Falcon, and the `.wasm` itself is fetched at runtime
(override the source with `setFalcon512WasmSource()` where relative URLs
don't resolve, e.g. bundled extensions). The Node-only file fallback
builds its `node:` specifiers at runtime, so browser bundlers never try
to resolve them.

## Tests

```bash
pnpm --filter @qbtc/crypto test
pnpm --filter @qbtc/crypto test:watch
pnpm --filter @qbtc/crypto typecheck
```
