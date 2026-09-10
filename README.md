# qbitcoin-js

TypeScript building blocks for wallets and tools on the **QBitcoin
protocol** — a Bitcoin-derived UTXO chain that pairs classical secp256k1
with post-quantum **Falcon-512** signatures. The packages implement the
protocol's cryptography and its node client once, so that every wallet,
web tool or service built on the chain shares a single, tested
implementation instead of carrying its own copy.

| Package | Purpose |
|---|---|
| [`@qbtc/crypto`](packages/crypto) | Keys, addresses and signatures: BIP-39/32 derivation for both signature families, address and script codecs, transaction serialization and signing, the canonical signed-message format, WIF, vault sealing, and the Bitcoin-side builders for the BTC ↔ QBTC conversion flows. |
| [`@qbtc/chain`](packages/chain) | The node's Esplora-compatible REST API as typed clients: balances, UTXOs, transactions, fee estimates, broadcast, failover across nodes — plus a thin client for public Bitcoin explorers. |

## Why

Wallet code is money code, and money code copied by hand goes wrong in
quiet ways: a byte-order fix lands in one app but not another, a
consensus parameter changes and one copy keeps the old value. The
QBitcoin ecosystem has several front ends — a desktop wallet, a browser
extension, a web converter — that all need the same primitives. This
repository is where those primitives live, with the properties that make
sharing them safe:

- **Consensus-sensitive details are tested against known vectors** —
  BIP-32, BIP-39 and Bitcoin test vectors for the standard parts,
  byte-exact fixtures for the protocol-specific ones — and the suites run
  on every change.
- **The packages carry no chain constants.** Address magic, derivation
  schemes, HKDF labels, message magic, conversion and fork parameters are
  supplied by the consumer as a `ChainProfile`. The same code serves
  mainnet, testnet and any other deployment of the protocol; nothing is
  baked in that a different chain would have to fork out.
- **Releases are pinned and provable.** Packages publish to npm with
  provenance from this repository's CI, consumers pin exact versions,
  and the Falcon-512 WASM binary ships with a SHA-256 pin and a
  reproducible build.

## Quick start

```bash
pnpm add @qbtc/crypto @qbtc/chain
```

Declare your chain once, then use the bound facade everywhere:

```ts
import { bindProfile, type ChainProfile } from '@qbtc/crypto';
import { ChainClient } from '@qbtc/chain';

// The chain's parameters live in your application, in one file that
// your own tests pin. Nothing here is guessed by the library.
const PROFILE: ChainProfile = {
  name: 'mychain',
  addrMagic: { mainnet: Uint8Array.of(/* … */), testnet: Uint8Array.of(/* … */) },
  addressRegex: { mainnet: /^…$/, testnet: /^…$/ },
  wifVersion: { mainnet: 0x80, testnet: 0xef },
  schemes: [/* DerivationScheme[] — exactly one 'active' */],
  metaV1SchemeId: '…',
  falconHdInfo: 'mychain/pq/falcon512/v1',
  appDataInfo: 'mychain/app-data/v1',
  messageMagic: 'MyChain Signed Message:\n',
  upgrade: null,
  downgrade: null,
  tokenSighashFork: { mainnet: 0, testnet: 0 },
};

const chain = bindProfile(PROFILE); // validated once; no global state

const address = chain.addressFromPubkey(publicKey, 'ecdsa', 'mainnet');

const client = new ChainClient({
  network: 'mainnet',
  endpoints: [
    { name: 'My node', url: 'https://node.example', protocol: 'esplora',
      network: 'mainnet', operator: 'me', priority: 1 },
  ],
});
const info = await client.getAddressInfo(address);
```

Every function behind the facade is also exported in a pure form that
takes the chain values as explicit parameters — the facade is
convenience, not a requirement. The full API is documented per package:
[`@qbtc/crypto`](packages/crypto/README.md),
[`@qbtc/chain`](packages/chain/README.md).

## Design

- **Pure ESM, side-effect free.** Both packages declare
  `"sideEffects": false`, so bundlers drop whatever you don't import. A
  page that needs only addresses, WIF and Bitcoin transactions bundles to
  about 47 KB minified with no Falcon code at all — the WASM glue is
  loaded lazily and only reaches bundles that call Falcon.
- **Audited primitives underneath.** secp256k1, hashing, BIP-32/39 and
  Base58 come from `@noble/curves`, `@noble/hashes` and `@scure/*`.
  Falcon-512 is the PQClean reference implementation compiled to
  WebAssembly (`tools/falcon512-wasm/`).
- **Runs where wallets run:** Node, Electron main processes, browser
  pages and extension service workers. `@qbtc/chain` needs only `fetch`.
- **No global state.** Two profiles can coexist in one process — a tool
  bridging two networks does not have to choose.
- **Sources ship as TypeScript.** Consumers compile the packages with
  their own toolchain; there is no build step and no dual CJS/ESM
  artifact to keep in sync.

## Frozen values

A shipped chain's profile is consensus- and storage-affecting: changing
derivation schemes, address magic, HKDF labels or WIF versions after
users hold funds strands those funds or makes stored data unreadable.
Keep your profile in one file, pin it with tests in your own repository,
and treat this repository's suite as covering the mechanics only — it
runs against a synthetic test profile by design.

## Development

Requires pnpm ≥ 10 and Node ≥ 22.

```bash
pnpm install
pnpm test        # every package's suite
pnpm typecheck
pnpm lint
```

Repository layout:

```
packages/crypto/        @qbtc/crypto
packages/chain/         @qbtc/chain
tools/falcon512-wasm/   reproducible build of the Falcon-512 WASM artifact
```

## Releases

Packages are versioned independently (semver) and published to npm from
CI on tags — `crypto-vX.Y.Z` and `chain-vX.Y.Z` — with npm provenance,
so every published tarball is traceable to a commit in this repository.
Pin exact versions in consumers. For local cross-repo work, point at a
checkout with a pnpm override:

```jsonc
"pnpm": { "overrides": { "@qbtc/crypto": "file:../qbitcoin-js/packages/crypto" } }
```

## Security

Report security-sensitive findings privately to the maintainers rather
than through a public issue.

## License

[MIT](LICENSE).
