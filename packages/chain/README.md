# @qbtc/chain

Esplora-compatible REST client for wallets and tools built on the
QBitcoin protocol. Talks to one or more nodes, normalizes responses into
typed domain objects, and broadcasts signed transactions. Ships no
endpoint URLs of its own — which nodes to talk to is the consumer's
deployment decision.

Pure TypeScript — no React, no DOM, no `chrome.storage`. It runs equally well in
a background service worker, a browser page, or a Node test process; only
`fetch` is required.

## Why a separate package

- **Failover and retry policy in one place.** Every call site (status pings,
  send flow, history pages, a dApp provider) gets the same backoff, node
  failover and error mapping.
- **Stable domain types across backends.** Consumers import `AddressInfo`,
  `Utxo`, `ChainTx` and never see the raw Esplora JSON shape.
- **One audit surface.** Every byte the wallet sends to a remote node flows
  through this package.

## Public API

```ts
import { ChainClient, nodesFor, type NodeEndpoint } from '@qbtc/chain';

// Your node list lives in YOUR app config.
const MY_NODES: NodeEndpoint[] = [
  {
    name: 'My node',
    url: 'https://node.example',
    protocol: 'esplora',
    network: 'mainnet',
    operator: 'me',
    priority: 1,
  },
];

const client = new ChainClient({
  network: 'mainnet',
  endpoints: nodesFor(MY_NODES, 'mainnet'), // priority-sorted subset
});

// Read
const info  = await client.getAddressInfo('<address>');
const spent = await client.getOutspend('<txid>', 0);
const raw   = await client.getTransactionHex('<txid>');
const utxos = await client.listUnspent('<address>');
const tx    = await client.getTransaction('<txid>');
const fees  = await client.getFeeEstimates();
const tip   = await client.getBlockchainInfo();
const node  = await client.getNodeStatus();

// Write
const { txid, endpoint } = await client.broadcastTransaction(signedHex);
```

An empty `endpoints` list is legitimate (the app boots, requests fail
with `ChainError` until the user configures a node).

All methods throw `ChainError` on failure; branch on `error.code`:

| Code | Meaning | Retry sensible? |
|--|--|--|
| `timeout` | Request didn't return within `timeoutMs` | yes |
| `network` | `fetch` rejected (DNS, TLS, abort) | yes |
| `http_5xx` | Server reachable, returned 500–599 | yes |
| `http_4xx` | Server reachable, returned 400–499 | no — request is wrong |
| `malformed_response` | 2xx but body unparseable | no — node is broken |
| `broadcast_rejected` | Tx rejected (bad sig, conflict, dust) | no |
| `invalid_argument` | Caller passed something obviously wrong | no |
| `unknown` | Should not happen — file a bug | no |

`isRetryableCode(code)` is the exported canonical check.

## Failover

`ChainClient` tries its endpoint list in order. Read methods advance to the
next endpoint on a retryable failure. `broadcastTransaction` tries only the
first node — re-broadcasting an already-propagated tx through a second node
doesn't help and complicates UX.

## Bitcoin side (upgrade flows)

`BtcEsploraClient` is a thin client for public Bitcoin Esplora instances
(address stats, UTXOs, fee estimates, broadcast) used by BTC→native
conversion flows. `btcEsploraDefaultsFor(network)` returns sensible public
defaults (mempool.space; testnet = testnet4) — overridable per call site.

## Configuration

```ts
new ChainClient({
  network: 'mainnet',
  endpoints: [...],
  // Optional: tune the transport.
  transport: { timeoutMs: 15_000, maxRetries: 2, backoffMs: 250 },
});
```

## Node status

`getNodeStatus()` maps the node's `/api/status` onto `NodeStatus`. The
sync fields are always present; everything about BTC conversion is
optional and simply absent on nodes without upgrade support:

| Field | Meaning |
|---|---|
| `chain`, `blocks`, `initialBlockDownload` | chain name, best height, still syncing |
| `bestBlockHash`, `bestBlockTime`, `genesisTime` | tip identity and timestamps (unix seconds) |
| `mempoolSize`, `mempoolBytes` | pending transactions and their size |
| `totalCoins` | circulating supply, atomic units |
| `btcSynced`, `btcHeaders`, `btcScanned` | Bitcoin-side sync: credits require the *scanned* height, which can trail the headers |
| `btcLockScriptHex`, `btcUpgradeAddress` | the BTC lock output the node credits conversions for — as scriptPubKey hex (lowercase) and as an address |
| `btcUpgraded`, `btcDowngraded` | cumulative BTC locked and released, satoshi |
| `minted`, `burned` | cumulative native coins created and destroyed by conversions |

All running totals are `bigint`; they grow without bound and are parsed
exactly whether the node sends numbers or digit strings.

**Check the lock script before you use it.** A client that ships the lock
script as a constant should compare it with what the node reports and
refuse to show a deposit address on any mismatch — a stale constant would
send bitcoin to an output the node no longer credits:

```ts
const status = await client.getNodeStatus();
if (status.btcLockScriptHex !== MY_CHAIN.upgrade.mainnet.lockScriptHex) {
  throw new Error('lock script mismatch: refusing to build a deposit');
}
```

When a status field is present but malformed, the call fails with
`ChainError('malformed_response')` instead of silently omitting the
field — a node emitting garbage in a consensus-relevant field must be
visible, not mistaken for one that does not report it.

## Tests

Unit tests run against JSON fixtures in `src/fixtures/` (written to the
documented Esplora shape of the node). If a real node disagrees with a
fixture, fix the parser, not the fixture.

```bash
pnpm --filter @qbtc/chain test
```

## Limitations

- **Esplora-only.** No JSON-RPC backend yet.
- **No caching.** Every call hits the network.
- **No push.** Polling only; no WebSocket subscriptions.
