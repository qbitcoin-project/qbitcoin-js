// ChainClient — the public surface for the wallet's chain access.
//
// Wraps one or more EsploraClient instances for a given network and
// implements failover: if the primary endpoint returns http_5xx, network
// or timeout, the next-priority node is tried before propagating the
// error up.
//
// For broadcast we do NOT failover automatically. A successful broadcast
// to node A means the tx is in the p2p network — re-broadcasting through
// node B is at best wasteful and at worst causes confusing UX (which
// node "owns" the broadcast?). Caller can manually retry.

import type { Network, NodeEndpoint } from './nodes';
import { ChainError, isRetryableCode } from './errors';
import { EsploraClient } from './EsploraClient';
import type {
  AddressInfo,
  BlockchainInfo,
  BroadcastResult,
  ChainTx,
  FeeEstimates,
  NodeStatus,
  TokenInfo,
  TokenTransfer,
  Outspend,
  Utxo,
} from './types';
import type { TransportOptions } from './transport';

export interface ChainClientConfig {
  readonly network: Network;
  /**
   * Node endpoints to use, in failover order (see `nodesFor` for
   * priority-sorting a mixed list). The package ships no endpoint URLs —
   * the consumer's app config owns the list.
   */
  readonly endpoints: readonly NodeEndpoint[];
  readonly transport?: TransportOptions;
}

export class ChainClient {
  private readonly clients: readonly EsploraClient[];
  readonly network: Network;

  constructor(config: ChainClientConfig) {
    this.network = config.network;
    // An empty list is a legitimate state, not a construction error: a
    // wallet may ship no public nodes (network not launched yet), and the
    // user adds their own node in Settings AFTER the app has started.
    // Requests made in the meantime fail with a ChainError; the status
    // indicator shows "unreachable" instead of the whole wallet refusing
    // to boot.
    this.clients = config.endpoints.map(
      (e) => new EsploraClient(e, config.transport),
    );
  }

  /** Currently active (primary) endpoint. Visible for diagnostics. */
  get endpoints(): readonly NodeEndpoint[] {
    return this.clients.map((c) => c.endpoint);
  }

  // ─── Read methods — each tries clients in order ────────────────────

  getBlockchainInfo(): Promise<BlockchainInfo> {
    return this.tryEachRead((c) => c.getBlockchainInfo());
  }

  getNodeStatus(): Promise<NodeStatus> {
    return this.tryEachRead((c) => c.getNodeStatus());
  }

  getAddressInfo(address: string): Promise<AddressInfo> {
    return this.tryEachRead((c) => c.getAddressInfo(address));
  }

  listUnspent(address: string): Promise<Utxo[]> {
    return this.tryEachRead((c) => c.listUnspent(address));
  }

  getTransaction(txid: string): Promise<ChainTx> {
    return this.tryEachRead((c) => c.getTransaction(txid));
  }

  getOutspend(txid: string, vout: number): Promise<Outspend> {
    return this.tryEachRead((c) => c.getOutspend(txid, vout));
  }

  getTransactionHex(txid: string): Promise<string> {
    return this.tryEachRead((c) => c.getTransactionHex(txid));
  }

  getAddressTransactions(address: string, afterTxid?: string): Promise<ChainTx[]> {
    return this.tryEachRead((c) =>
      c.getAddressTransactions(address, afterTxid),
    );
  }

  getAddressTransfers(address: string, tokenId: string, afterTxid?: string): Promise<TokenTransfer[]> {
    return this.tryEachRead((c) => c.getAddressTransfers(address, tokenId, afterTxid));
  }

  getFeeEstimates(): Promise<FeeEstimates> {
    return this.tryEachRead((c) => c.getFeeEstimates());
  }

  getTokenInfo(id: string): Promise<TokenInfo> {
    return this.tryEachRead((c) => c.getTokenInfo(id));
  }

  // ─── Broadcast — single attempt, no failover ───────────────────────

  /**
   * Send `rawHex` to the primary node. Does NOT fall back to other
   * nodes on failure — see file header for rationale.
   *
   * Returns the txid as confirmed by the node + which endpoint took it.
   */
  async broadcastTransaction(rawHex: string): Promise<BroadcastResult> {
    const primary = this.clients[0];
    if (primary === undefined) {
      throw new ChainError(
        'broadcast_unavailable',
        `No node endpoints configured for network '${this.network}' — add your own node in Settings.`,
      );
    }
    const txid = await primary.broadcastTransaction(rawHex);
    return { txid, endpoint: primary.endpoint };
  }

  // ─── Internals ─────────────────────────────────────────────────────

  /**
   * Try each EsploraClient in order. On a retryable failure (5xx,
   * network, timeout) advance to the next; on any non-retryable
   * failure propagate immediately (because 4xx means the request is
   * malformed, not the node).
   */
  private async tryEachRead<T>(
    op: (c: EsploraClient) => Promise<T>,
  ): Promise<T> {
    if (this.clients.length === 0) {
      throw new ChainError(
        'network',
        `No node endpoints configured for network '${this.network}' — add your own node in Settings.`,
      );
    }
    let lastError: unknown;
    for (const client of this.clients) {
      try {
        return await op(client);
      } catch (e) {
        lastError = e;
        if (e instanceof ChainError && !isRetryableCode(e.code)) {
          throw e;
        }
        // Otherwise, try the next endpoint.
      }
    }
    // We exhausted all endpoints. Re-throw the last error so the
    // caller sees the most-recent (and most-informative) reason.
    throw lastError;
  }
}
