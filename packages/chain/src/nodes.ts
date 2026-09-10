// Node endpoint model.
//
// The package ships no endpoint URLs of its own: which nodes a wallet
// talks to is a deployment decision of the consumer (its own public
// nodes, community nodes, the user's self-hosted node). Consumers keep
// their endpoint list in their app config and pass it to `ChainClient`
// (or to `nodesFor` for pre-filtering).

export type Protocol = 'esplora' | 'jsonrpc';
export type Network = 'mainnet' | 'testnet';

export interface NodeEndpoint {
  /** Human-readable label shown in Settings → Networks. */
  readonly name: string;
  /** Base URL — HTTPS only. No trailing slash. */
  readonly url: string;
  /** Which protocol the endpoint speaks. */
  readonly protocol: Protocol;
  /** Network this endpoint serves. */
  readonly network: Network;
  /** Operator name shown next to the entry in UI. */
  readonly operator: string;
  /**
   * Priority — lower wins. The wallet picks the smallest-priority reachable
   * endpoint for the active network. Failover moves to the next priority on
   * 5xx or timeout.
   */
  readonly priority: number;
}

/** Subset of `nodes` serving `network`, sorted by priority. */
export function nodesFor(
  nodes: readonly NodeEndpoint[],
  network: Network,
): NodeEndpoint[] {
  return nodes
    .filter((n) => n.network === network)
    .sort((a, b) => a.priority - b.priority);
}
