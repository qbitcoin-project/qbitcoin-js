// Error types for the chain package.
//
// All client-visible failures normalize into one of these. Callers
// (background SW, UI) switch on `code` to render specific messages
// and decide whether to retry — never reach into `.message` for
// matching.
//
// The principle here mirrors @qbtc/vault: a small set of
// distinguishable subclasses, never `throw new Error("...")` from
// the client surface.

/** Categorized reason for why a chain operation failed. */
export type ChainErrorCode =
  // Network-layer — could be transient
  | 'timeout'
  | 'network'
  // Response-layer — server reachable, returned something we couldn't use
  | 'http_5xx'
  | 'http_4xx'
  | 'malformed_response'
  // Operation-specific — broadcast endpoint not wired or returned validation failure
  | 'broadcast_unavailable'
  | 'broadcast_rejected'
  // Caller error — bad input that shouldn't have reached the wire
  | 'invalid_argument'
  // Last-resort
  | 'unknown';

/**
 * All errors thrown by ChainClient / EsploraClient. Carries a structured
 * `code` for branching plus the original cause when available.
 *
 * Why not separate subclasses per code: the categories overlap (a 503
 * during broadcast could be classified either way), and one class with a
 * discriminator keeps `switch (e.code)` exhaustive at the type level.
 */
export class ChainError extends Error {
  override readonly name = 'ChainError';
  readonly code: ChainErrorCode;
  /** HTTP status if applicable. */
  readonly status?: number;
  /** Underlying error (network, AbortSignal, parse error). */
  override readonly cause?: unknown;
  /** Which endpoint URL we were talking to. Useful for logging. */
  readonly endpoint?: string;

  constructor(
    code: ChainErrorCode,
    message: string,
    options: {
      readonly status?: number;
      readonly cause?: unknown;
      readonly endpoint?: string;
    } = {},
  ) {
    super(message);
    this.code = code;
    if (options.status !== undefined) this.status = options.status;
    if (options.cause !== undefined) this.cause = options.cause;
    if (options.endpoint !== undefined) this.endpoint = options.endpoint;
  }
}

/** True if `code` is something we could productively retry. */
export function isRetryableCode(code: ChainErrorCode): boolean {
  return code === 'timeout' || code === 'network' || code === 'http_5xx';
}
