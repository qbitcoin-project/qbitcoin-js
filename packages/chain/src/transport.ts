// HTTP transport — fetch wrapped with timeout, retry, and ChainError mapping.
//
// One responsibility per layer:
//
//   transport.ts     — single HTTP call, timeout, retry/backoff, error mapping
//   EsploraClient.ts — endpoint-specific URLs and response shapes
//   ChainClient.ts   — node failover, public API
//
// We deliberately do NOT use a library here (axios/got/ky). `fetch` is
// universal, the policy is small, and pulling in a dep on the critical
// signing path means trusting one more maintainer with our security
// posture.

import { ChainError, isRetryableCode, type ChainErrorCode } from './errors.js';
import { quoteLargeIntegers } from './jsonNumbers.js';

// ─── Configuration ───────────────────────────────────────────────────

export interface TransportOptions {
  /** Total per-call timeout in milliseconds. Defaults to 15s. */
  readonly timeoutMs?: number;
  /** Maximum retry attempts for retryable failures. Defaults to 2. */
  readonly maxRetries?: number;
  /** Base backoff in ms; doubles on each retry. Defaults to 250ms. */
  readonly backoffMs?: number;
  /** Inject a custom fetch (used by tests). */
  readonly fetchImpl?: typeof fetch;
  /**
   * Value for an `Authorization` header sent on every request (e.g. HTTP Basic
   * auth for a self-hosted node behind a password). Omitted when undefined.
   */
  readonly authHeader?: string;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RETRIES = 2;
const DEFAULT_BACKOFF_MS = 250;

// ─── Request types ───────────────────────────────────────────────────

export interface RequestSpec {
  readonly url: string;
  readonly method?: 'GET' | 'POST';
  /** Plain-text body. Used for `POST /api/tx` (Esplora convention). */
  readonly body?: string;
  /** Override Content-Type for POSTs. Defaults to text/plain. */
  readonly contentType?: string;
  /** Expected response shape — drives the parser. */
  readonly expect: 'json' | 'text';
}

// ─── Concurrency cap ─────────────────────────────────────────────────
//
// Cap concurrent requests to the node. Address discovery fires dozens at once; left
// unthrottled they overwhelm the node and tail latencies balloon (a ~60-address scan
// was observed degrading from ~0.6s to ~14s per request). Feeding a steady few keeps
// each request fast. Requests beyond the cap queue here in FIFO order. The cap is
// process-global because every request targets the same node.
const MAX_CONCURRENT_REQUESTS = 6;
let inFlight = 0;
const slotQueue: (() => void)[] = [];

async function acquireSlot(): Promise<void> {
  if (inFlight >= MAX_CONCURRENT_REQUESTS) {
    await new Promise<void>((resolve) => slotQueue.push(resolve));
  }
  inFlight++;
}

function releaseSlot(): void {
  inFlight--;
  const next = slotQueue.shift();
  if (next !== undefined) next();
}

// ─── Public API ──────────────────────────────────────────────────────

/**
 * Execute one HTTP request with retry + backoff + timeout. Returns the
 * parsed body on 2xx, throws ChainError on everything else.
 *
 * The retry policy: retry only on `timeout`, `network`, and `http_5xx`.
 * Never retry 4xx — the caller did something wrong, retrying won't help.
 */
export async function request<T>(
  spec: RequestSpec,
  options: TransportOptions = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
  const backoffMs = options.backoffMs ?? DEFAULT_BACKOFF_MS;
  const fetchImpl = options.fetchImpl ?? fetch;

  let attempt = 0;
  let lastError: ChainError;
  for (;;) {
    await acquireSlot();
    try {
      return (await doOnce(spec, timeoutMs, fetchImpl, options.authHeader)) as T;
    } catch (e) {
      // Unwrap unknown thrown value. Should not happen — doOnce always produces
      // ChainError — but be defensive.
      lastError = e instanceof ChainError ? e : new ChainError('unknown', 'Unexpected error in transport', { cause: e, endpoint: spec.url });
      if (!isRetryableCode(lastError.code) || attempt >= maxRetries) {
        throw lastError;
      }
    } finally {
      releaseSlot();
    }
    // Retryable: back off (full jitter, avoids thundering herds) outside the
    // concurrency slot so a queued request can run while we wait.
    const delay = Math.floor(Math.random() * backoffMs * 2 ** attempt);
    await sleep(delay);
    attempt++;
  }
}

// ─── Internals ───────────────────────────────────────────────────────

async function doOnce<T>(
  spec: RequestSpec,
  timeoutMs: number,
  fetchImpl: typeof fetch,
  authHeader?: string,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const headers: Record<string, string> = {};
  if (spec.method === 'POST') headers['Content-Type'] = spec.contentType ?? 'text/plain';
  if (authHeader !== undefined) headers['Authorization'] = authHeader;

  let response: Response;
  try {
    response = await fetchImpl(spec.url, {
      method: spec.method ?? 'GET',
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      body: spec.body,
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timer);
    if (isAbortError(e)) {
      throw new ChainError('timeout', `Request timed out after ${timeoutMs}ms`, {
        cause: e,
        endpoint: spec.url,
      });
    }
    throw new ChainError('network', describeNetworkError(e), {
      cause: e,
      endpoint: spec.url,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    const code: ChainErrorCode = response.status >= 500 ? 'http_5xx' : 'http_4xx';
    // Try to read a body for context, but don't fail the failure on parse.
    let detail = '';
    try {
      detail = (await response.text()).slice(0, 500);
    } catch {
      // ignore
    }
    throw new ChainError(
      code,
      `HTTP ${response.status} ${response.statusText}${detail ? `: ${detail}` : ''}`,
      { status: response.status, endpoint: spec.url },
    );
  }

  if (spec.expect === 'text') {
    try {
      return (await response.text()) as unknown as T;
    } catch (e) {
      throw new ChainError('malformed_response', 'Could not read response body', {
        cause: e,
        endpoint: spec.url,
      });
    }
  }

  // JSON
  let bodyText: string;
  try {
    bodyText = await response.text();
  } catch (e) {
    throw new ChainError('malformed_response', 'Could not read response body', {
      cause: e,
      endpoint: spec.url,
    });
  }
  try {
    // Integer literals beyond 2^53 (uint64 token amounts) are quoted first,
    // so their digits survive parsing; see jsonNumbers.ts.
    return JSON.parse(quoteLargeIntegers(bodyText)) as T;
  } catch (e) {
    throw new ChainError(
      'malformed_response',
      `Response is not valid JSON: ${bodyText.slice(0, 200)}`,
      { cause: e, endpoint: spec.url },
    );
  }
}

function isAbortError(e: unknown): boolean {
  return (
    typeof e === 'object' &&
    e !== null &&
    'name' in e &&
    (e as { name: string }).name === 'AbortError'
  );
}

function describeNetworkError(e: unknown): string {
  if (e instanceof Error) return `Network error: ${e.message}`;
  return 'Network error';
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
