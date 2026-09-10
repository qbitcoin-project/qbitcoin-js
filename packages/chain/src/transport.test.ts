import { describe, expect, it, vi } from 'vitest';
import { ChainError } from './errors';
import { request } from './transport';

// Helper — build a Response with the given status + body.
function res(
  status: number,
  body: string,
  contentType = 'application/json',
): Response {
  return new Response(body, {
    status,
    headers: { 'Content-Type': contentType },
  });
}

describe('transport.request', () => {
  it('returns parsed JSON on 200', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(res(200, '{"ok":true}'));
    const out = await request<{ ok: boolean }>(
      { url: 'https://example/api', expect: 'json' },
      { fetchImpl, maxRetries: 0 },
    );
    expect(out).toEqual({ ok: true });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('returns text on expect: text', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response('850000', { status: 200 }));
    const out = await request<string>(
      { url: 'https://example/api/blocks/tip/height', expect: 'text' },
      { fetchImpl, maxRetries: 0 },
    );
    expect(out).toBe('850000');
  });

  it('throws ChainError("http_4xx") on 400 without retry', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(res(400, '{"error":"bad"}'));
    await expect(
      request(
        { url: 'https://example/api', expect: 'json' },
        { fetchImpl, maxRetries: 3 },
      ),
    ).rejects.toMatchObject({
      name: 'ChainError',
      code: 'http_4xx',
      status: 400,
    });
    expect(fetchImpl).toHaveBeenCalledOnce(); // no retry on 4xx
  });

  it('throws ChainError("http_5xx") after exhausting retries', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(res(503, 'Service Unavailable'));
    await expect(
      request(
        { url: 'https://example/api', expect: 'json' },
        { fetchImpl, maxRetries: 2, backoffMs: 1 },
      ),
    ).rejects.toMatchObject({
      name: 'ChainError',
      code: 'http_5xx',
      status: 503,
    });
    // 1 initial + 2 retries = 3 calls
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('succeeds on retry when first call fails with 5xx', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(res(503, ''))
      .mockResolvedValueOnce(res(200, '{"ok":true}'));
    const out = await request<{ ok: boolean }>(
      { url: 'https://example/api', expect: 'json' },
      { fetchImpl, maxRetries: 2, backoffMs: 1 },
    );
    expect(out).toEqual({ ok: true });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('throws ChainError("malformed_response") on invalid JSON', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(res(200, 'not json{{{'));
    await expect(
      request(
        { url: 'https://example/api', expect: 'json' },
        { fetchImpl, maxRetries: 0 },
      ),
    ).rejects.toMatchObject({
      name: 'ChainError',
      code: 'malformed_response',
    });
  });

  it('throws ChainError("timeout") when fetch is aborted', async () => {
    const fetchImpl = vi.fn().mockImplementation((_url, init?: RequestInit) => {
      return new Promise((_resolve, reject) => {
        const signal = init?.signal;
        signal?.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    });
    await expect(
      request(
        { url: 'https://example/api', expect: 'json' },
        { fetchImpl, maxRetries: 0, timeoutMs: 5 },
      ),
    ).rejects.toMatchObject({
      name: 'ChainError',
      code: 'timeout',
    });
  });

  it('throws ChainError("network") on fetch rejection', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError('DNS failure'));
    await expect(
      request(
        { url: 'https://example/api', expect: 'json' },
        { fetchImpl, maxRetries: 0 },
      ),
    ).rejects.toMatchObject({
      name: 'ChainError',
      code: 'network',
    });
  });

  it('sends POST body with text/plain content-type by default', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response('txid123', { status: 200 }));
    await request(
      {
        url: 'https://example/api/tx',
        method: 'POST',
        body: 'deadbeef',
        expect: 'text',
      },
      { fetchImpl, maxRetries: 0 },
    );
    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe('POST');
    expect(init.body).toBe('deadbeef');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('text/plain');
  });

  it('attaches endpoint URL to thrown ChainError for logging', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(res(404, 'not found'));
    try {
      await request(
        { url: 'https://example/api/x', expect: 'json' },
        { fetchImpl, maxRetries: 0 },
      );
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ChainError);
      expect((e as ChainError).endpoint).toBe('https://example/api/x');
    }
  });
});
