import { describe, expect, it, vi } from 'vitest';
import {
  AnalysisTimeoutError,
  VirusTotalApiError,
  VirusTotalAuthError,
  VirusTotalClient,
  VirusTotalQuotaError,
} from '../src/virustotal';
import type { FetchLike } from '../src/virustotal';

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

interface FetchStub {
  fetch: FetchLike;
  calls: Array<{ url: string; method: string; body?: unknown }>;
}

function stubFetch(
  handler: (url: string, init: RequestInit | undefined, call: number) => Promise<Response>,
): FetchStub {
  const calls: FetchStub['calls'] = [];
  const fetch = async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = String(url);
    calls.push({ url: u, method: init?.method ?? 'GET', body: init?.body });
    return handler(u, init, calls.length);
  };
  return { fetch: fetch as unknown as FetchLike, calls };
}

function makeClient(fetchImpl: FetchLike): VirusTotalClient {
  return new VirusTotalClient({
    apiKey: 'test-key',
    fetchImpl,
    maxRetries: 2,
    retryBaseDelayMs: 1,
    requestTimeoutMs: 1000,
    uploadTimeoutMs: 1000,
    maxRetryAfterMs: 50,
  });
}

const FILE_REPORT = {
  data: {
    id: 'a'.repeat(64),
    attributes: {
      sha256: 'a'.repeat(64),
      last_analysis_date: 1771600000,
      size: 123456,
      meaningful_name: 'game.apk',
      last_analysis_stats: {
        malicious: 3,
        suspicious: 1,
        undetected: 60,
        harmless: 5,
        timeout: 1,
        'type-unsupported': 2,
      },
      last_analysis_results: {
        'Kaspersky': { category: 'malicious', result: 'Trojan.AndroidOS.Hebe.d' },
        'ESET-NOD32': { category: 'malicious', result: 'A Variant Of Android/Spy.SpyNote' },
        'Microsoft': { category: 'suspicious', result: 'Possible Threat' },
        'Google': { category: 'undetected', result: null },
        'CrowdStrike': { category: 'malicious', result: 'malicious/confidence/90' },
      },
    },
  },
};

describe('VirusTotalClient.getFileReport', () => {
  it('normalizes an existing report', async () => {
    const { fetch, calls } = stubFetch(() => Promise.resolve(jsonResponse(200, FILE_REPORT)));
    const report = await makeClient(fetch).getFileReport('a'.repeat(64));
    expect(report).not.toBeNull();
    expect(report!.stats).toEqual({
      malicious: 3,
      suspicious: 1,
      undetected: 60,
      harmless: 5,
      timeout: 1,
      other: 2,
    });
    expect(report!.totalEngines).toBe(72);
    expect(report!.lastAnalysisDate).toBe(1771600000);
    expect(report!.meaningfulName).toBe('game.apk');
    expect(report!.detections).toEqual([
      { engine: 'Kaspersky', category: 'malicious', result: 'Trojan.AndroidOS.Hebe.d' },
      { engine: 'ESET-NOD32', category: 'malicious', result: 'A Variant Of Android/Spy.SpyNote' },
      { engine: 'Microsoft', category: 'suspicious', result: 'Possible Threat' },
      { engine: 'CrowdStrike', category: 'malicious', result: 'malicious/confidence/90' },
    ]);
    expect(calls[0]!.url).toContain('/api/v3/files/aaaaaaaa');
    expect(calls.length).toBe(1);
  });

  it('caps extracted detections at 8 entries', async () => {
    const results: Record<string, { category: string; result: string }> = {};
    for (let i = 0; i < 12; i++) results[`engine${i}`] = { category: 'malicious', result: 'bad' };
    const { fetch } = stubFetch(() =>
      Promise.resolve(
        jsonResponse(200, {
          data: { attributes: { last_analysis_stats: { malicious: 12 }, last_analysis_results: results } },
        }),
      ),
    );
    const report = await makeClient(fetch).getFileReport('a'.repeat(64));
    expect(report!.detections.length).toBe(8);
  });

  it('returns null for an unknown hash (404) without retrying', async () => {
    const { fetch, calls } = stubFetch(() => Promise.resolve(new Response(null, { status: 404 })));
    const report = await makeClient(fetch).getFileReport('b'.repeat(64));
    expect(report).toBeNull();
    expect(calls.length).toBe(1);
  });

  it('retries a 429 and succeeds when Retry-After is small', async () => {
    const { fetch, calls } = stubFetch((_url, _init, call) =>
      call === 1
        ? Promise.resolve(jsonResponse(429, { error: 'QuotaExceededError' }, { 'retry-after': '0' }))
        : Promise.resolve(jsonResponse(200, FILE_REPORT)),
    );
    const report = await makeClient(fetch).getFileReport('a'.repeat(64));
    expect(report).not.toBeNull();
    expect(calls.length).toBe(2);
  });

  it('surfaces persistent 429s as a quota error', async () => {
    const { fetch, calls } = stubFetch(() =>
      Promise.resolve(jsonResponse(429, { error: 'QuotaExceededError' }, { 'retry-after': '0' })),
    );
    await expect(makeClient(fetch).getFileReport('a'.repeat(64))).rejects.toBeInstanceOf(VirusTotalQuotaError);
    expect(calls.length).toBe(3); // maxRetries=2 → 3 attempts
  });

  it('fails fast when Retry-After exceeds the configured cap', async () => {
    const { fetch, calls } = stubFetch(() =>
      Promise.resolve(jsonResponse(429, { error: 'QuotaExceededError' }, { 'retry-after': '3600' })),
    );
    await expect(makeClient(fetch).getFileReport('a'.repeat(64))).rejects.toBeInstanceOf(VirusTotalQuotaError);
    expect(calls.length).toBe(1);
  });

  it('treats 401 as a fatal auth error without retrying', async () => {
    const { fetch, calls } = stubFetch(() => Promise.resolve(jsonResponse(401, { error: 'AuthenticationError' })));
    await expect(makeClient(fetch).getFileReport('a'.repeat(64))).rejects.toBeInstanceOf(VirusTotalAuthError);
    expect(calls.length).toBe(1);
  });

  it('treats 403 as a fatal auth error', async () => {
    const { fetch, calls } = stubFetch(() =>
      Promise.resolve(jsonResponse(403, { error: { message: 'NotAllowedError' } })),
    );
    await expect(makeClient(fetch).getFileReport('a'.repeat(64))).rejects.toBeInstanceOf(VirusTotalAuthError);
    expect(calls.length).toBe(1);
  });

  it('retries transient 5xx responses and then succeeds', async () => {
    const { fetch, calls } = stubFetch((_url, _init, call) =>
      call <= 2 ? Promise.resolve(new Response('boom', { status: 502 })) : Promise.resolve(jsonResponse(200, FILE_REPORT)),
    );
    const report = await makeClient(fetch).getFileReport('a'.repeat(64));
    expect(report).not.toBeNull();
    expect(calls.length).toBe(3);
  });

  it('retries network failures and gives up as an API error', async () => {
    const { fetch, calls } = stubFetch(() => Promise.reject(new TypeError('fetch failed')));
    await expect(makeClient(fetch).getFileReport('a'.repeat(64))).rejects.toBeInstanceOf(VirusTotalApiError);
    expect(calls.length).toBe(3);
  });

  it('does not retry unexpected 4xx responses', async () => {
    const { fetch, calls } = stubFetch(() => Promise.resolve(new Response('nope', { status: 418 })));
    await expect(makeClient(fetch).getFileReport('a'.repeat(64))).rejects.toBeInstanceOf(VirusTotalApiError);
    expect(calls.length).toBe(1);
  });
});

describe('VirusTotalClient.uploadFile', () => {
  it('posts multipart form data and returns the analysis id', async () => {
    const { fetch, calls } = stubFetch((_url, _init, call) =>
      call === 1
        ? Promise.resolve(jsonResponse(200, { data: { id: 'analysis-xyz', type: 'analysis' } }))
        : Promise.resolve(jsonResponse(200, FILE_REPORT)),
    );
    const client = makeClient(fetch);
    const { analysisId } = await client.uploadFile('tests/fixtures/dummy.txt', 'dummy.apk');
    expect(analysisId).toBe('analysis-xyz');
    expect(calls[0]!.url).toContain('/api/v3/files');
    expect(calls[0]!.body).toBeInstanceOf(FormData);
    expect((calls[0]!.body as FormData).get('file')).toBeInstanceOf(Blob);
  });
});

describe('VirusTotalClient.pollAnalysis', () => {
  const completedAnalysis = {
    data: { id: 'analysis-xyz', attributes: { status: 'completed', stats: { malicious: 3 } } },
    meta: { file_sha256: 'a'.repeat(64) },
  };

  it('polls until completed and returns the full file report', async () => {
    const { fetch, calls } = stubFetch((url, _init, call) => {
      if (url.includes('/api/v3/analyses/')) {
        return Promise.resolve(
          call === 1
            ? jsonResponse(200, { data: { attributes: { status: 'queued' } } })
            : jsonResponse(200, completedAnalysis),
        );
      }
      return Promise.resolve(jsonResponse(200, FILE_REPORT));
    });
    const onTick = vi.fn();
    const report = await makeClient(fetch).pollAnalysis(
      'analysis-xyz',
      { intervalMs: 1, timeoutMs: 5000 },
      onTick,
    );
    expect(report.sha256).toBe('a'.repeat(64));
    expect(report.totalEngines).toBe(72);
    expect(onTick).toHaveBeenCalledTimes(1);
    expect(calls.length).toBe(3); // queued, completed, file report
  });

  it('falls back to analysis stats when the file report is missing', async () => {
    const { fetch } = stubFetch((url) => {
      if (url.includes('/api/v3/analyses/')) return Promise.resolve(jsonResponse(200, completedAnalysis));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    const report = await makeClient(fetch).pollAnalysis('analysis-xyz', { intervalMs: 1, timeoutMs: 5000 });
    expect(report.stats.malicious).toBe(3);
    expect(report.totalEngines).toBe(3);
  });

  it('throws AnalysisTimeoutError when the analysis never completes', async () => {
    const { fetch } = stubFetch(() =>
      Promise.resolve(jsonResponse(200, { data: { attributes: { status: 'running' } } })),
    );
    await expect(
      makeClient(fetch).pollAnalysis('analysis-xyz', { intervalMs: 1, timeoutMs: 15 }),
    ).rejects.toBeInstanceOf(AnalysisTimeoutError);
  });
});
