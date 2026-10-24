import { promises as fsp } from 'node:fs';
import { jitter, sleep } from './util';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class VirusTotalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VirusTotalError';
  }
}
/** 401/403 — wrong API key or disallowed operation. Never retried. */
export class VirusTotalAuthError extends VirusTotalError {
  constructor(message: string) {
    super(message);
    this.name = 'VirusTotalAuthError';
  }
}
/** 429 that persisted across retries or asks for an unreasonably long wait. */
export class VirusTotalQuotaError extends VirusTotalError {
  constructor(message: string) {
    super(message);
    this.name = 'VirusTotalQuotaError';
  }
}
export class VirusTotalApiError extends VirusTotalError {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = 'VirusTotalApiError';
  }
}
export class AnalysisTimeoutError extends VirusTotalError {
  constructor(message: string) {
    super(message);
    this.name = 'AnalysisTimeoutError';
  }
}

export interface VTDetectionStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  timeout: number;
  /** Every other VT category (type-unsupported, confirmed-timeout, memory-exception, …). */
  other: number;
}

export interface VTDetection {
  engine: string;
  category: string;
  result: string;
}

export interface VTFileReport {
  sha256: string;
  stats: VTDetectionStats;
  totalEngines: number;
  /** Unix seconds of VirusTotal's own last analysis, if known. */
  lastAnalysisDate: number | null;
  size: number | null;
  meaningfulName: string | null;
  /** Engines that flagged the file as malicious/suspicious (for AI context). */
  detections: VTDetection[];
}

export function normalizeStats(raw: Record<string, unknown> | null | undefined): VTDetectionStats | null {
  if (!raw || typeof raw !== 'object') return null;
  const num = (v: unknown): number =>
    typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0;
  const known = new Set(['malicious', 'suspicious', 'undetected', 'harmless', 'timeout']);
  const out: VTDetectionStats = {
    malicious: num(raw['malicious']),
    suspicious: num(raw['suspicious']),
    undetected: num(raw['undetected']),
    harmless: num(raw['harmless']),
    timeout: num(raw['timeout']),
    other: 0,
  };
  for (const [k, v] of Object.entries(raw)) {
    if (!known.has(k)) out.other += num(v);
  }
  return out;
}

export function totalEngines(s: VTDetectionStats): number {
  return s.malicious + s.suspicious + s.undetected + s.harmless + s.timeout + s.other;
}

export function vtFileLink(sha256: string): string {
  return `https://www.virustotal.com/gui/file/${sha256}`;
}

interface VTFileEnvelope {
  data?: { id?: string; attributes?: Record<string, unknown> };
}
interface VTAnalysisEnvelope {
  data?: { id?: string; attributes?: { status?: string; stats?: Record<string, unknown> } };
  meta?: { file_sha256?: string };
}

export interface VirusTotalClientOptions {
  apiKey: string;
  baseUrl?: string;
  fetchImpl?: FetchLike;
  maxRetries?: number;
  retryBaseDelayMs?: number;
  requestTimeoutMs?: number;
  uploadTimeoutMs?: number;
  /** Cap on Retry-After waits; longer waits surface as quota errors instead of stalling. */
  maxRetryAfterMs?: number;
}

interface RequestOptions {
  body?: RequestInit['body'];
  timeoutMs?: number;
  allow404?: boolean;
}

export class VirusTotalClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly requestTimeoutMs: number;
  private readonly uploadTimeoutMs: number;
  private readonly maxRetryAfterMs: number;

  constructor(opts: VirusTotalClientOptions) {
    this.apiKey = opts.apiKey;
    this.baseUrl = (opts.baseUrl ?? 'https://www.virustotal.com').replace(/\/+$/, '');
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
    this.maxRetries = opts.maxRetries ?? 3;
    this.retryBaseDelayMs = opts.retryBaseDelayMs ?? 500;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 30_000;
    this.uploadTimeoutMs = opts.uploadTimeoutMs ?? 120_000;
    this.maxRetryAfterMs = opts.maxRetryAfterMs ?? 60_000;
  }

  /** Existing file report by hash; null when VirusTotal has never seen the hash. */
  async getFileReport(sha256: string): Promise<VTFileReport | null> {
    const json = (await this.request('GET', `/api/v3/files/${sha256}`, {
      allow404: true,
    })) as VTFileEnvelope | null;
    if (!json) return null;
    const attrs = json.data?.attributes ?? {};
    const stats = normalizeStats(attrs['last_analysis_stats'] as Record<string, unknown> | undefined);
    if (!stats) return null; // known hash but never analysed → treat as unknown
    const lastAnalysisDate = attrs['last_analysis_date'];
    return {
      sha256: (attrs['sha256'] as string) ?? json.data?.id ?? sha256,
      stats,
      totalEngines: totalEngines(stats),
      lastAnalysisDate: typeof lastAnalysisDate === 'number' ? lastAnalysisDate : null,
      size: typeof attrs['size'] === 'number' ? (attrs['size'] as number) : null,
      meaningfulName: typeof attrs['meaningful_name'] === 'string' ? (attrs['meaningful_name'] as string) : null,
      detections: extractDetections(attrs['last_analysis_results']),
    };
  }

  async uploadFile(filePath: string, fileName: string): Promise<{ analysisId: string }> {
    const bytes = await fsp.readFile(filePath);
    const form = new FormData();
    form.append('file', new Blob([new Uint8Array(bytes)]), fileName);
    const json = (await this.request('POST', '/api/v3/files', {
      body: form,
      timeoutMs: this.uploadTimeoutMs,
    })) as { data?: { id?: string } };
    const analysisId = json?.data?.id;
    if (!analysisId) throw new VirusTotalApiError('VirusTotal upload response did not contain an analysis id');
    return { analysisId };
  }

  async getAnalysis(analysisId: string): Promise<VTAnalysisEnvelope> {
    return (await this.request('GET', `/api/v3/analyses/${analysisId}`)) as VTAnalysisEnvelope;
  }

  /**
   * Poll an analysis until VirusTotal reports it completed, then fetch the
   * full file report (falls back to the analysis' own stats if the file
   * report is not yet readable). Throws AnalysisTimeoutError on timeout —
   * the caller must treat that as FAILED, never clean.
   */
  async pollAnalysis(
    analysisId: string,
    opts: { intervalMs: number; timeoutMs: number },
    onTick?: (attempt: number, status: string) => void,
  ): Promise<VTFileReport> {
    const deadline = Date.now() + opts.timeoutMs;
    let attempt = 0;
    for (;;) {
      attempt++;
      const envelope = await this.getAnalysis(analysisId);
      const status = envelope?.data?.attributes?.status ?? 'unknown';
      if (status === 'completed') {
        const sha = envelope?.meta?.file_sha256 ?? null;
        if (sha) {
          const report = await this.getFileReport(sha).catch(() => null);
          if (report && report.totalEngines > 0) return report;
        }
        const stats = normalizeStats(envelope?.data?.attributes?.stats);
        if (stats) {
          return {
            sha256: sha ?? 'unknown',
            stats,
            totalEngines: totalEngines(stats),
            lastAnalysisDate: Math.floor(Date.now() / 1000),
            size: null,
            meaningfulName: null,
            detections: [],
          };
        }
        throw new VirusTotalApiError('VirusTotal analysis completed but returned no engine stats');
      }
      onTick?.(attempt, status);
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new AnalysisTimeoutError(
          `VirusTotal analysis ${analysisId} did not complete within ${Math.round(opts.timeoutMs / 1000)}s (last status: ${status})`,
        );
      }
      await sleep(Math.min(opts.intervalMs, remaining));
    }
  }

  private async request(method: string, path: string, opts: RequestOptions = {}): Promise<unknown> {
    const url = `${this.baseUrl}${path}`;
    const maxAttempts = this.maxRetries + 1;
    let attempt = 0;
    let lastStatus: number | undefined;
    let lastWhy = '';
    for (;;) {
      attempt++;
      let retryDelayMs: number | null = null;
      try {
        const res = await this.fetchImpl(url, {
          method,
          headers: { 'x-apikey': this.apiKey, accept: 'application/json' },
          body: opts.body,
          signal: AbortSignal.timeout(opts.timeoutMs ?? this.requestTimeoutMs),
        });
        if (res.ok) {
          const text = await res.text();
          return text ? (JSON.parse(text) as unknown) : null;
        }
        lastStatus = res.status;
        const errText = await res.text().catch(() => '');
        if (res.status === 404 && opts.allow404) return null;
        if (res.status === 401) {
          throw new VirusTotalAuthError('VirusTotal rejected the API key (HTTP 401)');
        }
        if (res.status === 403) {
          throw new VirusTotalAuthError(`VirusTotal denied the request (HTTP 403)${summarizeBody(errText)}`);
        }
        if (res.status === 429) {
          const retryAfterMs = parseRetryAfterMs(res.headers.get('retry-after'));
          if (retryAfterMs !== null && retryAfterMs > this.maxRetryAfterMs) {
            throw new VirusTotalQuotaError(
              `VirusTotal rate limit asks to wait ${Math.round(retryAfterMs / 1000)}s — too long to hold the scan`,
            );
          }
          retryDelayMs = retryAfterMs ?? this.backoffMs(attempt);
          lastWhy = `HTTP 429${summarizeBody(errText)}`;
        } else if (res.status >= 500 || res.status === 408) {
          retryDelayMs = this.backoffMs(attempt);
          lastWhy = `HTTP ${res.status}`;
        } else {
          throw new VirusTotalApiError(
            `VirusTotal returned HTTP ${res.status} for ${method} ${path}${summarizeBody(errText)}`,
            res.status,
          );
        }
        await res.body?.cancel().catch(() => {});
      } catch (e) {
        if (e instanceof VirusTotalError) throw e;
        retryDelayMs = this.backoffMs(attempt);
        lastWhy = e instanceof Error ? e.message : String(e);
        lastStatus = undefined;
      }
      if (attempt >= maxAttempts) {
        if (lastStatus === 429) {
          throw new VirusTotalQuotaError(
            `VirusTotal rate limit persisted after ${attempt} attempts (${lastWhy})`,
          );
        }
        throw new VirusTotalApiError(`VirusTotal request failed after ${attempt} attempts: ${lastWhy || 'unknown error'}`);
      }
      await sleep(retryDelayMs ?? this.backoffMs(attempt));
    }
  }

  private backoffMs(attempt: number): number {
    return this.retryBaseDelayMs * 2 ** (attempt - 1) + jitter(250);
  }
}

const DETECTION_LIMIT = 8;

/**
 * Pull engine results flagged as malicious/suspicious out of the VT
 * last_analysis_results map, capped at DETECTION_LIMIT entries.
 */
export function extractDetections(
  raw: unknown,
): VTDetection[] {
  if (!raw || typeof raw !== 'object') return [];
  const out: VTDetection[] = [];
  for (const [engine, entry] of Object.entries(raw as Record<string, unknown>)) {
    if (out.length >= DETECTION_LIMIT) break;
    if (!entry || typeof entry !== 'object') continue;
    const category = (entry as Record<string, unknown>)['category'];
    const result = (entry as Record<string, unknown>)['result'];
    if ((category === 'malicious' || category === 'suspicious') && typeof result === 'string') {
      out.push({ engine, category, result: result.slice(0, 80) });
    }
  }
  return out;
}

function parseRetryAfterMs(header: string | null): number | null {
  if (!header) return null;
  if (/^\d+$/.test(header.trim())) return Number(header.trim()) * 1000;
  const date = Date.parse(header);
  return Number.isNaN(date) ? null : Math.max(0, date - Date.now());
}

function summarizeBody(text: string): string {
  if (!text) return '';
  try {
    const json = JSON.parse(text) as { error?: { message?: string } | string };
    const message = typeof json.error === 'string' ? json.error : json.error?.message;
    return message ? `: ${message}` : '';
  } catch {
    return '';
  }
}
