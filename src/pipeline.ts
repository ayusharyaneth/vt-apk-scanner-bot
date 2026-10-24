import { randomUUID } from 'node:crypto';
import type { AiScanContext, AiSummarizer } from './ai';
import { buildSummaryPrompt } from './ai';
import { sanitizeFileName, sha256File, validateApkFile } from './apk';
import { classifyDetection } from './classify';
import type { Verdict } from './classify';
import type { Logger } from './logger';
import {
  formatScanFailure,
  formatScanReport,
  progressAnalyzing,
  progressCheckingVt,
  progressDownloaded,
  progressQueued,
  progressReceiving,
  progressUploading,
} from './report';
import type { ReportSource } from './report';
import { createScanDir, removeScanDir } from './tempfiles';
import type { ProgressReporter } from './telegram';
import type { Downloader } from './telegram';
import {
  AnalysisTimeoutError,
  VirusTotalApiError,
  VirusTotalAuthError,
  VirusTotalQuotaError,
} from './virustotal';
import type { VTFileReport } from './virustotal';
import { escapeHtml, formatBytes } from './util';

export interface ScanRuntimeConfig {
  authorizedIds: Set<number>;
  maxApkBytes: number;
  allowUploads: boolean;
  vtPollIntervalMs: number;
  vtPollTimeoutMs: number;
  vtReuseMaxAgeHours: number;
  cacheTtlMs: number;
  maliciousThreshold: number;
  suspiciousThreshold: number;
  unauthorizedReply: boolean;
}

/** Narrow interface over the VirusTotal client so tests can fake it. */
export interface VTApi {
  getFileReport(sha256: string): Promise<VTFileReport | null>;
  uploadFile(filePath: string, fileName: string): Promise<{ analysisId: string }>;
  pollAnalysis(
    analysisId: string,
    opts: { intervalMs: number; timeoutMs: number },
    onTick?: (attempt: number, status: string) => void,
  ): Promise<VTFileReport>;
}

export interface ScanJob {
  chatId: number;
  userId: number;
  userName?: string;
  fileId: string;
  fileName: string;
  fileSize?: number;
  /** Force a fresh VirusTotal analysis even if a report exists. */
  fresh: boolean;
}

export type ScanStatus = Verdict | 'unauthorized';

export interface ScanResult {
  scanId: string;
  status: ScanStatus;
  sha256?: string;
  error?: string;
}

export interface ScanDeps {
  cfg: ScanRuntimeConfig;
  vt: VTApi;
  reporter: ProgressReporter;
  downloader: Downloader;
  cache: ResultCache;
  inflight: Map<string, Promise<VTFileReport>>;
  log: Logger;
  /** Injectable for tests; defaults to a real mkdtemp under the OS temp dir. */
  createTempDir?: () => Promise<string>;
  /** Optional AI summarizer (GLM); absent → no AI section in reports. */
  ai?: AiSummarizer | null;
  now?: () => number;
}

export interface ResultCache {
  get(sha256: string): VTFileReport | null;
  set(sha256: string, report: VTFileReport): void;
}

export function createResultCache(ttlMs: number): ResultCache {
  const store = new Map<string, { report: VTFileReport; expiresAt: number }>();
  return {
    get(sha256) {
      const hit = store.get(sha256);
      if (!hit) return null;
      if (Date.now() > hit.expiresAt) {
        store.delete(sha256);
        return null;
      }
      return hit.report;
    },
    set(sha256, report) {
      if (ttlMs <= 0) return;
      store.set(sha256, { report, expiresAt: Date.now() + ttlMs });
    },
  };
}

export async function runScan(job: ScanJob, deps: ScanDeps): Promise<ScanResult> {
  const scanId = randomUUID();
  const now = deps.now ?? Date.now;
  const startedMs = now();
  const log = deps.log;
  const fileName = sanitizeFileName(job.fileName);

  log.info('scan.started', {
    scanId,
    chatId: job.chatId,
    userId: job.userId,
    fileName,
    fileSize: job.fileSize ?? null,
    fresh: job.fresh,
  });

  if (!deps.cfg.authorizedIds.has(job.userId) && !deps.cfg.authorizedIds.has(job.chatId)) {
    log.warn('scan.unauthorized', { scanId, chatId: job.chatId, userId: job.userId });
    if (deps.cfg.unauthorizedReply) {
      await deps.reporter.notify('⛔ You are not authorized to use this bot. This incident was logged.');
    }
    return { scanId, status: 'unauthorized' };
  }

  let sha: string | undefined;

  const fail = async (code: string, userReason: string, extra: Record<string, unknown> = {}): Promise<ScanResult> => {
    log.error('scan.failed', { scanId, code, sha256: sha ?? null, ...extra });
    await deps.reporter.final(
      formatScanFailure({ scanId, fileName, sha256: sha ?? null, reason: userReason }),
    );
    return { scanId, status: 'FAILED', sha256: sha, error: code };
  };

  const failFromError = async (e: unknown): Promise<ScanResult> => {
    if (e instanceof AnalysisTimeoutError) {
      return fail(
        'analysis_timeout',
        `VirusTotal did not finish the analysis within ${Math.round(deps.cfg.vtPollTimeoutMs / 1000)}s. This does NOT mean the file is clean — open the link below later for the finished analysis.`,
        { error: e.message },
      );
    }
    if (e instanceof VirusTotalQuotaError) {
      return fail('vt_rate_limited', 'VirusTotal rate limit or daily quota was reached. Please try again later. This does NOT mean the file is clean.', { error: e.message });
    }
    if (e instanceof VirusTotalAuthError) {
      return fail('vt_auth', 'The VirusTotal API rejected our credentials (check VIRUSTOTAL_API_KEY and account permissions). Nothing was scanned.', { error: e.message });
    }
    if (e instanceof VirusTotalApiError) {
      return fail('vt_error', 'The VirusTotal API failed while processing this file. This does NOT mean the file is clean.', { error: e.message });
    }
    return fail('internal_error', 'An internal error occurred while scanning. This does NOT mean the file is clean. Check the bot logs.', {
      error: e instanceof Error ? e.message : String(e),
    });
  };

  await deps.reporter.begin(progressReceiving(fileName, job.fileSize ?? null));

  if (job.fileSize !== undefined && job.fileSize > deps.cfg.maxApkBytes) {
    return fail(
      'file_too_large',
      `The file is ${formatBytes(job.fileSize)} — larger than this bot's limit of ${formatBytes(deps.cfg.maxApkBytes)}. It was not downloaded from Telegram and nothing was uploaded.`,
    );
  }

  let dir: string;
  try {
    dir = await (deps.createTempDir ?? createScanDir)();
  } catch (e) {
    return fail('temp_dir_failed', 'Could not create a secure temporary directory on the server (disk full or permission problem). Nothing was downloaded or scanned.', {
      error: e instanceof Error ? e.message : String(e),
    });
  }
  try {
    const dl = await deps.downloader.downloadTo(job.fileId, dir);
    log.info('scan.downloaded', { scanId, bytes: dl.bytes });
    await deps.reporter.progress(progressDownloaded(fileName, dl.bytes));

    const validation = await validateApkFile(dl.filePath);
    if (!validation.ok) {
      return fail('invalid_apk', `"${fileName}" does not appear to be a valid Android package: ${validation.reason}. Nothing was uploaded.`);
    }

    sha = await sha256File(dl.filePath);
    log.info('scan.hash', { scanId, sha256: sha, entries: validation.entryCount });
    await deps.reporter.progress(progressCheckingVt(fileName, sha));

    const finish = async (report: VTFileReport, source: ReportSource): Promise<ScanResult> => {
      if (!sha) {
        return fail('internal_error', 'Internal error: scan finished without a computed hash.');
      }
      const detection = classifyDetection(report.stats, deps.cfg);
      // The locally computed hash is authoritative. VirusTotal sometimes
      // omits the sha256 in analysis responses (reporting 'unknown') —
      // never surface that; the real hash is always known here.
      if (!/^[a-f0-9]{64}$/i.test(report.sha256)) {
        report.sha256 = sha;
      }
      if (detection.verdict === 'FAILED') {
        return fail('no_engine_results', 'VirusTotal returned results from zero engines, so no verdict can be given. This does NOT mean the file is clean.', {
          detection: detection.reason,
        });
      }
      const endedMs = now();
      const text = formatScanReport({
        fileName,
        sizeBytes: report.size ?? dl.bytes,
        sha256: report.sha256,
        verdict: detection.verdict,
        reason: detection.reason,
        stats: report.stats,
        totalEngines: report.totalEngines,
        completedAtEpochSec: source === 'fresh' || source === 'inflight'
          ? Math.floor(endedMs / 1000)
          : report.lastAnalysisDate,
        durationSec: source === 'fresh' || source === 'inflight' ? Math.round((endedMs - startedMs) / 1000) : null,
        source,
      });
      await deps.reporter.final(text);
      // Key the cache by the locally computed hash — never by a VT-provided value.
      deps.cache.set(sha, report);
      await appendAiSummary(deps, detection.verdict, fileName, report);
      log.info('scan.completed', {
        scanId,
        sha256: report.sha256,
        verdict: detection.verdict,
        source,
        malicious: report.stats.malicious,
        suspicious: report.stats.suspicious,
        totalEngines: report.totalEngines,
      });
      return { scanId, status: detection.verdict, sha256: report.sha256 };
    };

    if (!job.fresh) {
      const cached = deps.cache.get(sha);
      if (cached) return finish(cached, 'cache');

      const existing = await deps.vt.getFileReport(sha);
      if (existing) {
        if (isReusable(existing, deps.cfg, now)) {
          return finish(existing, 'existing');
        }
        log.info('scan.stale_report', { scanId, sha256: sha, lastAnalysisDate: existing.lastAnalysisDate });
      }
    } else {
      log.info('scan.fresh_requested', { scanId, sha256: sha });
    }

    if (!deps.cfg.allowUploads) {
      return fail('uploads_disabled', 'No existing VirusTotal report was found for this file, and automatic uploads are disabled by policy (ALLOW_UPLOADS=false). Nothing was uploaded.');
    }

    // Merge duplicate concurrent uploads of the identical file into one analysis.
    if (!job.fresh) {
      const running = deps.inflight.get(sha);
      if (running) {
        log.info('scan.inflight_merged', { scanId, sha256: sha });
        return finish(await running, 'inflight');
      }
    }

    await deps.reporter.progress(progressUploading(fileName));
    const analysisPromise = (async () => {
      const { analysisId } = await deps.vt.uploadFile(dl.filePath, fileName);
      log.info('scan.uploaded', { scanId, analysisId });
      await deps.reporter.progress(progressQueued(fileName));
      return await deps.vt.pollAnalysis(
        analysisId,
        { intervalMs: deps.cfg.vtPollIntervalMs, timeoutMs: deps.cfg.vtPollTimeoutMs },
        async (attempt, status) => {
          await deps.reporter.progress(progressAnalyzing(fileName, Math.round((now() - startedMs) / 1000)));
        },
      );
    })();
    deps.inflight.set(sha, analysisPromise);
    try {
      const report = await analysisPromise;
      return finish(report, 'fresh');
    } finally {
      deps.inflight.delete(sha);
    }
  } catch (e) {
    return failFromError(e);
  } finally {
    await removeScanDir(dir);
  }
}

function isReusable(report: VTFileReport, cfg: ScanRuntimeConfig, now: () => number): boolean {
  if (report.totalEngines <= 0) return false;
  if (cfg.vtReuseMaxAgeHours <= 0) return true; // always reuse existing reports
  if (!report.lastAnalysisDate) return false;
  const ageSec = Math.floor(now() / 1000) - report.lastAnalysisDate;
  return ageSec <= cfg.vtReuseMaxAgeHours * 3600;
}

/**
 * Best-effort AI commentary, sent as a separate message after the canonical
 * VirusTotal report. Any failure is logged and skipped — it must never
 * affect the scan outcome or the report itself.
 */
async function appendAiSummary(
  deps: ScanDeps,
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS',
  fileName: string,
  report: VTFileReport,
): Promise<void> {
  const ai = deps.ai;
  if (!ai) return;
  try {
    const ctx: AiScanContext = {
      fileName,
      verdict,
      stats: report.stats,
      totalEngines: report.totalEngines,
      detections: report.detections,
    };
    let text = await ai.summarize(buildSummaryPrompt(ctx));
    if (text.length > 1200) text = text.slice(0, 1200) + '…';
    await deps.reporter.notify(`🤖 <b>AI analysis (${escapeHtml(ai.model)}):</b>\n${escapeHtml(text)}`);
    deps.log.info('scan.ai_summary', { model: ai.model });
  } catch (e) {
    deps.log.warn('scan.ai_summary_failed', {
      model: ai.model,
      error: e instanceof Error ? e.message : String(e),
    });
  }
}
