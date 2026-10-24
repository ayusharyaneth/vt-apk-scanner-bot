import { createHash } from 'node:crypto';
import { existsSync, promises as fsp } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildApk } from './helpers/zip';
import { createResultCache, runScan } from '../src/pipeline';
import type { ScanDeps, ScanJob, ScanRuntimeConfig, VTApi } from '../src/pipeline';
import type { ProgressReporter } from '../src/telegram';
import { createLogger } from '../src/logger';
import {
  AnalysisTimeoutError,
  VirusTotalApiError,
  VirusTotalQuotaError,
} from '../src/virustotal';
import type { VTFileReport } from '../src/virustotal';

const APK_BYTES = buildApk();
const APK_SHA256 = createHash('sha256').update(APK_BYTES).digest('hex');
const AUTHORIZED_USER = 42;
const CHAT_ID = 1001;

function makeStats(overrides: Partial<VTFileReport['stats']> = {}): VTFileReport['stats'] {
  return { malicious: 0, suspicious: 0, undetected: 65, harmless: 5, timeout: 0, other: 0, ...overrides };
}

function makeReport(overrides: Partial<VTFileReport> = {}): VTFileReport {
  return {
    sha256: APK_SHA256,
    stats: makeStats(),
    totalEngines: 70,
    lastAnalysisDate: Math.floor(Date.now() / 1000) - 60,
    size: APK_BYTES.length,
    meaningfulName: 'game.apk',
    detections: [],
    ...overrides,
  };
}

class FakeReporter implements ProgressReporter {
  events: Array<{ kind: 'begin' | 'progress' | 'final' | 'notify'; text: string }> = [];

  async begin(text: string): Promise<void> {
    this.events.push({ kind: 'begin', text });
  }

  async progress(text: string): Promise<void> {
    this.events.push({ kind: 'progress', text });
  }

  async final(text: string): Promise<void> {
    this.events.push({ kind: 'final', text });
  }

  async notify(text: string): Promise<void> {
    this.events.push({ kind: 'notify', text });
  }

  get finalText(): string {
    const finals = this.events.filter((e) => e.kind === 'final');
    return finals[finals.length - 1]?.text ?? '';
  }
}

class FakeDownloader {
  lastDestDir: string | null = null;
  calls = 0;

  constructor(private readonly bytes: Buffer = APK_BYTES) {}

  downloadTo = async (_fileId: string, destDir: string): Promise<{ filePath: string; bytes: number }> => {
    this.calls++;
    this.lastDestDir = destDir;
    const filePath = join(destDir, 'payload.apk');
    await fsp.writeFile(filePath, this.bytes);
    return { filePath, bytes: this.bytes.length };
  };
}

function makeVt(): VTApi & { getFileReport: ReturnType<typeof vi.fn>; uploadFile: ReturnType<typeof vi.fn>; pollAnalysis: ReturnType<typeof vi.fn> } {
  return {
    getFileReport: vi.fn(),
    uploadFile: vi.fn(),
    pollAnalysis: vi.fn(),
  };
}

function makeDeps(overrides: Partial<ScanDeps> = {}): { deps: ScanDeps; reporter: FakeReporter; downloader: FakeDownloader; vt: ReturnType<typeof makeVt> } {
  const cfg: ScanRuntimeConfig = {
    authorizedIds: new Set([AUTHORIZED_USER]),
    maxApkBytes: 20 * 1024 * 1024,
    allowUploads: true,
    vtPollIntervalMs: 5,
    vtPollTimeoutMs: 200,
    vtReuseMaxAgeHours: 24,
    cacheTtlMs: 10 * 60_000,
    maliciousThreshold: 3,
    suspiciousThreshold: 1,
    unauthorizedReply: true,
  };
  const reporter = new FakeReporter();
  const downloader = new FakeDownloader();
  const vt = makeVt();
  const deps: ScanDeps = {
    cfg,
    vt,
    reporter,
    downloader,
    cache: createResultCache(cfg.cacheTtlMs),
    inflight: new Map(),
    log: createLogger('error'),
    ...overrides,
  };
  // Return the post-override instances so tests always observe the real ones.
  return {
    deps,
    reporter: deps.reporter as FakeReporter,
    downloader: deps.downloader as FakeDownloader,
    vt: deps.vt as ReturnType<typeof makeVt>,
  };
}

function makeJob(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    chatId: CHAT_ID,
    userId: AUTHORIZED_USER,
    userName: 'tester',
    fileId: 'file-1',
    fileName: 'game.apk',
    fileSize: APK_BYTES.length,
    fresh: false,
    ...overrides,
  };
}

/** Fresh-scan default fakes: unknown hash, upload + immediate completion. */
function scriptFreshScan(vt: ReturnType<typeof makeVt>, report: VTFileReport = makeReport()): void {
  vt.getFileReport.mockResolvedValue(null);
  vt.uploadFile.mockResolvedValue({ analysisId: 'analysis-1' });
  vt.pollAnalysis.mockImplementation(async (_id: string, _opts: unknown, onTick?: (a: number, s: string) => void) => {
    onTick?.(1, 'running');
    return report;
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('runScan — happy paths', () => {
  it('uploads an unknown APK, completes a fresh scan and reports CLEAN', async () => {
    const { deps, reporter, downloader, vt } = makeDeps();
    scriptFreshScan(vt, makeReport());
    const result = await runScan(makeJob(), deps);

    expect(result.status).toBe('CLEAN');
    expect(result.sha256).toBe(APK_SHA256);
    const text = reporter.finalText;
    expect(text).toContain('Status: CLEAN');
    expect(text).toContain('game.apk');
    expect(text).toContain(APK_SHA256);
    expect(text).toContain('https://www.virustotal.com/gui/file/' + APK_SHA256);
    expect(text).toContain('70 total');
    expect(text).toContain('Completed:');
    expect(vt.uploadFile).toHaveBeenCalledTimes(1);
    // Progress updates were sent during download and analysis.
    const kinds = reporter.events.map((e) => e.kind);
    expect(kinds[0]).toBe('begin');
    expect(kinds).toContain('progress');
    expect(kinds[kinds.length - 1]).toBe('final');
    // Temp directory was removed.
    expect(downloader.lastDestDir).not.toBeNull();
    expect(existsSync(downloader.lastDestDir!)).toBe(false);
  });

  it('reports MALICIOUS when enough engines flag the file', async () => {
    const { deps, reporter, vt } = makeDeps();
    scriptFreshScan(vt, makeReport({ stats: makeStats({ malicious: 23, undetected: 42 }), totalEngines: 70 }));
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('MALICIOUS');
    expect(reporter.finalText).toContain('Status: MALICIOUS');
    expect(reporter.finalText).toContain('23 malicious');
    expect(reporter.finalText).toContain('23/70 engines');
  });

  it('reports SUSPICIOUS for 1–2 malicious detections', async () => {
    const { deps, reporter, vt } = makeDeps();
    scriptFreshScan(vt, makeReport({ stats: makeStats({ malicious: 1, undetected: 64 }) }));
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('SUSPICIOUS');
    expect(reporter.finalText).toContain('Status: SUSPICIOUS');
  });

  it('reuses a recent existing VirusTotal report without uploading', async () => {
    const { deps, reporter, vt } = makeDeps();
    vt.getFileReport.mockResolvedValue(makeReport({ lastAnalysisDate: Math.floor(Date.now() / 1000) - 3600 }));
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('CLEAN');
    expect(vt.uploadFile).not.toHaveBeenCalled();
    expect(reporter.finalText).toContain('Existing VirusTotal report reused');
  });

  it('re-analyzes when the existing report is older than the reuse window', async () => {
    const { deps, vt } = makeDeps();
    vt.getFileReport.mockResolvedValue(makeReport({ lastAnalysisDate: Math.floor(Date.now() / 1000) - 25 * 3600 }));
    scriptFreshScan(vt);
    vt.getFileReport.mockResolvedValueOnce(
      makeReport({ lastAnalysisDate: Math.floor(Date.now() / 1000) - 25 * 3600 }),
    );
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('CLEAN');
    expect(vt.uploadFile).toHaveBeenCalledTimes(1);
  });

  it('forces a fresh scan with fresh=true even when a recent report exists', async () => {
    const { deps, vt } = makeDeps();
    scriptFreshScan(vt);
    const result = await runScan(makeJob({ fresh: true }), deps);
    expect(result.status).toBe('CLEAN');
    expect(vt.getFileReport).not.toHaveBeenCalled();
    expect(vt.uploadFile).toHaveBeenCalledTimes(1);
  });
});

describe('runScan — duplicates and caching', () => {
  it('serves an immediate re-upload of the same file from cache without contacting VirusTotal', async () => {
    const { deps, vt } = makeDeps();
    scriptFreshScan(vt);
    await runScan(makeJob(), deps);
    expect(vt.getFileReport).toHaveBeenCalledTimes(1);
    expect(vt.uploadFile).toHaveBeenCalledTimes(1);

    const result = await runScan(makeJob({ fileId: 'file-2' }), deps);
    expect(result.status).toBe('CLEAN');
    expect(vt.getFileReport).toHaveBeenCalledTimes(1); // unchanged
    expect(vt.uploadFile).toHaveBeenCalledTimes(1); // unchanged
  });

  it('merges a concurrent duplicate upload into the in-flight analysis', async () => {
    const { deps, vt } = makeDeps();
    scriptFreshScan(vt);
    const first = runScan(makeJob(), deps);
    // Simulate a second scan of the identical file arriving while the first is in flight.
    const result2 = await runScan(makeJob({ fileId: 'file-2', userId: AUTHORIZED_USER }), deps);
    const result1 = await first;
    expect(result1.status).toBe('CLEAN');
    expect(result2.status).toBe('CLEAN');
  });
});

describe('runScan — authorization', () => {
  it('rejects unauthorized senders before downloading anything', async () => {
    const { deps, reporter, downloader } = makeDeps();
    const result = await runScan(makeJob({ userId: 999 }), deps);
    expect(result.status).toBe('unauthorized');
    expect(downloader.calls).toBe(0);
    expect(reporter.events.some((e) => e.kind === 'notify' && e.text.includes('not authorized'))).toBe(true);
  });

  it('stays silent for unauthorized senders when unauthorizedReply=false', async () => {
    const { deps, reporter } = makeDeps({
      cfg: {
        authorizedIds: new Set([AUTHORIZED_USER]),
        maxApkBytes: 20 * 1024 * 1024,
        allowUploads: true,
        vtPollIntervalMs: 5,
        vtPollTimeoutMs: 200,
        vtReuseMaxAgeHours: 24,
        cacheTtlMs: 10 * 60_000,
        maliciousThreshold: 3,
        suspiciousThreshold: 1,
        unauthorizedReply: false,
      },
    });
    const result = await runScan(makeJob({ userId: 999 }), deps);
    expect(result.status).toBe('unauthorized');
    expect(reporter.events.length).toBe(0);
  });

  it('authorizes by chat id (group allowlist)', async () => {
    const base = makeDeps();
    const { deps, vt, reporter } = makeDeps({
      cfg: { ...base.deps.cfg, authorizedIds: new Set([-100999]) },
    });
    scriptFreshScan(vt);
    const result = await runScan(makeJob({ chatId: -100999, userId: 777 }), deps);
    expect(result.status).toBe('CLEAN');
    expect(reporter.finalText).toContain('Status: CLEAN');
  });
});

describe('runScan — failures (never reported as clean)', () => {
  it('fails cleanly when the file is larger than the size limit, before downloading', async () => {
    const { deps, reporter, downloader } = makeDeps();
    const result = await runScan(makeJob({ fileSize: 21 * 1024 * 1024 }), deps);
    expect(result.status).toBe('FAILED');
    expect(downloader.calls).toBe(0);
    expect(reporter.finalText).toContain('Scan failed');
    expect(reporter.finalText).toContain('NOT classified as clean');
  });

  it('fails on files that are not valid APKs', async () => {
    const badDownloader = new FakeDownloader(Buffer.from('definitely not a zip file'));
    const { deps, reporter } = makeDeps({ downloader: badDownloader as unknown as FakeDownloader });
    const result = await runScan(makeJob({ fileName: 'fake.apk' }), deps);
    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('invalid_apk');
    expect(reporter.finalText).toContain('not a ZIP archive');
  });

  it('fails when the VirusTotal API errors', async () => {
    const { deps, reporter, vt } = makeDeps();
    vt.getFileReport.mockRejectedValue(new VirusTotalApiError('HTTP 500 persisted', 500));
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('vt_error');
    expect(reporter.finalText).toContain('NOT classified as clean');
    expect(reporter.finalText).not.toContain('Status: CLEAN');
  });

  it('fails with a quota message when VirusTotal rate limits the upload', async () => {
    const { deps, reporter, vt } = makeDeps();
    vt.getFileReport.mockResolvedValue(null);
    vt.uploadFile.mockRejectedValue(new VirusTotalQuotaError('429 persisted'));
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('vt_rate_limited');
    expect(reporter.finalText).toContain('rate limit');
  });

  it('fails when the analysis does not complete in time and never says clean', async () => {
    const { deps, reporter, vt } = makeDeps();
    vt.getFileReport.mockResolvedValue(null);
    vt.uploadFile.mockResolvedValue({ analysisId: 'analysis-slow' });
    vt.pollAnalysis.mockRejectedValue(new AnalysisTimeoutError('timed out'));
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('analysis_timeout');
    expect(reporter.finalText).toContain('did not finish');
    expect(reporter.finalText).not.toContain('CLEAN');
  });

  it('fails when a completed analysis has zero engine results', async () => {
    const { deps, reporter, vt } = makeDeps();
    scriptFreshScan(
      vt,
      makeReport({
        stats: { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0, other: 0 },
        totalEngines: 0,
      }),
    );
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('no_engine_results');
  });

  it('refuses to upload when uploads are disabled by policy', async () => {
    const { deps, reporter, vt } = makeDeps();
    vt.getFileReport.mockResolvedValue(null);
    deps.cfg.allowUploads = false;
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('uploads_disabled');
    expect(reporter.finalText).toContain('disabled by policy');
    expect(vt.uploadFile).not.toHaveBeenCalled();
  });

  it('cleans up the temp directory even when the scan fails', async () => {
    const badDownloader = new FakeDownloader(Buffer.from('x'));
    const { deps, downloader } = makeDeps({ downloader: badDownloader as unknown as FakeDownloader });
    await runScan(makeJob(), deps);
    expect((downloader as FakeDownloader).lastDestDir).not.toBeNull();
    expect(existsSync((downloader as FakeDownloader).lastDestDir!)).toBe(false);
  });
});

describe('runScan — downloader errors', () => {
  it('fails when the Telegram download itself errors', async () => {
    const failing = {
      downloadTo: vi.fn().mockRejectedValue(new Error('Telegram file download failed with HTTP 400')),
    };
    const { deps, reporter } = makeDeps({ downloader: failing as unknown as FakeDownloader });
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('internal_error');
    expect(reporter.finalText).toContain('Scan failed');
  });
});

describe('runScan — AI summary (NIM)', () => {
  it('appends an AI analysis message after the report when configured', async () => {
    const fakeAi = {
      model: 'z-ai/glm-5.3',
      summarize: vi.fn().mockResolvedValue('High-risk Android trojan; 23 of 70 engines agree.'),
    };
    const { deps, reporter, vt } = makeDeps({ ai: fakeAi });
    scriptFreshScan(
      vt,
      makeReport({
        stats: makeStats({ malicious: 23, suspicious: 3, undetected: 40 }),
        detections: [{ engine: 'Kaspersky', category: 'malicious', result: 'Trojan.AndroidOS.Hebe.d' }],
      }),
    );
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('MALICIOUS');
    expect(fakeAi.summarize).toHaveBeenCalledTimes(1);
    const prompt = fakeAi.summarize.mock.calls[0]![0] as string;
    expect(prompt).toContain('Verdict: MALICIOUS');
    expect(prompt).toContain('Kaspersky: Trojan.AndroidOS.Hebe.d');
    const aiEvents = reporter.events.filter((e) => e.kind === 'notify');
    expect(aiEvents.length).toBe(1);
    expect(aiEvents[0]!.text).toContain('AI analysis (z-ai/glm-5.3)');
    expect(aiEvents[0]!.text).toContain('High-risk Android trojan');
  });

  it('still completes the scan when the AI call fails', async () => {
    const failingAi = { model: 'z-ai/glm-5.3', summarize: vi.fn().mockRejectedValue(new Error('NIM API returned HTTP 500')) };
    const { deps, reporter, vt } = makeDeps({ ai: failingAi });
    scriptFreshScan(vt);
    const result = await runScan(makeJob(), deps);
    expect(result.status).toBe('CLEAN');
    expect(reporter.finalText).toContain('Status: CLEAN');
    expect(reporter.events.filter((e) => e.kind === 'notify').length).toBe(0);
  });

  it('sends no AI message when no summarizer is configured', async () => {
    const { deps, reporter, vt } = makeDeps();
    scriptFreshScan(vt);
    await runScan(makeJob(), deps);
    expect(reporter.events.filter((e) => e.kind === 'notify').length).toBe(0);
  });
});

// Ensure the temp dirs referenced by FakeDownloader live under the OS temp dir
// so a leaked test dir cannot pollute the repository.
describe('temp isolation', () => {
  it('downloads into the OS temp directory', async () => {
    const { deps, downloader, vt } = makeDeps();
    scriptFreshScan(vt);
    await runScan(makeJob(), deps);
    expect((downloader as FakeDownloader).lastDestDir?.startsWith(tmpdir())).toBe(true);
  });
});
