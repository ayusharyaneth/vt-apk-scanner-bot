import type { Verdict } from './classify';
import type { VTDetectionStats } from './virustotal';
import { vtFileLink } from './virustotal';
import { escapeHtml, formatBytes } from './util';

export const TELEGRAM_MESSAGE_LIMIT = 4096;
/** Keep a safety margin below Telegram's 4096-char limit. */
const SAFE_LIMIT = 4000;

export type ReportSource = 'cache' | 'existing' | 'fresh' | 'inflight';

export interface ScanReportInput {
  fileName: string;
  sizeBytes: number | null;
  sha256: string;
  verdict: Verdict;
  reason?: string;
  stats: VTDetectionStats;
  totalEngines: number;
  completedAtEpochSec: number | null;
  durationSec: number | null;
  source: ReportSource;
}

export interface ScanFailureInput {
  scanId: string;
  fileName: string;
  sha256: string | null;
  reason: string;
}

const VERDICT_EMOJI: Record<Verdict, string> = {
  CLEAN: '✅',
  SUSPICIOUS: '⚠️',
  MALICIOUS: '🚨',
  PENDING: '⏳',
  FAILED: '❌',
};

export function verdictEmoji(verdict: Verdict): string {
  return VERDICT_EMOJI[verdict];
}

function fmtUtc(epochSec: number | null): string {
  if (!epochSec) return 'unknown';
  return new Date(epochSec * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function sourceNote(source: ReportSource, completedAtEpochSec: number | null): string {
  switch (source) {
    case 'fresh':
      return 'Fresh VirusTotal analysis triggered by this upload.';
    case 'existing':
      return `Existing VirusTotal report reused (last analyzed ${fmtUtc(completedAtEpochSec)}).`;
    case 'cache':
      return 'Result served from this bot\u2019s short-term cache for a recently scanned identical file.';
    case 'inflight':
      return 'Identical file was scanned moments ago; this is that result.';
  }
}

export function formatScanReport(input: ScanReportInput): string {
  const { stats } = input;
  const name = escapeHtml(input.fileName);
  const flagged = stats.malicious + stats.suspicious;
  const pct = input.totalEngines > 0 ? ((flagged / input.totalEngines) * 100).toFixed(1) : '0.0';
  const lines = [
    `🛡 <b>APK Scan Report</b>`,
    ``,
    `📦 <b>File:</b> <code>${name}</code>${input.sizeBytes !== null ? ` (${formatBytes(input.sizeBytes)})` : ''}`,
    `🔐 <b>SHA-256:</b> <code>${escapeHtml(input.sha256)}</code>`,
    `${VERDICT_EMOJI[input.verdict]} <b>Status: ${input.verdict}</b>${input.reason ? ` — ${escapeHtml(input.reason)}` : ''}`,
    `🧪 <b>Engines (${input.totalEngines} total):</b> 🚨 ${stats.malicious} malicious · ⚠️ ${stats.suspicious} suspicious · ✅ ${stats.harmless} harmless · 🔎 ${stats.undetected} undetected · ⏸ ${stats.timeout + stats.other} no-result`,
    `📈 <b>Detection rate:</b> ${flagged}/${input.totalEngines} engines (${pct}%)`,
    `🕒 <b>Completed:</b> ${fmtUtc(input.completedAtEpochSec)}${input.durationSec !== null ? ` — scan took ${input.durationSec}s` : ''}`,
    `🔗 <a href="${vtFileLink(input.sha256)}">Full report on VirusTotal</a>`,
    ``,
    `<i>${escapeHtml(sourceNote(input.source, input.completedAtEpochSec))}</i>`,
  ];
  return lines.join('\n');
}

export function formatScanFailure(input: ScanFailureInput): string {
  const lines = [
    `❌ <b>Scan failed — no verdict</b>`,
    ``,
    `📦 <b>File:</b> <code>${escapeHtml(input.fileName)}</code>`,
  ];
  if (input.sha256) {
    lines.push(`🔐 <b>SHA-256:</b> <code>${escapeHtml(input.sha256)}</code>`);
    lines.push(`🔗 <a href="${vtFileLink(input.sha256)}">Check VirusTotal manually</a>`);
  }
  lines.push(``, `❗ <b>Reason:</b> ${escapeHtml(input.reason)}`, ``, `<i>The file was NOT classified as clean. Nothing was executed.</i>`, ``, `<i>Scan reference: ${input.scanId}</i>`);
  return lines.join('\n');
}

/** Progress/status texts shown while the scan runs. */
export function progressReceiving(fileName: string, fileSizeBytes: number | null): string {
  const size = fileSizeBytes !== null && fileSizeBytes > 0 ? ` (${formatBytes(fileSizeBytes)})` : '';
  return `⏳ <b>APK received</b> — <code>${escapeHtml(fileName)}</code>${size}\nDownloading from Telegram…`;
}

export function progressDownloaded(bytes: number): string {
  return `⏳ Downloaded ${formatBytes(bytes)} — validating APK and computing SHA-256…`;
}

export function progressCheckingVt(sha256: string): string {
  return `⏳ SHA-256: <code>${sha256}</code>\nChecking VirusTotal for an existing report…`;
}

export function progressUploading(): string {
  return `⏳ No recent report found — uploading to VirusTotal for a fresh analysis…`;
}

export function progressQueued(): string {
  return `⏳ Upload accepted — analysis queued at VirusTotal (this can take a few minutes)…`;
}

export function progressAnalyzing(attempt: number, elapsedSec: number, status: string): string {
  return `⏳ Analysis in progress (status: ${escapeHtml(status)}, ${elapsedSec}s elapsed, check ${attempt})…`;
}

/**
 * Split a message into parts that each fit Telegram's limit. Splits on line
 * boundaries where possible; never breaks a line in the middle unless a
 * single line exceeds the limit.
 */
export function splitHtmlMessage(text: string, limit = SAFE_LIMIT): string[] {
  if (text.length <= limit) return [text];
  const parts: string[] = [];
  let remaining = text;
  while (remaining.length > limit) {
    let cut = remaining.lastIndexOf('\n', limit);
    if (cut <= 0) cut = limit;
    parts.push(remaining.slice(0, cut));
    remaining = remaining.slice(cut).replace(/^\n/, '');
  }
  if (remaining.length > 0) parts.push(remaining);
  return parts;
}
