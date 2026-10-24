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

/** A well-formed lowercase/uppercase hex SHA-256 — the only value safe to embed in a VT link. */
const HEX64 = /^[a-f0-9]{64}$/i;

function vtLink(sha256: string): string | null {
  return HEX64.test(sha256) ? vtFileLink(sha256) : null;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function fmtCompact(epochSec: number | null): string {
  if (!epochSec) return 'unknown time';
  const d = new Date(epochSec * 1000);
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${hh}:${mm} UTC`;
}

function sourceNote(source: ReportSource, completedAtEpochSec: number | null): string {
  switch (source) {
    case 'fresh':
      return 'Fresh analysis · uploaded by this scan';
    case 'existing':
      return `Existing report · last analyzed ${fmtCompact(completedAtEpochSec)}`;
    case 'cache':
      return 'Cached result · identical file scanned recently';
    case 'inflight':
      return 'Merged with an identical scan in progress';
  }
}

export function formatScanReport(input: ScanReportInput): string {
  const { stats } = input;
  const flagged = stats.malicious + stats.suspicious;
  const pct = input.totalEngines > 0 ? ((flagged / input.totalEngines) * 100).toFixed(1) : '0.0';
  const link = vtLink(input.sha256);
  const size = input.sizeBytes !== null ? ` · ${formatBytes(input.sizeBytes)}` : '';
  const lines: string[] = [
    `${VERDICT_EMOJI[input.verdict]} <b>${input.verdict}</b> — ${flagged}/${input.totalEngines} engines flagged (${pct}%)`,
    ``,
    `📦 ${escapeHtml(input.fileName)}${size}`,
    `🔐 <code>${escapeHtml(input.sha256)}</code>`,
    `🧪 🚨 ${stats.malicious} · ⚠️ ${stats.suspicious} · ✅ ${stats.harmless} · 🔎 ${stats.undetected} · ⏸ ${stats.timeout + stats.other}`,
    `🕒 ${fmtCompact(input.completedAtEpochSec)}${input.durationSec !== null ? ` · ${input.durationSec}s` : ''}`,
  ];
  if (link) lines.push(``, `🔗 <a href="${link}">VirusTotal report</a>`);
  lines.push(`<i>${escapeHtml(sourceNote(input.source, input.completedAtEpochSec))}</i>`);
  return lines.join('\n');
}

export function formatScanFailure(input: ScanFailureInput): string {
  const lines = [
    `❌ <b>FAILED — no verdict</b>`,
    ``,
    `📦 ${escapeHtml(input.fileName)}`,
  ];
  if (input.sha256) {
    lines.push(`🔐 <code>${escapeHtml(input.sha256)}</code>`);
  }
  lines.push(``, `❗ ${escapeHtml(input.reason)}`);
  const link = input.sha256 ? vtLink(input.sha256) : null;
  if (link) lines.push(``, `🔗 <a href="${link}">Check VirusTotal manually</a>`);
  lines.push(
    `<i>Not treated as clean · nothing was executed</i>`,
    `<i>Ref: ${input.scanId}</i>`,
  );
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
