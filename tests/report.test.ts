import { describe, expect, it } from 'vitest';
import {
  formatScanFailure,
  formatScanReport,
  splitHtmlMessage,
  verdictEmoji,
} from '../src/report';
import type { VTDetectionStats } from '../src/virustotal';

function stats(overrides: Partial<VTDetectionStats> = {}): VTDetectionStats {
  return {
    malicious: 0,
    suspicious: 0,
    undetected: 60,
    harmless: 10,
    timeout: 1,
    other: 0,
    ...overrides,
  };
}

const baseInput = {
  fileName: 'game.apk',
  sizeBytes: 5 * 1024 * 1024,
  sha256: 'a'.repeat(64),
  totalEngines: 71,
  completedAtEpochSec: 1771600000,
  durationSec: 95,
  source: 'fresh' as const,
};

describe('formatScanReport', () => {
  it('includes every required field for a malicious verdict', () => {
    const text = formatScanReport({
      ...baseInput,
      verdict: 'MALICIOUS',
      stats: stats({ malicious: 12, suspicious: 3, undetected: 45 }),
    });
    expect(text).toContain('game.apk');
    expect(text).toContain('5.00 MB');
    expect(text).toContain('a'.repeat(64));
    expect(text).toContain('Status: MALICIOUS');
    expect(text).toContain('12 malicious');
    expect(text).toContain('3 suspicious');
    expect(text).toContain('45 undetected');
    expect(text).toContain('Engines (71 total)');
    expect(text).toContain('15/71 engines (21.1%)');
    expect(text).toContain('Completed:');
    expect(text).toContain('https://www.virustotal.com/gui/file/' + 'a'.repeat(64));
    expect(text.length).toBeLessThan(4000);
  });

  it('shows distinct status markers for clean, suspicious and malicious', () => {
    const clean = formatScanReport({ ...baseInput, verdict: 'CLEAN', stats: stats() });
    const suspicious = formatScanReport({ ...baseInput, verdict: 'SUSPICIOUS', stats: stats({ malicious: 1 }) });
    const malicious = formatScanReport({ ...baseInput, verdict: 'MALICIOUS', stats: stats({ malicious: 9 }) });
    expect(clean).toContain('Status: CLEAN');
    expect(clean).not.toContain('Status: MALICIOUS');
    expect(suspicious).toContain('Status: SUSPICIOUS');
    expect(malicious).toContain('Status: MALICIOUS');
    expect(new Set([verdictEmoji('CLEAN'), verdictEmoji('SUSPICIOUS'), verdictEmoji('MALICIOUS'), verdictEmoji('PENDING'), verdictEmoji('FAILED')]).size).toBe(5);
  });

  it('escapes HTML in filenames', () => {
    const text = formatScanReport({
      ...baseInput,
      fileName: 'evil<img src=x onerror=alert(1)>.apk',
      verdict: 'CLEAN',
      stats: stats(),
    });
    expect(text).not.toContain('<img');
    expect(text).toContain('&lt;img');
  });

  it('notes when an existing VirusTotal report was reused', () => {
    const text = formatScanReport({
      ...baseInput,
      verdict: 'CLEAN',
      stats: stats(),
      source: 'existing',
      durationSec: null,
    });
    expect(text).toContain('Existing VirusTotal report reused');
  });
});

describe('formatScanFailure', () => {
  it('clearly states no verdict was reached and never says clean', () => {
    const text = formatScanFailure({
      scanId: 'abc-123',
      fileName: 'broken.apk',
      sha256: 'b'.repeat(64),
      reason: 'analysis did not complete',
    });
    expect(text).toContain('Scan failed');
    expect(text).toContain('NOT classified as clean');
    expect(text).toContain('https://www.virustotal.com/gui/file/' + 'b'.repeat(64));
    expect(text).toContain('abc-123');
    expect(text).not.toContain('CLEAN');
  });
});

describe('splitHtmlMessage', () => {
  it('returns short messages unchanged', () => {
    expect(splitHtmlMessage('hello')).toEqual(['hello']);
  });

  it('splits long messages on line boundaries within the Telegram limit', () => {
    const line = 'x'.repeat(100);
    const long = Array.from({ length: 60 }, (_, i) => `${i} ${line}`).join('\n');
    const parts = splitHtmlMessage(long, 1000);
    expect(parts.length).toBeGreaterThan(1);
    for (const part of parts) expect(part.length).toBeLessThanOrEqual(1000);
    expect(parts.join('\n').replace(/\n+/g, '\n')).toBe(long);
  });

  it('hard-splits a single line longer than the limit', () => {
    const parts = splitHtmlMessage('y'.repeat(2500), 1000);
    expect(parts.length).toBe(3);
    expect(parts[0]!.length).toBe(1000);
  });
});
