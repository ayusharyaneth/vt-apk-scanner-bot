import { describe, expect, it } from 'vitest';
import { classifyDetection } from '../src/classify';
import type { VTDetectionStats } from '../src/virustotal';

const cfg = { maliciousThreshold: 3, suspiciousThreshold: 1 };

function stats(overrides: Partial<VTDetectionStats> = {}): VTDetectionStats {
  return {
    malicious: 0,
    suspicious: 0,
    undetected: 60,
    harmless: 10,
    timeout: 0,
    other: 0,
    ...overrides,
  };
}

describe('classifyDetection', () => {
  it('classifies zero detections as CLEAN', () => {
    expect(classifyDetection(stats(), cfg).verdict).toBe('CLEAN');
  });

  it('classifies a single malicious detection as SUSPICIOUS (below threshold)', () => {
    expect(classifyDetection(stats({ malicious: 1 }), cfg).verdict).toBe('SUSPICIOUS');
    expect(classifyDetection(stats({ malicious: 2 }), cfg).verdict).toBe('SUSPICIOUS');
  });

  it('classifies suspicious-only detections as SUSPICIOUS', () => {
    expect(classifyDetection(stats({ suspicious: 2 }), cfg).verdict).toBe('SUSPICIOUS');
  });

  it('classifies at or above the malicious threshold as MALICIOUS', () => {
    expect(classifyDetection(stats({ malicious: 3 }), cfg).verdict).toBe('MALICIOUS');
    expect(classifyDetection(stats({ malicious: 45 }), cfg).verdict).toBe('MALICIOUS');
  });

  it('never classifies zero engine results as CLEAN', () => {
    const result = classifyDetection(
      { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0, other: 0 },
      cfg,
    );
    expect(result.verdict).toBe('FAILED');
    if (result.verdict === 'FAILED') expect(result.reason).toMatch(/zero engines/i);
  });

  it('supports a stricter single-engine malicious threshold', () => {
    const strict = { maliciousThreshold: 1, suspiciousThreshold: 1 };
    expect(classifyDetection(stats({ malicious: 1 }), strict).verdict).toBe('MALICIOUS');
  });
});
