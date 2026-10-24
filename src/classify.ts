import type { VTDetectionStats } from './virustotal';

export type Verdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'PENDING' | 'FAILED';

export interface ClassifyThresholds {
  maliciousThreshold: number;
  suspiciousThreshold: number;
}

export type DetectionVerdict =
  | { verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'; reason?: string }
  | { verdict: 'FAILED'; reason: string };

/**
 * Classify completed VirusTotal stats. An analysis with zero engine results
 * can never be CLEAN — it is FAILED so incomplete data is never reported as
 * safe.
 */
export function classifyDetection(stats: VTDetectionStats, cfg: ClassifyThresholds): DetectionVerdict {
  const total =
    stats.malicious + stats.suspicious + stats.undetected + stats.harmless + stats.timeout + stats.other;
  if (total <= 0) {
    return { verdict: 'FAILED', reason: 'VirusTotal returned results from zero engines' };
  }
  if (stats.malicious >= cfg.maliciousThreshold) {
    return { verdict: 'MALICIOUS', reason: `${stats.malicious}/${total} engines flagged the file as malicious` };
  }
  if (stats.malicious >= 1 || stats.suspicious >= cfg.suspiciousThreshold) {
    return {
      verdict: 'SUSPICIOUS',
      reason: `${stats.malicious} malicious / ${stats.suspicious} suspicious of ${total} engines`,
    };
  }
  return { verdict: 'CLEAN' };
}
