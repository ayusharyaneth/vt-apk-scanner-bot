import type { VTDetectionStats } from './virustotal';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class GlmError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GlmError';
  }
}

export interface AiConfig {
  apiKey: string;
  apiBase: string;
  model: string;
  timeoutMs: number;
  summaryMaxChars: number;
}

/** Best-effort summarizer; implementations must throw on failure. */
export interface AiSummarizer {
  readonly model: string;
  summarize(prompt: string): Promise<string>;
}

export interface AiScanContext {
  fileName: string;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
  stats: VTDetectionStats;
  totalEngines: number;
  /** Detections from engines that flagged the file (may be empty for CLEAN). */
  detections: Array<{ engine: string; category: string; result: string }>;
}

const SYSTEM_PROMPT = [
  'You are a malware-analysis assistant inside a security Telegram bot.',
  'You receive VirusTotal scan statistics for an Android APK and write a short plain-language risk assessment.',
  'Rules:',
  '- Always agree with the provided verdict; never downgrade MALICIOUS or SUSPICIOUS findings.',
  '- 2 to 4 sentences, plain text, no markdown, English only.',
  '- If detections are listed, name the most notable flagged behaviors or engine results when they are informative.',
  '- If the file is CLEAN, say so but note that no scan is a guarantee of safety.',
  '- Never invent details that are not in the provided data.',
].join('\n');

export function buildSummaryPrompt(ctx: AiScanContext): string {
  const flagged = ctx.stats.malicious + ctx.stats.suspicious;
  const pct = ctx.totalEngines > 0 ? ((flagged / ctx.totalEngines) * 100).toFixed(1) : '0.0';
  const lines = [
    `APK file: ${ctx.fileName}`,
    `Verdict: ${ctx.verdict}`,
    `Engine results (out of ${ctx.totalEngines}): malicious=${ctx.stats.malicious}, suspicious=${ctx.stats.suspicious}, harmless=${ctx.stats.harmless}, undetected=${ctx.stats.undetected}, no-result=${ctx.stats.timeout + ctx.stats.other}`,
    `Detection rate: ${flagged}/${ctx.totalEngines} (${pct}%)`,
  ];
  if (ctx.detections.length > 0) {
    lines.push('Detections:');
    for (const d of ctx.detections.slice(0, 8)) {
      lines.push(`- ${d.engine}: ${d.result} (${d.category})`);
    }
  }
  return lines.join('\n');
}

export interface GlmClientOptions {
  apiKey: string;
  apiBase?: string;
  model?: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}

/**
 * Minimal Zhipu open-platform chat-completions client (non-streaming).
 * Summaries are best-effort: any failure throws GlmError and the caller
 * must continue without the AI section.
 */
export class GlmClient implements AiSummarizer {
  readonly model: string;
  private readonly apiKey: string;
  private readonly apiBase: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchLike;

  constructor(opts: GlmClientOptions) {
    this.apiKey = opts.apiKey;
    this.apiBase = (opts.apiBase ?? 'https://open.bigmodel.cn/api/paas/v4').replace(/\/+$/, '');
    this.model = opts.model ?? 'glm-5.3-flash';
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  async summarize(prompt: string): Promise<string> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.apiBase}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: this.model,
          stream: false,
          temperature: 0.2,
          max_tokens: 400,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: prompt },
          ],
        }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new GlmError(`GLM request failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      throw new GlmError(`GLM API returned HTTP ${res.status}`);
    }
    let json: { choices?: Array<{ message?: { content?: unknown } }> };
    try {
      json = (await res.json()) as typeof json;
    } catch {
      throw new GlmError('GLM API returned malformed JSON');
    }
    const content = json.choices?.[0]?.message?.content;
    const text = typeof content === 'string' ? content.trim() : '';
    if (!text) throw new GlmError('GLM API returned an empty summary');
    return text;
  }
}
