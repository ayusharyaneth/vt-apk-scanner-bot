import { describe, expect, it } from 'vitest';
import { buildSummaryPrompt, GlmClient, GlmError } from '../src/ai';
import type { AiScanContext, FetchLike } from '../src/ai';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function context(overrides: Partial<AiScanContext> = {}): AiScanContext {
  return {
    fileName: 'game.apk',
    verdict: 'MALICIOUS',
    stats: { malicious: 23, suspicious: 3, undetected: 40, harmless: 4, timeout: 0, other: 0 },
    totalEngines: 70,
    detections: [
      { engine: 'Kaspersky', category: 'malicious', result: 'Trojan.AndroidOS.Hebe.d' },
      { engine: 'Microsoft', category: 'suspicious', result: 'Possible Threat' },
    ],
    ...overrides,
  };
}

function client(fetchImpl: FetchLike): GlmClient {
  return new GlmClient({ apiKey: 'test-key', fetchImpl, timeoutMs: 1000 });
}

describe('buildSummaryPrompt', () => {
  it('includes verdict, counts, detection rate and detections', () => {
    const prompt = buildSummaryPrompt(context());
    expect(prompt).toContain('game.apk');
    expect(prompt).toContain('Verdict: MALICIOUS');
    expect(prompt).toContain('malicious=23');
    expect(prompt).toContain('26/70 (37.1%)');
    expect(prompt).toContain('Kaspersky: Trojan.AndroidOS.Hebe.d');
  });

  it('omits the detections section when there are none', () => {
    const prompt = buildSummaryPrompt(context({ verdict: 'CLEAN', detections: [] }));
    expect(prompt).toContain('Verdict: CLEAN');
    expect(prompt).not.toContain('Detections:');
  });
});

describe('GlmClient.summarize', () => {
  it('sends a chat-completions request and returns the content', async () => {
    let captured: RequestInit | undefined;
    let url = '';
    const fetchImpl = async (input: string | URL, init?: RequestInit): Promise<Response> => {
      url = String(input);
      captured = init;
      return jsonResponse(200, { choices: [{ message: { content: '  High risk Android trojan.  ' } }] });
    };
    const text = await client(fetchImpl).summarize('APK file: game.apk\nVerdict: MALICIOUS');
    expect(text).toBe('High risk Android trojan.');
    expect(url).toContain('https://open.bigmodel.cn/api/paas/v4/chat/completions');
    const body = JSON.parse(String(captured!.body)) as Record<string, unknown>;
    expect(body['model']).toBe('glm-5.3-flash');
    expect(body['stream']).toBe(false);
    const messages = body['messages'] as Array<{ role: string; content: string }>;
    expect(messages[0]!.role).toBe('system');
    expect(messages[1]!.content).toContain('game.apk');
    expect((captured!.headers as Record<string, string>)['authorization']).toBe('Bearer test-key');
  });

  it('honors a custom model and api base', async () => {
    const custom = new GlmClient({
      apiKey: 'k',
      apiBase: 'https://custom.example/v4/',
      model: 'glm-5.3-flash',
      timeoutMs: 1000,
      fetchImpl: (input) => {
        expect(String(input)).toBe('https://custom.example/v4/chat/completions');
        return Promise.resolve(jsonResponse(200, { choices: [{ message: { content: 'ok' } }] }));
      },
    });
    await expect(custom.summarize('x')).resolves.toBe('ok');
  });

  it('throws GlmError on HTTP errors', async () => {
    const fetchImpl = async (): Promise<Response> => jsonResponse(401, { error: { message: 'invalid api key' } });
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(GlmError);
  });

  it('throws GlmError on malformed JSON', async () => {
    const fetchImpl = async (): Promise<Response> => new Response('not json', { status: 200 });
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(GlmError);
  });

  it('throws GlmError when no content is returned', async () => {
    const fetchImpl = async (): Promise<Response> => jsonResponse(200, { choices: [] });
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(GlmError);
  });

  it('throws GlmError on network failure', async () => {
    const fetchImpl = async (): Promise<Response> => {
      throw new TypeError('fetch failed');
    };
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(GlmError);
  });
});
