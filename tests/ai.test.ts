import { describe, expect, it } from 'vitest';
import { buildSummaryPrompt, NimClient, NimError } from '../src/ai';
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

function client(fetchImpl: FetchLike): NimClient {
  return new NimClient({ apiKey: 'test-key', fetchImpl, timeoutMs: 1000 });
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

describe('NimClient.summarize', () => {
  it('sends an OpenAI-compatible chat-completions request and returns the content', async () => {
    let captured: RequestInit | undefined;
    let url = '';
    const fetchImpl = async (input: string | URL, init?: RequestInit): Promise<Response> => {
      url = String(input);
      captured = init;
      return jsonResponse(200, { choices: [{ message: { content: '  High risk Android trojan.  ' } }] });
    };
    const text = await client(fetchImpl).summarize('APK file: game.apk\nVerdict: MALICIOUS');
    expect(text).toBe('High risk Android trojan.');
    expect(url).toBe('https://integrate.api.nvidia.com/v1/chat/completions');
    const body = JSON.parse(String(captured!.body)) as Record<string, unknown>;
    expect(body['model']).toBe('z-ai/glm-5.3');
    expect(body['stream']).toBe(false);
    const messages = body['messages'] as Array<{ role: string; content: string }>;
    expect(messages[0]!.role).toBe('system');
    expect(messages[1]!.content).toContain('game.apk');
    expect((captured!.headers as Record<string, string>)['authorization']).toBe('Bearer test-key');
  });

  it('honors a custom model and api base', async () => {
    const custom = new NimClient({
      apiKey: 'k',
      apiBase: 'https://custom.example/v1/',
      model: 'z-ai/glm-5.2',
      timeoutMs: 1000,
      fetchImpl: (input) => {
        expect(String(input)).toBe('https://custom.example/v1/chat/completions');
        return Promise.resolve(jsonResponse(200, { choices: [{ message: { content: 'ok' } }] }));
      },
    });
    await expect(custom.summarize('x')).resolves.toBe('ok');
  });

  it('throws NimError on HTTP errors', async () => {
    const fetchImpl = async (): Promise<Response> => jsonResponse(401, { error: { message: 'invalid api key' } });
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(NimError);
  });

  it('throws NimError on malformed JSON', async () => {
    const fetchImpl = async (): Promise<Response> => new Response('not json', { status: 200 });
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(NimError);
  });

  it('throws NimError when no content is returned', async () => {
    const fetchImpl = async (): Promise<Response> => jsonResponse(200, { choices: [] });
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(NimError);
  });

  it('throws NimError on network failure', async () => {
    const fetchImpl = async (): Promise<Response> => {
      throw new TypeError('fetch failed');
    };
    await expect(client(fetchImpl).summarize('x')).rejects.toBeInstanceOf(NimError);
  });
});
