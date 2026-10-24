import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config';

const VALID_ENV: Record<string, string> = {
  TELEGRAM_BOT_TOKEN: '123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-2s',
  VIRUSTOTAL_API_KEY: 'vt-key-0123456789abcdef0123456789abcdef',
  AUTHORIZED_IDS: '42, -1001234567890',
};

describe('loadConfig', () => {
  it('rejects missing required variables and lists every problem', () => {
    try {
      loadConfig({}, { dotEnvPath: null });
      expect.unreachable('loadConfig should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      const message = (e as ConfigError).message;
      expect(message).toContain('TELEGRAM_BOT_TOKEN');
      expect(message).toContain('VIRUSTOTAL_API_KEY');
      expect(message).toContain('AUTHORIZED_IDS');
    }
  });

  it('parses authorized ids including negative group chat ids', () => {
    const cfg = loadConfig({ ...VALID_ENV }, { dotEnvPath: null });
    expect([...cfg.authorizedIds].sort()).toEqual([-1001234567890, 42]);
  });

  it('applies safe defaults for optional settings', () => {
    const cfg = loadConfig({ ...VALID_ENV }, { dotEnvPath: null });
    expect(cfg.vtPollIntervalMs).toBe(20_000);
    expect(cfg.vtPollTimeoutMs).toBe(300_000);
    expect(cfg.maxApkBytes).toBe(20 * 1024 * 1024);
    expect(cfg.maliciousThreshold).toBe(3);
    expect(cfg.allowUploads).toBe(true);
  });

  it('rejects malformed values', () => {
    expect(() =>
      loadConfig({ ...VALID_ENV, TELEGRAM_BOT_TOKEN: 'not-a-token' }, { dotEnvPath: null }),
    ).toThrow(/TELEGRAM_BOT_TOKEN/);
    expect(() =>
      loadConfig({ ...VALID_ENV, AUTHORIZED_IDS: 'abc' }, { dotEnvPath: null }),
    ).toThrow(/AUTHORIZED_IDS/);
    expect(() =>
      loadConfig({ ...VALID_ENV, VT_POLL_INTERVAL_SECONDS: 'fast' }, { dotEnvPath: null }),
    ).toThrow(/VT_POLL_INTERVAL_SECONDS/);
    expect(() =>
      loadConfig({ ...VALID_ENV, MAX_APK_BYTES: '999999999' }, { dotEnvPath: null }),
    ).toThrow(/MAX_APK_BYTES/);
  });

  it('honors explicit overrides and toggles', () => {
    const cfg = loadConfig(
      {
        ...VALID_ENV,
        ALLOW_UPLOADS: 'false',
        MALICIOUS_THRESHOLD: '1',
        VT_REUSE_MAX_AGE_HOURS: '0',
        LOG_LEVEL: 'DEBUG',
      },
      { dotEnvPath: null },
    );
    expect(cfg.allowUploads).toBe(false);
    expect(cfg.maliciousThreshold).toBe(1);
    expect(cfg.vtReuseMaxAgeHours).toBe(0);
    expect(cfg.logLevel).toBe('debug');
  });

  it('disables the AI summary when no NIM key is present', () => {
    const cfg = loadConfig({ ...VALID_ENV }, { dotEnvPath: null });
    expect(cfg.ai).toBeNull();
  });

  it('parses optional NVIDIA NIM settings with defaults and overrides', () => {
    const cfg = loadConfig({ ...VALID_ENV }, { dotEnvPath: null });
    expect(cfg.ai).toBeNull();
    const withAi = loadConfig(
      {
        ...VALID_ENV,
        NVIDIA_API_KEY: 'nvapi-secret-key',
        NIM_API_BASE: 'https://custom.example/v1/',
        NIM_MODEL: 'z-ai/glm-5.2',
        NIM_TIMEOUT_SECONDS: '15',
        NIM_SUMMARY_MAX_CHARS: '400',
      },
      { dotEnvPath: null },
    );
    expect(withAi.ai).toEqual({
      apiKey: 'nvapi-secret-key',
      apiBase: 'https://custom.example/v1',
      model: 'z-ai/glm-5.2',
      timeoutMs: 15_000,
      summaryMaxChars: 400,
    });
    // NIM_API_KEY works as an alias for NVIDIA_API_KEY.
    const alias = loadConfig({ ...VALID_ENV, NIM_API_KEY: 'alias-key' }, { dotEnvPath: null });
    expect(alias.ai!.apiKey).toBe('alias-key');
    expect(alias.ai!.model).toBe('z-ai/glm-5.3');
    expect(() =>
      loadConfig({ ...VALID_ENV, NVIDIA_API_KEY: 'k', NIM_TIMEOUT_SECONDS: '5s' }, { dotEnvPath: null }),
    ).toThrow(/NIM_TIMEOUT_SECONDS/);
  });
});
