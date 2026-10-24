import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AiConfig } from './ai';

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

export const MAX_APK_BYTES_HARD_CAP = 32 * 1024 * 1024; // VirusTotal standard upload limit
export const TELEGRAM_DOWNLOAD_CAP = 20 * 1024 * 1024; // Telegram Bot API getFile limit

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super('Invalid configuration:\n  - ' + problems.join('\n  - '));
    this.name = 'ConfigError';
  }
}

export interface AppConfig {
  telegramBotToken: string;
  virustotalApiKey: string;
  authorizedIds: Set<number>;
  allowUploads: boolean;
  unauthorizedReply: boolean;
  vtApiBase: string;
  vtPollIntervalMs: number;
  vtPollTimeoutMs: number;
  vtMaxRetries: number;
  vtRequestTimeoutMs: number;
  vtUploadTimeoutMs: number;
  vtMaxRetryAfterMs: number;
  vtReuseMaxAgeHours: number;
  cacheTtlMs: number;
  maliciousThreshold: number;
  suspiciousThreshold: number;
  maxApkBytes: number;
  logLevel: string;
  /** Optional NVIDIA NIM AI summary; null when no API key is configured. */
  ai: AiConfig | null;
}

/**
 * Minimal .env loader (no external dependency). Real environment variables
 * always take precedence over values from the file.
 */
export function loadDotEnv(env: Record<string, string | undefined>, filePath?: string): void {
  const target = filePath ?? join(projectRoot, '.env');
  if (!existsSync(target)) return;
  const text = readFileSync(target, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    if (key && (env[key] === undefined || env[key] === '')) env[key] = value;
  }
}

export function loadConfig(
  env: Record<string, string | undefined> = process.env,
  opts: { dotEnvPath?: string | null } = {},
): AppConfig {
  if (opts.dotEnvPath !== null) loadDotEnv(env, opts.dotEnvPath ?? undefined);
  const problems: string[] = [];

  const telegramBotToken = requiredString(env, 'TELEGRAM_BOT_TOKEN', problems);
  if (telegramBotToken && !/^\d+:[A-Za-z0-9_-]{30,}$/.test(telegramBotToken)) {
    problems.push('TELEGRAM_BOT_TOKEN does not look like a Telegram bot token (expected "<numeric id>:<token>)"');
  }
  const virustotalApiKey = requiredString(env, 'VIRUSTOTAL_API_KEY', problems);

  const authorizedIds = new Set<number>();
  const rawIds = env['AUTHORIZED_IDS']?.trim();
  if (!rawIds) {
    problems.push(
      'AUTHORIZED_IDS is required: comma-separated Telegram user and/or chat ids (e.g. "123456789,-1001234567890"). Use /id in the bot to find yours.',
    );
  } else {
    for (const token of rawIds.split(/[\s,;]+/).filter(Boolean)) {
      const n = Number(token);
      if (!Number.isInteger(n) || n === 0) {
        problems.push(`AUTHORIZED_IDS: "${token}" is not a valid Telegram id (user ids are positive, group ids negative)`);
      } else {
        authorizedIds.add(n);
      }
    }
    if (authorizedIds.size === 0 && problems.length === 0) {
      problems.push('AUTHORIZED_IDS must contain at least one id');
    }
  }

  const cfg: AppConfig = {
    telegramBotToken,
    virustotalApiKey,
    authorizedIds,
    allowUploads: boolEnv(env, 'ALLOW_UPLOADS', problems, true),
    unauthorizedReply: boolEnv(env, 'UNAUTHORIZED_REPLY', problems, true),
    vtApiBase: stringEnv(env, 'VT_API_BASE', 'https://www.virustotal.com').replace(/\/+$/, ''),
    vtPollIntervalMs: intEnv(env, 'VT_POLL_INTERVAL_SECONDS', problems, 20, 5, 3600) * 1000,
    vtPollTimeoutMs: intEnv(env, 'VT_POLL_TIMEOUT_SECONDS', problems, 300, 30, 7200) * 1000,
    vtMaxRetries: intEnv(env, 'VT_MAX_RETRIES', problems, 3, 0, 10),
    vtRequestTimeoutMs: intEnv(env, 'VT_REQUEST_TIMEOUT_SECONDS', problems, 30, 5, 300) * 1000,
    vtUploadTimeoutMs: intEnv(env, 'VT_UPLOAD_TIMEOUT_SECONDS', problems, 120, 10, 600) * 1000,
    vtMaxRetryAfterMs: intEnv(env, 'VT_MAX_RETRY_AFTER_MS', problems, 60_000, 1000, 3_600_000),
    vtReuseMaxAgeHours: intEnv(env, 'VT_REUSE_MAX_AGE_HOURS', problems, 24, 0, 24 * 365),
    cacheTtlMs: intEnv(env, 'CACHE_TTL_MINUTES', problems, 30, 0, 24 * 60) * 60_000,
    maliciousThreshold: intEnv(env, 'MALICIOUS_THRESHOLD', problems, 3, 1, 100),
    suspiciousThreshold: intEnv(env, 'SUSPICIOUS_THRESHOLD', problems, 1, 1, 100),
    maxApkBytes: intEnv(env, 'MAX_APK_BYTES', problems, TELEGRAM_DOWNLOAD_CAP, 1024, MAX_APK_BYTES_HARD_CAP),
    logLevel: stringEnv(env, 'LOG_LEVEL', 'info').toLowerCase(),
    ai: null,
  };

  // Accept the NIM-conventional NVIDIA_API_KEY, plus NIM_API_KEY as an alias.
  const nimApiKey = (env['NVIDIA_API_KEY'] ?? env['NIM_API_KEY'] ?? '').trim();
  cfg.ai = nimApiKey
    ? {
        apiKey: nimApiKey,
        apiBase: stringEnv(env, 'NIM_API_BASE', 'https://integrate.api.nvidia.com/v1').replace(/\/+$/, ''),
        model: stringEnv(env, 'NIM_MODEL', 'z-ai/glm-5.3'),
        timeoutMs: intEnv(env, 'NIM_TIMEOUT_SECONDS', problems, 30, 5, 120) * 1000,
        summaryMaxChars: intEnv(env, 'NIM_SUMMARY_MAX_CHARS', problems, 600, 100, 2000),
      }
    : null;

  if (problems.length > 0) throw new ConfigError(problems);
  return cfg;
}

function requiredString(
  env: Record<string, string | undefined>,
  name: string,
  problems: string[],
): string {
  const v = env[name]?.trim();
  if (!v) {
    problems.push(`${name} is required`);
    return '';
  }
  return v;
}

function stringEnv(
  env: Record<string, string | undefined>,
  name: string,
  def: string,
): string {
  const v = env[name]?.trim();
  return v ? v : def;
}

function intEnv(
  env: Record<string, string | undefined>,
  name: string,
  problems: string[],
  def: number,
  min: number,
  max: number,
): number {
  const v = env[name]?.trim();
  if (v === undefined || v === '') return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) {
    problems.push(`${name} must be an integer between ${min} and ${max} (got "${v}")`);
    return def;
  }
  return n;
}

function boolEnv(
  env: Record<string, string | undefined>,
  name: string,
  problems: string[],
  def: boolean,
): boolean {
  const v = env[name]?.trim().toLowerCase();
  if (v === undefined || v === '') return def;
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  problems.push(`${name} must be true or false (got "${v}")`);
  return def;
}
