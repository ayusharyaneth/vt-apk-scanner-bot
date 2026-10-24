import { createApp } from './bot';
import { NimClient } from './ai';
import { ConfigError, loadConfig } from './config';
import { createLogger, registerSecret } from './logger';
import { createResultCache } from './pipeline';
import { cleanupLiveDirs, sweepStaleTempDirs } from './tempfiles';
import { VirusTotalClient } from './virustotal';
import { errorMessage } from './util';

async function main(): Promise<void> {
  let cfg;
  try {
    cfg = loadConfig();
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(e.message + '\n');
    } else {
      process.stderr.write(`Failed to load configuration: ${errorMessage(e)}\n`);
    }
    process.exitCode = 1;
    return;
  }

  const log = createLogger(cfg.logLevel);
  // Safety net: if the token/key ever reaches a log line, it is redacted.
  registerSecret(cfg.telegramBotToken);
  registerSecret(cfg.virustotalApiKey);
  registerSecret(cfg.ai?.apiKey);

  log.info('startup.config', {
    authorizedIds: [...cfg.authorizedIds],
    maxApkBytes: cfg.maxApkBytes,
    allowUploads: cfg.allowUploads,
    vtPollIntervalMs: cfg.vtPollIntervalMs,
    vtPollTimeoutMs: cfg.vtPollTimeoutMs,
    vtReuseMaxAgeHours: cfg.vtReuseMaxAgeHours,
    maliciousThreshold: cfg.maliciousThreshold,
    suspiciousThreshold: cfg.suspiciousThreshold,
    aiEnabled: cfg.ai !== null,
    aiModel: cfg.ai?.model ?? null,
    logLevel: cfg.logLevel,
  });

  await sweepStaleTempDirs(60 * 60_000, log);

  const vt = new VirusTotalClient({
    apiKey: cfg.virustotalApiKey,
    baseUrl: cfg.vtApiBase,
    maxRetries: cfg.vtMaxRetries,
    requestTimeoutMs: cfg.vtRequestTimeoutMs,
    uploadTimeoutMs: cfg.vtUploadTimeoutMs,
    maxRetryAfterMs: cfg.vtMaxRetryAfterMs,
  });
  const bot = createApp({
    cfg,
    log,
    vt,
    cache: createResultCache(cfg.cacheTtlMs),
    ai: cfg.ai
      ? new NimClient({
          apiKey: cfg.ai.apiKey,
          apiBase: cfg.ai.apiBase,
          model: cfg.ai.model,
          timeoutMs: cfg.ai.timeoutMs,
        })
      : null,
  });

  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    log.info('shutdown.requested');
    bot.stop();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);

  try {
    await bot.start({
      drop_pending_updates: true,
      allowed_updates: ['message'],
      onStart: (me) => log.info('bot.started', { botUsername: me.username ?? null }),
    });
  } finally {
    bot.stop();
    await cleanupLiveDirs();
    log.info('shutdown.complete');
  }
}

main().catch((e) => {
  process.stderr.write(`Fatal error: ${errorMessage(e)}\n`);
  process.exitCode = 1;
});
