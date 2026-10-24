import { Bot, GrammyError } from 'grammy';
import type { Context } from 'grammy';
import { isApkDocument } from './apk';
import type { AiSummarizer } from './ai';
import type { AppConfig } from './config';
import type { Logger } from './logger';
import { runScan } from './pipeline';
import type { ResultCache, ScanJob } from './pipeline';
import type { VTFileReport } from './virustotal';
import type { VirusTotalClient } from './virustotal';
import { TelegramDownloader, TelegramReporter } from './telegram';
import { errorMessage, sleep } from './util';

export interface AppServices {
  cfg: AppConfig;
  log: Logger;
  vt: VirusTotalClient;
  cache: ResultCache;
  inflight?: Map<string, Promise<VTFileReport>>;
  /** Optional AI summarizer; used only when cfg.ai is configured. */
  ai?: AiSummarizer | null;
}

const HELP_TEXT = [
  '🛡 <b>APK Malware Scanner</b>',
  '',
  'Send me an APK file as an attachment and I will scan it with VirusTotal automatically and reply with the report.',
  '',
  '<b>Commands</b>',
  '/scan — reply to an APK message to force a fresh re-scan',
  '/id — show your user id and chat id (needed for AUTHORIZED_IDS)',
  '',
  'Only authorized users can trigger scans.',
].join('\n');

export function createApp(services: AppServices): Bot {
  const { cfg, log } = services;
  const bot = new Bot(cfg.telegramBotToken);

  // Retry Telegram API calls once when the server asks us to slow down (429).
  bot.api.config.use(async (prev, method, payload, signal) => {
    try {
      return await prev(method, payload, signal);
    } catch (e) {
      if (e instanceof GrammyError && e.error_code === 429) {
        const wait = Number(e.parameters?.retry_after ?? 1) + 1;
        log.warn('telegram.flood_wait', { method, waitSeconds: wait });
        await sleep(wait * 1000);
        return await prev(method, payload, signal);
      }
      throw e;
    }
  });

  const downloader = new TelegramDownloader({
    token: cfg.telegramBotToken,
    maxBytes: cfg.maxApkBytes,
    log,
    getFile: (fileId) => bot.api.getFile(fileId),
  });

  const runJob = (job: ScanJob) =>
    runScan(job, {
      cfg: {
        authorizedIds: cfg.authorizedIds,
        maxApkBytes: cfg.maxApkBytes,
        allowUploads: cfg.allowUploads,
        vtPollIntervalMs: cfg.vtPollIntervalMs,
        vtPollTimeoutMs: cfg.vtPollTimeoutMs,
        vtReuseMaxAgeHours: cfg.vtReuseMaxAgeHours,
        cacheTtlMs: cfg.cacheTtlMs,
        maliciousThreshold: cfg.maliciousThreshold,
        suspiciousThreshold: cfg.suspiciousThreshold,
        unauthorizedReply: cfg.unauthorizedReply,
      },
      vt: services.vt,
      reporter: new TelegramReporter(bot.api, job.chatId, log),
      downloader,
      cache: services.cache,
      inflight: services.inflight ?? new Map<string, Promise<VTFileReport>>(),
      ai: cfg.ai ? services.ai ?? null : null,
      log,
    });

  // Automatic APK scans — no command needed.
  bot.on('message:document', async (ctx) => {
    const doc = ctx.message.document;
    if (!isApkDocument(doc)) {
      log.debug('bot.ignored_document', {
        chatId: ctx.chat.id,
        mime: doc.mime_type ?? null,
        fileName: doc.file_name ?? null,
      });
      return;
    }
    log.info('bot.apk_received', {
      chatId: ctx.chat.id,
      userId: ctx.from?.id ?? null,
      fileName: doc.file_name ?? null,
      fileSize: doc.file_size ?? null,
    });
    await runJob({
      chatId: ctx.chat.id,
      userId: ctx.from?.id ?? 0,
      userName: ctx.from?.username ?? undefined,
      fileId: doc.file_id,
      fileName: doc.file_name ?? 'unknown.apk',
      fileSize: doc.file_size,
      fresh: false,
    });
  });

  // Fresh re-scan: reply to an APK message with /scan.
  bot.command('scan', async (ctx) => {
    const replied = ctx.message?.reply_to_message?.document;
    if (!replied || !isApkDocument(replied)) {
      await reply(ctx, log, 'Usage: reply to an APK message with /scan to force a fresh re-scan on VirusTotal.');
      return;
    }
    await runJob({
      chatId: ctx.chat.id,
      userId: ctx.from?.id ?? 0,
      userName: ctx.from?.username ?? undefined,
      fileId: replied.file_id,
      fileName: replied.file_name ?? 'unknown.apk',
      fileSize: replied.file_size,
      fresh: true,
    });
  });

  bot.command(['start', 'help'], async (ctx) => {
    await reply(ctx, log, HELP_TEXT);
  });

  bot.command('id', async (ctx) => {
    await reply(
      ctx,
      log,
      `🆔 Your user id: <code>${ctx.from?.id ?? 'unknown'}</code>\n💬 This chat id: <code>${ctx.chat.id}</code>`,
    );
  });

  bot.catch((err) => {
    log.error('bot.unhandled_error', {
      updateId: err.ctx?.update?.update_id ?? null,
      error: errorMessage(err.error),
    });
  });

  return bot;
}

async function reply(ctx: Context, log: Logger, text: string): Promise<void> {
  try {
    await ctx.reply(text, { parse_mode: 'HTML', link_preview_options: { is_disabled: true } });
  } catch (e) {
    log.warn('bot.reply_failed', { error: errorMessage(e) });
  }
}
