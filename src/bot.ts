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
import { Semaphore, errorMessage, escapeHtml, sleep } from './util';

export interface AppServices {
  cfg: AppConfig;
  log: Logger;
  vt: VirusTotalClient;
  cache: ResultCache;
  inflight?: Map<string, Promise<VTFileReport>>;
  /** Optional AI summarizer; used only when cfg.ai is configured. */
  ai?: AiSummarizer | null;
}

const BRAND = '🛡 <b>APK Malware Scanner</b>';

/** Short onboarding message for /start. */
const START_TEXT = (name?: string): string =>
  [
    BRAND,
    '',
    `Hey${name ? ` ${escapeHtml(name)}` : ''} — send me an Android APK and I'll scan it against 70+ antivirus engines via VirusTotal, right here in this chat.`,
    '',
    '📎 Attach the file — the scan starts automatically.',
    '↩️ Reply <code>/scan</code> to an earlier APK to force a fresh re-scan.',
  ].join('\n');

/** Detailed reference for /help. */
const HELP_TEXT: string = [
  BRAND,
  '',
  '<b>How scanning works</b>',
  '1. Attach an APK file (.apk, up to 20 MB) and send it',
  '2. The scan starts automatically — you\'ll see live progress',
  '3. You get a verdict, engine counts and a VirusTotal link',
  '',
  '<b>Commands</b>',
  '/scan — reply to an APK message to force a fresh re-scan',
  '/id — show your Telegram ids (needed for AUTHORIZED_IDS)',
  '',
  '<b>Good to know</b>',
  '• Files are never executed — only hashed and analyzed',
  '• Known files get instant results; new ones take 1–3 minutes',
  '• Only authorized users can trigger scans',
].join('\n');

/**
 * Registered with Telegram on startup so these appear in the bot's menu
 * (the button next to the text field) and in the "/" command list.
 */
export const BOT_COMMANDS: ReadonlyArray<{ command: string; description: string }> = [
  { command: 'start', description: 'Start the bot and see how it works' },
  { command: 'scan', description: 'Reply to an APK message — force a fresh re-scan' },
  { command: 'id', description: 'Show your Telegram user id and chat id' },
  { command: 'help', description: 'How to use the scanner' },
];

/** Push BOT_COMMANDS to Telegram. Best-effort: never blocks startup. */
export async function registerBotCommands(api: Bot['api'], log: Logger): Promise<void> {
  try {
    await api.setMyCommands([...BOT_COMMANDS]);
    log.info('bot.commands_registered', { count: BOT_COMMANDS.length });
  } catch (e) {
    log.warn('bot.commands_register_failed', {
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

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

  // Caps concurrent scans and the waiting queue so a flood of documents
  // cannot exhaust memory, disk, or the VirusTotal daily quota.
  const limiter = new Semaphore(cfg.maxConcurrentScans, cfg.scanQueueLimit);

  const runJob = async (job: ScanJob) => {
    const release = await limiter.acquire();
    if (!release) {
      log.warn('scan.busy_rejected', { chatId: job.chatId, userId: job.userId, queued: limiter.queued });
      await new TelegramReporter(bot.api, job.chatId, log).notify(
        '⏳ The scanner is busy with other uploads right now. Please wait a moment and send the file again.',
      );
      return;
    }
    try {
      return await runScan(job, {
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
    } finally {
      release();
    }
  };

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
      await reply(
        ctx,
        log,
        '↩️ Reply to an APK message with <code>/scan</code> to force a fresh VirusTotal analysis.',
      );
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

  bot.command('start', async (ctx) => {
    await reply(ctx, log, START_TEXT(ctx.from?.first_name));
  });

  bot.command('help', async (ctx) => {
    await reply(ctx, log, HELP_TEXT);
  });

  bot.command('id', async (ctx) => {
    await reply(
      ctx,
      log,
      [
        '🪪 <b>Your Telegram ids</b>',
        '',
        `👤 User: <code>${ctx.from?.id ?? 'unknown'}</code>`,
        `💬 Chat: <code>${ctx.chat.id}</code>`,
        '',
        'Add your user id to <code>AUTHORIZED_IDS</code> to enable scanning.',
      ].join('\n'),
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
