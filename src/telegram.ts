import { createWriteStream } from 'node:fs';
import { join } from 'node:path';
import { Transform } from 'node:stream';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import type { Api } from 'grammy';
import type { Logger } from './logger';
import { splitHtmlMessage } from './report';
import { errorMessage, formatBytes } from './util';
import type { FetchLike } from './virustotal';

const SEND_OPTS = {
  parse_mode: 'HTML',
  link_preview_options: { is_disabled: true },
} as const;

export interface ProgressReporter {
  /** Send the initial status message for this scan. */
  begin(text: string): Promise<void>;
  /** Update the status message (no-op when the text is unchanged). */
  progress(text: string): Promise<void>;
  /** Replace the status message with the final report (split if too long). */
  final(text: string): Promise<void>;
  /** Standalone message outside the status flow (e.g. auth denial). */
  notify(text: string): Promise<void>;
}

/**
 * Sends one status message per scan and edits it as the scan progresses, so
 * the chat is not flooded with progress messages. Best-effort: if Telegram
 * rejects an edit (message deleted, etc.) we fall back to sending a new
 * message. A flood-wait transformer on the grammy Api handles rate limits.
 */
export class TelegramReporter implements ProgressReporter {
  private messageId: number | null = null;
  private lastText = '';

  constructor(
    private readonly api: Api,
    private readonly chatId: number,
    private readonly log: Logger,
  ) {}

  private async send(text: string): Promise<number> {
    const msg = await this.api.sendMessage(this.chatId, text, SEND_OPTS);
    return msg.message_id;
  }

  private async edit(text: string): Promise<void> {
    if (this.messageId === null) throw new Error('no status message yet');
    await this.api.editMessageText(this.chatId, this.messageId, text, SEND_OPTS);
  }

  async begin(text: string): Promise<void> {
    try {
      this.messageId = await this.send(text);
      this.lastText = text;
    } catch (e) {
      this.log.error('telegram.begin_failed', { chatId: this.chatId, error: errorMessage(e) });
    }
  }

  async progress(text: string): Promise<void> {
    if (text === this.lastText) return;
    try {
      if (this.messageId !== null) await this.edit(text);
      else this.messageId = await this.send(text);
      this.lastText = text;
    } catch (e) {
      // Message may have been deleted; retry once as a fresh message.
      try {
        this.messageId = await this.send(text);
        this.lastText = text;
      } catch (e2) {
        this.log.warn('telegram.progress_failed', { chatId: this.chatId, error: errorMessage(e2 ?? e) });
      }
    }
  }

  async final(text: string): Promise<void> {
    const parts = splitHtmlMessage(text);
    try {
      if (this.messageId !== null) await this.edit(parts[0]!);
      else this.messageId = await this.send(parts[0]!);
      for (const part of parts.slice(1)) await this.send(part);
    } catch {
      // Edit failed (deleted message etc.) — deliver the report as new message(s).
      try {
        for (const part of parts) await this.send(part);
      } catch (e) {
        this.log.error('telegram.final_failed', { chatId: this.chatId, error: errorMessage(e) });
      }
    }
  }

  async notify(text: string): Promise<void> {
    try {
      for (const part of splitHtmlMessage(text)) await this.send(part);
    } catch (e) {
      this.log.error('telegram.notify_failed', { chatId: this.chatId, error: errorMessage(e) });
    }
  }
}

export interface Downloader {
  downloadTo(fileId: string, destDir: string): Promise<{ filePath: string; bytes: number }>;
}

export interface TelegramDownloaderOptions {
  token: string;
  maxBytes: number;
  log: Logger;
  getFile: (fileId: string) => Promise<{ file_path?: string }>;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
}

/**
 * Downloads a Telegram document into the scan's temp directory under a fixed
 * name. The download URL embeds the bot token, so it is never logged (the
 * token is also registered for redaction). Enforces the size cap mid-stream.
 */
export class TelegramDownloader implements Downloader {
  private readonly fetchImpl: FetchLike;

  constructor(private readonly opts: TelegramDownloaderOptions) {
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  async downloadTo(fileId: string, destDir: string): Promise<{ filePath: string; bytes: number }> {
    const info = await this.opts.getFile(fileId);
    const remotePath = info?.file_path;
    if (!remotePath) throw new Error('Telegram did not return a file path for this document');
    const url = `https://api.telegram.org/file/bot${this.opts.token}/${remotePath}`;

    let res: Response;
    try {
      res = await this.fetchImpl(url, { signal: AbortSignal.timeout(this.opts.timeoutMs ?? 180_000) });
    } catch (e) {
      throw new Error(`Could not download the file from Telegram: ${errorMessage(e)}`);
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      throw new Error(`Telegram file download failed with HTTP ${res.status}`);
    }
    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared && declared > this.opts.maxBytes) {
      await res.body?.cancel().catch(() => {});
      throw new Error(`File exceeds the scan size limit of ${formatBytes(this.opts.maxBytes)}`);
    }
    if (!res.body) throw new Error('Telegram returned an empty download stream');

    const maxBytes = this.opts.maxBytes;
    let bytes = 0;
    const counter = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        bytes += chunk.length;
        if (bytes > maxBytes) cb(new Error(`File exceeds the scan size limit of ${formatBytes(maxBytes)}`));
        else cb(null, chunk);
      },
    });
    const dest = join(destDir, 'payload.apk');
    try {
      await pipeline(
        Readable.fromWeb(res.body as unknown as WebReadableStream),
        counter,
        createWriteStream(dest),
      );
    } catch (e) {
      throw new Error(`Download failed: ${errorMessage(e)}`);
    }
    if (bytes === 0) throw new Error('Downloaded file is empty');
    return { filePath: dest, bytes };
  }
}
