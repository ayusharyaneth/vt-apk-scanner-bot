import { createHash } from 'node:crypto';
import { createReadStream, promises as fsp } from 'node:fs';

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const EOCD_MIN_SIZE = 22;
const EOCD_MAX_SCAN = EOCD_MIN_SIZE + 65_535; // max zip comment length

export interface TelegramDocumentLike {
  file_name?: string;
  mime_type?: string;
}

/** A document is treated as an APK by Telegram's mime type or the .apk extension. */
export function isApkDocument(doc: TelegramDocumentLike | undefined | null): boolean {
  if (!doc) return false;
  if (doc.mime_type === 'application/vnd.android.package-archive') return true;
  return /\.apk$/i.test(doc.file_name ?? '');
}

export interface ApkValidationOk {
  ok: true;
  entryCount: number;
}
export interface ApkValidationBad {
  ok: false;
  reason: string;
}
export type ApkValidation = ApkValidationOk | ApkValidationBad;

/**
 * Structural APK validation without extraction or execution: a real APK is a
 * ZIP archive whose central directory contains AndroidManifest.xml. We parse
 * only the End-Of-Central-Directory record and central directory entry names.
 * ZIP64 and malformed archives are rejected.
 */
export async function validateApkFile(filePath: string): Promise<ApkValidation> {
  const stat = await fsp.stat(filePath).catch(() => null);
  if (!stat || !stat.isFile() || stat.size === 0) return { ok: false, reason: 'file is empty or unreadable' };
  const size = stat.size;

  const handle = await fsp.open(filePath, 'r').catch(() => null);
  if (!handle) return { ok: false, reason: 'file cannot be opened' };
  try {
    // Must start with a local file header signature ("PK\x03\x04").
    const head = Buffer.alloc(4);
    await handle.read(head, 0, 4, 0);
    if (head.readUInt32LE(0) !== LOCAL_SIGNATURE) return { ok: false, reason: 'not a ZIP archive (missing PK signature)' };

    // Locate the End-Of-Central-Directory record.
    const scanLen = Math.min(size, EOCD_MAX_SCAN);
    const tail = Buffer.alloc(scanLen);
    await handle.read(tail, 0, scanLen, size - scanLen);
    let eocd = -1;
    for (let i = tail.length - EOCD_MIN_SIZE; i >= 0; i--) {
      if (tail.readUInt32LE(i) === EOCD_SIGNATURE) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return { ok: false, reason: 'ZIP structure unreadable (no end-of-central-directory record)' };

    const entryCount = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      return { ok: false, reason: 'ZIP64 archives are not supported' };
    }
    if (entryCount === 0) return { ok: false, reason: 'archive contains no entries' };
    const eocdPos = size - scanLen + eocd;
    // cdOffset is normally absolute; tolerate archives with prepended bytes by
    // falling back to "central directory immediately precedes the EOCD".
    let centralStart = cdOffset;
    if (centralStart + cdSize > eocdPos || centralStart + cdSize > size || centralStart < 0) {
      centralStart = eocdPos - cdSize;
    }
    if (centralStart < 0 || centralStart + cdSize > size) {
      return { ok: false, reason: 'ZIP central directory is truncated or corrupt' };
    }
    const central = Buffer.alloc(cdSize);
    const { bytesRead } = await handle.read(central, 0, cdSize, centralStart);
    if (bytesRead !== cdSize) return { ok: false, reason: 'ZIP central directory is truncated or corrupt' };

    let pos = 0;
    let seen = 0;
    let hasManifest = false;
    while (seen < entryCount) {
      if (pos + 46 > central.length) return { ok: false, reason: 'ZIP central directory is truncated or corrupt' };
      if (central.readUInt32LE(pos) !== CENTRAL_SIGNATURE) {
        return { ok: false, reason: 'ZIP central directory is corrupt' };
      }
      const nameLen = central.readUInt16LE(pos + 28);
      const extraLen = central.readUInt16LE(pos + 30);
      const commentLen = central.readUInt16LE(pos + 32);
      const nameStart = pos + 46;
      if (nameStart + nameLen > central.length) return { ok: false, reason: 'ZIP central directory is corrupt' };
      const name = central.subarray(nameStart, nameStart + nameLen).toString('utf8');
      if (name === 'AndroidManifest.xml') hasManifest = true;
      pos = nameStart + nameLen + extraLen + commentLen;
      seen++;
    }
    if (!hasManifest) return { ok: false, reason: 'missing AndroidManifest.xml (not an Android package)' };
    return { ok: true, entryCount };
  } finally {
    await handle.close().catch(() => {});
  }
}

/** Streaming SHA-256 of a file (never loads the whole file into memory). */
export async function sha256File(filePath: string): Promise<string> {
  return await new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/** Sanitize a user-supplied filename for display/reporting (never used as a path). */
export function sanitizeFileName(name: string | undefined): string {
  const cleaned = (name ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
  return cleaned || 'unknown.apk';
}
