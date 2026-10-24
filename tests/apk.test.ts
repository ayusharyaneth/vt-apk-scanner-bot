import { createHash, randomUUID } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApk, buildZip } from './helpers/zip';
import { isApkDocument, sanitizeFileName, sha256File, validateApkFile } from '../src/apk';

let testDir: string;

beforeAll(async () => {
  testDir = await fsp.mkdtemp(join(tmpdir(), 'apktest-'));
});

afterAll(async () => {
  await fsp.rm(testDir, { recursive: true, force: true }).catch(() => {});
});

async function writeTemp(data: Buffer | string, ext = '.bin'): Promise<string> {
  const p = join(testDir, `${randomUUID()}${ext}`);
  await fsp.writeFile(p, data);
  return p;
}

describe('isApkDocument', () => {
  it('detects by Telegram mime type', () => {
    expect(isApkDocument({ mime_type: 'application/vnd.android.package-archive' })).toBe(true);
  });

  it('detects by .apk extension regardless of case', () => {
    expect(isApkDocument({ file_name: 'game.APK' })).toBe(true);
    expect(isApkDocument({ file_name: 'app.apk' })).toBe(true);
  });

  it('rejects other documents', () => {
    expect(isApkDocument({ file_name: 'doc.pdf', mime_type: 'application/pdf' })).toBe(false);
    expect(isApkDocument({})).toBe(false);
    expect(isApkDocument(undefined)).toBe(false);
  });
});

describe('validateApkFile', () => {
  it('accepts a structurally valid APK and reports entry count', async () => {
    const p = await writeTemp(buildApk());
    const result = await validateApkFile(p);
    expect(result).toEqual({ ok: true, entryCount: 4 });
  });

  it('accepts an APK with only AndroidManifest.xml', async () => {
    const p = await writeTemp(buildZip([{ name: 'AndroidManifest.xml', data: 'x' }]));
    expect(await validateApkFile(p)).toEqual({ ok: true, entryCount: 1 });
  });

  it('rejects a ZIP without AndroidManifest.xml', async () => {
    const p = await writeTemp(buildZip([{ name: 'README.txt', data: 'not an apk' }]));
    const result = await validateApkFile(p);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('AndroidManifest.xml');
  });

  it('rejects a non-ZIP file', async () => {
    const p = await writeTemp('this is just a text file, not an apk');
    const result = await validateApkFile(p);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('not a ZIP archive');
  });

  it('rejects a PK signature followed by garbage', async () => {
    const p = await writeTemp(Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from('garbage' + 'x'.repeat(64))]));
    const result = await validateApkFile(p);
    expect(result.ok).toBe(false);
  });

  it('rejects an empty file', async () => {
    const p = await writeTemp(Buffer.alloc(0));
    const result = await validateApkFile(p);
    expect(result.ok).toBe(false);
  });
});

describe('sha256File', () => {
  it('computes the SHA-256 of the file contents', async () => {
    const bytes = buildApk();
    const p = await writeTemp(bytes, '.apk');
    expect(await sha256File(p)).toBe(createHash('sha256').update(bytes).digest('hex'));
  });
});

describe('sanitizeFileName', () => {
  it('strips control characters and collapses whitespace', () => {
    expect(sanitizeFileName('bad\u0000name\u0007here.apk')).toBe('bad name here.apk');
  });

  it('truncates very long names and provides a fallback', () => {
    expect(sanitizeFileName('a'.repeat(500)).length).toBeLessThanOrEqual(120);
    expect(sanitizeFileName(undefined)).toBe('unknown.apk');
    expect(sanitizeFileName('   ')).toBe('unknown.apk');
  });
});
