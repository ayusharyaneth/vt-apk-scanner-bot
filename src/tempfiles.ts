import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Logger } from './logger';

const PREFIX = 'apkscan-';
const liveDirs = new Set<string>();

/**
 * Per-scan temporary directory (0700 via mkdtemp semantics). APKs are stored
 * under a fixed internal name — user-supplied filenames never touch the
 * filesystem as paths.
 */
export async function createScanDir(): Promise<string> {
  const dir = await fsp.mkdtemp(join(tmpdir(), PREFIX));
  liveDirs.add(dir);
  return dir;
}

export async function removeScanDir(dir: string): Promise<void> {
  liveDirs.delete(dir);
  await fsp.rm(dir, { recursive: true, force: true }).catch(() => {
    // best effort — sweepStaleTempDirs at next startup removes leftovers
  });
}

/** Remove any apkscan-* temp dirs older than the given age (crash leftovers). */
export async function sweepStaleTempDirs(olderThanMs = 60 * 60_000, log?: Logger): Promise<number> {
  let removed = 0;
  const parent = tmpdir();
  let entries: string[] = [];
  try {
    entries = await fsp.readdir(parent);
  } catch {
    return 0;
  }
  const cutoff = Date.now() - olderThanMs;
  for (const entry of entries) {
    if (!entry.startsWith(PREFIX)) continue;
    const full = join(parent, entry);
    try {
      const stat = await fsp.stat(full);
      if (stat.mtimeMs < cutoff && !liveDirs.has(full)) {
        await fsp.rm(full, { recursive: true, force: true });
        removed++;
      }
    } catch {
      // unreadable entry — ignore
    }
  }
  if (removed > 0) log?.info('temp.swept', { removed });
  return removed;
}

/** Best-effort cleanup of dirs belonging to in-flight scans (shutdown path). */
export async function cleanupLiveDirs(): Promise<void> {
  for (const dir of [...liveDirs]) {
    await removeScanDir(dir);
  }
}
