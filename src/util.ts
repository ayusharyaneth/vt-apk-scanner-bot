export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function jitter(ms: number): number {
  return Math.floor(Math.random() * ms);
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return 'unknown size';
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(kb < 10 ? 1 : 0)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(mb < 10 ? 2 : 1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

export function escapeHtml(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/**
 * Counting semaphore used to cap concurrent scans. acquire() resolves with a
 * release function as soon as a slot is free, or with null immediately when
 * the queue is full (caller should refuse the job instead of growing the
 * queue without bound).
 */
export class Semaphore {
  private active = 0;
  private waiters: Array<() => void> = [];

  constructor(
    private readonly limit: number,
    private readonly maxQueued: number,
  ) {}

  get running(): number {
    return this.active;
  }

  get queued(): number {
    return this.waiters.length;
  }

  async acquire(): Promise<(() => void) | null> {
    if (this.active < this.limit) {
      this.active++;
      return () => this.release();
    }
    if (this.waiters.length >= this.maxQueued) return null;
    return await new Promise<(() => void)>((resolve) => {
      this.waiters.push(() => {
        this.active++;
        resolve(() => this.release());
      });
    });
  }

  private release(): void {
    this.active--;
    const next = this.waiters.shift();
    if (next) next();
  }
}
