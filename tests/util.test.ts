import { describe, expect, it } from 'vitest';
import { Semaphore } from '../src/util';

describe('Semaphore (scan concurrency limiter)', () => {
  it('allows up to the limit concurrently', async () => {
    const sem = new Semaphore(2, 5);
    const r1 = await sem.acquire();
    const r2 = await sem.acquire();
    expect(r1).not.toBeNull();
    expect(r2).not.toBeNull();
    expect(sem.running).toBe(2);
  });

  it('queues waiters until a slot is released', async () => {
    const sem = new Semaphore(1, 5);
    const r1 = await sem.acquire();
    expect(sem.queued).toBe(0);
    const pending = sem.acquire();
    expect(sem.queued).toBe(1);
    expect(sem.running).toBe(1);
    r1!();
    const r2 = await pending;
    expect(r2).not.toBeNull();
    expect(sem.running).toBe(1);
    expect(sem.queued).toBe(0);
    r2!();
    expect(sem.running).toBe(0);
  });

  it('returns null instead of growing the queue past the cap', async () => {
    const sem = new Semaphore(1, 1);
    const r1 = await sem.acquire();
    void sem.acquire(); // occupies the only queue slot
    expect(await sem.acquire()).toBeNull();
    expect(sem.queued).toBe(1);
    r1!();
  });

  it('never over-commits slots when many releases race', async () => {
    const sem = new Semaphore(3, 10);
    const first = await Promise.all(Array.from({ length: 3 }, () => sem.acquire()));
    expect(first.every((r) => r !== null)).toBe(true);
    const queued = Array.from({ length: 7 }, () => sem.acquire());
    expect(sem.running).toBe(3);
    expect(sem.queued).toBe(7);
    // Each release wakes exactly one waiter — drain all 7 sequentially.
    for (const r of first) r!();
    for (let i = 0; i < 7; i++) {
      const r = await Promise.race(queued);
      expect(r).not.toBeNull();
      r!();
    }
    expect(sem.running).toBe(0);
    expect(sem.queued).toBe(0);
  });
});
