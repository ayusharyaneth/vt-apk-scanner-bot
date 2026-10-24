import { describe, expect, it } from 'vitest';
import { BOT_COMMANDS } from '../src/bot';

describe('BOT_COMMANDS (Telegram menu registration)', () => {
  it('registers every command the help text promises', () => {
    const names = BOT_COMMANDS.map((c) => c.command).sort();
    expect(names).toEqual(['help', 'id', 'scan', 'start']);
  });

  it('uses valid Telegram command names and descriptions', () => {
    for (const c of BOT_COMMANDS) {
      expect(c.command).toMatch(/^[a-z0-9_]{1,32}$/); // lowercase, no slash, 1-32 chars
      expect(c.description.length).toBeGreaterThan(0);
      expect(c.description.length).toBeLessThanOrEqual(256);
    }
  });

  it('has no duplicate commands', () => {
    expect(new Set(BOT_COMMANDS.map((c) => c.command)).size).toBe(BOT_COMMANDS.length);
  });
});
