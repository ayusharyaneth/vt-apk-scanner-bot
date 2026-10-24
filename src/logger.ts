const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;
export type LogLevel = keyof typeof LEVELS;

const registeredSecrets: string[] = [];

/**
 * Register a secret (bot token, API key) so that it is replaced with
 * [REDACTED] if it ever ends up in a log field — e.g. inside a URL.
 */
export function registerSecret(value: string | undefined): void {
  if (value && value.length >= 8 && !registeredSecrets.includes(value)) {
    registeredSecrets.push(value);
  }
}

function redact(text: string): string {
  let out = text;
  for (const secret of registeredSecrets) {
    if (out.includes(secret)) out = out.split(secret).join('[REDACTED]');
  }
  return out;
}

export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}

export function createLogger(minLevel: string): Logger {
  const threshold = LEVELS[(minLevel as LogLevel) in LEVELS ? (minLevel as LogLevel) : 'info'];
  const write = (level: LogLevel, event: string, fields?: Record<string, unknown>): void => {
    if (LEVELS[level] < threshold) return;
    const record = { ts: new Date().toISOString(), level, event, ...(fields ?? {}) };
    let line: string;
    try {
      line = JSON.stringify(record);
    } catch {
      line = JSON.stringify({ ts: record.ts, level, event, note: 'unserializable fields dropped' });
    }
    process.stdout.write(redact(line) + '\n');
  };
  return {
    debug: (event, fields) => write('debug', event, fields),
    info: (event, fields) => write('info', event, fields),
    warn: (event, fields) => write('warn', event, fields),
    error: (event, fields) => write('error', event, fields),
  };
}
