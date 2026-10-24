# Security & Privacy

## Threat model

The bot's inputs are untrusted on every axis:

- **Uploaded files are never executed.** They are only read as bytes: streamed
  hashing (SHA-256) and ZIP central-directory parsing for structural
  validation. No extraction, no dynamic analysis, no shell-outs.
- **User-supplied filenames never touch the filesystem.** Files are stored
  under a fixed internal name (`payload.apk`) inside a fresh
  `mkdtemp` directory per scan; filenames are sanitized only for display.
- **Sender authorization happens first.** Unknown senders are rejected before
  a single byte is downloaded from Telegram. Both user id and chat id are
  checked against `AUTHORIZED_IDS`.
- **Size caps are enforced mid-stream.** An oversized download is aborted as
  soon as the limit is crossed, not after it lands on disk.

## Secrets handling

- `TELEGRAM_BOT_TOKEN`, `VIRUSTOTAL_API_KEY` and `NVIDIA_API_KEY` are supplied
  via environment variables or `.env` (never hardcoded, never committed —
  `.gitignore` excludes `.env`).
- Every secret is registered with the logger at startup; if one ever reaches a
  log line (e.g. inside a URL) it is replaced with `[REDACTED]` before the line
  is written.
- Startup logs print the effective configuration **without** any secret values,
  so the running setup stays auditable.

## Filesystem hygiene

- Per-scan temp directories are removed in a `finally` block — on success,
  failure, and crash paths alike.
- Leftover directories from a hard crash (older than 1 hour) are swept at
  startup.
- Nothing under the project directory is ever written during a scan.

## VirusTotal and privacy policy

VirusTotal uploads become **publicly visible** on virustotal.com. That is how
the service works for everyone. Consequences and controls:

- Set `ALLOW_UPLOADS=false` to run in **hash-lookup-only mode**: the bot
  computes the SHA-256 locally and queries existing reports, but uploads
  nothing. If no report exists, it says so instead of uploading.
- Keep `AUTHORIZED_IDS` strict. Only people you trust should be able to spend
  your quota — and push files into VirusTotal's corpus under your key.
- The same applies to the optional AI summary: file metadata (verdict, engine
  counts, detection names) is sent to NVIDIA NIM over HTTPS when
  `NVIDIA_API_KEY` is set. The file itself is never sent to the AI.

## Rate limits and abuse resistance

- VirusTotal 429 responses honor `Retry-After`, capped by
  `VT_MAX_RETRY_AFTER_MS`; longer waits surface as a clean FAILED message
  rather than a stalled scan.
- Transient 5xx/network errors retry with exponential backoff + jitter
  (`VT_MAX_RETRIES`), so a flaky network cannot turn into a request storm.
- Telegram flood-waits (429 with `retry_after`) are honored and retried once
  by the API middleware.
- Analysis polling uses a fixed interval under the public per-minute quota.

## Shutdown and lifecycle

SIGINT/SIGTERM trigger a graceful stop: polling halts, in-flight scans finish,
temp directories are cleaned, then the process exits.
