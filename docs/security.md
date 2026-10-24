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

## Availability (DoS resistance)

- **Scan concurrency is capped** (`MAX_CONCURRENT_SCANS`, default 2) with a
  bounded queue (`SCAN_QUEUE_LIMIT`, default 5). A flood of APK documents —
  malicious or accidental — cannot spawn unbounded 20 MB downloads, temp
  directories, or VirusTotal uploads; excess senders get a "scanner is busy"
  reply. This protects memory, disk, and the daily VT quota.
- Temp-directory creation failures (disk full) are contained: the scan reports
  FAILED gracefully instead of throwing an unhandled error.

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

## Known trade-offs (documented, by design)

- **Group allowlists are broad.** If a chat id is in `AUTHORIZED_IDS`, *any*
  member of that group can trigger scans and spend the VirusTotal quota.
  Prefer user-id allowlists for tighter control.
- **AI prompt-injection surface.** The AI summary prompt includes engine names
  and result strings from VirusTotal — third-party data. Mitigations: the AI
  output is clearly labeled and never authoritative, cannot change the scan
  verdict, and is HTML-escaped before sending. Still, do not act on the AI
  text alone.
- **`/id` answers anyone.** It only echoes the requester's own ids back to
  them (needed for onboarding); it reveals nothing about other users.
