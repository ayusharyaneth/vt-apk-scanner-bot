# APK Malware Scanner — Telegram Bot

A Telegram bot that **automatically scans every APK a user sends** with the
[VirusTotal](https://www.virustotal.com) API and replies with a full verdict
report **in the same chat**. No commands are needed for a normal scan: send the
APK, get the report.

```
┌──────────┐  APK    ┌────────────┐  hash / upload   ┌────────────┐
│ Telegram ├────────►│ this bot   ├─────────────────►│ VirusTotal │
│  chat    │◄────────┤ (grammY)   │◄───── report ────┤  API v3    │
└──────────┘ report  └────────────┘                  └────────────┘
```

## What the report contains

Filename, file size, SHA-256, final status (**CLEAN / SUSPICIOUS / MALICIOUS / PENDING / FAILED**),
per-category engine counts (malicious / suspicious / harmless / undetected / no-result),
total engines, detection rate with percentage, scan completion time (UTC), scan
duration, the source of the result (fresh analysis / reused existing report / bot cache),
and a clickable link to the full VirusTotal report.

**Incomplete or failed scans are never classified as clean.** A timeout, quota
error, or zero-engine result always produces a FAILED report that says so
explicitly.

Progress is reported live by editing a single status message: *downloading →
validating & hashing → checking VirusTotal → uploading → analysis in progress →
final report*.

## How a scan works

1. A document is treated as an APK by Telegram's mime type
   (`application/vnd.android.package-archive`) or the `.apk` extension.
2. The sender (user id or chat id) must be in `AUTHORIZED_IDS` or processing
   stops before anything is downloaded.
3. The file is downloaded to a fresh, private temp directory under a fixed name
   (`payload.apk`) — user-supplied filenames never touch the filesystem.
4. Structural validation: ZIP magic bytes and a `AndroidManifest.xml` entry in
   the central directory (parsed without extraction). Anything else is rejected
   as *not a valid APK*.
5. Streaming SHA-256, then `GET /api/v3/files/{sha256}`:
   - a report newer than `VT_REUSE_MAX_AGE_HOURS` is reused (no upload), or
   - the APK is uploaded (`POST /api/v3/files`) and the analysis is polled
     (`GET /api/v3/analyses/{id}`) until completed.
6. Verdict thresholds: `malicious ≥ MALICIOUS_THRESHOLD` → **MALICIOUS**;
   `malicious ≥ 1` or `suspicious ≥ SUSPICIOUS_THRESHOLD` → **SUSPICIOUS**;
   otherwise **CLEAN** (only when the analysis completed with engine results).
7. The final report replaces the status message; the temp directory is deleted
   in a `finally` block no matter how the scan ends.

Duplicate handling: identical files are deduplicated three ways — VirusTotal's
own hash reports, an in-flight merge (two users sending the same file at once
trigger one analysis), and a short-lived in-memory result cache.

Optional fresh scan: **reply to an APK message with `/scan`** to force a new
VirusTotal analysis even if a report exists. `/id` prints your user/chat id,
`/start` and `/help` print usage.

## Optional: AI risk assessment (GLM 5.3 Flash)

If `GLM_API_KEY` is set, the bot additionally calls the **GLM 5.3 Flash**
model (Zhipu open-platform chat API) after each completed scan and replies
with a second message — a 2–4 sentence plain-language risk assessment that
names the notable engine detections. Properties of this design:

- The canonical VirusTotal verdict is **never** altered or replaced by the AI
  output; it arrives as a clearly labeled follow-up message.
- Best-effort only: an AI timeout, quota, or API error is logged and skipped —
  the scan report is always delivered regardless.
- No `GLM_API_KEY` → the feature is fully off and no AI traffic happens.
- The key is stored like the other secrets (env var / `.env`) and redacted
  from logs.

Optional AI settings (defaults in `.env.example`): `GLM_API_BASE`
(`https://open.bigmodel.cn/api/paas/v4`), `GLM_MODEL` (`glm-5.3-flash`),
`GLM_TIMEOUT_SECONDS` (30), `GLM_SUMMARY_MAX_CHARS` (600).

## Security & privacy

- Secrets (`TELEGRAM_BOT_TOKEN`, `VIRUSTOTAL_API_KEY`) come from environment
  variables or a `.env` file and are **never logged** — a redaction layer
  replaces them with `[REDACTED]` if they ever reach a log line.
- **Uploaded APKs are never executed.** They are only read as bytes: hashing
  and ZIP central-directory parsing. They are treated as untrusted input
  everywhere (fixed storage name, sanitized display names, size caps).
- Temp files live in per-scan `mkdtemp` directories and are always removed;
  crash leftovers older than an hour are swept at startup.
- **Privacy policy control:** VirusTotal uploads are public by default. If the
  APKs are private/confidential, set `ALLOW_UPLOADS=false` — the bot then only
  performs hash lookups and tells the user when no report exists, uploading
  nothing. Combine this with a strict `AUTHORIZED_IDS` allowlist.
- Rate/quota aware: 429 responses honor `Retry-After` (bounded by
  `VT_MAX_RETRY_AFTER_MS`), transient 5xx/network errors retry with exponential
  backoff + jitter, Telegram flood-waits are retried once automatically.
- Graceful shutdown on SIGINT/SIGTERM: polling stops, temp dirs cleaned.

## Setup

Requires **Node.js ≥ 20.15** (tested on Node 24). One runtime dependency
(`grammy`); dev dependencies are TypeScript tooling and vitest only.

```bash
npm install
cp .env.example .env     # then fill in the three required values
npm start
```

Required configuration:

| Variable | Meaning |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `VIRUSTOTAL_API_KEY` | Key from virustotal.com → My API key |
| `AUTHORIZED_IDS` | Comma-separated Telegram user and/or chat ids allowed to scan (send `/id` to the bot to discover them) |

Optional configuration (defaults in `.env.example`): `ALLOW_UPLOADS`,
`UNAUTHORIZED_REPLY`, `VT_POLL_INTERVAL_SECONDS` (20), `VT_POLL_TIMEOUT_SECONDS`
(300), `VT_MAX_RETRIES` (3), `VT_REUSE_MAX_AGE_HOURS` (24),
`MALICIOUS_THRESHOLD` (3), `SUSPICIOUS_THRESHOLD` (1), `MAX_APK_BYTES`
(20971520 — Telegram bots cannot download more than 20 MB), `CACHE_TTL_MINUTES`
(30), `LOG_LEVEL` (info).

Real environment variables always win over `.env` values. The startup log
prints the effective (non-secret) configuration for auditability.

## Testing

```bash
npm test          # vitest — 80 tests
npm run typecheck # tsc --noEmit
```

Covered scenarios: clean / suspicious / malicious classification, existing-hash
reuse, stale reports, forced fresh scans, duplicate files (cache + in-flight
merge), unauthorized senders (with and without reply), oversize files, invalid
APKs, API failures (5xx, network), rate limits (transient and persistent 429,
over-long Retry-After), auth errors (401/403), analysis timeouts, zero-engine
analyses, upload-policy refusal, temp-dir cleanup on every failure path, report
formatting/escaping/length splitting, and config validation.

The test suite is fully offline (VirusTotal and Telegram are faked); it does
**not** prove anything about your real API key or bot token.

## Deploying on a VPS (Ubuntu — full walkthrough)

The bot polls Telegram's API outbound, so **no open ports, domain, or TLS
certificate is needed** — any small VPS (1 vCPU / 1 GB RAM) works. All steps
below assume Ubuntu 22.04/24.04 and run as `root` over SSH (switch to `sudo`
if you use a normal user).

### 1. Install Node.js 20+ on the VPS

```bash
ssh root@YOUR_VPS_IP
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs git
node --version    # must be v20.15 or newer
```

### 2. Clone the repository

Private repo → authenticate first with one of:
- `gh auth login` (GitHub CLI), or
- a personal access token when git asks for a password, or
- a deploy key (ssh-keygen + add to repo → Settings → Deploy keys).

```bash
git clone https://github.com/ayusharyaneth/apk-scanner-bot.git /opt/apk-scanner-bot
cd /opt/apk-scanner-bot
```

### 3. Install dependencies and verify

```bash
npm ci
npm run typecheck
npm test
```

### 4. Create the secrets file

```bash
nano /opt/apk-scanner-bot/.env
```

Minimum required content:

```
TELEGRAM_BOT_TOKEN=<from @BotFather>
VIRUSTOTAL_API_KEY=<from virustotal.com/gui/my-apikey>
AUTHORIZED_IDS=<your Telegram user id>   # send /id to the bot to discover it
```

Optional: `GLM_API_KEY` (AI summaries) — see the AI section above and
`.env.example` for every other knob. Lock the file down:

```bash
chmod 600 /opt/apk-scanner-bot/.env
```

### 5. Run as a systemd service (auto-start + auto-restart)

```bash
useradd -r -s /usr/sbin/nologin apkbot
chown -R apkbot:apkbot /opt/apk-scanner-bot

cat > /etc/systemd/system/apk-scanner-bot.service <<'EOF'
[Unit]
Description=APK malware scanner Telegram bot
After=network-online.target

[Service]
WorkingDirectory=/opt/apk-scanner-bot
ExecStart=/usr/bin/node node_modules/tsx/dist/cli.mjs src/main.ts
Restart=on-failure
RestartSec=5
User=apkbot
Group=apkbot
EnvironmentFile=/opt/apk-scanner-bot/.env

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now apk-scanner-bot
```

### 6. Verify and test

```bash
systemctl status apk-scanner-bot    # should be "active (running)"
journalctl -u apk-scanner-bot -f    # live logs — wait for {"event":"bot.started"}
```

Then send an APK (≤ 20 MB) as a document to your bot in Telegram: you get
progress updates, the full VirusTotal report, and (if configured) the AI
summary — all in the same chat.

### 7. Day-2 operations

| Task | Command |
| --- | --- |
| Live logs | `journalctl -u apk-scanner-bot -f` |
| Restart / stop | `systemctl restart apk-scanner-bot` / `systemctl stop ...` |
| Update code | `cd /opt/apk-scanner-bot && git pull && npm ci && systemctl restart apk-scanner-bot` |
| Change config | edit `.env`, then `systemctl restart apk-scanner-bot` |

### 8. Hardening checklist

- The bot runs as the dedicated `apkbot` user, never root; `.env` is `chmod 600`.
- Firewall is safe to default-deny inbound (the bot is outbound-only):
  `ufw default deny incoming && ufw allow OpenSSH && ufw enable`
- Keep the VPS patched (`apt update && apt upgrade`, or enable
  `unattended-upgrades`).
- Keep `AUTHORIZED_IDS` limited to your own ids — it is the gate protecting
  your VirusTotal quota (4 req/min, 500 uploads/day on the free tier).
- Confidential APKs? Set `ALLOW_UPLOADS=false` (hash-lookup-only mode).

### Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Invalid configuration: ...` at startup | Missing/typo'd `.env` value — the error names the variables |
| `Call to 'getMe' failed! (401)` | Wrong `TELEGRAM_BOT_TOKEN` |
| `VirusTotal rejected the API key (HTTP 401)` in scan logs | Wrong `VIRUSTOTAL_API_KEY` |
| Every scan "unauthorized" | `AUTHORIZED_IDS` missing/wrong — check `/id` output |
| Bot silent after sending APK | Send the file as a **document** (attachment), filename ending `.apk` |

Local (non-VPS) runs stay simple: `cp .env.example .env`, fill it in, `npm start`.

## Limitations

- **Telegram caps bot file downloads at 20 MB** — larger APKs are refused
  before download. (VirusTotal would accept up to 32 MB on the standard
  endpoint, but the Telegram cap is binding.)
- **VirusTotal public API quota is 4 requests/minute and 500/day** — polling
  defaults (20 s) stay under the per-minute cap; a busy day of fresh scans can
  hit the daily cap, which surfaces as a clear FAILED message, never as clean.
- First-time (fresh) analyses can take several minutes; the bot reports
  progress and gives up after `VT_POLL_TIMEOUT_SECONDS`.
- The duplicate-result cache is in memory — it resets on restart (VirusTotal's
  own hash reports still deduplicate across restarts).
- Verdicts are engine-count thresholds on VirusTotal results, not a guarantee;
  a CLEAN verdict means "no engine flagged it", nothing more.
- VirusTotal free keys upload files publicly. Use `ALLOW_UPLOADS=false` for
  confidential samples.

## Project layout

```
src/
  main.ts        entrypoint: config, logging, shutdown
  bot.ts         grammY wiring: handlers, /scan, /help, /id, flood-wait retry
  pipeline.ts    scan orchestration (auth → download → hash → lookup/upload → poll → report)
  virustotal.ts  VT API v3 client: retries, rate limits, upload, polling
  ai.ts          optional GLM 5.3 Flash summary client + prompt builder
  telegram.ts    status-message reporter + streaming Telegram downloader
  apk.ts         APK detection, ZIP/manifest validation, SHA-256
  classify.ts    verdict thresholds (never clean without completed results)
  report.ts      HTML report + progress texts + 4096-char splitting
  config.ts      env/.env loading with full validation
  logger.ts      structured JSON logging with secret redaction
  tempfiles.ts   per-scan temp dirs, startup sweep, shutdown cleanup
tests/           vitest suites for every module (offline)
```
