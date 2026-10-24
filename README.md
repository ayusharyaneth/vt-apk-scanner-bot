<div align="center">

# 🛡 APK Malware Scanner Bot

**A Telegram bot that automatically scans every APK it receives with the [VirusTotal](https://www.virustotal.com) API — and replies with a full verdict report in the same chat.**

No commands. No manual steps. Send an APK → get the report.

[![CI](https://github.com/ayusharyaneth/apk-scanner-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/ayusharyaneth/apk-scanner-bot/actions/workflows/ci.yml)
[![Node.js](https://img.shields.io/badge/node-%E2%89%A520.15-339933?logo=node.js&logoColor=white)](package.json)
[![Tests](https://img.shields.io/badge/tests-80%20passing-3fbf6b)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

---

## Features

- 🔍 **Automatic scanning** — every document with an `.apk` extension or the Android mime type is scanned on arrival; the sender just sends the file
- 📊 **Complete reports** — filename, size, SHA-256, verdict, per-category engine counts, detection rate, completion time, and a clickable link to the full VirusTotal report
- 🚦 **Honest verdicts** — CLEAN / SUSPICIOUS / MALICIOUS / PENDING / FAILED, with a hard rule: *an incomplete, timed-out, or empty analysis is never reported as clean*
- 🔁 **Quota-friendly** — reuses existing VirusTotal reports by hash, deduplicates concurrent uploads of the same file, and caches recent results
- 🤖 **Optional AI summaries** — a 2–4 sentence plain-language risk assessment via NVIDIA NIM (GLM-5.3), clearly separated from the canonical verdict
- 🔐 **Security-first** — sender allowlist, files never executed, secrets redacted from logs, per-scan temp directories with guaranteed cleanup, graceful shutdown
- ⚡ **One runtime dependency** (`grammy`) — everything else is hand-rolled and unit-tested

## How it works

```
┌──────────┐   APK    ┌─────────────────────┐   hash / upload    ┌────────────┐
│ Telegram ├─────────►│  scan pipeline      ├───────────────────►│ VirusTotal │
│  chat    │◄─────────┤  (this bot, grammY) │◄──── report ───────┤  API v3    │
└──────────┘  report  └─────────────────────┘                    └────────────┘
                        │           ▲
                        ▼           │ status message edits
                 ┌──────────────┐
                 │ NVIDIA NIM   │  (optional AI summary)
                 └──────────────┘
```

1. A document is detected as an APK by Telegram's mime type or its `.apk` extension.
2. The sender is checked against the `AUTHORIZED_IDS` allowlist **before** anything is downloaded.
3. The file is streamed into a private per-scan temp directory under a fixed name — user-supplied filenames never touch the filesystem.
4. Structural validation (ZIP magic bytes + `AndroidManifest.xml` in the central directory, parsed without extraction), then a streaming SHA-256.
5. `GET /api/v3/files/{sha256}` — a report newer than the reuse window is served without uploading; otherwise the APK is uploaded and the analysis polled until completion.
6. Thresholds decide the verdict; the report is sent and the temp directory removed — in a `finally` block, on every path.

**Bot commands**

| Command | Purpose |
| --- | --- |
| *(send an APK)* | Automatic scan — no command needed |
| `/scan` *(reply to an APK)* | Force a fresh VirusTotal analysis, bypassing report reuse |
| `/id` | Show your user id and chat id (for `AUTHORIZED_IDS`) |
| `/start`, `/help` | Usage help |

## Table of contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [AI risk assessment (optional)](#optional-ai-risk-assessment-nvidia-nim--glm-53)
- [Security & privacy](#security--privacy)
- [Testing](#testing)
- [Deploying on a VPS (Ubuntu)](#deploying-on-a-vps-ubuntu--full-walkthrough)
- [Limitations](#limitations)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [License](#license)

## Requirements

**Runtime**

| Requirement | Details |
| --- | --- |
| Node.js | **v20.15 or newer** (tested on Node 24) — includes the npm package manager |
| Operating system | Any that runs Node: Linux (VPS/desktop), Windows, macOS |
| Network | Outbound HTTPS access to `api.telegram.org`, `www.virustotal.com` and (optionally) `integrate.api.nvidia.com` |
| Hardware | Minimal — 1 vCPU / 1 GB RAM and ~50 MB disk (plus temp space up to your `MAX_APK_BYTES` per scan) |
| Runtime dependency | `grammy` (installed automatically via `npm install` / `npm ci`) — no other runtime dependencies |

**Accounts & credentials**

| Requirement | Where to get it | Configured via |
| --- | --- | --- |
| Telegram bot token | Create a bot with [@BotFather](https://t.me/BotFather) on Telegram | `TELEGRAM_BOT_TOKEN` |
| VirusTotal API key | [virustotal.com](https://www.virustotal.com/gui/my-apikey) — free tier is enough (4 req/min, 500 uploads/day) | `VIRUSTOTAL_API_KEY` |
| Authorized Telegram ids | Your own Telegram user id (and/or group chat id) — send `/id` to the running bot to discover it | `AUTHORIZED_IDS` |
| *(Optional)* NVIDIA NIM API key | Only for AI risk summaries — free key at [build.nvidia.com](https://build.nvidia.com) | `NVIDIA_API_KEY` (alias: `NIM_API_KEY`) |

Secrets are supplied by environment variables or a `.env` file (see
[`.env.example`](.env.example)) — never hardcode them.

## Quick start

```bash
git clone https://github.com/ayusharyaneth/apk-scanner-bot.git
cd apk-scanner-bot
npm install
cp .env.example .env        # fill in the three required values
npm start
```

Then send an APK to your bot on Telegram. First-time analyses can take a few
minutes (VirusTotal analyzes unknown files in real time); known hashes get an
instant report.

## Configuration

All settings come from environment variables (a `.env` file is loaded
automatically; real environment variables win). Full list with defaults in
[`.env.example`](.env.example).

| Variable | Default | Description |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | — | **Required.** Bot token from @BotFather |
| `VIRUSTOTAL_API_KEY` | — | **Required.** VirusTotal API key |
| `AUTHORIZED_IDS` | — | **Required.** Comma-separated Telegram user/chat ids allowed to scan |
| `ALLOW_UPLOADS` | `true` | Upload unknown APKs to VirusTotal. `false` = hash-lookup-only mode for confidential files |
| `UNAUTHORIZED_REPLY` | `true` | Reply to unauthorized senders (false = ignore silently) |
| `VT_POLL_INTERVAL_SECONDS` | `20` | Analysis status poll interval (stays under the 4 req/min quota) |
| `VT_POLL_TIMEOUT_SECONDS` | `300` | Give up waiting for an analysis after this |
| `VT_MAX_RETRIES` | `3` | Retries for transient VT errors (5xx, network) |
| `VT_REUSE_MAX_AGE_HOURS` | `24` | Reuse an existing VT report only if newer than this (0 = always reuse) |
| `MALICIOUS_THRESHOLD` | `3` | Engines flagging malicious ≥ this → MALICIOUS |
| `SUSPICIOUS_THRESHOLD` | `1` | Engines flagging suspicious ≥ this → SUSPICIOUS |
| `MAX_APK_BYTES` | `20971520` | Hard size cap (Telegram bots cannot download more than 20 MB) |
| `CACHE_TTL_MINUTES` | `30` | In-memory duplicate-result cache lifetime |
| `NVIDIA_API_KEY` | *(unset = off)* | Enable AI summaries via NVIDIA NIM |
| `NIM_API_BASE` | `https://integrate.api.nvidia.com/v1` | NIM endpoint |
| `NIM_MODEL` | `z-ai/glm-5.3` | NIM model id (see the model's page on build.nvidia.com) |
| `NIM_TIMEOUT_SECONDS` | `30` | AI request timeout |
| `NIM_SUMMARY_MAX_CHARS` | `600` | Max AI summary length shown in chat |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |

## Optional: AI risk assessment (NVIDIA NIM — GLM-5.3)

If `NVIDIA_API_KEY` is set, each completed scan is followed by a second,
clearly labeled message — `🤖 AI analysis (z-ai/glm-5.3)` — a 2–4 sentence
plain-language risk assessment naming the notable engine detections.

- The canonical VirusTotal verdict is **never** altered or replaced; the AI
  output is an additional message and cannot downgrade a finding.
- Best-effort only: an AI timeout, quota, or API error is logged and skipped —
  the scan report is always delivered.
- No key → the feature is fully off and no AI traffic happens.
- The key is redacted from logs like every other secret.

## Security & privacy

- **Secrets** (`TELEGRAM_BOT_TOKEN`, `VIRUSTOTAL_API_KEY`, `NVIDIA_API_KEY`)
  come from environment variables or `.env` and are never logged — a
  redaction layer replaces them with `[REDACTED]` if they ever reach a log line.
- **Uploaded APKs are never executed.** They are only read as bytes: hashing
  and ZIP central-directory parsing. They are treated as untrusted everywhere
  (fixed storage name, sanitized display names, size caps).
- **Temp files** live in per-scan `mkdtemp` directories and are always removed;
  crash leftovers older than an hour are swept at startup.
- **Privacy policy control:** VirusTotal uploads are public by default. If the
  APKs are private/confidential, set `ALLOW_UPLOADS=false` — the bot then only
  performs hash lookups, uploads nothing, and says so when no report exists.
- **Rate/quota aware:** 429 responses honor `Retry-After` (bounded), transient
  5xx/network errors retry with exponential backoff + jitter, Telegram
  flood-waits are retried automatically.
- **Graceful shutdown** on SIGINT/SIGTERM: polling stops, temp dirs cleaned.

## Testing

```bash
npm test          # vitest — 80 tests
npm run typecheck # tsc --noEmit
```

Coverage highlights: clean / suspicious / malicious classification, existing-hash
reuse, stale reports, forced fresh scans, duplicate files (cache + in-flight
merge), unauthorized senders, oversize files, invalid APKs, API failures (5xx,
network), rate limits (transient/persistent 429, over-long Retry-After), auth
errors, analysis timeouts, zero-engine analyses, upload-policy refusal,
temp-dir cleanup on every failure path, report formatting/escaping/length
splitting, config validation, and the NIM AI client.

The suite is fully offline (VirusTotal, Telegram and NIM are faked); CI runs it
on Node 20 and 22 for every push.

## Deploying on a VPS (Ubuntu — full walkthrough)

The bot polls Telegram's API outbound, so **no open ports, domain, or TLS
certificate is needed** — any small VPS (1 vCPU / 1 GB RAM) works. All steps
assume Ubuntu 22.04/24.04 run as `root` over SSH.

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
- a deploy key (ssh-keygen + add under repo → Settings → Deploy keys).

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

Optional: `NVIDIA_API_KEY` (AI summaries) — see the AI section above and
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
  defaults stay under the per-minute cap; hitting the daily cap surfaces as a
  clear FAILED message, never as clean.
- First-time (fresh) analyses can take several minutes; the bot reports
  progress and gives up after `VT_POLL_TIMEOUT_SECONDS`.
- The duplicate-result cache is in memory — it resets on restart (VirusTotal's
  own hash reports still deduplicate across restarts).
- Verdicts are engine-count thresholds on VirusTotal results, not a guarantee;
  a CLEAN verdict means "no engine flagged it", nothing more.
- VirusTotal uploads are public — use `ALLOW_UPLOADS=false` for confidential
  samples.

## Project layout

```
src/
  main.ts        entrypoint: config, logging, shutdown
  bot.ts         grammY wiring: handlers, /scan, /help, /id, flood-wait retry
  pipeline.ts    scan orchestration (auth → download → hash → lookup/upload → poll → report)
  virustotal.ts  VT API v3 client: retries, rate limits, upload, polling
  ai.ts          optional NVIDIA NIM (GLM-5.3) summary client + prompt builder
  telegram.ts    status-message reporter + streaming Telegram downloader
  apk.ts         APK detection, ZIP/manifest validation, SHA-256
  classify.ts    verdict thresholds (never clean without completed results)
  report.ts      HTML report + progress texts + 4096-char splitting
  config.ts      env/.env loading with full validation
  logger.ts      structured JSON logging with secret redaction
  tempfiles.ts   per-scan temp dirs, startup sweep, shutdown cleanup
tests/           vitest suites for every module (offline)
```

## Contributing

Issues and pull requests are welcome. For changes, please:

1. Keep the test suite green: `npm run typecheck && npm test`
2. Add tests for new behavior — the existing suites cover every module offline
3. Never commit secrets or `.env`

## License

Released under the [MIT License](LICENSE).
