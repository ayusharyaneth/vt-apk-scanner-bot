<div align="center">

# 🛡 APK Malware Scanner Bot

**Send an APK to your Telegram bot → get a VirusTotal verdict report in the same chat.**

No commands. No manual steps. Nothing is ever executed.

[![CI](https://github.com/ayusharyaneth/vt-apk-scanner-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/ayusharyaneth/vt-apk-scanner-bot/actions/workflows/ci.yml)
[![Node.js](https://img.shields.io/badge/node-%E2%89%A520.15-339933?logo=node.js&logoColor=white)](package.json)
[![Tests](https://img.shields.io/badge/tests-80%20passing-3fbf6b)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

---

## Features

- 🔍 **Automatic scanning** — every `.apk` document sent to the bot is scanned on arrival
- 📊 **Complete reports** — SHA-256, verdict, engine counts, detection rate, completion time, VirusTotal link
- 🚦 **Honest verdicts** — CLEAN / SUSPICIOUS / MALICIOUS / PENDING / FAILED; an incomplete or timed-out analysis is *never* reported as clean
- 🔁 **Quota-friendly** — existing VT reports reused by hash, duplicate uploads deduplicated
- 🤖 **Optional AI summary** — 2–4 sentence risk assessment via NVIDIA NIM (GLM-5.3)
- 🔐 **Security-first** — sender allowlist, files never executed, secrets redacted from logs, temp files always cleaned

## How it works

```
┌──────────┐   APK    ┌─────────────────────┐   hash / upload    ┌────────────┐
│ Telegram ├─────────►│  scan pipeline      ├───────────────────►│ VirusTotal │
│  chat    │◄─────────┤  (this bot, grammY) │◄──── report ───────┤  API v3    │
└──────────┘  report  └─────────────────────┘                    └────────────┘
```

Download → ZIP/manifest validation (no extraction) → SHA-256 → existing-report
lookup → upload + poll if unknown → verdict by thresholds → report. Duplicate
files reuse VirusTotal's own reports, an in-memory cache, or an in-flight merge.

**Bot commands:** send an APK (automatic) · `/scan` as a reply forces a fresh
re-scan · `/id` shows your ids · `/help` prints usage.

## Documentation

| Document | Contents |
| --- | --- |
| [Configuration](docs/configuration.md) | Every environment variable, defaults, precedence |
| [Deployment](docs/deployment.md) | Full VPS walkthrough (Ubuntu): systemd, hardening, troubleshooting |
| [Architecture](docs/architecture.md) | Scan pipeline, module map, design decisions |
| [Security & privacy](docs/security.md) | Threat model, secrets handling, VirusTotal upload policy |
| [Testing](docs/testing.md) | What the 80 tests cover, how to run them |

## Requirements

- **Node.js ≥ 20.15**, outbound HTTPS to `api.telegram.org` and `www.virustotal.com`
- **Telegram bot token** ([@BotFather](https://t.me/BotFather)) → `TELEGRAM_BOT_TOKEN`
- **VirusTotal API key** ([virustotal.com](https://www.virustotal.com/gui/my-apikey), free tier suffices) → `VIRUSTOTAL_API_KEY`
- **Your Telegram id** (send `/id` to the bot) → `AUTHORIZED_IDS`
- *Optional:* NVIDIA NIM key ([build.nvidia.com](https://build.nvidia.com)) → `NVIDIA_API_KEY` for AI summaries

## Quick start

```bash
git clone https://github.com/ayusharyaneth/vt-apk-scanner-bot.git
cd vt-apk-scanner-bot
npm install
cp .env.example .env        # fill in the three required values
npm start
```

First-time analyses take a few minutes (VirusTotal analyzes unknown files in
real time); known hashes get an instant report.

## Configuration

All settings come from environment variables or `.env` (real environment
variables win). **Every option, default, and description is documented in
[`docs/configuration.md`](docs/configuration.md)** — including `ALLOW_UPLOADS`
(set `false` to never upload confidential APKs), verdict thresholds, poll
intervals, and size caps.

| Required | Purpose |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `AUTHORIZED_IDS` | Comma-separated Telegram user/chat ids allowed to scan |

## Security & privacy

- Secrets come from env vars/`.env` and are redacted if they ever reach a log line
- APKs are only read as bytes (hashing, ZIP parsing) — **never executed**
- Rate limits, retries, and Telegram flood-waits are handled automatically
- Full threat model and the VirusTotal upload-privacy policy:
  [`docs/security.md`](docs/security.md)

## Testing

```bash
npm test          # vitest — 80 tests, fully offline
npm run typecheck # tsc --noEmit
```

CI runs both on Node 20 and 22 for every push. Coverage includes clean /
malicious / suspicious classification, report reuse, fresh scans, duplicates,
unauthorized senders, API failures, rate limits, timeouts, invalid APKs, and
config validation — full breakdown in [`docs/testing.md`](docs/testing.md).

## Deploying on a VPS

Any small VPS (1 vCPU / 1 GB RAM) works — the bot is outbound-only, so no open
ports, domain, or TLS is needed. Node install → clone → `.env` → systemd
service: **the complete step-by-step guide lives in
[`docs/deployment.md`](docs/deployment.md)**, including the systemd unit,
day-2 operations, hardening checklist, and troubleshooting table.

## Limitations

- Telegram caps bot file downloads at 20 MB (larger APKs are refused)
- VirusTotal free quota: 4 req/min, 500 uploads/day — quota exhaustion is
  reported as FAILED, never as clean
- VT uploads are public — use `ALLOW_UPLOADS=false` for confidential samples
- A CLEAN verdict means "no engine flagged it", not a guarantee of safety

## Project layout

```
src/  bot.ts · pipeline.ts · virustotal.ts · ai.ts · telegram.ts ·
      apk.ts · classify.ts · report.ts · config.ts · logger.ts · tempfiles.ts
tests/  vitest suites for every module (offline)
```

## Contributing

Issues and PRs are welcome — keep `npm run typecheck && npm test` green, add
tests for new behavior, and never commit secrets.

## License

Released under the [MIT License](LICENSE).
