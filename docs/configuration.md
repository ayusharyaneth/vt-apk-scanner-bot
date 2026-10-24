# Configuration

All settings come from environment variables. A `.env` file in the project
root is loaded automatically (no extra dependency); **real environment
variables always win** over `.env` values. Full defaults in
[`.env.example`](../.env.example).

## Required

| Variable | Description |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Bot token from [@BotFather](https://t.me/BotFather). Format `<numeric id>:<token>` — validated at startup. |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key from [virustotal.com](https://www.virustotal.com/gui/my-apikey). Free tier: 4 requests/min, 500 uploads/day. |
| `AUTHORIZED_IDS` | Comma-separated Telegram **user ids** and/or **chat ids** allowed to trigger scans (group chats have negative ids). Send `/id` to the running bot to discover yours. Unknown senders are rejected before any download. |

## Optional — core behavior

| Variable | Default | Description |
| --- | --- | --- |
| `ALLOW_UPLOADS` | `true` | Upload unknown APKs to VirusTotal for fresh analysis. Set `false` for confidential files — hash-lookup-only mode, nothing is ever uploaded. |
| `UNAUTHORIZED_REPLY` | `true` | Send "not authorized" replies to unknown senders. `false` = ignore silently. |
| `MAX_APK_BYTES` | `20971520` | Hard size cap per APK. Telegram caps bot downloads at 20 MB, so larger values cannot help. |
| `CACHE_TTL_MINUTES` | `30` | How long an identical file's recent result is served from the in-memory cache (0 = disabled). VirusTotal's own hash reports still deduplicate across restarts. |
| `MALICIOUS_THRESHOLD` | `3` | Engines flagging the file malicious ≥ this → **MALICIOUS**. |
| `SUSPICIOUS_THRESHOLD` | `1` | Any malicious detection, or suspicious ≥ this → **SUSPICIOUS**. Never applies to incomplete analyses (those are FAILED). |
| `MAX_CONCURRENT_SCANS` | `2` | Maximum APKs scanned at the same time (1–10). Flood protection. |
| `SCAN_QUEUE_LIMIT` | `5` | Scans may wait in queue when busy; beyond this senders get a "scanner is busy" reply (0 = no queue). |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error`. Logs are structured JSON; all registered secrets are redacted. |

## Optional — VirusTotal tuning

| Variable | Default | Description |
| --- | --- | --- |
| `VT_POLL_INTERVAL_SECONDS` | `20` | Seconds between analysis status polls (5–3600). Default stays under the 4 req/min public quota. |
| `VT_POLL_TIMEOUT_SECONDS` | `300` | Give up waiting for a fresh analysis after this many seconds (30–7200). The scan is reported FAILED, never clean. |
| `VT_MAX_RETRIES` | `3` | Retry attempts for transient errors (5xx, network failures, bounded 429 waits). |
| `VT_REQUEST_TIMEOUT_SECONDS` | `30` | Per-request HTTP timeout for metadata calls. |
| `VT_UPLOAD_TIMEOUT_SECONDS` | `120` | HTTP timeout for file uploads. |
| `VT_MAX_RETRY_AFTER_MS` | `60000` | Longest `Retry-After` wait honored before failing with a quota error. |
| `VT_REUSE_MAX_AGE_HOURS` | `24` | Reuse an existing VirusTotal report only if newer than this (0 = always reuse regardless of age). |
| `VT_API_BASE` | `https://www.virustotal.com` | VirusTotal API base URL. |

## Optional — AI risk assessment (NVIDIA NIM)

The AI feature is **off unless a key is set**; no key means no AI traffic at all.

| Variable | Default | Description |
| --- | --- | --- |
| `NVIDIA_API_KEY` | *(unset)* | Free key from [build.nvidia.com](https://build.nvidia.com). `NIM_API_KEY` works as an alias. |
| `NIM_API_BASE` | `https://integrate.api.nvidia.com/v1` | NIM OpenAI-compatible endpoint. |
| `NIM_MODEL` | `z-ai/glm-5.3` | Model id — find the exact id on the model's page at build.nvidia.com (any NIM-hosted model works). |
| `NIM_TIMEOUT_SECONDS` | `30` | AI request timeout (5–120). A timeout is logged and skipped — the scan report is always delivered. |
| `NIM_SUMMARY_MAX_CHARS` | `600` | Maximum displayed summary length (100–2000). |

## Precedence example

```bash
# .env
VT_POLL_INTERVAL_SECONDS=30
```

```bash
# shell
VT_POLL_INTERVAL_SECONDS=10 npm start   # 10 wins — real env beats .env
```
