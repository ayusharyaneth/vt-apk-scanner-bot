# Architecture

## Scan pipeline

```
Telegram update (message:document)
        │
        ▼
┌────────────────────────────┐
│ bot.ts (grammY)            │  APK detected by mime type / .apk extension
│  flood-wait middleware     │
└──────────┬─────────────────┘
           ▼
┌────────────────────────────┐
│ pipeline.ts  runScan()     │
│ 1. authorization check     │  user id / chat id ∈ AUTHORIZED_IDS — before any download
│ 2. size check              │  rejected before download if > MAX_APK_BYTES
│ 3. download                │  telegram.ts → streamed, size-capped, fixed name
│ 4. validate                │  apk.ts → ZIP magic + AndroidManifest.xml (no extraction)
│ 5. hash                    │  apk.ts → streaming SHA-256
│ 6. lookup                  │  cache → VT file report (if fresh) → upload if unknown
│ 7. poll                    │  VT analyses endpoint until completed (interval/timeout)
│ 8. classify + report       │  classify.ts → report.ts → Telegram message
└────────────────────────────┘
        finally: temp dir removed — on every path
```

## Module map

| Module | Responsibility |
| --- | --- |
| `src/main.ts` | Entrypoint: load config, register secrets for redaction, build clients, wire SIGINT/SIGTERM |
| `src/bot.ts` | grammY setup: document handler (auto-scan), `/scan`, `/id`, `/help`, flood-wait retry middleware, per-chat reporter construction |
| `src/pipeline.ts` | The orchestrator above; also the result cache and in-flight duplicate merge |
| `src/virustotal.ts` | VT API v3 client — `GET /files/{sha256}`, `POST /files` (multipart), `GET /analyses/{id}`; retry/backoff, `Retry-After` handling, typed error classes (`Auth`, `Quota`, `Api`, `AnalysisTimeout`) |
| `src/ai.ts` | Optional NVIDIA NIM (OpenAI-compatible) client + prompt builder; best-effort by contract |
| `src/telegram.ts` | `TelegramReporter` (one live-edited status message per scan, fallback to new messages) and `TelegramDownloader` (streaming, mid-stream size cap, token never logged) |
| `src/apk.ts` | APK detection, ZIP/central-directory validation without extraction, streaming SHA-256, filename sanitizing |
| `src/classify.ts` | Threshold logic; zero-engine results are FAILED, never CLEAN |
| `src/report.ts` | HTML report formatting, progress texts, 4096-char message splitting |
| `src/config.ts` | `.env`/environment loading with full validation and helpful multi-error messages |
| `src/logger.ts` | Structured JSON logging with secret redaction |
| `src/tempfiles.ts` | Per-scan `mkdtemp` dirs, startup sweep of crash leftovers, shutdown cleanup |

## Design decisions

- **One status message, edited live.** Progress updates edit a single Telegram
  message instead of spamming the chat; if the edit fails (deleted message),
  it falls back to sending a new message.
- **Three layers of duplicate handling.** VirusTotal's own hash reports (free),
  an in-flight merge (two users sending the same file share one analysis), and
  a TTL cache (instant answer for recently scanned files).
- **Failures are a verdict, not an exception.** Timeouts, quota errors and
  empty analyses produce an explicit FAILED report telling the user the file
  was *not* classified as clean — never a silent fallback to CLEAN.
- **Narrow interfaces for testability.** `VTApi`, `Downloader`,
  `ProgressReporter`, `AiSummarizer` are small interfaces; tests inject fakes,
  so the whole pipeline is exercised offline.
- **No framework beyond grammY.** Config loading, logging, ZIP parsing and
  HTTP handling are hand-rolled to keep the dependency surface minimal.

## AI summary flow (optional)

```
scan completed ──► buildSummaryPrompt(verdict, stats, top detections)
              ──► POST {NIM_API_BASE}/chat/completions  (model: z-ai/glm-5.3)
              ──► reply: "🤖 AI analysis (<model>)" as a separate message
       any failure ──► log warn, skip — never blocks the scan report
```

The system prompt pins the model to the provided verdict (it cannot downgrade
MALICIOUS/SUSPICIOUS findings), limits length, and forbids inventing details.
