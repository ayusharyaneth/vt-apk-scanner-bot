# Testing

```bash
npm test          # vitest — 80 tests
npm run typecheck # tsc --noEmit
```

The suite is **fully offline** — VirusTotal, Telegram and NVIDIA NIM are all
faked — so it runs anywhere, quickly, with no keys. CI runs it on Node 20 and
22 for every push and pull request.

## Test files

| File | What it covers |
| --- | --- |
| `tests/pipeline.test.ts` | The full scan orchestration: happy paths, duplicates, authorization, and every failure mode |
| `tests/virustotal.test.ts` | VT client: report parsing, detection extraction, retries, rate limits, auth errors, upload, polling |
| `tests/apk.test.ts` | APK detection, ZIP/manifest structural validation (including corrupt archives), SHA-256, filename sanitizing |
| `tests/classify.test.ts` | Verdict thresholds — including the rule that zero engine results can never be CLEAN |
| `tests/report.test.ts` | Report contents for every verdict, HTML escaping, message splitting under Telegram's 4096-char limit |
| `tests/config.test.ts` | Required/optional parsing, defaults, invalid values, NVIDIA NIM settings |
| `tests/ai.test.ts` | NIM client: request shape, custom base/model, HTTP/JSON/empty/network failures |
| `tests/helpers/zip.ts` | Builds real in-memory ZIP/APK fixtures for validation tests |

## Covered scenarios

**Scan outcomes** — clean reports; malicious detections at/above threshold;
suspicious (1–2 malicious, or suspicious-only); existing-hash reuse; stale
reports past the reuse window; forced fresh scans (`/scan`); duplicate files
served from cache; concurrent duplicates merged into one in-flight analysis.

**Authorization** — unauthorized user ids rejected before download; chat-id
(group) allowlists; silent mode via `UNAUTHORIZED_REPLY=false`.

**Failures — never reported as clean** — oversize files refused before
download; non-APK and corrupt ZIP files; VirusTotal 5xx and network errors;
persistent 429 quota errors; over-long `Retry-After`; 401/403 auth errors;
analysis timeouts; completed analyses with zero engine results; upload-policy
refusal (`ALLOW_UPLOADS=false`); Telegram download errors. Every failure path
sends a FAILED report and cleans up the temp directory — verified.

**Clients** — retry/backoff behavior, `Retry-After` parsing, 404-as-null for
unknown hashes, multipart upload shape, poll-until-completed with tick
callbacks, AI request shape and error mapping, config validation for every
variable.
