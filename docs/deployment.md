# Deployment — Hosting on a VPS (Ubuntu)

Step-by-step deployment for a typical Linux VPS (Ubuntu 22.04/24.04).
The bot is a single long-running Node.js process that polls Telegram's API —
**no public port, domain, TLS certificate, or reverse proxy is required**, which
makes it very easy to host.

## 1. Get a VPS

Any small VPS works (1 vCPU / 1 GB RAM is plenty). Ubuntu 22.04 or 24.04
recommended. You need SSH access:

```bash
ssh root@YOUR_VPS_IP
```

## 2. Install Node.js 20+

The bot requires Node ≥ 20.15 (tested on Node 24):

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -apt-get install -y nodejs git
node --version
```

> **What is `/opt`?** It is a standard Linux directory — by the Filesystem
> Hierarchy Standard, `/opt` is where manually-installed, self-contained
> server software lives (as opposed to packages installed via `apt`, which go
> under `/usr`). It exists by default on every Ubuntu system, so there is
> nothing to install; the `mkdir -p` below is just an idempotent safeguard.
> Any directory works (e.g. `/srv/vt-apk-scanner-bot`) as long as you use the
> same path in the systemd unit (step 6).

```bash
mkdir -p /opt    # safeguard — /opt already exists on stock Ubuntu
```

## 3. Copy the project to the VPS

**Option A — via Git** (recommended). The repository is public, so cloning
needs **no account or authentication**:

```bash
git clone https://github.com/ayusharyaneth/vt-apk-scanner-bot.git /opt/vt-apk-scanner-bot
```

You only ever need GitHub credentials on the VPS if you want to `git push`
from there (updates normally flow PC → GitHub → `git pull` on the VPS).

**Option B — direct copy from your Windows PC** (run in PowerShell):

```powershell
scp -r "path\to\vt-apk-scanner-bot" root@YOUR_VPS_IP:/opt/vt-apk-scanner-bot
```

⚠️ **Never copy or commit your `.env` file** — create it directly on the VPS
(step 5). This matters even more now that the repo is public: everything in
Git history is world-readable, so the only acceptable place for secrets is the
`.env` file on the machine that runs the bot.

## 4. Install dependencies and verify

```bash
cd /opt/vt-apk-scanner-bot
npm ci
npm run typecheck
npm test
```

## 5. Create the secrets file on the VPS

```bash
nano /opt/vt-apk-scanner-bot/.env
```

Minimum required content (see [configuration.md](configuration.md) for everything):

```
TELEGRAM_BOT_TOKEN=...
VIRUSTOTAL_API_KEY=...
AUTHORIZED_IDS=your_telegram_user_id
# optional:
NVIDIA_API_KEY=...
```

Lock it down:

```bash
chmod 600 /opt/vt-apk-scanner-bot/.env
```

## 6. Run it under systemd (auto-start, auto-restart)

Create a dedicated user (don't run as root):

```bash
useradd -r -s /usr/sbin/nologin apkbot
chown -R apkbot:apkbot /opt/vt-apk-scanner-bot
```

Create the service:

```bash
nano /etc/systemd/system/vt-apk-scanner-bot.service
```

```ini
[Unit]
Description=APK malware scanner Telegram bot
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/vt-apk-scanner-bot
ExecStart=/usr/bin/node node_modules/tsx/dist/cli.mjs src/main.ts
Restart=on-failure
RestartSec=5
User=apkbot
Group=apkbot
EnvironmentFile=/opt/vt-apk-scanner-bot/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now vt-apk-scanner-bot
systemctl status vt-apk-scanner-bot     # should say "active (running)"
journalctl -u vt-apk-scanner-bot -f     # live logs (Ctrl+C to exit)
```

The log line `{"event":"bot.started"}` means it is live.

### Validating the setup with dummy data

You can validate every step above **before** you have real keys. Run the same
command systemd would run, with placeholder values in `.env`:

```bash
node node_modules/tsx/dist/cli.mjs src/main.ts
```

Expected output with **dummy credentials** — this is success, not a failure:

```
{"event":"startup.config","authorizedIds":[424242], ...}          ← .env parsed, config valid
Fatal error: Call to 'deleteWebhook' failed! (401: Unauthorized)  ← expected with a dummy token
```

The `startup.config` line proves the clone, `npm ci`, `.env` parsing and the
code all work. The 401 is correct behavior — Telegram rejected the *dummy*
token; only real credentials complete startup (`{"event":"bot.started"}`).
The VirusTotal and NVIDIA keys are first exercised when the first scan runs:
a wrong `VIRUSTOTAL_API_KEY` shows up in scan logs as `VirusTotal rejected the
API key (HTTP 401)` — see Troubleshooting below.

Once real credentials are in place and `bot.started` appears, send an APK and
watch `journalctl` for `bot.apk_received` → `scan.started` → `scan.completed`.

## 7. Test it

On Telegram, send an APK (≤ 20 MB) as a document to your bot. Expect:

1. `⏳ APK received — downloading…`
2. `⏳ SHA-256: …` (instant for files VirusTotal knows, minutes for new ones)
3. The full report with verdict, engine counts and the VirusTotal link
4. (if NVIDIA NIM configured) a `🤖 AI analysis` follow-up message

## Day-2 operations

| Task | Command |
| --- | --- |
| View logs | `journalctl -u vt-apk-scanner-bot -f` |
| Restart | `systemctl restart vt-apk-scanner-bot` |
| Stop | `systemctl stop vt-apk-scanner-bot` |
| Update code | `cd /opt/vt-apk-scanner-bot && git pull && npm ci && systemctl restart vt-apk-scanner-bot` |
| Change config | edit `/opt/vt-apk-scanner-bot/.env`, then restart |

## Security hardening checklist

- [ ] Run as the dedicated `apkbot` user (done above), never root
- [ ] `.env` is `chmod 600` and owned by `apkbot`
- [ ] `AUTHORIZED_IDS` lists only your own ids — this is the gate that stops
      strangers from spending your VirusTotal quota. With a public repo anyone
      can find the bot's name in the code and message it, so this allowlist is
      your only access control: prefer **user ids** over group-chat ids, and
      treat unauthorized-message spam as expected background noise
      (`UNAUTHORIZED_REPLY=false` silences the replies if it gets noisy)
- [ ] Keep the VPS patched: `apt update && apt upgrade` regularly (or enable
      `unattended-upgrades`)
- [ ] Firewall: the bot only makes **outbound** HTTPS calls, so you can default-
      deny all inbound ports except SSH: `ufw default deny incoming && ufw allow OpenSSH && ufw enable`
- [ ] If the APKs are confidential, set `ALLOW_UPLOADS=false` (hash-lookup mode)
- [ ] Never put secrets anywhere in the repository — it is public, so every
      file, every commit, and the full Git history are world-readable. Secrets
      live only in `.env` on the machines that need them

## Troubleshooting

- **`Invalid configuration: ...` at start** → a variable is missing/typo'd in
  `.env`; the error names exactly which ones.
- **`Call to 'getMe' failed! (401 ...)`** → wrong `TELEGRAM_BOT_TOKEN`.
- **`VirusTotal rejected the API key (HTTP 401)`** in scan logs → wrong
  `VIRUSTOTAL_API_KEY`.
- **`authorizedIds` empty / every scan unauthorized** → `AUTHORIZED_IDS` is
  missing or malformed (comma-separated numeric ids; send `/id` to the bot to
  discover yours).
- **Nothing happens at all** → check the bot was started (`systemctl status`)
  and that you sent the file as a *document* (attachment), not a photo, and
  that the filename ends in `.apk`.
