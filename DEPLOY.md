# Hosting the APK Scanner Bot on a VPS (Ubuntu)

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
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs git
node --version   # must be v20.15 or newer
```

## 3. Copy the project to the VPS

**Option A — via Git** (recommended): push this project to a private GitHub
repo, then:

```bash
git clone https://github.com/YOU/apk-scanner-bot.git /opt/apk-scanner-bot
```

**Option B — direct copy from your Windows PC** (run in PowerShell, from the
project's parent directory):

```powershell
scp -r "C:\Users\kushw\.zcode\workspace\db1fd1d8-ef0d-4cd4-b754-2f5a43de3cc0" root@YOUR_VPS_IP:/opt/apk-scanner-bot
```

⚠️ **Never copy your `.env` file to a Git repo** — only via `scp` or by
creating it directly on the VPS (step 5).

## 4. Install dependencies and verify

```bash
cd /opt/apk-scanner-bot
npm ci
npm run typecheck
npm test
```

## 5. Create the secrets file on the VPS

```bash
nano /opt/apk-scanner-bot/.env
```

Fill in (see `.env.example` for all options):

```
TELEGRAM_BOT_TOKEN=...
VIRUSTOTAL_API_KEY=...
AUTHORIZED_IDS=your_telegram_user_id
# optional:
GLM_API_KEY=...
```

Lock it down:

```bash
chmod 600 /opt/apk-scanner-bot/.env
```

## 6. Run it under systemd (auto-start, auto-restart)

Create a dedicated user (don't run as root):

```bash
useradd -r -s /usr/sbin/nologin apkbot
chown -R apkbot:apkbot /opt/apk-scanner-bot
```

Create the service:

```bash
nano /etc/systemd/system/apk-scanner-bot.service
```

```ini
[Unit]
Description=APK malware scanner Telegram bot
After=network-online.target
Wants=network-online.target

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
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now apk-scanner-bot
systemctl status apk-scanner-bot     # should say "active (running)"
journalctl -u apk-scanner-bot -f     # live logs (Ctrl+C to exit)
```

The log line `{"event":"bot.started"}` means it is live.

## 7. Test it

On Telegram, send an APK (≤ 20 MB) as a document to your bot. Expect:

1. `⏳ APK received — downloading…`
2. `⏳ SHA-256: …` (instant for files VirusTotal knows, minutes for new ones)
3. The full report with verdict, engine counts and the VirusTotal link
4. (if GLM configured) a `🤖 AI analysis` follow-up message

## Day-2 operations

| Task | Command |
| --- | --- |
| View logs | `journalctl -u apk-scanner-bot -f` |
| Restart | `systemctl restart apk-scanner-bot` |
| Stop | `systemctl stop apk-scanner-bot` |
| Update code | `cd /opt/apk-scanner-bot && git pull && npm ci && systemctl restart apk-scanner-bot` |
| Change config | edit `/opt/apk-scanner-bot/.env`, then restart |

## Security hardening checklist

- [ ] Run as the dedicated `apkbot` user (done above), never root
- [ ] `.env` is `chmod 600` and owned by `apkbot`
- [ ] `AUTHORIZED_IDS` lists only your own ids — this is the gate that stops
      strangers from spending your VirusTotal quota
- [ ] Keep the VPS patched: `apt update && apt upgrade` regularly (or enable
      `unattended-upgrades`)
- [ ] Firewall: the bot only makes **outbound** HTTPS calls, so you can default-
      deny all inbound ports except SSH: `ufw default deny incoming && ufw allow OpenSSH && ufw enable`
- [ ] If the APKs are confidential, set `ALLOW_UPLOADS=false` (hash-lookup mode)

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
