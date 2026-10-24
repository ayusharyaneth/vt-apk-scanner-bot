# Deployment — Testing locally & Hosting on a VPS (Ubuntu)

Two ways to run the bot. Start with the **local quick test** — it works in any
terminal (Windows PowerShell/Git Bash, macOS, Linux) and proves everything
works before you touch a server. Then deploy to the VPS with the full
systemd walkthrough.

> **Why `/opt` failed in your terminal:** `/opt` is a Linux-only directory
> (standard location for manually-installed server software). It does not
> exist on Windows, and Git Bash maps it into `C:\Program Files\Git\` where
> `mkdir` and `git clone` fail with permission errors. The local test below
> uses your **home directory** instead, which works everywhere. `/opt` is used
> only on the Linux VPS, where it exists by default.

## Local quick test (any terminal, no VPS needed)

Requires [Node.js](https://nodejs.org) ≥ 20.15 installed locally. Run these in
whatever terminal you have — including PowerShell or Git Bash on Windows:

```bash
git clone https://github.com/ayusharyaneth/vt-apk-scanner-bot.git
cd vt-apk-scanner-bot
npm install
cp .env.example .env     # Windows PowerShell: copy .env.example .env
npm start
```

Fill the three required values into `.env` (see step 5 below for where to get
them). What you should see:

- **Real credentials** → `{"event":"bot.started", ...}` — open Telegram, send
  an APK (≤ 20 MB) to your bot, and get the report.
- **Placeholder/dummy credentials** → the `startup.config` log line followed
  by `401: Unauthorized` — that is *correct* behavior with a fake token (see
  [Validating with dummy data](#validating-the-setup-with-dummy-data) below).
- `Ctrl+C` stops the bot cleanly (temp dirs are cleaned up on shutdown).

The rest of this guide is for the real hosting setup on a VPS.

---

# Hosting on a VPS (Ubuntu 22.04/24.04)

Any small VPS (1 vCPU / 1 GB RAM) works. The bot polls Telegram's API
outbound — **no open ports, domain, TLS certificate, or reverse proxy is
required**. The install directory is kept in an `APP_DIR` variable so you
cannot mistype it; it is set to the Linux-standard `/opt` location. All steps
run as `root` over SSH (use `sudo` if you log in as a normal user).

## 1. Get a VPS

```bash
ssh root@YOUR_VPS_IP
```

## 2. Install Node.js 20+ and set the install directory

The bot requires Node ≥ 20.15 (tested on Node 24):

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs git
node --version   # must be v20.15 or newer

# Where the bot will live. /opt is the standard Linux location for
# manually-installed server software and exists by default on Ubuntu —
# no mkdir needed (add one if you prefer: mkdir -p "$APP_DIR").
export APP_DIR=/opt/vt-apk-scanner-bot
```

> The `APP_DIR` variable only lives in your current SSH session — if you
> reconnect, set it again. Prefer a different location (e.g.
> `/srv/vt-apk-scanner-bot`)? Just change the variable; the rest of the guide
> adapts.

## 3. Copy the project to the VPS

The repository is public, so cloning needs **no account or authentication**:

```bash
git clone https://github.com/ayusharyaneth/vt-apk-scanner-bot.git "$APP_DIR"
```

You only ever need GitHub credentials on the VPS if you want to `git push`
from there (updates normally flow PC → GitHub → `git pull` on the VPS).

Alternative — direct copy from your Windows PC (run in PowerShell):

```powershell
scp -r "path\to\vt-apk-scanner-bot" root@YOUR_VPS_IP:/opt/vt-apk-scanner-bot
```

⚠️ **Never copy or commit your `.env` file** — create it directly on the VPS
(step 5). This matters because the repo is public: everything in Git history
is world-readable, so the only acceptable place for secrets is the `.env`
file on the machine that runs the bot.

## 4. Install dependencies and verify

```bash
cd "$APP_DIR"
npm ci
npm run typecheck
npm test
```

## 5. Create the secrets file on the VPS

```bash
nano "$APP_DIR/.env"
```

Minimum required content (see [configuration.md](configuration.md) for everything):

```
TELEGRAM_BOT_TOKEN=...        # from @BotFather on Telegram
VIRUSTOTAL_API_KEY=...        # from virustotal.com/gui/my-apikey
AUTHORIZED_IDS=your_telegram_user_id   # send /id to the bot to discover it
# optional:
NVIDIA_API_KEY=...            # from build.nvidia.com — AI summaries
```

Lock it down:

```bash
chmod 600 "$APP_DIR/.env"
```

## 6. Run it under systemd (auto-start, auto-restart)

Create a dedicated user (don't run as root):

```bash
useradd -r -s /usr/sbin/nologin apkbot
chown -R apkbot:apkbot "$APP_DIR"
```

Create the service — this inserts your `$APP_DIR` automatically:

```bash
cat > /etc/systemd/system/vt-apk-scanner-bot.service <<EOF
[Unit]
Description=APK malware scanner Telegram bot
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node $APP_DIR/node_modules/tsx/dist/cli.mjs $APP_DIR/src/main.ts
Restart=on-failure
RestartSec=5
User=apkbot
Group=apkbot
EnvironmentFile=$APP_DIR/.env

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vt-apk-scanner-bot
systemctl status vt-apk-scanner-bot     # should say "active (running)"
journalctl -u vt-apk-scanner-bot -f     # live logs (Ctrl+C to exit)
```

Check the generated unit looks right before starting (`cat
/etc/systemd/system/vt-apk-scanner-bot.service`) — every path in it must be
the absolute real path, because systemd does not expand `~` or `$APP_DIR` on
its own; the heredoc above already did that for you.

The log line `{"event":"bot.started"}` means it is live.

### Validating the setup with dummy data

You can validate every step above **before** you have real keys. Run the same
program systemd would run, with placeholder values in `.env` — from the
install directory this is simply:

```bash
cd "$APP_DIR" && npm start
```

(The raw equivalent, exactly as the service launches it:
`node "$APP_DIR/node_modules/tsx/dist/cli.mjs" "$APP_DIR/src/main.ts"`.)

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
| Update code | `cd "$APP_DIR" && git pull && npm ci && systemctl restart vt-apk-scanner-bot` |
| Change config | edit `"$APP_DIR/.env"`, then restart |

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

- **`mkdir: cannot create directory '/opt': Permission denied` (or clone into
  `/opt` fails)** → you are running this on **Windows or macOS**, not on the
  Ubuntu VPS. `/opt` is Linux-only. Use the [Local quick test](#local-quick-test-any-terminal-no-vps-needed)
  instead; on the VPS, `/opt` always exists.
- **`Invalid configuration: ...` at start** → a variable is missing/typo'd in
  `.env`; the error names exactly which ones.
- **`Call to 'getMe' failed! (401 ...)`** → wrong `TELEGRAM_BOT_TOKEN` (with
  placeholder credentials this failure is expected — see the dummy-data
  section above).
- **`VirusTotal rejected the API key (HTTP 401)`** in scan logs → wrong
  `VIRUSTOTAL_API_KEY`.
- **`authorizedIds` empty / every scan unauthorized** → `AUTHORIZED_IDS` is
  missing or malformed (comma-separated numeric ids; send `/id` to the bot to
  discover yours).
- **Nothing happens at all** → check the bot was started (`systemctl status`)
  and that you sent the file as a *document* (attachment), not a photo, and
  that the filename ends in `.apk`.
- **Service start fails with `No such file or directory` on `ExecStart`** →
  `APP_DIR` was different when the unit was generated than where the repo
  actually is. Fix the paths in
  `/etc/systemd/system/vt-apk-scanner-bot.service`, then
  `systemctl daemon-reload`.
