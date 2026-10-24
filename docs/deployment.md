# Deployment — Hosting on a VPS (Ubuntu 22.04/24.04)

Any small VPS (1 vCPU / 1 GB RAM) works. The bot polls Telegram's API
outbound — **no open ports, domain, TLS certificate, or reverse proxy is
required**. The install directory is kept in an `APP_DIR` variable so you
cannot mistype it; it is set to the Linux-standard `/opt` location. All steps
run as `root` over SSH (use `sudo` if you log in as a normal user).

## 1. Get a VPS

Any Ubuntu 22.04/24.04 VPS works. Connect:

```bash
ssh root@YOUR_VPS_IP
```

## 2. Install Node.js 20+ and set the install directory

The bot requires Node ≥ 20.15 (tested on Node 24):

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs git
node --version   # must be v20.15 or newer

```

> The `APP_DIR` variable only lives in your current SSH session — if you
> reconnect, set it again. Prefer a different location (e.g.
> `/srv/vt-apk-scanner-bot`)? Just change the variable; the rest of the guide
> adapts.

## 3. Clone the project and install dependencies

The repository is public, so cloning needs **no account or authentication**:

```bash
git clone https://github.com/ayusharyaneth/vt-apk-scanner-bot.git "$APP_DIR"
cd "$APP_DIR"
npm ci
npm run typecheck
npm test
```

All 87 tests should pass. You only ever need GitHub credentials on the VPS if
you want to `git push` from there (updates normally flow PC → GitHub →
`git pull` on the VPS).

⚠️ **Never commit your `.env` file** — create it directly on the VPS (next
step). The repo is public: everything in Git history is world-readable, so the
only acceptable place for secrets is the `.env` file on the machine that runs
the bot.

## 4. Create the secrets file on the VPS

```bash
nano "$APP_DIR/.env"
```

See [configuration.md](configuration.md) for the full env.

Lock the file down:

```bash
chmod 600 "$APP_DIR/.env"
```

## 5. Run it under systemd (auto-start, auto-restart)

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

The log line `{"event":"bot.started"}` means the bot is live. From this point
on, sending an APK to your bot in Telegram produces the full VirusTotal report
in the same chat — no commands needed.

## 6. Test it

On Telegram, send an APK (≤ 20 MB) as a document to your bot. Expect:

1. `⏳ APK received — downloading…`
2. `⏳ SHA-256: …` (instant for files VirusTotal knows, minutes for new ones)
3. The full report with verdict, engine counts and the VirusTotal link
4. (if NVIDIA NIM configured) a `🤖 AI analysis` follow-up message

The same flow is visible in the logs: `bot.apk_received` → `scan.started` →
`scan.completed`.

## Day-2 operations

| Task | Command |
| --- | --- |
| View logs | `journalctl -u vt-apk-scanner-bot -f` |
| Restart | `systemctl restart vt-apk-scanner-bot` |
| Stop | `systemctl stop vt-apk-scanner-bot` |
| Update code | `export APP_DIR=/opt/vt-apk-scanner-bot; cd "$APP_DIR" && git pull && npm ci && systemctl restart vt-apk-scanner-bot` |
| Change config | edit `"$APP_DIR/.env"`, then `systemctl restart vt-apk-scanner-bot` |

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
  Ubuntu VPS. `/opt` is Linux-only — run these commands on the VPS over SSH
  (`ssh root@YOUR_VPS_IP`, step 1); on Ubuntu, `/opt` always exists.
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
- **Service start fails with `No such file or directory` on `ExecStart`** →
  `APP_DIR` was different when the unit was generated than where the repo
  actually is. Fix the paths in
  `/etc/systemd/system/vt-apk-scanner-bot.service`, then
  `systemctl daemon-reload`.
