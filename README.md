# Caddy Reverse Proxy Bootstrap

PowerShell bootstrap to install and configure Caddy on Windows to expose a local HTTPS endpoint at `https://localhost:8443` that reverse‑proxies to Tally at `http://127.0.0.1:9000`.

This enables browser code (including service workers) to call Tally from a secure origin without mixed‑content or certificate errors.

## What the script does

- Installs Caddy (Webi first, then direct download fallback) with legacy‑friendly TLS and download logic.
- Optionally skips installation when `caddy.exe` already exists at `C:\ProgramData\TallyHttpsProxy\caddy.exe` (SkipInstall mode).
- Writes a Caddyfile under `C:\ProgramData\TallyHttpsProxy\Caddyfile`:
  - Global options: `admin 127.0.0.1:<port>` where `<port>` is auto‑selected from 2019–2022 if free.
  - Site: `https://localhost:8443` with `tls internal` and `reverse_proxy http://127.0.0.1:9000` (HTTP/1.1 transport).
- Auto‑formats and validates the Caddyfile (`caddy fmt` + `caddy validate`).
- Preflight trust: briefly starts Caddy, waits for the admin API, runs `caddy trust`, then stops.
- Creates/starts a background service:
  - Uses Caddy’s `service` subcommand if available; otherwise falls back to `sc.exe`.
- Adds a Windows Firewall rule for TCP 8443 (Domain/Private profiles).
- Prints a quick health check and the chosen admin API URL.

## Prerequisites

- Run in 64‑bit PowerShell as Administrator on 64‑bit Windows. On true 32‑bit Windows, use “PowerShell (x86)”.
- Windows needs modern TLS (TLS 1.2+). Very old systems may require KB3140245 and enabling TLS 1.2 in Schannel.
- If behind a corporate proxy/SSL inspection, set environment variables before running:
  - `setx HTTPS_PROXY http://user:pass@proxy:port`
  - `setx HTTP_PROXY http://user:pass@proxy:port`

## Run

```
powershell -ExecutionPolicy Bypass -File .\static\tools\tally-proxy-bootstrap.ps1
```

After success:
- Visit `https://localhost:8443` (first visit may trigger the local CA creation).
- In your app (e.g., Loupe), set the Tally host to `https://localhost:8443`.

## SkipInstall mode (optional)

If you hit download/extraction issues, place a compatible `caddy.exe` at:

```
C:\ProgramData\TallyHttpsProxy\caddy.exe
```

Then re‑run the script. It will skip the installer and go straight to configuration.

## Manual trust and validation (if needed)

If the script could not complete trust automatically, you can do it manually. All commands below should run in an elevated PowerShell in `C:\ProgramData\TallyHttpsProxy`.

1) Format and validate the config

```
./caddy.exe fmt --overwrite .\Caddyfile
./caddy.exe validate --config .\Caddyfile --adapter caddyfile
```

2) Start Caddy in a console to verify logs

```
./caddy.exe run --config .\Caddyfile --adapter caddyfile
```

In a second window, confirm the admin API (port echoed by the script, usually 2019):

```
curl.exe -s http://127.0.0.1:2019/config
```

3) Install trust (required for browsers to accept `https://localhost:8443` without warnings)

```
./caddy.exe trust --config .\Caddyfile --adapter caddyfile
```

Then stop the console Caddy (Ctrl+C) and let the background service run.

## Troubleshooting

- Hangs on “Downloading …”
  - Network/proxy issue. Test with: `curl.exe -I --max-time 20 https://github.com/caddyserver/caddy/releases/latest/download/caddy_windows_amd64.zip`
  - Set `HTTP(S)_PROXY` env vars and retry.

- Admin API not reachable / trust skipped
  - Check which admin port the script selected (it prints it). Verify: `netstat -ano | findstr :<port>`
  - Run `./caddy.exe run --config .\Caddyfile --adapter caddyfile` to see logs.
  - If port 2019 is occupied, the script will try 2020–2022 automatically.

- “unknown command service”
  - Your Caddy build doesn’t include the `service` subcommand. The script falls back to a Windows service via `sc.exe`.

- Certificate warning in the browser
  - Run the manual trust steps above. Browsers require a trusted certificate to call `https://localhost:8443` from JS/service workers.

## Customize ports (optional)

Edit the top of `static\tools\tally-proxy-bootstrap.ps1` if you need to change defaults:

- `ListenPort = 8443` — external HTTPS port
- `TallyPort = 9000` — Tally HTTP port

## Uninstall / cleanup

- Stop and remove the service:
  - `sc.exe stop TallyHttpsProxy`
  - `sc.exe delete TallyHttpsProxy`
- Remove firewall rule in “Windows Defender Firewall with Advanced Security” or reconfigure as needed.
- Delete `C:\ProgramData\TallyHttpsProxy` if you want to remove config/binaries.

---

If you run into issues, capture the last 50 lines of `C:\ProgramData\TallyHttpsProxy\preflight.log` (if present) or the console output of `caddy run`, and share them for quick guidance.

