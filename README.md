# Dns

Async DNS tester / network telemetry tool (Termux & Linux friendly).

## Files

| File | What it is |
|------|------------|
| `advanced_core.py` | The CLI tool — async DNS/game telemetry, DNS manager, APN benchmark (Shizuku). |
| `web_server.py` | Dependency-free local web server that serves the dashboard and re-uses the measurement code from `advanced_core.py`. |
| `web/` | The dashboard front-end (`index.html`, `app.css`, `app.js`). |

## Run the CLI

```bash
python advanced_core.py
```

## Run the local web console

```bash
python web_server.py                    # auto-opens your browser on http://localhost:8000
python web_server.py --port 9000        # pick a port
python web_server.py --no-open          # don't auto-open; just print the link
python web_server.py --all              # bind 0.0.0.0 so other devices on your LAN can open it
python web_server.py --background       # no auto-open (for boot scripts)
python web_server.py --install-autostart # (Termux) start automatically at boot via Termux:Boot
python advanced_core.py --web           # same as above, straight from the CLI entry point
```

On Termux it opens automatically via `termux-open-url` (install `termux-tools`);
on desktop it uses `open` / `xdg-open` / the Python `webbrowser` module. If
nothing opens, the server always prints the local link to paste into a browser.

You can also start it from the CLI menu with the `[W]` option.

For autostart: install the **Termux:Boot** app from F-Droid, open it once, then
run `python web_server.py --install-autostart` and reboot. The console will come
up on your LAN automatically.

### What the dashboard does

- **Scanner** — ping any DNS servers (one per line or comma separated) and watch
  results stream in live with latency bars, jitter, loss and status.
- **Stability** — deterministic 0–100 ranking built up across every scan this session.
- **Saved DNS** — add/remove entries in your DNS list (shared with the CLI).
- **Probe Lab** — DNS resolve, TCP ping, TLS handshake, HTTP GET and MTU advice.
- **Device** — a read-only Shizuku snapshot (operator, network type, active interface, VPN).

Everything runs on your machine; no external services, no dependencies beyond
the Python standard library.
