# Dns

Async DNS tester / network telemetry tool (Termux & Linux friendly).

## Files

| File | What it is |
|------|------------|
| `advanced_core.py` | The whole tool in one file — async DNS/game telemetry, DNS manager, APN benchmark (Shizuku), **and** the local web console (HTTP server + dashboard UI embedded). |

Everything is in a single `advanced_core.py`: the CLI, the web server, and the
dashboard front-end (HTML/CSS/JS are embedded as strings). There is nothing else
to copy alongside it — just run the one file.

## Run the CLI

```bash
python advanced_core.py
```

## Run the local web console

```bash
python advanced_core.py --web                    # auto-opens your browser on http://localhost:8000
python advanced_core.py --web --port 9000        # pick a port
python advanced_core.py --web --no-open          # don't auto-open; just print the link
python advanced_core.py --web --all              # bind 0.0.0.0 so other devices on your LAN can open it
python advanced_core.py --web --background       # no auto-open (for boot scripts)
python advanced_core.py --web --install-autostart # (Termux) start automatically at boot via Termux:Boot
python advanced_core.py --web --api-key sk-or-... # default OpenRouter key for AI analysis
```

For AI analysis you can also export the key instead of passing the flag:

```bash
export OPENROUTER_API_KEY=sk-or-...
python advanced_core.py --web
```

On Termux it opens automatically via `termux-open-url` (install `termux-tools`);
on desktop it uses `open` / `xdg-open` / the Python `webbrowser` module. If
nothing opens, the server always prints the local link to paste into a browser.

You can also start it from the CLI menu with the `[W]` option.

For autostart: install the **Termux:Boot** app from F-Droid, open it once, then
run `python advanced_core.py --web --install-autostart` and reboot. The console
will come up on your LAN automatically.

### What the dashboard does

- **Bulk Scanner** — paste thousands of DNS servers (one per line or comma
  separated). They are scanned in parallel with a thread pool; tune **workers**
  (concurrency) and **chunk** (how often progress is reported). Results stream in
  live with latency bars, jitter, loss and status. Filter, show alive-only, and
  **export CSV**.
- **Stability** — deterministic 0–100 ranking built up across every scan and
  **saved to disk** (`~/.dns_console_history.json`) so it keeps building between
  sessions. Clear it any time.
- **Saved DNS** — add one, or paste many at once. Persisted to `~/dns_list.txt`
  and shared with the CLI's DNS manager.
- **Probe Lab** — DNS resolve, TCP ping, TLS handshake, HTTP GET, **game
  latency** (protocol-aware, per profile) and MTU advice.
- **Network · VPN** — public egress IP, country, ISP, active interface, VPN
  tunnel flag and MTU — check what your VPN exposes.
- **Device** — a read-only Shizuku snapshot (operator, network type, interface, VPN).
- **APN Benchmark** — lists carrier APNs; benchmarking switches the preferred
  APN, tests each, then restores the original (Shizuku; confirm-gated).
- **Game Profiles** — add/remove profiles (shared with the CLI).
- **Diagnosis** — reference-host + gateway reachability with a quality rating.
- **Import DNS list** — drop or paste **any** file and every DNS server in it is
  detected. Handles plain text, CSV, JSON, logs, HTML/XML, UTF-16, gzip, and ZIP
  containers (`.zip`, `.xlsx`, `.ods`, `.docx`). Then save the list or scan it
  straight away.
- **AI Analysis (OpenRouter)** — send your scan or history to an OpenRouter model
  for a plain-English ranking and a primary/backup recommendation. Paste a key in
  the UI (kept in your browser) or start the server with `--api-key` /
  `$OPENROUTER_API_KEY`.

Everything runs on your machine; no external services, no dependencies beyond
the Python standard library. The only outbound call is to OpenRouter, and only
when you click an AI button.
