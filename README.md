# Dns

Async DNS tester / network telemetry tool (Termux & Linux friendly).

## Files

| File | What it is |
|------|------------|
| `advanced_core.py` | The whole tool in one file — async DNS/game telemetry, DNS manager, APN benchmark (Shizuku), **and** the local web console (HTTP server + dashboard UI embedded). |

Everything is in a single `advanced_core.py`: the CLI, the web server, and the
dashboard front-end (HTML/CSS/JS are embedded as strings). There is nothing else
to copy alongside it — just run the one file.

## Android app

There is also an Android build that packages the exact same `advanced_core.py`
into an installable APK. It is a thin native shell: the script runs inside the
app (bundled with [Chaquopy](https://chaquo.com/chaquopy/)) and the app shows the
same local web console in a full-screen WebView. Nothing about the UI is
reimplemented — it is the same page you get from `--web`.

Download the latest signed APK from the
[**Releases page**](https://github.com/Onlyicing1/Dns/releases/latest):

1. Open the Releases page on your phone and download `dns-console-*.apk`.
2. Tap the file and allow "Install unknown apps" for your browser when prompted.
3. Open **DNS Console**. The engine starts automatically and the dashboard loads.

Notes:

- Requires Android 7.0 (API 24) or newer. Builds ship `arm64-v8a` (all modern
  phones) and `x86_64` (emulators).
- The engine listens on `127.0.0.1` only — nothing on your network can reach it.
- The APK is signed with a public keystore that lives in `android/keystore/`
  (committed on purpose, so CI can sign without repository secrets). See
  `android/keystore.properties` for the security trade-off.
- Local scans, DNS management, and AI analysis all work as on desktop. Features
  that need root or Shizuku (APN benchmark, some device telemetry) behave on
  Android exactly as they do in Termux — they need the same access.

To build it yourself:

```bash
cd android
./gradlew :app:assembleRelease     # needs JDK 17 + Android SDK 34
```

Pushing a tag like `v1.0.0` (or running the **Android Release** workflow by hand)
builds the APK and attaches it to a GitHub Release.

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
  (concurrency), **chunk** (how often progress is reported), **protocol** and
  **timeout**. The protocol can be **UDP (53)**, **TCP (53)**, **TLS / DoT (853)**,
  **UDP + TCP** together, or **Auto** (try each until one answers) — the results
  table shows which protocol actually replied. Pick a **probe target** (Google,
  a game or a CDN) so every server is asked to resolve that host, and tick
  **geo-locate** to resolve each server's country/ASN. Large lists are sent with
  a POST body, so tens of thousands of servers no longer overflow the URL.
  Results stream in live with latency bars, jitter, loss and status. Filter,
  show alive-only, and **export CSV** (includes country/ASN). After a scan the
  panel also suggests **recommended pairs** — a fastest pair and a
  best-diversity pair from different countries.
- **Fixed 3-row deck, no page scroll** — all thirteen sections sit side by side
  in a dashboard that fills the screen in at most **three rows**, so nothing is
  off-screen and the page never scrolls. Each card is a tile that opens and
  closes in place: click its header (or the chevron, or anywhere on a collapsed
  tile) to expand/collapse it, and the state is remembered in your browser.
  **expand all / collapse all** live in the dock bar at the top, and the **⤢**
  button on any card pops it into a full-screen **focus** overlay (Esc or ✕ to
  close). Tall content scrolls *inside* its own card, so the page itself stays put.
- **Navigation** — a hamburger menu (top-left) opens a side drawer listing every
  section; tapping a section opens and flashes it (everything is already on
  screen, so there is nothing to scroll to).
- **Auto-Test** — a timer that re-runs the scan on an interval, forever (or for a
  fixed number of cycles). Fully customizable: interval, protocol, packets,
  workers, target source (scanner box or saved list), **probe target**, and
  latency/jitter/loss alert thresholds. Set a **chunk size** to test only that
  many servers per cycle and **rotate through the list**, so a huge list is
  covered progressively instead of all at once. A countdown ring shows the time
  to the next cycle, and a live log records every cycle and alert.
- **Stability** — deterministic 0–100 ranking built up across every scan and
  **saved to disk** (`~/.dns_console_history.json`) so it keeps building between
  sessions. Clear it any time.
- **Saved DNS** — add one, or paste many at once. Persisted to `~/dns_list.txt`
  and shared with the CLI's DNS manager.
- **Probe Lab** — DNS resolve, TCP ping, TLS handshake, HTTP GET, **game
  latency** (protocol-aware, per profile), MTU advice, and a **UDP / TCP / TLS**
  probe that tests all three DNS transports side by side. The protocol probe
  takes a **resolver IP** and a **probe target**, so you can ask a specific
  server (e.g. `1.1.1.1`) to resolve a chosen game/CDN host over UDP, TCP and DoT.
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
  for a plain-English ranking and a primary/backup recommendation. A model menu
  lets you filter the full OpenRouter catalogue by **free** or **paid** and shows
  each model's input price. Paste a key in the UI (kept in your browser) or start
  the server with `--api-key` / `$OPENROUTER_API_KEY`.
- **Appearance** — six theme presets plus custom accent/text/muted/background
  colours, font family, font size, UI density and effect toggles (aurora, grid,
  scanlines, sparkles). Saved in your browser and applied instantly.


Everything runs on your machine; no external services, no dependencies beyond
the Python standard library. The only outbound call is to OpenRouter, and only
when you click an AI button.
