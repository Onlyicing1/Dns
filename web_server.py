#!/usr/bin/env python3
"""
Local web console for the DNS tester.

Starts a small, dependency-free HTTP server (Python standard library only) that
serves an interactive dashboard and re-uses the measurement functions already
present in advanced_core.py (DNS latency, DNS resolution, TCP/TLS/HTTP probes).

Designed for Termux/Android and desktop alike:
  * after launch it tries to open the browser automatically
    (termux-open-url -> am start -> open/xdg-open -> webbrowser), and
  * always prints a clickable local link so you are never stuck.

Run:  python web_server.py            # auto-open, port 8000
      python web_server.py --port 9000 --no-open
"""

import argparse
import asyncio
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(HERE, "web")
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Reuse the advanced_core module if the CLI already imported it (avoids a second,
# independent copy of its caches when launched from the menu). Fall back to a
# normal import when this file is run directly.
core = sys.modules.get("advanced_core")
if core is None:
    import advanced_core as core  # noqa: E402  (path setup must come first)

# Server-side running history so the UI can show a stability ranking across scans.
_HISTORY = {}
_HISTORY_LOCK = threading.Lock()


# --------------------------------------------------------------------------
#  Small helpers
# --------------------------------------------------------------------------
def pick_port(host, preferred, tries=25):
    """Return the first free TCP port at or after `preferred`."""
    for port in range(preferred, preferred + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    return preferred


def open_browser(url):
    """Best-effort: open `url` in the platform browser. Returns True if a launcher ran."""
    candidates = []
    if shutil.which("termux-open-url"):
        candidates.append(["termux-open-url", url])
    if shutil.which("termux-open"):
        candidates.append(["termux-open", url])
    if shutil.which("am"):
        candidates.append(["am", "start", "-a", "android.intent.action.VIEW", "-d", url])
    system = platform.system()
    if system == "Darwin" and shutil.which("open"):
        candidates.append(["open", url])
    if system == "Windows":
        try:
            os.startfile(url)  # type: ignore[attr-defined]
            return True
        except Exception:
            pass
    if shutil.which("xdg-open"):
        candidates.append(["xdg-open", url])

    for cmd in candidates:
        try:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            return True
        except Exception:
            continue

    try:
        import webbrowser

        return webbrowser.open(url)
    except Exception:
        return False


def measure_http(url, timeout=6.0):
    """Return (ok, status_code, elapsed_ms, size_bytes) for a URL."""
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dns-console/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = res.read(65536)
            elapsed = (time.perf_counter() - start) * 1000
            return True, res.status, round(elapsed, 1), len(body)
    except urllib.error.HTTPError as e:  # server answered, just not 2xx
        elapsed = (time.perf_counter() - start) * 1000
        return True, e.code, round(elapsed, 1), 0
    except Exception:
        elapsed = (time.perf_counter() - start) * 1000
        return False, None, round(elapsed, 1), 0


def device_info():
    """Read-only device/network snapshot via Shizuku.

    Only queries state (getprop / pgrep / ip route) — never mutates the system.
    Each underlying command has its own timeout, so this returns promptly even
    when Shizuku/rish is unavailable."""
    shizuku = core.is_shizuku_running()
    operator, net_type = core.get_live_hardware_data()
    iface = core.detect_active_interface()
    return {
        "shizuku": shizuku,
        "operator": operator,
        "network_type": net_type,
        "interface": iface,
        "vpn": core.is_vpn_interface(iface),
    }


def mtu_recommendation():
    """Read-only MTU recommendation (VPN -> fixed, cellular -> probing)."""
    mtu, mode, iface = core.resolve_smart_mtu()
    return {"mtu": mtu, "mode": mode, "interface": iface}


def _fold_history(target, latency, loss, jitter):
    with _HISTORY_LOCK:
        core.update_stability_history(
            _HISTORY,
            [{"pair": [target], "latency": latency, "loss": loss, "jitter": jitter}],
        )


def _stability_snapshot(top_n=10):
    with _HISTORY_LOCK:
        if not _HISTORY:
            return []
        fastest = min(v["latency_sum"] / v["cycles"] for v in _HISTORY.values())
        rows = []
        for dns_ip, rec in _HISTORY.items():
            score, success_rate, spike_ratio = core.compute_stability_score(rec, fastest)
            rows.append(
                {
                    "target": dns_ip,
                    "cycles": rec["cycles"],
                    "success_rate": round(success_rate * 100, 1),
                    "score": score,
                    "spikes": rec["jitter_spike_cycles"],
                    "status": core.stability_status_label(score, success_rate, spike_ratio),
                }
            )
        rows.sort(key=lambda r: r["score"], reverse=True)
        return rows[:top_n]


# --------------------------------------------------------------------------
#  HTTP handler
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "DnsConsole/1.0"

    def log_message(self, *args):  # keep the console quiet
        pass

    # ---- response helpers -------------------------------------------------
    def _send_json(self, obj, status=200):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path, content_type):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            self._send_json({"error": "not found"}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    # ---- routing ----------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        query = parse_qs(parsed.query)

        if route in ("/", "/index.html"):
            self._send_file(os.path.join(WEB_DIR, "index.html"), "text/html; charset=utf-8")
        elif route == "/app.css":
            self._send_file(os.path.join(WEB_DIR, "app.css"), "text/css; charset=utf-8")
        elif route == "/app.js":
            self._send_file(os.path.join(WEB_DIR, "app.js"), "application/javascript; charset=utf-8")
        elif route == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        elif route == "/api/health":
            self._send_json({"ok": True, "service": "dns-console", "version": "1.0"})
        elif route == "/api/dns-list":
            self._send_json({"list": core.load_dns_list()})
        elif route == "/api/stability":
            self._send_json({"rows": _stability_snapshot()})
        elif route == "/api/device":
            self._send_json(device_info())
        elif route == "/api/mtu":
            self._send_json(mtu_recommendation())
        elif route == "/api/scan":
            self._stream_scan(query)
        else:
            self._send_json({"error": "unknown route"}, 404)

    def do_POST(self):
        route = urlparse(self.path).path
        body = self._read_json()

        if route == "/api/dns-list":
            dns_list = core.load_dns_list()
            add = (body.get("add") or "").strip()
            delete = (body.get("delete") or "").strip()
            if add:
                if add not in dns_list:
                    dns_list.append(add)
                    core.save_dns_list(dns_list)
            if delete and delete in dns_list:
                dns_list.remove(delete)
                core.save_dns_list(dns_list)
            self._send_json({"list": core.load_dns_list()})
        elif route == "/api/tools/resolve":
            host = (body.get("host") or "").strip()
            dns = (body.get("dns") or "8.8.8.8").strip()
            if not host:
                self._send_json({"error": "host required"}, 400)
                return
            start = time.perf_counter()
            ip = core.native_dns_resolver(host, dns)
            ms = round((time.perf_counter() - start) * 1000, 1)
            self._send_json({"host": host, "dns": dns, "ip": ip, "ms": ms, "ok": bool(ip)})
        elif route == "/api/tools/tcp":
            host = (body.get("host") or "").strip()
            port = int(body.get("port") or 443)
            if not host:
                self._send_json({"error": "host required"}, 400)
                return
            rtt, ok = core.tcp_ping(host, port, timeout=3.0)
            self._send_json({"host": host, "port": port, "ok": ok, "ms": round(rtt, 1) if rtt else None})
        elif route == "/api/tools/tls":
            host = (body.get("host") or "").strip()
            port = int(body.get("port") or 443)
            if not host:
                self._send_json({"error": "host required"}, 400)
                return
            ms, ok = asyncio.run(core.measure_tls_handshake(host, port))
            self._send_json({"host": host, "port": port, "ok": ok, "ms": round(ms, 1) if ms else None})
        elif route == "/api/tools/http":
            url = (body.get("url") or "").strip()
            if not url:
                self._send_json({"error": "url required"}, 400)
                return
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            ok, status, ms, size = measure_http(url)
            self._send_json({"url": url, "ok": ok, "status": status, "ms": ms, "bytes": size})
        else:
            self._send_json({"error": "unknown route"}, 404)

    # ---- server-sent events: live DNS scan --------------------------------
    def _stream_scan(self, query):
        targets = []
        for raw in query.get("targets", [""])[0].split(","):
            raw = raw.strip()
            if raw:
                targets.append(raw)
        if query.get("dnslist", ["0"])[0] in ("1", "true", "yes"):
            targets = core.load_dns_list()
        # de-duplicate, keep order
        seen = set()
        targets = [t for t in targets if not (t in seen or seen.add(t))]

        try:
            count = max(1, min(10, int(query.get("count", ["3"])[0])))
        except ValueError:
            count = 3

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def emit(obj):
            self.wfile.write(b"data: " + json.dumps(obj).encode("utf-8") + b"\n\n")
            self.wfile.flush()

        try:
            emit({"type": "start", "targets": targets, "count": count})
            if not targets:
                emit({"type": "done", "summary": {"total": 0, "ok": 0, "failed": 0}})
                return

            async def run_one(target):
                latency, loss, jitter = await core.async_ping_dns_core(target, 53, count)
                ok = latency < 9000
                _fold_history(target, latency if ok else 2000.0, loss, jitter)
                return {
                    "type": "result",
                    "target": target,
                    "latency": round(latency, 1) if ok else None,
                    "loss": round(loss, 1),
                    "jitter": round(jitter, 1) if ok else None,
                    "status": "ok" if ok else "fail",
                }

            async def run_all():
                done = 0
                ok_count = 0
                tasks = [asyncio.ensure_future(run_one(t)) for t in targets]
                for fut in asyncio.as_completed(tasks):
                    res = await fut
                    done += 1
                    if res["status"] == "ok":
                        ok_count += 1
                    emit(res)
                    emit({"type": "progress", "done": done, "total": len(targets)})
                return done, ok_count

            done, ok_count = asyncio.run(run_all())
            emit({"type": "summary", "rows": _stability_snapshot()})
            emit({"type": "done", "summary": {"total": done, "ok": ok_count, "failed": done - ok_count}})
        except (BrokenPipeError, ConnectionResetError):
            pass  # client navigated away
        except Exception as exc:  # never kill the server thread
            try:
                emit({"type": "error", "message": str(exc)})
            except Exception:
                pass


# --------------------------------------------------------------------------
#  Entry point
# --------------------------------------------------------------------------
def install_termux_autostart():
    """Install a Termux:Boot script that launches the console (background) at boot.

    Requires the Termux:Boot app; the script lives in ~/.termux/boot/ and starts the
    server on the LAN so the phone's dashboard is reachable from other devices."""
    boot_dir = os.path.expanduser("~/.termux/boot")
    script = os.path.join(boot_dir, "start-dns-console.sh")
    target = os.path.join(HERE, "web_server.py")
    body = (
        "#!/data/data/com.termux/files/usr/bin/sh\n"
        "# Auto-generated by web_server.py --install-autostart\n"
        "termux-wake-lock\n"
        f"exec python {target} --all --background\n"
    )
    try:
        os.makedirs(boot_dir, exist_ok=True)
        with open(script, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(script, 0o755)
    except OSError as exc:
        print(f"  [X] Could not install autostart: {exc}")
        print("      (Are you in Termux? Is ~ writable?)")
        return
    print("=" * 62)
    print("  Termux autostart installed")
    print("=" * 62)
    print(f"  Script : {script}")
    print("  It runs: python web_server.py --all --background")
    print()
    print("  To activate it, install the Termux:Boot app from F-Droid,")
    print("  open it once, then reboot. The console will start automatically.")
    print("=" * 62)


def _lan_ip():
    """Best-effort local IP for the 'bind all interfaces' hint (no packets sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local web console for the DNS tester.")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="preferred port (default 8000)")
    parser.add_argument("--no-open", action="store_true", help="do not try to open the browser")
    parser.add_argument("--all", action="store_true",
                        help="bind 0.0.0.0 so other devices on your LAN can open it")
    parser.add_argument("--background", action="store_true",
                        help="start hidden (no auto-open, suitable for Termux:Boot)")
    parser.add_argument("--install-autostart", action="store_true",
                        help="(Termux) install a Termux:Boot script that starts this console at boot")
    # argv=None -> parse the process arguments (CLI use); pass [] when called from the menu.
    args = parser.parse_args(argv)

    if args.install_autostart:
        install_termux_autostart()
        return

    host = "0.0.0.0" if args.all else args.host
    port = pick_port(host, args.port)
    httpd = ThreadingHTTPServer((host, port), Handler)

    shown_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    url = f"http://{shown_host}:{port}/"

    print("=" * 62)
    print("  DNS CONSOLE  -  local web interface")
    print("=" * 62)
    print(f"  Serving at : {url}")
    print(f"  Bound to   : {host}:{port}")
    if host == "0.0.0.0":
        print(f"  LAN link   : http://{_lan_ip()}:{port}/  (from other devices)")
    print("  Stop with  : Ctrl+C")
    print("=" * 62)

    if args.background:
        args.no_open = True

    if not args.no_open:
        threading.Timer(0.7, lambda: open_browser(url)).start()
        print("  Opening your browser automatically...")
    print("  If nothing opens, copy the link above into your browser.")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down. Bye.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
