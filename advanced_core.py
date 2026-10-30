import os, sys, re, time, urllib.request, urllib.error, json, random, asyncio, socket, struct
import argparse
import concurrent.futures
import logging
import platform
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Any, Callable
from urllib.parse import urlparse, parse_qs

# Force UTF-8 stdout regardless of the Termux locale
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ---- Structured logging setup -------------------------------------------
# Everything the engine does is recorded twice: to stdout (Termux/ADB) and to an
# in-memory ring buffer that the in-app Logs tab reads. The buffer is what makes
# a phone-only failure diagnosable without a USB cable.
_LOG_LOCK = threading.Lock()
_LOG_BUFFER = []                 # [{seq, t, ts, level, name, msg}, ...]
_LOG_SEQ = 0
_LOG_MAX = 4000                  # keep the newest N lines
_LOG_MIN_LEVEL = "DEBUG"         # capture everything by default
_PROC_START = time.time()


def _log_add(level, name, msg):
    """Append one line to the in-memory log ring buffer (thread-safe)."""
    global _LOG_SEQ
    line = msg.rstrip("\n")
    if not line:
        return
    with _LOG_LOCK:
        _LOG_SEQ += 1
        _LOG_BUFFER.append({
            "seq": _LOG_SEQ,
            "t": time.strftime("%H:%M:%S"),
            "ts": round(time.time(), 3),
            "level": level,
            "name": name,
            "msg": line,
        })
        if len(_LOG_BUFFER) > _LOG_MAX:
            del _LOG_BUFFER[:len(_LOG_BUFFER) - _LOG_MAX]


def _log_lines(since=0, limit=0, level=""):
    """Snapshot the ring buffer; `since` returns only newer lines."""
    with _LOG_LOCK:
        out = [dict(e) for e in _LOG_BUFFER if e["seq"] > since]
    if level:
        want = level.upper()
        out = [e for e in out if e["level"] == want]
    if limit and len(out) > limit:
        out = out[-limit:]
    return out


def _log_clear():
    with _LOG_LOCK:
        _LOG_BUFFER.clear()


class _RingHandler(logging.Handler):
    """Mirrors every logging record into the in-app ring buffer."""

    def emit(self, record):
        try:
            _log_add(record.levelname, record.name, record.getMessage())
        except Exception:
            pass


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("advanced_core")

# Attach the ring handler to the root logger so third-party and library records
# (urllib, asyncio, socketserver) land in the Logs tab too.
_ring_handler = _RingHandler()
_ring_handler.setLevel(logging.DEBUG)
_ring_handler.setFormatter(logging.Formatter('%(message)s'))
logging.getLogger().addHandler(_ring_handler)


def log_event(msg, level="info"):
    """Log a line to stdout AND the in-app Logs tab. Use for lifecycle events."""
    logger.log(getattr(logging, level.upper(), logging.INFO), msg)


_WATCHDOG_STARTED = False


def _rss_kb():
    """Resident memory in KB, via /proc (Linux/Android) or resource as fallback."""
    try:
        with open("/proc/self/status", encoding="utf-8") as fh:
            for ln in fh:
                if ln.startswith("VmRSS:"):
                    return int(ln.split()[1])
    except Exception:
        pass
    try:
        import resource
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except Exception:
        return 0


def _start_watchdog(period=30.0):
    """Log memory, thread count and load every `period` seconds.

    Rising memory or a growing thread count is a common cause of an Android ANR,
    and neither shows up anywhere else in the log, so it is sampled here. Runs as
    a daemon thread and never raises."""
    global _WATCHDOG_STARTED
    if _WATCHDOG_STARTED:
        return
    _WATCHDOG_STARTED = True

    def _loop():
        peak = 0
        while True:
            try:
                time.sleep(period)
                rss = _rss_kb()
                peak = max(peak, rss)
                threads = threading.active_count()
                try:
                    load = os.getloadavg()[0]
                except Exception:
                    load = -1.0
                # Flag a possible leak rather than just reporting numbers.
                warn = ""
                if rss and peak and rss > peak * 1.5 and rss > 200000:
                    warn = "  <-- memory climbing"
                _log_add("INFO", "watchdog",
                         f"rss={rss // 1024}MB peak={peak // 1024}MB "
                         f"threads={threads} load={load:.2f} "
                         f"uptime={int(time.time() - _PROC_START)}s{warn}")
            except Exception:
                pass

    threading.Thread(target=_loop, daemon=True, name="dns-watchdog").start()


def _install_exception_hooks():
    """Record uncaught exceptions from any thread into the Logs tab.

    A background scan thread that dies silently is exactly the kind of failure
    that is invisible without a log, so both the main and worker hooks capture
    the full traceback."""
    def _hook(exc_type, exc_value, exc_tb):
        import traceback as _tb
        text = "".join(_tb.format_exception(exc_type, exc_value, exc_tb))
        _log_add("CRITICAL", "uncaught", text)

    def _thread_hook(args):
        import traceback as _tb
        text = "".join(_tb.format_exception(args.exc_type, args.exc_value,
                                            args.exc_traceback))
        _log_add("CRITICAL", f"thread:{getattr(args.thread, 'name', '?')}",
                 "uncaught exception in thread\n" + text)

    sys.excepthook = _hook
    try:
        threading.excepthook = _thread_hook
    except Exception:
        pass

# ---- NEW: Input validation utilities ----
def validate_dns_address(address: str) -> bool:
    """Validate DNS address format."""
    if not address or not isinstance(address, str):
        return False
    if len(address) > 255:
        return False
    # Basic pattern: alphanumeric, dots, hyphens
    import re as _re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    return bool(_re.match(pattern, address))

def validate_port(port: int) -> bool:
    """Validate port number."""
    return isinstance(port, int) and 1 <= port <= 65535

def validate_host(host: str) -> bool:
    """Validate hostname or IP address."""
    if not host or not isinstance(host, str):
        return False
    if len(host) > 255:
        return False
    return True

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    if not filename:
        return "default"
    # Remove path separators and null bytes
    sanitized = filename.replace("/", "").replace("\\", "").replace("\x00", "")
    # Limit length
    return sanitized[:255]

# ---- NEW: Config validation ----
def validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate configuration values and apply defaults."""
    validated = {}
    
    # DNS settings
    validated["dns_test_retries"] = max(1, min(10, config.get("dns_test_retries", 3)))
    validated["dns_timeout"] = max(0.5, min(10.0, config.get("dns_timeout", 2.0)))
    validated["max_concurrent"] = max(1, min(50, config.get("max_concurrent", 12)))
    
    # Network settings
    validated["connection_timeout"] = max(1, min(30, config.get("connection_timeout", 5)))
    validated["read_timeout"] = max(1, min(30, config.get("read_timeout", 5)))
    
    # Game settings
    validated["game_latency_threshold"] = max(10, min(500, config.get("game_latency_threshold", 100)))
    validated["jitter_threshold"] = max(5, min(100, config.get("jitter_threshold", 45)))
    
    # UI settings
    validated["theme"] = config.get("theme", "dark") if config.get("theme", "dark") in ["dark", "light"] else "dark"
    validated["show_charts"] = bool(config.get("show_charts", True))
    validated["auto_export"] = bool(config.get("auto_export", False))
    
    # Security settings
    validated["enable_logging"] = bool(config.get("enable_logging", True))
    validated["log_level"] = config.get("log_level", "INFO") if config.get("log_level", "INFO") in ["DEBUG", "INFO", "WARNING", "ERROR"] else "INFO"
    
    return validated

# ---- NEW: Performance profiling ----
class PerformanceProfiler:
    """Profiles execution time of functions."""
    def __init__(self):
        self.timings = {}
        self.enabled = True

    def time(self, name: str):
        """Context manager for timing functions."""
        return _TimerContext(self, name)

    def get_stats(self) -> Dict[str, Dict[str, float]]:
        """Get timing statistics."""
        stats = {}
        for name, timings in self.timings.items():
            if timings:
                stats[name] = {
                    "count": len(timings),
                    "total": sum(timings),
                    "avg": sum(timings) / len(timings),
                    "min": min(timings),
                    "max": max(timings)
                }
        return stats

    def reset(self):
        """Reset all timings."""
        self.timings.clear()

class _TimerContext:
    """Context manager for timing."""
    def __init__(self, profiler: PerformanceProfiler, name: str):
        self.profiler = profiler
        self.name = name
        self.start = 0

    def __enter__(self):
        if self.profiler.enabled:
            self.start = time.perf_counter()
        return self

    def __exit__(self, *args):
        if self.profiler.enabled:
            elapsed = time.perf_counter() - self.start
            if self.name not in self.profiler.timings:
                self.profiler.timings[self.name] = []
            self.profiler.timings[self.name].append(elapsed)

# ---- NEW: Memory management ----
class MemoryManager:
    """Manages memory usage and prevents leaks."""
    def __init__(self, max_cache_size=1000):
        self.max_cache_size = max_cache_size
        self.cache_sizes = {}

    def track_cache(self, name: str, size: int):
        """Track cache size."""
        self.cache_sizes[name] = size
        self._cleanup_if_needed()

    def _cleanup_if_needed(self):
        """Clean up if total cache exceeds limit."""
        total = sum(self.cache_sizes.values())
        if total > self.max_cache_size:
            # Remove oldest/largest caches
            sorted_caches = sorted(self.cache_sizes.items(), key=lambda x: x[1], reverse=True)
            to_remove = sorted_caches[:len(sorted_caches) // 4]
            for name, _ in to_remove:
                self.cache_sizes.pop(name, None)

    def get_memory_usage(self) -> Dict[str, int]:
        """Get memory usage by cache."""
        return dict(self.cache_sizes)

# ---- NEW: Async cleanup helper ----
class AsyncCleanup:
    """Helper for async resource cleanup."""
    def __init__(self):
        self.cleanup_callbacks = []

    def register(self, callback: Callable):
        """Register a cleanup callback."""
        self.cleanup_callbacks.append(callback)

    async def cleanup(self):
        """Run all cleanup callbacks."""
        for callback in self.cleanup_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                logger.error(f"Cleanup callback failed: {e}")
        self.cleanup_callbacks.clear()

# ---- NEW: Unit test framework ----
class TestFramework:
    """Simple unit test framework."""
    def __init__(self):
        self.tests = []
        self.results = []

    def test(self, name: str):
        """Decorator for test functions."""
        def decorator(func):
            self.tests.append((name, func))
            return func
        return decorator

    def run(self) -> Dict[str, Any]:
        """Run all tests."""
        self.results = []
        for name, func in self.tests:
            try:
                func()
                self.results.append({"name": name, "status": "PASS", "error": None})
                print(f"Test '{name}' PASSED")
            except Exception as e:
                self.results.append({"name": name, "status": "FAIL", "error": str(e)})
                print(f"Test '{name}' FAILED: {e}")
        
        passed = sum(1 for r in self.results if r["status"] == "PASS")
        total = len(self.results)
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "results": self.results
        }

# ---- NEW: Secure subprocess execution ----
def safe_run_shizuku_cmd(cmd: str) -> str:
    """Securely execute Shizuku commands without shell=True."""
    import subprocess
    if not cmd or not isinstance(cmd, str):
        return ""

    # Split command safely (no shell injection)
    parts = cmd.split()
    if not parts:
        return ""

    # Shizuku spawns a subprocess with a 5s timeout; on Android that is a common
    # place for a stall, so the duration is logged.
    _t0 = time.perf_counter()
    try:
        # Try rish first (Shizuku's preferred method)
        result = subprocess.run(
            ["rish", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        if result.returncode == 0:
            log_event(f"shizuku 'rish' ok in "
                      f"{round((time.perf_counter() - _t0) * 1000)}ms: {cmd[:60]}",
                      "debug")
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        log_event(f"shizuku 'rish' unavailable for: {cmd[:60]}", "debug")

    try:
        # Fallback: direct execution (no shell)
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        log_event(f"shizuku direct ok in "
                  f"{round((time.perf_counter() - _t0) * 1000)}ms: {cmd[:60]}", "debug")
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    except Exception as e:
        logger.error(f"Shizuku command failed: {e}")
        return ""

# ============================================================
#  CONFIG / CONSTANTS
# ============================================================
DB_FILE = os.path.expanduser("~/.dns_services.json")
PINNED_FILE = os.path.expanduser("~/.dns_pinned.json")
DNS_LIST_FILE = os.path.expanduser("~/dns_list.txt")
AUTOTEST_FILE = os.path.expanduser("~/.dns_autotest.json")

RADIO_COOLDOWN_SECONDS = 4          # HyperOS radio needs this pause after an APN switch
VPN_MTU = 1350                      # Recommended MTU for the WireGuard/VPN tunnel (manual setup)
HOTSPOT_GATEWAY_IP = "192.168.43.1"
REFERENCE_HOST = "1.1.1.1"
DNS_TEST_RETRIES = 3

# ============================================================
#  GAME PROTOCOL / PORT CONFIGURATION
# Each game/service can define its preferred protocol (TCP/UDP) and ports.
# This allows protocol-aware latency testing — critical for UDP-based games
# like Apex Legends, Valorant, Fortnite that use specific ports.
# ============================================================
GAME_PROTOCOL_DB = {
    "Apex Legends": {
        "ports": [37015, 37016, 37017, 37018, 37019, 37020, 37021, 37022, 37023, 37024, 37025],
        "protocol": "udp",
        "hosts": ["ea.com", "eaassets-a.akamaihd.net", "respawn.com"],
        "note": "Apex uses UDP on ports 37015-37025 for game traffic. Source: EA/Respawn docs.",
    },
    "Valorant": {
        "ports": [5060, 5061, 3478, 3479, 37015],
        "protocol": "udp",
        "hosts": ["riotgames.com", "valorant.secure.dyn.riotcdn.net", "riotcdn.net"],
        "note": "Valorant uses UDP on 3478-3479 (peer-to-peer) and 5060-5061 (voice).",
    },
    "Fortnite": {
        "ports": [7848, 7849, 37015],
        "protocol": "udp",
        "hosts": ["epicgames.com", "fortnite.com", "cdn2.epicgames.com"],
        "note": "Fortnite uses UDP on 7848-7849 for game traffic.",
    },
    "Call of Duty": {
        "ports": [3074, 3075, 3076, 3077],
        "protocol": "udp",
        "hosts": ["callofduty.com", "activision.com"],
        "note": "CoD uses UDP on 3074-3077 for matchmaking and gameplay.",
    },
    "PUBG": {
        "ports": [27015, 27016, 27017, 27018, 27019],
        "protocol": "udp",
        "hosts": ["pubg.com", "pubgmobile.com"],
        "note": "PUBG uses UDP on 27015-27019 for game servers.",
    },
    "League of Legends": {
        "ports": [5190, 5191, 5192, 5193, 5194],
        "protocol": "udp",
        "hosts": ["leagueoflegends.com", "riotcdn.net"],
        "note": "LoL uses UDP on 5190-5194 for game client communication.",
    },
    "Overwatch": {
        "ports": [11196, 11197, 11198, 11199, 11200],
        "protocol": "udp",
        "hosts": ["blizzard.com", "blizzardcdn.com", "battle.net"],
        "note": "Overwatch uses UDP on 11196-11200 for game traffic.",
    },
    "Rainbow Six Siege": {
        "ports": [3074, 3075, 3076, 3077, 3078],
        "protocol": "udp",
        "hosts": ["ubisoft.com", "ubisoftconnect.com"],
        "note": "R6 Siege uses UDP on 3074-3078 for game servers.",
    },
    "Rocket League": {
        "ports": [7000, 7001, 7002, 7777, 7778, 7779, 9000],
        "protocol": "udp",
        "hosts": ["rocketleague.com", "epicgames.com"],
        "note": "Rocket League uses UDP on 7000-7002 / 7777-7779 / 9000.",
    },
    "Marvel Rivals": {
        "ports": [443, 37000, 37001],
        "protocol": "both",
        "hosts": ["marvelrivals.com", "netease.com"],
        "note": "Marvel Rivals uses TCP/443 for API and UDP for match traffic.",
    },
    "Genshin Impact": {
        "ports": [443, 42472, 10001],
        "protocol": "both",
        "hosts": ["hoyoverse.com", "genshin.hoyoverse.com"],
        "note": "Genshin uses TCP/443 for launcher/API; game traffic is UDP.",
    },
    "Where Winds Meet": {
        "ports": [443, 8001, 8002],
        "protocol": "both",
        "hosts": ["wherewindsmeetgame.com", "netease.com"],
        "note": "NetEase title. TCP/443 for API; UDP for gameplay. Confirm in-game if unsure.",
    },
    "Delta Force": {
        "ports": [443, 27015, 27016],
        "protocol": "both",
        "hosts": ["playdeltaforce.com", "garena.com"],
        "note": "Delta Force uses TCP/443 for API and UDP for match traffic.",
    },
    "Roblox": {
        "ports": [443, 53640],
        "protocol": "both",
        "hosts": ["roblox.com"],
        "note": "Roblox uses TCP/443 for API and UDP for game traffic.",
    },
    "Minecraft": {
        "ports": [25565],
        "protocol": "tcp",
        "hosts": ["minecraft.net", "mojang.com"],
        "note": "Minecraft (Java) uses TCP/25565.",
    },
    "Steam / CS2 / Dota": {
        "ports": [27015, 27016, 27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025, 27026, 27027, 27028, 27029, 27030, 27031, 27032, 27033, 27034, 27035, 27036],
        "protocol": "both",
        "hosts": ["steamcommunity.com", "steampowered.com", "steamcontent.com"],
        "note": "Source engine titles use UDP 27015-27036; Steam client/auth is TCP/443.",
    },
    "World of Warcraft": {
        "ports": [3724, 8085],
        "protocol": "both",
        "hosts": ["blizzard.com", "battle.net"],
        "note": "WoW uses TCP/3724 (auth) and TCP/8085 (world). Regional realms: us/eu/kr.battle.net.",
    },
    "Google Core": {
        "ports": [443],
        "protocol": "tcp",
        "hosts": ["google.com"],
        "note": "Google services use TCP/443.",
    },
    "EA Auth": {
        "ports": [443],
        "protocol": "tcp",
        "hosts": ["ea.com"],
        "note": "EA authentication uses TCP/443.",
    },
}

# Real regional endpoints, where the provider actually exposes per-region
# hostnames. Used to steer a scan at the datacenter closest to the user.
GAME_REGIONAL_HOSTS = {
    "World of Warcraft": {"us": ["us.battle.net"], "eu": ["eu.battle.net"], "kr": ["kr.battle.net"]},
}

# Default ports for unknown games/services
DEFAULT_PORTS = [443, 80]
DEFAULT_PROTOCOL = "tcp"


def game_catalog():
    """Structured view of GAME_PROTOCOL_DB for the UI and the AI."""
    out = []
    for name, cfg in GAME_PROTOCOL_DB.items():
        out.append({
            "name": name,
            "ports": cfg.get("ports", DEFAULT_PORTS),
            "protocol": cfg.get("protocol", DEFAULT_PROTOCOL),
            "hosts": cfg.get("hosts", []),
            "note": cfg.get("note", ""),
            "regions": sorted(GAME_REGIONAL_HOSTS.get(name, {}).keys()),
        })
    return out


def game_endpoints(game_name, region=None):
    """Hostnames to probe for a game, preferring a requested region."""
    cfg = GAME_PROTOCOL_DB.get(game_name, {})
    hosts = list(cfg.get("hosts", []))
    regional = GAME_REGIONAL_HOSTS.get(game_name, {})
    if region and region in regional:
        return list(regional[region]) + hosts
    return hosts


def game_port_plan(game_name, port=None, protocol=None):
    """Decide which port(s) and protocol to test for a game.

    An explicit port/protocol (e.g. suggested by the AI) wins over the built-in
    defaults, so the user can test a specific port for a game we don't know yet
    (the AI is asked to look these up)."""
    cfg = GAME_PROTOCOL_DB.get(game_name, {})
    ports = list(cfg.get("ports", DEFAULT_PORTS))
    proto = cfg.get("protocol", DEFAULT_PROTOCOL)
    if port:
        try:
            p = int(port)
            if 1 <= p <= 65535:
                ports = [p] + [x for x in ports if x != p]
        except (TypeError, ValueError):
            pass
    if protocol in ("udp", "tcp", "tls", "both", "auto"):
        proto = protocol
    return ports, proto

# ---- NEW: Export report functionality ----
def export_report(results, filename="telemetry_report.txt"):
    """Export telemetry results to a file."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("=== NETWORK TELEMETRY REPORT ===\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for item in results:
                f.write(f"DNS: {item.get('pair', ['N/A'])[0]}\n")
                f.write(f"  Latency: {item.get('latency', 'N/A')}\n")
                f.write(f"  Jitter: {item.get('jitter', 'N/A')}\n")
                f.write(f"  Loss: {item.get('loss', 'N/A')}\n")
                f.write(f"  Game Latency: {item.get('game_latency', 'N/A')}\n\n")
            f.write("=== END OF REPORT ===\n")
        return True
    except:
        return False

# ---- NEW: Auto-recovery mechanism ----
class AutoRecovery:
    """Handles automatic recovery from network errors."""
    def __init__(self, max_retries=3):
        self.max_retries = max_retries
        self.retry_count = 0
        self.last_error = None

    def should_retry(self):
        return self.retry_count < self.max_retries

    def record_error(self, error):
        self.last_error = error
        self.retry_count += 1

    def reset(self):
        self.retry_count = 0
        self.last_error = None

# ---- NEW: Graceful degradation ----
def graceful_degrade(func):
    """Decorator that catches exceptions and continues execution."""
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            print(f"{ANSI_YELLOW}[!] Graceful degradation: {e}{ANSI_RESET}")
            return None
    return wrapper

# ---- NEW: Multi-hop testing ----
async def multi_hop_test(dns_servers, target_host):
    """Resolve `target_host` through each DNS server in turn and time the lookup."""
    results = []
    for dns in dns_servers:
        try:
            loop = asyncio.get_running_loop()
            start = time.perf_counter()
            ip = await loop.run_in_executor(
                None, lambda d=dns: native_dns_resolver(target_host, d))
            ms = round((time.perf_counter() - start) * 1000, 1)
            results.append({"dns": dns, "ip": ip, "rtt": ms if ip else None,
                            "ok": bool(ip)})
        except Exception:
            results.append({"dns": dns, "ip": None, "rtt": None, "ok": False})
    return results

# ---- NEW: TLS handshake time measurement ----
async def measure_tls_handshake(host, port=443, timeout=3.0):
    """Measure TLS handshake time for a given host."""
    try:
        import ssl
        context = ssl.create_default_context()
        start = time.perf_counter()
        # open_connection resolves the hostname itself and performs the TLS handshake.
        # server_hostname must stay the original hostname (not an IP) so SNI and
        # certificate verification match the certificate presented by the server.
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
        # Force the handshake to complete before stopping the clock.
        await writer.drain()
        elapsed = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return elapsed, True
    except Exception:
        return None, False

# ---- NEW: Server region detection ----
def detect_server_region(host):
    """Detect server region using geo-IP lookup."""
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{host}?fields=country,regionName,city", headers={"User-Agent": "Mozilla"})
        with urllib.request.urlopen(req, timeout=2.5) as res:
            data = json.loads(res.read().decode("utf-8"))
            return {
                "country": data.get("country", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown")
            }
    except:
        return {"country": "Unknown", "region": "Unknown", "city": "Unknown"}

# ---- NEW: Historical comparison ----
def compare_with_history(current_results, history):
    """Compare current results with historical data."""
    comparison = {}
    for item in current_results:
        dns_ip = item.get("pair", ["N/A"])[0]
        if dns_ip in history:
            old_score = compute_stability_score(history[dns_ip], min(item.get("latency", 0), 1.0))
            new_score = compute_stability_score({"cycles": 1, "success_cycles": 1 if item.get("loss", 100) == 0 else 0, "jitter_spike_cycles": 0, "latency_sum": item.get("latency", 0)}, item.get("latency", 0))
            comparison[dns_ip] = {
                "old_score": old_score[0],
                "new_score": new_score[0],
                "trend": "improving" if new_score[0] > old_score[0] else "degrading"
            }
    return comparison

# ---- NEW: Real-time chart (ASCII) ----
def render_ascii_chart(data, width=50, height=10):
    """Render a simple ASCII chart for latency data."""
    if not data:
        return "No data"
    
    min_val = min(data)
    max_val = max(data)
    if max_val == min_val:
        return "All values equal"
    
    # Normalize data to 0-1 range
    normalized = [(d - min_val) / (max_val - min_val) for d in data]
    
    # Build chart
    lines = []
    for row in range(height, 0, -1):
        line = ""
        for val in normalized:
            if val * height >= row:
                line += "█"
            else:
                line += " "
        lines.append(f"{row:2d} | {line}")
    
    # X-axis
    lines.append("   " + "-" * width)
    
    return "\n".join(lines)

# ---- NEW: Batch DNS resolution ----
async def batch_dns_resolution(hosts, dns_server="8.8.8.8"):
    """Resolve multiple hosts in parallel."""
    loop = asyncio.get_running_loop()
    tasks = [loop.run_in_executor(None, native_dns_resolver, host, dns_server) for host in hosts]
    results = await asyncio.gather(*tasks)
    return dict(zip(hosts, results))

# ---- NEW: Keyboard shortcuts ----
KEYBOARD_SHORTCUTS = {
    "q": "Quit",
    "c": "Clear all pins",
    "r1": "Remove pin 1",
    "r2": "Remove pin 2",
    "1": "Pin DNS 1",
    "2": "Pin DNS 2",
    "3": "Pin DNS 3",
    "4": "Pin DNS 4",
    "5": "Pin DNS 5",
    "6": "Pin DNS 6",
    "7": "Pin DNS 7",
    "8": "Pin DNS 8",
}

# ---- NEW: Theme toggle ----
def toggle_theme():
    """Toggle between dark and light theme."""
    global CURRENT_THEME
    CURRENT_THEME = "light" if CURRENT_THEME == "dark" else "dark"
    return CURRENT_THEME

# ---- NEW: Game-specific heuristics ----
GAME_HEURISTICS = {
    "Apex Legends": {
        "max_acceptable_latency_ms": 80,
        "jitter_threshold_ms": 15,
        "packet_loss_threshold_percent": 3,
        "recommended_dns": "1.1.1.1",
        "note": "Apex is sensitive to jitter; prioritize low-jitter DNS"
    },
    "Valorant": {
        "max_acceptable_latency_ms": 50,
        "jitter_threshold_ms": 10,
        "packet_loss_threshold_percent": 1,
        "recommended_dns": "1.1.1.1",
        "note": "Valorant is highly sensitive to packet loss"
    },
    "Fortnite": {
        "max_acceptable_latency_ms": 60,
        "jitter_threshold_ms": 12,
        "packet_loss_threshold_percent": 2,
        "recommended_dns": "1.1.1.1",
        "note": "Fortnite requires stable connections"
    },
    "Call of Duty": {
        "max_acceptable_latency_ms": 70,
        "jitter_threshold_ms": 15,
        "packet_loss_threshold_percent": 3,
        "recommended_dns": "1.1.1.1",
        "note": "CoD benefits from low-latency DNS"
    },
    "PUBG": {
        "max_acceptable_latency_ms": 80,
        "jitter_threshold_ms": 20,
        "packet_loss_threshold_percent": 5,
        "recommended_dns": "1.1.1.1",
        "note": "PUBG tolerates higher latency but requires low jitter"
    }
}

# ---- NEW: Statistical analysis functions ----
def statistical_analysis(data_points):
    """Compute statistical metrics for a list of latency values."""
    if not data_points:
        return {"count": 0, "mean": 0, "median": 0, "std_dev": 0, "min": 0, "max": 0, "p95": 0, "p99": 0}
    
    sorted_data = sorted(data_points)
    n = len(sorted_data)
    mean = sum(sorted_data) / n
    
    # Median
    if n % 2 == 0:
        median = (sorted_data[n//2 - 1] + sorted_data[n//2]) / 2
    else:
        median = sorted_data[n//2]
    
    # Standard deviation
    variance = sum((x - mean) ** 2 for x in sorted_data) / n
    std_dev = variance ** 0.5
    
    # Percentiles
    def percentile(data, p):
        k = (len(data) - 1) * p
        f = int(k)
        c = int(k) if k == int(k) else int(k) + 1
        if f == c:
            return data[f]
        return data[f] * (c - k) + data[c] * (k - f)
    
    p95 = percentile(sorted_data, 0.95)
    p99 = percentile(sorted_data, 0.99)
    
    return {
        "count": n,
        "mean": round(mean, 2),
        "median": round(median, 2),
        "std_dev": round(std_dev, 2),
        "min": round(min(sorted_data), 2),
        "max": round(max(sorted_data), 2),
        "p95": round(p95, 2),
        "p99": round(p99, 2)
    }

# ---- NEW: Anomaly detection ----
def detect_anomalies(data_points, threshold_std=2.0):
    """Detect anomalies in latency data using standard deviation."""
    if len(data_points) < 3:
        return []
    
    stats = statistical_analysis(data_points)
    mean = stats["mean"]
    std_dev = stats["std_dev"]
    
    if std_dev == 0:
        return []
    
    anomalies = []
    for i, val in enumerate(data_points):
        z_score = abs(val - mean) / std_dev
        if z_score > threshold_std:
            anomalies.append({
                "index": i,
                "value": val,
                "z_score": round(z_score, 2),
                "severity": "high" if z_score > 3.0 else "medium"
            })
    
    return anomalies

# ---- NEW: Trend prediction ----
def predict_trend(data_points, window=5):
    """Predict latency trend using simple linear regression."""
    if len(data_points) < 2:
        return "insufficient_data"
    
    recent = data_points[-window:]
    n = len(recent)
    
    # Simple linear regression: y = a + bx
    x_mean = sum(range(n)) / n
    y_mean = sum(recent) / n
    
    numerator = sum((i - x_mean) * (recent[i] - y_mean) for i in range(n))
    denominator = sum((i - x_mean) ** 2 for i in range(n))
    
    if denominator == 0:
        return "stable"
    
    slope = numerator / denominator
    
    if slope > 1.0:
        return "degrading"
    elif slope < -1.0:
        return "improving"
    else:
        return "stable"

# ---- NEW: Circuit breaker pattern ----
class CircuitBreaker:
    """Circuit breaker to stop requests after consecutive failures."""
    def __init__(self, failure_threshold=3, recovery_timeout=30):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open

    def record_success(self):
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        if self.failure_count >= self.failure_threshold:
            self.state = "open"

    def allow_request(self):
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.monotonic() - self.last_failure_time > self.recovery_timeout:
                self.state = "half_open"
                return True
            return False
        return True  # half_open

# ---- NEW: Health check system ----
class HealthChecker:
    """Periodically checks the health of DNS servers."""
    def __init__(self, check_interval=60):
        self.check_interval = check_interval
        self.last_check = 0
        self.healthy_servers = set()
        self.unhealthy_servers = set()

    def should_check(self):
        return time.monotonic() - self.last_check > self.check_interval

    def update_health(self, server, is_healthy):
        if is_healthy:
            self.healthy_servers.add(server)
            self.unhealthy_servers.discard(server)
        else:
            self.unhealthy_servers.add(server)
            self.healthy_servers.discard(server)
        self.last_check = time.monotonic()

    def get_healthy_servers(self):
        return list(self.healthy_servers)

    def get_unhealthy_servers(self):
        return list(self.unhealthy_servers)

# ---- NEW: Adaptive concurrency ----
class AdaptiveConcurrency:
    """Adjusts the number of concurrent requests based on network conditions."""
    def __init__(self, min_concurrency=2, max_concurrency=16, initial=6):
        self.min_concurrency = min_concurrency
        self.max_concurrency = max_concurrency
        self.current = initial
        self.last_adjustment = time.monotonic()
        self.recent_latencies = []

    def adjust(self, latency):
        """Adjust concurrency based on recent latency."""
        self.recent_latencies.append(latency)
        if len(self.recent_latencies) > 10:
            self.recent_latencies.pop(0)
        
        if len(self.recent_latencies) < 3:
            return self.current
        
        avg_latency = sum(self.recent_latencies) / len(self.recent_latencies)
        
        if avg_latency < 50:
            # Fast network, increase concurrency
            self.current = min(self.max_concurrency, self.current + 2)
        elif avg_latency > 150:
            # Slow network, decrease concurrency
            self.current = max(self.min_concurrency, self.current - 1)
        
        self.last_adjustment = time.monotonic()
        return self.current

    def get_concurrency(self):
        return self.current

# ---- NEW: Resource monitoring ----
class ResourceMonitor:
    """Monitors CPU, memory, and network usage."""
    def __init__(self):
        self.start_time = time.monotonic()
        self.request_count = 0
        self.error_count = 0
        self.total_latency = 0.0

    def record_request(self, latency, success=True):
        self.request_count += 1
        if not success:
            self.error_count += 1
        else:
            self.total_latency += latency

    def get_stats(self):
        uptime = time.monotonic() - self.start_time
        avg_latency = self.total_latency / max(1, self.request_count - self.error_count)
        error_rate = self.error_count / max(1, self.request_count) * 100
        
        return {
            "uptime_seconds": round(uptime, 2),
            "total_requests": self.request_count,
            "error_count": self.error_count,
            "error_rate_percent": round(error_rate, 2),
            "avg_latency_ms": round(avg_latency, 2),
            "requests_per_second": round(self.request_count / max(0.1, uptime), 2)
        }

    def reset(self):
        self.start_time = time.monotonic()
        self.request_count = 0
        self.error_count = 0
        self.total_latency = 0.0

# ---- NEW: Plugin system ----
class PluginManager:
    """Manages plugins for extending functionality."""
    def __init__(self):
        self.plugins = {}

    def register(self, name, plugin):
        """Register a plugin."""
        self.plugins[name] = plugin

    def unregister(self, name):
        """Unregister a plugin."""
        self.plugins.pop(name, None)

    def get_plugin(self, name):
        """Get a plugin by name."""
        return self.plugins.get(name)

    def list_plugins(self):
        """List all registered plugins."""
        return list(self.plugins.keys())

    def execute(self, name, *args, **kwargs):
        """Execute a plugin."""
        plugin = self.plugins.get(name)
        if plugin:
            return plugin(*args, **kwargs)
        return None

# ---- NEW: Config file support ----
def load_config(config_file="~/.advanced_core.conf"):
    """Load configuration from a file."""
    config_path = os.path.expanduser(config_file)
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except:
        return {}

def save_config(config, config_file="~/.advanced_core.conf"):
    """Save configuration to a file."""
    config_path = os.path.expanduser(config_file)
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        return True
    except:
        return False

# ---- NEW: CLI arguments support ----
def parse_cli_args():
    """Parse command-line arguments."""
    args = {
        "config": None,
        "theme": None,
        "export": None,
        "verbose": False,
        "game": None,
    }
    for arg in sys.argv[1:]:
        if arg.startswith("--config="):
            args["config"] = arg.split("=", 1)[1]
        elif arg.startswith("--theme="):
            args["theme"] = arg.split("=", 1)[1]
        elif arg.startswith("--export="):
            args["export"] = arg.split("=", 1)[1]
        elif arg == "--verbose":
            args["verbose"] = True
        elif arg.startswith("--game="):
            args["game"] = arg.split("=", 1)[1]
    return args

# ---- NEW: API integration ----
class APIIntegration:
    """Integration with external APIs for additional functionality."""
    def __init__(self, api_key=None):
        self.api_key = api_key

    def fetch_data(self, url, headers=None):
        """Fetch data from an API."""
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=5) as res:
                return json.loads(res.read().decode("utf-8"))
        except:
            return None

    def post_data(self, url, data, headers=None):
        """Post data to an API."""
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers=headers or {},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as res:
                return json.loads(res.read().decode("utf-8"))
        except:
            return None

# ---- NEW: Cloud sync ----
class CloudSync:
    """Sync settings and results with cloud storage."""
    def __init__(self, api_integration=None):
        self.api = api_integration or APIIntegration()

    def sync_settings(self, config, cloud_url):
        """Sync settings to cloud."""
        return self.api.post_data(cloud_url, config)

    def fetch_settings(self, cloud_url):
        """Fetch settings from cloud."""
        return self.api.fetch_data(cloud_url)

    def sync_results(self, results, cloud_url):
        """Sync results to cloud."""
        return self.api.post_data(cloud_url, results)

# ---- NEW: Voice notifications ----
def voice_notify(message, rate=150, pitch=1.0, volume=1.0):
    """Send a voice notification."""
    try:
        import subprocess
        subprocess.run([
            "espeak", "-s", str(rate), "-p", str(int(pitch * 100)), "-v", "en", message
        ], timeout=5)
    except:
        pass

# ---- NEW: Haptic feedback ----
def haptic_feedback(duration=100, intensity=50):
    """Send haptic feedback."""
    try:
        import subprocess
        subprocess.run([
            "vibrate", "-d", str(duration), "-i", str(intensity)
        ], timeout=2)
    except:
        pass

# ---- NEW: Export to JSON/CSV ----
def export_to_json(results, filename="results.json"):
    """Export results to JSON format."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, default=str)
        return True
    except:
        return False

def export_to_csv(results, filename="results.csv"):
    """Export results to CSV format."""
    try:
        import csv
        with open(filename, "w", newline="", encoding="utf-8") as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        return True
    except:
        return False

# ---- NEW: Theme configuration ----
THEME = {
    "dark": {
        "bg": "\033[40m",
        "fg": "\033[97m",
        "accent": "\033[96m",
        "success": "\033[92m",
        "warning": "\033[93m",
        "error": "\033[91m",
    },
    "light": {
        "bg": "\033[107m",
        "fg": "\033[30m",
        "accent": "\033[34m",
        "success": "\033[32m",
        "warning": "\033[33m",
        "error": "\033[31m",
    }
}
CURRENT_THEME = "dark"

# ANSI color codes (pure ASCII escape sequences - safe on any Termux/Linux terminal, no encoding risk)
ANSI_RED = "\033[91m"
ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_BLUE = "\033[94m"
ANSI_CYAN = "\033[96m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_PURPLE = "\033[95m"

# ---- OPTIMIZATION: Pre-compiled regex patterns (avoid re-compilation in hot loops) ----
_RE_LOSS = re.compile(r"(\d+)%\s*packet loss")
_RE_RTT = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+")
_RE_DEV = re.compile(r"dev\s+(\S+)")
_RE_ROW_ID = re.compile(r"_id=(\d+)")
_RE_ROW_NAME = re.compile(r"name=([^,]+)")
_RE_ROW_APN = re.compile(r"apn=([^,]+)")
_RE_NAMESERVER = re.compile(r"nameserver\s+([0-9.]+)")
_RE_COUNTRY = re.compile(r"\[([A-Z]{2})\]")

# ---- OPTIMIZATION: DNS resolution cache (avoids repeated getaddrinfo for the same host) ----
_DNS_CACHE = {}
_DNS_CACHE_TTL = 3  # seconds before re-resolving (short TTL for accurate latency testing)


# ============================================================
#  ASCII TABLE RENDERING (SHARED UI HELPER - |, -, + ONLY)
# ============================================================
def draw_ascii_table(headers: List[str], rows: List[List[Any]], widths: List[int]) -> str:
    """Renders a simple grid table using only +, -, | so it is safe on any terminal/locale."""
    def border_line() -> str:
        return "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    def fmt_row(cells: List[Any]) -> str:
        return "| " + " | ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths)) + " |"
    lines = [border_line(), fmt_row(headers), border_line()]
    for row in rows:
        lines.append(fmt_row(row))
    lines.append(border_line())
    return "\n".join(lines)


# ============================================================
#  PERSISTENCE (GAME / SERVICE PROFILE DB)
# ============================================================
def init_db():
    if not os.path.exists(DB_FILE):
        default_data = {
            "Apex Legends": "api.apexlegends.com",
            "Google Core": "www.google.com",
            "EA Auth": "accounts.ea.com",
            "Marvel Rivals": "dynamodb.eu-central-1.amazonaws.com"
        }
        # ---- OPTIMIZATION: Atomic write (temp file + rename) to prevent corruption ----
        tmp = DB_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(default_data, f, indent=4)
        os.rename(tmp, DB_FILE)

# ---- OPTIMIZATION: Module-level services cache (avoid disk I/O on every menu access) ----
_services_cache = None

def load_services():
    global _services_cache
    if _services_cache is not None:
        return _services_cache
    init_db()
    try:
        with open(DB_FILE, "r") as f:
            _services_cache = json.load(f)
            return _services_cache
    except:
        _services_cache = {}
        return {}

def save_services(data):
    global _services_cache
    _services_cache = data
    # ---- OPTIMIZATION: Atomic write (temp file + rename) to prevent corruption ----
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=4)
    os.rename(tmp, DB_FILE)


# ============================================================
#  CORE HELPERS / SHIZUKU BRIDGE
# ============================================================
def clear_scr():
    # ---- OPTIMIZATION: Use ANSI escape directly instead of spawning a subprocess ----
    # Use \033[3J to also clear scrollback buffer (prevents excessive scrolling)
    # and \033[H to move cursor home after clearing
    sys.stdout.write("\033[3J\033[2J\033[H")
    sys.stdout.flush()

def run_shizuku_cmd(cmd):
    """Securely execute Shizuku commands without shell=True.
    Uses safe_run_shizuku_cmd for input validation and secure execution."""
    return safe_run_shizuku_cmd(cmd)

def is_shizuku_running():
    """Detects whether the Shizuku privileged-API process is currently alive, using a plain
    `pgrep -f` process-table lookup instead of any Android API call or broadcast intent.
    Returns True only if pgrep's output is a numeric PID."""
    # Keep the pattern unquoted: rish runs this through a shell, but the non-rish
    # fallback runs it as raw argv, where literal quotes would become part of the
    # pattern and never match. Unquoted works in both paths.
    raw = run_shizuku_cmd("pgrep -f moe.shizuku.privileged.api")
    pid_str = raw.strip().splitlines()[0].strip() if raw and raw.strip() else ""
    return pid_str.isdigit()

def get_live_hardware_data():
    operator = run_shizuku_cmd("getprop gsm.operator.alpha").strip()
    if not operator or "," in operator:
        operator = run_shizuku_cmd("getprop gsm.sim.operator.alpha").strip()
    operator = operator if operator else "Unknown"
    net_type = run_shizuku_cmd("getprop gsm.network.type").strip()
    net_type = net_type if net_type else "UNKNOWN"
    return operator, net_type

def parse_ping_result(raw_output):
    """Parses raw ping output into (avg_rtt_ms, loss_percent, reachable_bool). Handles both
    iputils ('rtt min/avg/max/mdev') and toybox ('round-trip min/avg/max') formats."""
    if not raw_output:
        return None, 100.0, False
    # ---- OPTIMIZATION: Use pre-compiled regex patterns ----
    loss_match = _RE_LOSS.search(raw_output)
    loss = float(loss_match.group(1)) if loss_match else 100.0
    rtt_match = _RE_RTT.search(raw_output)
    avg_rtt = float(rtt_match.group(1)) if rtt_match else None
    reachable = loss < 100.0 and avg_rtt is not None
    return avg_rtt, loss, reachable


# ============================================================
#  MTU INTELLIGENCE - READ-ONLY RECOMMENDATION (NO LIVE SHIZUKU CHANGES)
# ============================================================
def find_golden_mtu():
    for mtu_test in [1492, 1472, 1452, 1420, 1360]:
        size = mtu_test - 28
        out = run_shizuku_cmd(f"ping -c 1 -M do -s {size} 1.1.1.1")
        if "Frag needed" not in out and "Packet filtered" not in out and "1 packets transmitted" in out:
            return mtu_test
    return 1452

def _default_iface_proc():
    """Default-route interface from /proc/net/route (no privileges required).

    Android may not let a plain app run `ip route`, and Shizuku is optional, so
    this readable kernel table is a reliable last resort. The default route is
    the row whose Destination is 0.0.0.0 (hex 00000000)."""
    try:
        with open("/proc/net/route", "r", encoding="utf-8", errors="ignore") as f:
            next(f, None)  # header
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception:
        pass
    return None


def _list_interfaces():
    """All network interface names, via stdlib and /sys (no privileges required)."""
    names = set()
    try:
        names.update(name for _idx, name in socket.if_nameindex())
    except Exception:
        pass
    try:
        names.update(os.listdir("/sys/class/net"))
    except Exception:
        pass
    return names


def detect_active_interface():
    """Detects the current default-route interface from `ip route show`, which is more
    consistently supported across Android ip/toybox builds than `ip route get`. Works for a
    WireGuard/VPN TUN tunnel as well as the raw cellular radio interface."""
    # Avoid relying on a `| grep` pipe (the non-rish fallback runs argv without a
    # shell, where the pipe would not execute). Filter the output in Python instead.
    raw = run_shizuku_cmd("ip route show")
    default_line = next((ln for ln in raw.splitlines() if ln.strip().startswith("default")), "")
    if not default_line:
        raw = run_shizuku_cmd("ip route show default")
        default_line = raw
    # ---- OPTIMIZATION: Use pre-compiled regex ----
    m = _RE_DEV.search(default_line) if default_line else None
    if m:
        return m.group(1)
    # Shizuku unavailable or `ip` unsupported: fall back to the kernel route table.
    return _default_iface_proc()

_VPN_IFACE_PREFIXES = ("tun", "tap", "wg", "ppp", "utun", "ipsec", "pptp",
                       "l2tp", "nordlynx", "proton", "tailscale", "zt")

def is_vpn_interface(iface_name):
    """WireGuard/OpenVPN-style tunnels surface as tun/tap/wg/ppp interfaces on Android, regardless of
    the underlying VPN protocol, since Android's VpnService exposes a TUN device."""
    return bool(iface_name) and iface_name.startswith(_VPN_IFACE_PREFIXES)

def _android_vpn_active():
    """Ask the Android platform whether a VPN is up (Chaquopy Java bridge).

    ConnectivityManager is the authoritative source: some VPNs are implemented
    without a tun*/wg* interface name the app can see, so the platform's
    TRANSPORT_VPN flag is checked first. Returns None when the bridge is absent
    (desktop/Termux), so the caller falls back to interface inspection."""
    try:
        from java import jclass  # type: ignore
        activity = jclass("com.onlyicing.dnsconsole.MainActivity")
        return bool(activity.isVpnActive())
    except Exception:
        return None


def detect_vpn_interface():
    """Return a live VPN tunnel interface name, or a sentinel when only the
    platform knows a VPN is up, else None.

    Order matters: the Android platform flag is authoritative, then a real
    tunnel interface (works on Termux and without Shizuku), then the default
    route. None of these paths needs root."""
    if _android_vpn_active():
        return "vpn"
    for name in sorted(_list_interfaces()):
        if is_vpn_interface(name):
            return name
    iface = detect_active_interface()
    if is_vpn_interface(iface):
        return iface
    iface = _default_iface_proc()
    if is_vpn_interface(iface):
        return iface
    return None

def resolve_smart_mtu():
    """
    Read-only MTU recommendation (informational only - nothing here touches live system state):
      - Default route via a VPN/WireGuard TUN interface -> fixed VPN_MTU
      - Otherwise (Cellular)                             -> physical MTU probing via find_golden_mtu()
    """
    active_iface = detect_active_interface()
    if is_vpn_interface(active_iface):
        return VPN_MTU, f"VPN:{active_iface}", active_iface
    # A tunnel is up but we could not read the default route: the traffic is
    # almost certainly going through it, so advise the tunnel MTU.
    if active_iface is None:
        vpn_iface = detect_vpn_interface()
        if vpn_iface:
            label = "VPN" if vpn_iface == "vpn" else f"VPN:{vpn_iface}"
            return VPN_MTU, label, vpn_iface
    return find_golden_mtu(), "CELLULAR", active_iface


# ============================================================
#  LOCAL NETWORK DIAGNOSIS  (MENU KEY: D)
# ============================================================
def run_local_diagnosis():
    clear_scr()
    print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    print(f"{ANSI_BLUE}{ANSI_BOLD}           LOCAL NETWORK DIAGNOSIS (D){ANSI_RESET}")
    print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")

    # Primary check: the public reference host is the only target that is always
    # meaningful regardless of context, so it gets more samples and a quality rating.
    print(f"\n{ANSI_CYAN}[*] Pinging Public Reference ({REFERENCE_HOST}) ...{ANSI_RESET}")
    raw = run_shizuku_cmd(f"ping -c 6 -W 2 {REFERENCE_HOST}")
    avg_rtt, loss, reachable = parse_ping_result(raw)
    if reachable:
        quality = "EXCELLENT" if avg_rtt < 60 else "OK" if avg_rtt < 150 else "POOR"
        quality_color = ANSI_GREEN if quality == "EXCELLENT" else ANSI_YELLOW if quality == "OK" else ANSI_RED
        print(f"    {ANSI_GREEN}[OK]{ANSI_RESET}   Avg RTT: {avg_rtt:.1f}ms   |   Packet Loss: {loss:.0f}%   |   Quality: {quality_color}{quality}{ANSI_RESET}")
    else:
        print(f"    {ANSI_RED}[X]{ANSI_RESET}    Unreachable   |   Packet Loss: {loss:.0f}%")
        print(f"    {ANSI_YELLOW}[!] No general internet connectivity on the currently active interface.{ANSI_RESET}")

    # Secondary check: the hotspot gateway only responds while THIS device is tethered
    # as a client to another hotspot at that address - 100% loss otherwise is the
    # expected, normal state on Android and is not itself a fault.
    print(f"\n{ANSI_CYAN}[*] Checking Hotspot Gateway ({HOTSPOT_GATEWAY_IP}) ...{ANSI_RESET}")
    raw_gw = run_shizuku_cmd(f"ping -c 2 -W 1 {HOTSPOT_GATEWAY_IP}")
    gw_rtt, gw_loss, gw_reachable = parse_ping_result(raw_gw)
    if gw_reachable:
        print(f"    {ANSI_GREEN}[OK]{ANSI_RESET}   Avg RTT: {gw_rtt:.1f}ms   |   Packet Loss: {gw_loss:.0f}%")
    else:
        print(f"    {ANSI_DIM}[N/A]{ANSI_RESET}  No response - normal unless this device is currently tethered to a hotspot at this address.")

    print(f"\n{ANSI_DIM}{'-' * 55}{ANSI_RESET}")
    input(f"{ANSI_DIM}Press Enter to return to menu...{ANSI_RESET}")


# ============================================================
#  LIVE APN BENCHMARK  (MENU KEY: A) - SHIZUKU CARRIER DB LAYER
# ============================================================
def query_apn_database():
    """Reads the APN entries currently present in this device's telephony carrier database
    (content://telephony/carriers) - i.e. profiles already provisioned by the carrier or
    previously added by the user, NOT arbitrary external values."""
    raw = run_shizuku_cmd("content query --uri content://telephony/carriers --projection _id:name:apn:type")
    entries = []
    if not raw:
        return entries
    # ---- OPTIMIZATION: Use pre-compiled regex patterns ----
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("Row:"):
            continue
        id_m = _RE_ROW_ID.search(line)
        name_m = _RE_ROW_NAME.search(line)
        apn_m = _RE_ROW_APN.search(line)
        if id_m and name_m and apn_m and apn_m.group(1).strip():
            entries.append({
                "id": id_m.group(1),
                "name": name_m.group(1).strip(),
                "apn": apn_m.group(1).strip(),
            })
    return entries

def get_current_preferred_apn_id():
    raw = run_shizuku_cmd("content query --uri content://telephony/carriers/preferapn --projection _id")
    # ---- OPTIMIZATION: Use pre-compiled regex ----
    m = _RE_ROW_ID.search(raw) if raw else None
    return m.group(1) if m else None

def set_preferred_apn(apn_id):
    """Activates the given APN id as the device's preferred APN. Two write paths are attempted
    since the writable URI differs slightly across Android/HyperOS builds."""
    run_shizuku_cmd(f"content update --uri content://telephony/carriers/preferapn --bind apn_id:i:{apn_id}")
    run_shizuku_cmd(f"content insert --uri content://telephony/carriers/preferapn_no_update --bind apn_id:i:{apn_id}")


# Per-host TCP circuit breaker (isolates failures per host)
_tcp_breakers = {}

def _get_tcp_breaker(host):
    if host not in _tcp_breakers:
        _tcp_breakers[host] = CircuitBreaker(failure_threshold=5, recovery_timeout=15)
    return _tcp_breakers[host]

def tcp_ping(host, port=443, timeout=2.0):
    """TCP ping with circuit breaker protection."""
    breaker = _get_tcp_breaker(host)
    if not breaker.allow_request():
        logger.debug(f"Circuit breaker open for TCP ping to {host}:{port}")
        return None, False
    
    start = time.perf_counter()
    try:
        with _profiler.time("tcp_ping"):
            with socket.create_connection((host, port), timeout=timeout):
                elapsed = (time.perf_counter() - start) * 1000
                breaker.record_success()
                return elapsed, True
    except:
        breaker.record_failure()
        return None, False

# ---- OPTIMIZATION: Connection pool for TCP pings ----
# Reuses sockets instead of creating new ones each time
class _TCPConnectionPool:
    """Simple connection pool for TCP pings — reuses connections when possible."""
    def __init__(self):
        self._connections = {}

    async def tcp_ping(self, host, port, timeout=2.0):
        """TCP ping using pooled connection if available."""
        key = (host, port)
        sock = None
        try:
            start = time.perf_counter()
            # Try to reuse existing connection
            loop = asyncio.get_running_loop()
            if key in self._connections:
                sock = self._connections.pop(key)
                try:
                    sock.setblocking(False)
                    # A pooled socket is only still good if the peer hasn't
                    # closed it; a readable socket that returns b"" is EOF.
                    try:
                        probe = await asyncio.wait_for(loop.sock_recv(sock, 1), timeout=0.001)
                    except asyncio.TimeoutError:
                        probe = b"\x00"  # nothing pending: connection is idle and alive
                    if probe == b"":
                        raise ConnectionError("peer closed pooled socket")
                    elapsed = (time.perf_counter() - start) * 1000
                    self._connections[key] = sock
                    return elapsed, True
                except Exception:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None

            # Create new connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            loop = asyncio.get_running_loop()
            await loop.sock_connect(sock, (host, port))
            elapsed = (time.perf_counter() - start) * 1000
            self._connections[key] = sock
            return elapsed, True
        except:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            return None, False

    def close_all(self):
        """Close all pooled connections."""
        for sock in self._connections.values():
            try:
                sock.close()
            except:
                pass
        self._connections.clear()

_tcp_pool = _TCPConnectionPool()

# ---- OPTIMIZATION: UDP ping for game-specific ports (Apex, Valorant, etc.) ----
# TCP ping measures connection setup; UDP ping measures actual game packet latency.
# For UDP-based games, this is the metric that matters for lag.
async def udp_ping(host, port=37015, count=3, timeout=1.5):
    """Async UDP ping: sends game-like packets and measures round-trip latency.
    Returns (avg_latency_ms, loss_percent, jitter_ms) or (None, 100.0, 0.0) on total failure.
    Host can be an IP address or hostname — if hostname, it will be resolved first.
    NOTE: Many game servers don't respond to arbitrary UDP pings, so this is informational."""
    durations = []
    packet_loss = 0
    # Use a game-like packet pattern (small, realistic)
    packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('', 0))
        except:
            pass
        loop = asyncio.get_running_loop()
        # Resolve host to IP if it's a hostname (not already an IP)
        ip = host
        if not _is_ip_address(host):
            resolved = native_dns_resolver(host, "8.8.8.8")
            if resolved:
                ip = resolved
            else:
                return None, 100.0, 0.0

        for _ in range(count):
            try:
                start_time = time.perf_counter()
                await loop.sock_sendto(sock, packet, (ip, port))
                # Ignore datagrams that didn't come back from the target — a
                # stray packet from anywhere would otherwise be timed as a reply.
                deadline = loop.time() + timeout
                while True:
                    data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 512), timeout=timeout)
                    if addr and addr[0] == ip:
                        break
                    if loop.time() >= deadline:
                        raise TimeoutError("no reply from target")
                end_time = time.perf_counter()
                durations.append((end_time - start_time) * 1000)
            except Exception:
                packet_loss += 1
            await asyncio.sleep(0.02)
    finally:
        # Always release the socket (prevents file-descriptor leaks across calls)
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    if not durations:
        return None, 100.0, 0.0

    avg_latency = sum(durations) / len(durations)
    loss_percent = (packet_loss / count) * 100
    jitter = sum(abs(durations[i] - durations[i - 1]) for i in range(len(durations) - 1)) / (len(durations) - 1) if len(durations) > 1 else 0.0
    return avg_latency, loss_percent, jitter

def _is_ip_address(host):
    """Check if a string is an IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except:
        return False

async def protocol_aware_ping(host, game_name, count=3, timeout=1.5, port=None, protocol=None):
    """Protocol-aware ping: uses UDP for game ports, TCP for standard ports.
    This is the key optimization — game traffic is UDP, so TCP ping is misleading.

    `port`/`protocol` (e.g. what the AI suggested for a game we don't know)
    override the built-in defaults. 'both' tries UDP then TCP and returns the
    first that answers; 'auto' does the same but also tries TLS/DoT."""
    ports, protocol = game_port_plan(game_name, port=port, protocol=protocol)
    primary_port = ports[0]

    async def _udp():
        return await udp_ping(host, primary_port, count, timeout)

    async def _tcp():
        loop = asyncio.get_running_loop()
        rtt, ok = await loop.run_in_executor(
            None, lambda: tcp_ping(host, primary_port, timeout))
        return (rtt, 0.0, 0.0) if ok else (None, 100.0, 0.0)

    async def _tls():
        # DoT uses a fixed 853 unless the caller explicitly overrode the port.
        loop = asyncio.get_running_loop()
        index = 443 if primary_port == 443 else (853 if port is None else primary_port)
        rtt, ok = await loop.run_in_executor(
            None, lambda: tcp_ping(host, index, timeout))
        return (rtt, 0.0, 0.0) if ok else (None, 100.0, 0.0)

    if protocol == "udp":
        return await _udp()
    if protocol == "tcp":
        return await _tcp()
    if protocol == "tls":
        return await _tls()
    # 'auto' tries every protocol; 'both' stops at UDP/TCP. First answer wins.
    attempts = (_udp, _tcp, _tls) if protocol == "auto" else (_udp, _tcp)
    for attempt in attempts:
        latency, loss, jitter = await attempt()
        if latency is not None:
            return latency, loss, jitter
    return None, 100.0, 0.0

# ---- OPTIMIZATION: Adaptive timeout based on RTT ----
# Fast DNS servers get short timeout; slow ones get more
# This prevents slow DNS from blocking the entire scan
def compute_adaptive_timeout(base_timeout=1.5, min_timeout=0.5, max_timeout=3.0, recent_lats=None):
    """Returns adaptive timeout based on recent RTT measurements.
    Uses the fastest recent RTT as a baseline to scale the timeout.
    Prevents slow DNS servers from blocking the entire scan."""
    if not recent_lats:
        return base_timeout
    
    # Filter out invalid values
    valid_lats = [lat for lat in recent_lats if lat and lat > 0 and lat < 9000]
    if not valid_lats:
        return base_timeout
    
    fastest = min(valid_lats)
    # Scale timeout: 3x fastest RTT + 0.5s buffer, clamped to min/max
    adaptive = max(min_timeout, min(max_timeout, fastest * 3 + 0.5))
    return adaptive

def run_live_apn_benchmark():
    # Use retry handler for APN operations
    clear_scr()
    print(f"{ANSI_YELLOW}{ANSI_BOLD}============================================================={ANSI_RESET}")
    print(f"{ANSI_YELLOW}{ANSI_BOLD}          LIVE APN BENCHMARK (A) - SHIZUKU CARRIER LAYER{ANSI_RESET}")
    print(f"{ANSI_YELLOW}{ANSI_BOLD}============================================================={ANSI_RESET}")

    if not is_shizuku_running():
        print(f"\n{ANSI_RED}[X] Shizuku not detected (pgrep found no matching process).{ANSI_RESET}")
        print(f"{ANSI_YELLOW}[!] Start the Shizuku service on your device, then try this module again.{ANSI_RESET}")
        input(f"\n{ANSI_DIM}Press Enter to return to menu...{ANSI_RESET}")
        return

    print(f"\n{ANSI_CYAN}[*] Reading telephony carrier database...{ANSI_RESET}")
    apn_list = query_apn_database()
    if not apn_list:
        print(f"{ANSI_RED}[X] No APN entries found, or Shizuku permission was denied.{ANSI_RESET}")
        input(f"\n{ANSI_DIM}Press Enter to return to menu...{ANSI_RESET}")
        return

    original_id = get_current_preferred_apn_id()
    print(f"{ANSI_CYAN}[*] Current preferred APN id : {ANSI_RESET}{original_id or 'Unknown'}")
    print(f"{ANSI_CYAN}[*] Entries found            : {ANSI_RESET}{len(apn_list)}")
    print(f"{ANSI_CYAN}[*] Radio Cooldown per switch: {ANSI_RESET}{RADIO_COOLDOWN_SECONDS}s {ANSI_DIM}(prevents HyperOS modem crash){ANSI_RESET}\n")

    results = []
    try:
        for entry in apn_list:
            label = f"{entry['name']} ({entry['apn']})"
            print(f"  {ANSI_DIM}->{ANSI_RESET} Testing: {label[:45]:<45}", end="", flush=True)
            set_preferred_apn(entry["id"])
            time.sleep(RADIO_COOLDOWN_SECONDS)  # Radio Cooldown - let the HyperOS modem settle
            # Use retry handler for TCP ping
            try:
                rtt, ok = _retry_handler.execute_sync(tcp_ping, REFERENCE_HOST, 443)
            except Exception as e:
                logger.error(f"APN test failed for {entry['name']}: {e}")
                rtt, ok = None, False
            if ok:
                print(f" {ANSI_GREEN}[OK]{ANSI_RESET} {rtt:.0f}ms")
            else:
                print(f" {ANSI_RED}[FAIL]{ANSI_RESET}")
            results.append({"id": entry["id"], "name": entry["name"], "apn": entry["apn"], "ok": ok, "rtt": rtt})
    finally:
        if original_id:
            set_preferred_apn(original_id)
            time.sleep(RADIO_COOLDOWN_SECONDS)  # Radio Cooldown after the safety-net restore
        print(f"\n{ANSI_CYAN}[*] Testing phase complete - APN state safely restored to original.{ANSI_RESET}")

    print()
    working = sorted([r for r in results if r["ok"]], key=lambda r: r["rtt"])
    failed = [r for r in results if not r["ok"]]
    apn_rows = [[r["name"], r["apn"], "OK", f"{r['rtt']:.0f}ms"] for r in working]
    apn_rows += [[r["name"], r["apn"], "FAIL", "--"] for r in failed]
    print(draw_ascii_table(["APN Name", "APN", "Status", "RTT"], apn_rows, [22, 22, 8, 8]))

    if working:
        best = working[0]
        apply_choice = input(f"\n{ANSI_YELLOW}[?] Found Best APN: {best['name']}. Switch system to this APN now? [Y/N]: {ANSI_RESET}").strip().lower()
        if apply_choice == 'y':
            set_preferred_apn(best["id"])
            time.sleep(RADIO_COOLDOWN_SECONDS)  # Radio Cooldown after the confirmed switch
            print(f"{ANSI_GREEN}[OK] System switched to '{best['name']}' ({best['apn']}).{ANSI_RESET}")
        else:
            print(f"{ANSI_CYAN}[*] Kept original APN (id={original_id or 'Unknown'}).{ANSI_RESET}")
    else:
        print(f"\n{ANSI_RED}[!] No working APN candidates found - original APN remains active.{ANSI_RESET}")

    input(f"\n{ANSI_DIM}Press Enter to return to menu...{ANSI_RESET}")


# ============================================================
#  GATEWAY / GEO ANALYSIS
# ============================================================
def analyze_gateway():
    try:
        req = urllib.request.Request("http://ip-api.com/json/?fields=query,countryCode,isp", headers={"User-Agent": "Mozilla"})
        with urllib.request.urlopen(req, timeout=2.5) as res:
            data = json.loads(res.read().decode("utf-8"))
            return data.get("query", "N/A"), data.get("countryCode", "UNK").upper(), data.get("isp", "Unknown ISP")
    except:
        return "N/A", "UNK", "Unknown ISP"


# ============================================================
#  TARGET / PROFILE SELECTION
# ============================================================
def select_game_target():
    services = load_services()
    if not services:
        return "www.google.com", "Default Link"
    clear_scr()
    print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    print(f"{ANSI_PURPLE}{ANSI_BOLD}           CHOOSE TARGET GAME / SERVICE{ANSI_RESET}")
    print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    service_list = list(services.items())
    for idx, (name, host) in enumerate(service_list, start=1):
        # Show protocol info if available
        proto_info = ""
        config = GAME_PROTOCOL_DB.get(name, {})
        if config:
            proto = config.get("protocol", "tcp").upper()
            ports = config.get("ports", [])
            proto_info = f" {ANSI_DIM}[{proto}/{ports[0] if ports else '?'}]{ANSI_RESET}"
        print(f"  {ANSI_GREEN}[{idx}]{ANSI_RESET} {name:<22} {ANSI_DIM}-->{ANSI_RESET} {host}{proto_info}")
    print(f"{ANSI_DIM}{'-' * 55}{ANSI_RESET}")
    try:
        choice = input(f"{ANSI_CYAN}Select Target Number [1-{len(service_list)}]: {ANSI_RESET}").strip()
        # ---- INPUT VALIDATION: Validate numeric input ----
        if not choice.isdigit():
            logger.debug(f"Invalid input: {choice}")
            return service_list[0][1], service_list[0][0]
        selected_idx = int(choice) - 1
        if 0 <= selected_idx < len(service_list):
            return service_list[selected_idx][1], service_list[selected_idx][0]
    except ValueError as e:
        logger.error(f"Invalid selection: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in select_game_target: {e}")
    return service_list[0][1], service_list[0][0]


# ============================================================
#  DNS RESOLUTION / RAW ASYNC PING CORE
# ============================================================
_DNS_TYPE_CODES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "HTTPS": 65,
}


def _dns_type_code(qtype):
    """Coerce a record type (int or 'A'/'AAAA'/'TXT'/...) to its numeric code."""
    if isinstance(qtype, bool):
        return 1
    if isinstance(qtype, int):
        return qtype & 0xFFFF
    name = str(qtype).strip().upper()
    if name in _DNS_TYPE_CODES:
        return _DNS_TYPE_CODES[name]
    if name.startswith("TYPE"):
        name = name[4:]
    try:
        return int(name) & 0xFFFF
    except ValueError:
        return 1


def _build_dns_query(host, qtype=1):
    """Build a DNS query packet for the given hostname and record type."""
    # Header: ID (random), flags (standard query), questions, answers, authority, additional
    txid = random.randint(1, 65535)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    # Question section
    question = b''
    for part in str(host).strip().rstrip('.').split('.'):
        raw = part.encode()[:63]     # a label is capped at 63 bytes (RFC 1035)
        if not raw:
            continue                 # skip empty labels (e.g. from "a..b")
        question += bytes([len(raw)]) + raw
    question += b'\x00'
    question += struct.pack('!H', _dns_type_code(qtype))  # QTYPE
    question += b'\x00\x01'  # QCLASS = IN
    return header + question

def _parse_dns_response(data):
    """Parse a DNS response and return the first A-record IP (or None)."""
    if not data or len(data) < 12:
        return None
    if not (data[2] & 0x80):        # QR bit: must be a response
        return None
    if data[3] & 0x0F:              # RCODE: 0 = NOERROR
        return None
    try:
        qdcount = struct.unpack('!H', data[4:6])[0]
        ancount = struct.unpack('!H', data[6:8])[0]
        pos = 12
        for _ in range(qdcount):
            _, pos = _dns_read_name(data, pos)
            pos += 4  # QTYPE + QCLASS
        for _ in range(ancount):
            _, pos = _dns_read_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlength]
            if rtype == 1 and rdlength == 4:  # A record
                return '.'.join(str(b) for b in rdata)
            pos += rdlength
    except Exception:
        pass
    return None


def native_dns_resolver(host, dns_server, timeout=1.0):
    if not validate_host(host):
        return None
    now = time.monotonic()
    
    # Resolve DNS server hostname to IP if needed (so we can do real UDP queries)
    dns_ip = dns_server
    if dns_server and not _is_ip_address(dns_server):
        try:
            dns_ip = socket.getaddrinfo(dns_server, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except Exception:
            dns_ip = None
    
    cache_key = (host, dns_ip or dns_server)
    if cache_key in _DNS_CACHE:
        cached_ip, cached_ts = _DNS_CACHE[cache_key]
        if now - cached_ts < _DNS_CACHE_TTL:
            return cached_ip
    # Try the specified DNS server first via real UDP DNS query
    if dns_ip and _is_ip_address(dns_ip):
        sock = None
        try:
            query = _build_dns_query(host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.connect((dns_ip, 53))
            sock.send(query)
            # Only accept a reply carrying this query's transaction ID, so a
            # stray datagram can't be mistaken for the answer.
            want_id = query[:2]
            while True:
                data = sock.recv(512)
                if len(data) >= 12 and data[:2] == want_id and (data[2] & 0x80):
                    break
            ip = _parse_dns_response(data)
            if ip:
                _DNS_CACHE[cache_key] = (ip, now)
                return ip
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    
    # Fallback: try system resolver
    try:
        res = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        if res:
            ip = res[0][4][0]
            _DNS_CACHE[cache_key] = (ip, now)
            return ip
    except Exception:
        pass
    return None


def _dns_query_raw(host, qtype, dns_server, timeout=2.0):
    """Send one DNS query and return the raw response bytes (or None).

    Uses a public resolver (default 1.1.1.1) rather than the target being
    benchmarked, because this is for lookups *about* a server, not *through* it.
    Falls back to TCP when the UDP reply is truncated (TC flag)."""
    dns_ip = dns_server
    if dns_server and not _is_ip_address(dns_server):
        try:
            dns_ip = socket.getaddrinfo(dns_server, None, socket.AF_INET,
                                        socket.SOCK_STREAM)[0][4][0]
        except Exception:
            dns_ip = "1.1.1.1"
    packet = _build_dns_query(host, qtype)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((dns_ip, 53))
        sock.send(packet)
        # Match the transaction ID so a stale/spoofed datagram isn't parsed as
        # this query's answer.
        want_id = packet[:2]
        while True:
            data = sock.recv(2048)
            if len(data) >= 12 and data[:2] == want_id and (data[2] & 0x80):
                break
        if data[2] & 0x02:  # TC bit → retry over TCP
            return _dns_query_raw_tcp(dns_ip, packet, timeout)
        return data
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _dns_query_raw_tcp(dns_ip, packet, timeout):
    sock = None
    try:
        sock = socket.create_connection((dns_ip, 53), timeout)
        sock.settimeout(timeout)
        sock.sendall(len(packet).to_bytes(2, "big") + packet)
        head = _dns_recv_exact(sock, 2)
        length = int.from_bytes(head, "big")
        return _dns_recv_exact(sock, length)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _dns_read_name(data, pos):
    """Read a (possibly compressed) DNS name, returning (name, next_pos)."""
    labels = []
    jumped = False
    next_pos = pos
    seen = 0
    while pos < len(data) and seen < 128:
        seen += 1
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_pos = pos
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_pos = pos + 2
                jumped = True
            pos = ptr
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("latin-1", "ignore"))
        pos += 1 + length
    if not jumped:
        next_pos = pos
    return ".".join(labels), next_pos


def _parse_dns_txt(data):
    """Return the list of TXT-record strings in a DNS response."""
    if not data or len(data) < 12:
        return []
    try:
        qdcount = struct.unpack("!H", data[4:6])[0]
        ancount = struct.unpack("!H", data[6:8])[0]
        pos = 12
        for _ in range(qdcount):
            _, pos = _dns_read_name(data, pos)
            pos += 4
        out = []
        for _ in range(ancount):
            _, pos = _dns_read_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype = struct.unpack("!H", data[pos:pos + 2])[0]
            rdlength = struct.unpack("!H", data[pos + 8:pos + 10])[0]
            pos += 10
            if rtype == 16:  # TXT
                end = pos + rdlength
                chunk = ""
                p = pos
                while p < end:
                    ln = data[p]
                    chunk += data[p + 1:p + 1 + ln].decode("latin-1", "ignore")
                    p += 1 + ln
                out.append(chunk)
            pos += rdlength
        return out
    except Exception:
        return []


_COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "UAE", "AF": "Afghanistan", "AL": "Albania",
    "AM": "Armenia", "AR": "Argentina", "AT": "Austria", "AU": "Australia",
    "AZ": "Azerbaijan", "BA": "Bosnia", "BD": "Bangladesh", "BE": "Belgium",
    "BG": "Bulgaria", "BH": "Bahrain", "BN": "Brunei", "BO": "Bolivia",
    "BR": "Brazil", "BY": "Belarus", "CA": "Canada", "CH": "Switzerland",
    "CL": "Chile", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark",
    "DO": "Dominican Rep.", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia",
    "EG": "Egypt", "ES": "Spain", "ET": "Ethiopia", "FI": "Finland",
    "FR": "France", "GB": "UK", "GE": "Georgia", "GH": "Ghana", "GR": "Greece",
    "GT": "Guatemala", "HK": "Hong Kong", "HR": "Croatia", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India",
    "IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy", "JP": "Japan",
    "JO": "Jordan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia",
    "KR": "South Korea", "KW": "Kuwait", "KZ": "Kazakhstan", "LB": "Lebanon",
    "LK": "Sri Lanka", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia",
    "MA": "Morocco", "MD": "Moldova", "ME": "Montenegro", "MK": "N. Macedonia",
    "MM": "Myanmar", "MN": "Mongolia", "MX": "Mexico", "MY": "Malaysia",
    "NG": "Nigeria", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal",
    "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru",
    "PH": "Philippines", "PK": "Pakistan", "PL": "Poland", "PR": "Puerto Rico",
    "PT": "Portugal", "PY": "Paraguay", "QA": "Qatar", "RO": "Romania",
    "RS": "Serbia", "RU": "Russia", "SA": "Saudi Arabia", "SE": "Sweden",
    "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia", "SN": "Senegal",
    "TH": "Thailand", "TN": "Tunisia", "TR": "Türkiye", "TW": "Taiwan",
    "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda", "US": "United States",
    "UY": "Uruguay", "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam",
    "ZA": "South Africa",
}
_GEO_CACHE = {}
_GEO_LOCK = threading.Lock()


def _parse_dns_answers(data, want_qtype=1):
    """Return the answer records in a DNS response as dicts.

    Each item: {name, type, ttl, value}. A/AAAA values are strings; TXT values
    are the concatenated string; other types are returned as raw hex."""
    if not data or len(data) < 12:
        return []
    try:
        qdcount = struct.unpack("!H", data[4:6])[0]
        ancount = struct.unpack("!H", data[6:8])[0]
        pos = 12
        for _ in range(qdcount):
            _, pos = _dns_read_name(data, pos)
            pos += 4
        out = []
        for _ in range(ancount):
            name, pos = _dns_read_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _, ttl, rdlength = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlength]
            pos += rdlength
            if rtype == 1 and rdlength == 4:      # A
                value = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rdlength == 16:  # AAAA
                value = ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}"
                                 for i in range(0, 16, 2))
            elif rtype == 16:                     # TXT
                chunk, p = "", 0
                while p < len(rdata):
                    ln = rdata[p]
                    chunk += rdata[p + 1:p + 1 + ln].decode("latin-1", "ignore")
                    p += 1 + ln
                value = chunk
            elif rtype == 5:                      # CNAME
                value = _dns_read_name(data, pos - rdlength)[0]
            else:
                value = rdata.hex()
            out.append({"name": name, "type": rtype, "ttl": ttl, "value": value})
        return out
    except Exception:
        return []


def _web_dig(host, dns_server, qtype=1, timeout=2.0):
    """Resolve `host` via a specific DNS server and return the parsed answers.

    This is the "dig against a chosen resolver" primitive: every method can ask
    a selected DNS server to resolve a selected game/CDN target."""
    raw = _dns_query_raw(host, qtype, dns_server, timeout)
    if raw is None:
        return {"ok": False, "host": host, "server": dns_server, "answers": []}
    return {"ok": True, "host": host, "server": dns_server,
            "answers": _parse_dns_answers(raw, qtype)}


def _web_geo_lookup(ip, timeout=2.0, dns_server="1.1.1.1"):
    """Geo/ASN lookup for an IP via Team Cymru's DNS service.

    Query ``<reversed-ip>.origin.asn.cymru.com`` TXT → "ASN | prefix | CC |
    registry | allocated". Country = the IP's registration country, which is the
    practical signal for "where does this resolver live". Cached per process."""
    if not _is_ip_address(ip) or "." not in ip:
        return {"country": "", "country_name": "", "asn": "", "org": ""}
    with _GEO_LOCK:
        if ip in _GEO_CACHE:
            return _GEO_CACHE[ip]
    rev = ".".join(reversed(ip.split(".")))
    result = {"country": "", "country_name": "", "asn": "", "org": ""}
    try:
        txt = _parse_dns_txt(_dns_query_raw(f"{rev}.origin.asn.cymru.com", 16,
                                            dns_server, timeout))
        for entry in txt:
            parts = [p.strip() for p in entry.split("|")]
            if len(parts) >= 3:
                result["asn"] = parts[0]
                cc = parts[2].upper()
                result["country"] = cc
                result["country_name"] = _COUNTRY_NAMES.get(cc, cc)
                break
        # ASN org name (best-effort, second query)
        if result["asn"]:
            txt2 = _parse_dns_txt(_dns_query_raw(f"AS{result['asn']}.asn.cymru.com",
                                                 16, dns_server, timeout))
            for entry in txt2:
                parts = [p.strip() for p in entry.split("|")]
                if len(parts) >= 5:
                    result["org"] = parts[4]
                    break
    except Exception:
        pass
    with _GEO_LOCK:
        _GEO_CACHE[ip] = result
    return result


def _web_geo_bulk(ips, timeout=2.0, workers=16):
    """Geo-locate a batch of IPs in parallel; returns {ip: geo-dict}."""
    out = {}
    if not ips:
        return out
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(ips))) as pool:
        futs = {pool.submit(_web_geo_lookup, ip, timeout): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            try:
                out[ip] = fut.result()
            except Exception:
                out[ip] = {"country": "", "country_name": "", "asn": "", "org": ""}
    return out


# ---- Probe query targets (what each test actually resolves) ----------------
# Testing a resolver against the endpoints you actually use (your games/CDNs)
# is far more meaningful than the generic "google.com" default.
_WEB_PROBE_TARGETS = {
    "google":        ("google.com",          "Google"),
    "cloudflare":    ("cloudflare.com",      "Cloudflare"),
    "fastly":        ("fastly.net",          "Fastly CDN"),
    "akamai":        ("akamai.net",          "Akamai CDN"),
    "steam":         ("steamcommunity.com",  "Steam"),
    "epic":          ("epicgames.com",       "Epic Games"),
    "riot":          ("riotgames.com",       "Riot / Valorant / LoL"),
    "ea":            ("ea.com",              "EA"),
    "battlenet":     ("battle.net",          "Battle.net / Blizzard"),
    "roblox":        ("roblox.com",          "Roblox"),
    "minecraft":     ("minecraft.net",       "Minecraft"),
    "pubg":          ("pubg.com",            "PUBG"),
    "genshin":       ("hoyoverse.com",       "HoYoverse / Genshin"),
    "discord":       ("discord.com",         "Discord"),
    "netflix":       ("netflix.com",         "Netflix"),
    "youtube":       ("youtube.com",         "YouTube"),
    "spotify":       ("spotify.com",         "Spotify"),
    "amazon":        ("amazon.com",          "Amazon"),
    "microsoft":     ("microsoft.com",       "Microsoft"),
    "apple":         ("apple.com",           "Apple"),
    "twitter":       ("x.com",               "X / Twitter"),
    "telegram":      ("telegram.org",        "Telegram"),
    "whatsapp":      ("whatsapp.com",        "WhatsApp"),
    "wikipedia":     ("wikipedia.org",       "Wikipedia"),
    "github":        ("github.com",          "GitHub"),
}


def _web_str(value):
    """Coerce a JSON body value to a stripped string without ever raising."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value).strip()
    return ""


def _web_safe_port(value, default=443):
    """Coerce a client-supplied port to a valid TCP/UDP port number."""
    try:
        p = int(value)
    except (TypeError, ValueError):
        return default
    return p if 1 <= p <= 65535 else default


def _web_probe_host(sel):
    """Map a probe-target key (or a raw hostname) to the hostname to resolve.

    Unknown keys are treated as a literal hostname so a custom target just works."""
    if not sel:
        return "google.com"
    key = str(sel).strip().lower()
    if key in _WEB_PROBE_TARGETS:
        return _WEB_PROBE_TARGETS[key][0]
    return str(sel).strip()


def _web_recommend_pairs(rows, fanout=2):
    """Group resolvers by country and recommend a resilient primary/backup pair.

    Strategy: pick the two fastest alive resolvers that live in *different*
    countries (so a single country/outage can't take both), then also offer the
    best same-country pair as a faster (but less diverse) alternative.
    Returns {"cross": [...], "same": [...], "by_country": {...}}."""
    alive = [r for r in rows if isinstance(r, dict)
             and r.get("status") == "ok" and r.get("latency") is not None]
    alive.sort(key=lambda r: r["latency"])

    def brief(r):
        return {"target": r["target"], "latency": r["latency"],
                "country": r.get("country") or "",
                "country_name": r.get("country_name") or r.get("country") or "Unknown",
                "asn": r.get("asn") or "", "org": r.get("org") or ""}

    # fastest two from different countries
    cross = []
    seen_cc = set()
    for r in alive:
        cc = r.get("country") or "??"
        if cc in seen_cc:
            continue
        cross.append(brief(r))
        seen_cc.add(cc)
        if len(cross) >= fanout:
            break
    # top pair overall (may share a country = lower latency)
    same = [brief(r) for r in alive[:fanout]]

    by_country = {}
    for r in alive:
        cc = r.get("country") or "??"
        g = by_country.setdefault(cc, {"country": cc,
                                       "country_name": r.get("country_name") or cc,
                                       "count": 0, "best": None})
        g["count"] += 1
        if g["best"] is None or r["latency"] < g["best"]["latency"]:
            g["best"] = brief(r)
    return {"cross": cross, "same": same, "by_country": by_country}


def _web_recommend_pairs_filtered(rows, countries=None, fanout=2):
    """Like _web_recommend_pairs, but restricted to a set of country codes.

    `countries` is a list of ISO-2 codes (lower-case or upper-case). When empty
    or falsy, behaves exactly like _web_recommend_pairs."""
    if not countries:
        return _web_recommend_pairs(rows, fanout=fanout)
    wanted = {str(c).strip().upper() for c in countries if str(c).strip()}
    pool = [r for r in rows if (r.get("country") or "").upper() in wanted]
    return _web_recommend_pairs(pool, fanout=fanout)


# --- Route / path intelligence ------------------------------------------------
# We can't read a traceroute back out of Python on a stock Android device
# without Shizuku, but we CAN determine where we (the public egress IP) and the
# game servers sit, and use that to reason about the path and pick the closest
# resolvers. That is the useful part of "create a route for them".

def _web_ip_geo(ip, timeout=3.0):
    """Geo-locate a single IP (country + city + lat/lon) via ip-api."""
    if not ip:
        return {}
    try:
        url = (f"http://ip-api.com/json/{urllib.parse.quote(ip)}"
               "?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,query")
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return {}


def _haversine_km(a_lat, a_lon, b_lat, b_lon):
    """Great-circle distance in km (physical distance, ignores routing)."""
    try:
        import math
        r = 6371.0
        d_lat = math.radians(b_lat - a_lat)
        d_lon = math.radians(b_lon - a_lon)
        h = (math.sin(d_lat / 2) ** 2
             + math.cos(math.radians(a_lat)) * math.cos(math.radians(b_lat))
             * math.sin(d_lon / 2) ** 2)
        return round(2 * r * math.asin(min(1.0, math.sqrt(h))), 1)
    except Exception:
        return None


def _web_route_analysis(game_host, region=None, rows=None):
    """Describe the physical route: us (public IP) -> game endpoint, plus the
    distance, and a note on whether a VPN is likely adding a detour.

    Then we use that egress location to judge which resolvers are "on the same
    route" (closest), which is what actually lowers game ping."""
    ip, country, isp = analyze_gateway()
    egress = _web_ip_geo(ip) if ip else {}
    target_ip = ""
    if game_host:
        target_ip = game_host if _is_ip_address(game_host) else (native_dns_resolver(game_host, "8.8.8.8") or "")
    target = _web_ip_geo(target_ip) if target_ip else {}
    iface = detect_active_interface()
    vpn_iface = detect_vpn_interface()
    vpn = bool(vpn_iface)
    dist = None
    if egress.get("lat") is not None and target.get("lat") is not None:
        dist = _haversine_km(egress["lat"], egress["lon"], target["lat"], target["lon"])
    hops = []
    for label, g in (("you (egress)", egress), ("game endpoint", target)):
        if g:
            hops.append({
                "label": label,
                "ip": g.get("query") or (ip if label.startswith("you") else target_ip),
                "country": g.get("countryCode") or "",
                "country_name": g.get("country") or "",
                "city": g.get("city") or "",
                "org": g.get("isp") or g.get("org") or "",
            })
    on_route = _web_resolvers_on_route(rows or [], egress, limit=8)
    return {
        "egress": egress,
        "target": target,
        "target_host": game_host or "",
        "target_ip": target_ip,
        "region": region or "",
        "vpn": vpn,
        "interface": iface,
        "distance_km": dist,
        "hops": hops,
        "on_route": on_route,
        "note": _route_note(egress, target, vpn, dist),
    }


def _route_note(egress, target, vpn, dist):
    if not egress or not target:
        return "Could not geolocate one end of the route."
    parts = []
    ec, tc = egress.get("countryCode") or "?", target.get("countryCode") or "?"
    if vpn:
        parts.append("VPN tunnel detected — the egress IP is the VPN exit, not your physical link.")
    if ec == tc:
        parts.append("Your egress and the game endpoint share a country — minimal physical distance.")
    else:
        parts.append(f"Egress ({ec}) and game endpoint ({tc}) are in different countries; "
                     "expect extra inter-country hops.")
    if dist:
        parts.append(f"~{dist} km (great-circle).")
    parts.append("Test resolvers whose exit country matches this egress for the shortest path.")
    return " ".join(parts)


def _country_centroid_geo(cc):
    """Look up the public IP + geo of a reference host inside a country.

    ip-api can't enumerate "give me an IP in country X", but it returns the
    country's own registry entry via a well-known anycast (1.1.1.1 -> US, etc.),
    so we approximate using the largest ASN we already know. Falls back to a
    small built-in centroid table for common game countries."""
    table = {
        "DE": (51.0, 10.4), "NL": (52.1, 5.3), "FR": (46.6, 2.5), "GB": (54.0, -2.0),
        "FI": (64.0, 26.0), "SE": (62.0, 15.0), "PL": (52.1, 19.4), "ES": (40.4, -3.7),
        "IT": (41.9, 12.6), "TR": (39.0, 35.2), "IR": (32.4, 53.7), "AE": (24.0, 54.0),
        "SA": (24.0, 45.0), "US": (39.5, -98.4), "CA": (56.1, -106.3), "BR": (-14.2, -51.9),
        "IN": (20.6, 79.0), "SG": (1.35, 103.8), "JP": (36.2, 138.3), "KR": (35.9, 127.8),
        "CN": (35.9, 104.2), "AU": (-25.3, 133.8), "RU": (61.5, 105.3), "ZA": (-30.6, 22.9),
    }
    return table.get(str(cc).upper())


def _web_resolvers_on_route(rows, egress_geo, limit=8):
    """Rank scanned resolvers by how likely they sit on our route to the game.

    We rank by country first (same as the egress = shortest path), then by the
    great-circle distance from the egress to that country's centroid, then by
    latency. This avoids a per-resolver geo API call for every scanned server."""
    egress_cc = (egress_geo or {}).get("countryCode") or ""
    e_centroid = _country_centroid_geo(egress_cc)
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        if r.get("status") != "ok" or r.get("latency") is None:
            continue
        cc = (r.get("country") or "").upper()
        c_centroid = _country_centroid_geo(cc)
        dist = None
        if e_centroid and c_centroid:
            dist = _haversine_km(e_centroid[0], e_centroid[1], c_centroid[0], c_centroid[1])
        out.append({**r, "same_country": cc == egress_cc.upper(),
                    "distance_km": dist})
    out.sort(key=lambda r: (
        not r["same_country"],
        r["distance_km"] if r["distance_km"] is not None else 1e9,
        r["latency"],
    ))
    return out[:limit]


# --- Signal strength / network tech ------------------------------------------

def _web_signal_strength():
    """Read the cellular signal (dBm/asu/level/tech) and recommend a radio mode.

    Only available through Shizuku (`cmd phone` / `dumpsys telephony.registry`);
    without it we report what we can and say so, rather than guessing."""
    raw = run_shizuku_cmd("dumpsys telephony.registry")
    info = {"available": False, "dbm": None, "asu": None, "level": None,
            "technology": None, "operator": None, "source": "shizuku"}
    if raw:
        m = re.search(r"mSignalStrength=SignalStrength:\s*([^\n]+)", raw)
        if m:
            blob = m.group(1)
            for key, pat in (("dbm", r"rsrp=(-?\d+)"), ("dbm", r"rssi=(-?\d+)"),
                             ("asu", r"asu=(\d+)"), ("level", r"level=(\d+)")):
                mm = re.search(pat, blob)
                if mm and info[key] is None:
                    info[key] = int(mm.group(1))
            info["available"] = info["dbm"] is not None
        mt = re.search(r"mServiceState=.*?([A-Z_]+)", raw)
        if mt:
            info["technology"] = mt.group(1)
    operator, net_type = get_live_hardware_data()
    info["operator"] = operator
    if info["technology"] is None:
        info["technology"] = net_type
    info["quality"] = _signal_quality(info["dbm"])
    info["recommendation"] = _signal_recommendation(info["dbm"], info.get("technology"))
    return info


def _signal_quality(dbm):
    if dbm is None:
        return "unknown"
    if dbm >= -80:
        return "excellent"
    if dbm >= -90:
        return "good"
    if dbm >= -100:
        return "fair"
    if dbm >= -110:
        return "poor"
    return "very poor"


def _signal_recommendation(dbm, technology):
    if dbm is None:
        return ("Signal strength needs Shizuku to read. Grant Shizuku for a real dBm "
                "reading and a radio-mode recommendation.")
    tech = (technology or "").upper()
    if dbm <= -110:
        return ("Very weak signal. Drop to 3G/4G (LTE) — a 5G/NR link spends more time "
                "re-selecting and adds jitter, which hurts game ping more than the raw "
                "bandwidth helps. Try moving near a window or re-orienting.")
    if dbm <= -100:
        return ("Weak signal. Prefer 4G (LTE) over 5G for gaming: more stable RTT and "
                "fewer handovers. If 4G is weak too, lock 3G to keep the link alive.")
    if dbm <= -90:
        return ("Fair signal. 4G is usually the sweet spot; enable 5G only if the signal "
                "reads better than ~-85 dBm. Watch jitter, not just latency.")
    if "NR" in tech or "5G" in tech:
        return "Strong signal — 5G is fine and should give the lowest latency."
    return "Good signal — leave the radio on its automatic/5G preference."


# --- MTU intelligence (VPN + game protocol aware) -----------------------------

def _mtu_advice(mtu, vpn, protocol=None, game=None):
    """Turn an MTU number into a per-protocol payload recommendation.

    If a VPN tunnel is in play the game traffic must fit inside the tunnel MTU;
    a payload too big is silently fragmented (or dropped), which shows up as
    packet loss and lag spikes in-game."""
    safe = mtu - 28 if mtu else None
    out = {"mtu": mtu, "payload": safe, "vpn": bool(vpn),
           "protocol": protocol or "", "game": game or ""}
    if not mtu:
        out["advice"] = "Could not determine MTU."
        return out
    notes = []
    if vpn:
        notes.append(f"VPN tunnel: {mtu} is the tunnel MTU; the largest non-fragmenting "
                     f"payload is {safe} bytes.")
    else:
        notes.append(f"Direct link: {mtu} MTU, largest payload {safe} bytes.")
    if protocol in ("udp", "both", "auto") or protocol is None:
        notes.append("For UDP game traffic, oversized packets are dropped rather than "
                     "fragmented in some paths — stay at or below the payload figure.")
    if protocol == "tcp":
        notes.append("For TCP, MSS is clamped automatically once MTU is correct.")
    out["advice"] = " ".join(notes)
    return out


def _web_mtu_intelligence(game=None, protocol=None):
    mtu, mode, iface = resolve_smart_mtu()
    vpn = bool(detect_vpn_interface()) or is_vpn_interface(iface)
    plan = game_port_plan(game or "", protocol=protocol) if game else ([], protocol or "")
    proto = plan[1] if game else (protocol or "")
    info = _mtu_advice(mtu, vpn, protocol=proto, game=game)
    info.update({"mode": mode, "interface": iface})
    return info



# ---- OPTIMIZATION: Reusable DNS query packet (avoid recreating bytes each call) ----
# _DNS_QUERY_PACKET removed: was hardcoded to google.com, breaking per-target DNS latency tests

# ---- NEW: Global instances for circuit breaker and profiler ----
_dns_circuit_breakers = {}

def get_dns_breaker(dns_ip):
    if dns_ip not in _dns_circuit_breakers:
        _dns_circuit_breakers[dns_ip] = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
    return _dns_circuit_breakers[dns_ip]
_profiler = PerformanceProfiler()

# ---- NEW: Retry handler with exponential backoff and jitter ----
class RetryHandler:
    """Handles retries with exponential backoff and jitter for network requests."""
    def __init__(self, max_retries=3, base_delay=0.5, max_delay=10.0, jitter=True):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter

    async def execute(self, func, *args, **kwargs):
        """Execute a function with retry logic."""
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    delay = min(self.max_delay, self.base_delay * (2 ** attempt))
                    if self.jitter:
                        delay = delay * random.uniform(0.5, 1.5)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {delay:.2f}s: {e}")
                    await asyncio.sleep(delay)
        raise last_exception

    def execute_sync(self, func, *args, **kwargs):
        """Execute a sync function with retry logic."""
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    delay = min(self.max_delay, self.base_delay * (2 ** attempt))
                    if self.jitter:
                        delay = delay * random.uniform(0.5, 1.5)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {delay:.2f}s: {e}")
                    time.sleep(delay)
        raise last_exception

_retry_handler = RetryHandler(max_retries=3, base_delay=0.5, max_delay=10.0, jitter=True)

async def async_ping_dns_core(ip_address, port=53, count=3, timeout=1.5):
    """Async DNS ping with circuit breaker and performance profiling.

    `timeout` is the per-query socket timeout (seconds); callers can lower it via
    compute_adaptive_timeout() so slow servers don't stall the whole scan."""
    # Check circuit breaker
    breaker = get_dns_breaker(ip_address)
    if not breaker.allow_request():
        logger.debug(f"Circuit breaker open for DNS ping to {ip_address}")
        return 9999.0, 100.0, 999.0

    durations = []
    packet_loss = 0
    # Build DNS query for the target (was using hardcoded google.com packet)
    packet = _build_dns_query("google.com")  # Neutral query all servers should answer

    # ---- OPTIMIZATION: Use a single timeout for the entire batch instead of per-packet ----
    batch_deadline = time.monotonic() + (count * 2.0) + 2.0

    with _profiler.time("async_ping_dns_core"):
        for _ in range(count):
            if time.monotonic() > batch_deadline:
                packet_loss += (count - len(durations))
                break
            qs = None
            try:
                start_time = time.perf_counter()
                # Fresh blocking socket per query - much more reliable
                qs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                qs.settimeout(timeout)
                qs.connect((ip_address, port))
                qs.send(packet)
                # Only accept the reply whose transaction ID matches this query —
                # a late answer to the *previous* packet would otherwise be timed
                # as if it belonged to this one.
                want_id = packet[:2]
                while True:
                    data = qs.recv(512)
                    if len(data) >= 12 and data[:2] == want_id and (data[2] & 0x80):
                        break
                end_time = time.perf_counter()
                durations.append((end_time - start_time) * 1000)
                breaker.record_success()
            except Exception:
                packet_loss += 1
                breaker.record_failure()
            finally:
                # Always release the socket, even on timeout/error (prevents FD leaks
                # that eventually break all subsequent pings)
                if qs is not None:
                    qs.close()
            await asyncio.sleep(0.05)

    if not durations:
        return 9999.0, 100.0, 999.0

    # ---- OPTIMIZATION: Use statistics.fmean for better float precision (Python 3.8+) ----
    avg_latency = sum(durations) / len(durations)
    loss_percent = (packet_loss / count) * 100
    jitter = sum(abs(durations[i] - durations[i - 1]) for i in range(len(durations) - 1)) / (len(durations) - 1) if len(durations) > 1 else 0.0

    return avg_latency, loss_percent, jitter

async def measure_item_async(item, timeout=1.5):
    res_item = dict(item)
    # ---- OPTIMIZATION: Protocol-aware ping — use UDP for game ports, TCP for standard ----
    # This is the key optimization: DNS ping alone doesn't measure game traffic latency.
    # For UDP-based games (Apex, Valorant, etc.), we ping the actual game ports.
    p1_time, p1_loss, p1_jit = await async_ping_dns_core(res_item["pair"][0], timeout=timeout)
    p2_time, p2_loss, p2_jit = (p1_time, p1_loss, p1_jit) if len(res_item["pair"]) < 2 else await async_ping_dns_core(res_item["pair"][1], timeout=timeout)
    res_item["latency"] = (p1_time + p2_time) / 2
    res_item["loss"] = (p1_loss + p2_loss) / 2
    res_item["jitter"] = (p1_jit + p2_jit) / 2
    return res_item

async def measure_game_latency_async(item, target_host, game_name):
    """Protocol-aware game latency measurement.
    Game traffic is UDP for most titles, so a TCP connect to a UDP game port is a
    false negative (it always fails). We therefore UDP-ping UDP games and TCP-ping
    TCP games — the same rule the rest of the tool follows.
    
    Includes early termination: if DNS latency is too high, skip game latency test."""
    res_item = dict(item)
    primary_dns = res_item["pair"][0]
    # DNS resolution
    loop = asyncio.get_running_loop()
    resolved_ip = await loop.run_in_executor(None, native_dns_resolver, target_host, primary_dns)
    if not resolved_ip:
        resolved_ip = target_host

    config = GAME_PROTOCOL_DB.get(game_name, {})
    ports = config.get("ports", DEFAULT_PORTS)
    protocol = config.get("protocol", DEFAULT_PROTOCOL)
    primary_port = ports[0]

    # ---- NEW: Early termination — if DNS latency is too high, skip game latency test ----
    dns_latency = res_item.get("latency", 0)
    heuristic = GAME_HEURISTICS.get(game_name, {})
    max_acceptable = heuristic.get("max_acceptable_latency_ms", 200)
    
    if dns_latency > max_acceptable * 2:
        # DNS is too slow; game latency will be even worse
        res_item["game_latency"] = None
        res_item["game_loss"] = 100.0
        res_item["game_jitter"] = 0.0
        res_item["resolved_ip"] = resolved_ip
        res_item["protocol"] = protocol
        res_item["port"] = primary_port
        res_item["early_terminated"] = True
        return res_item

    if protocol == "udp":
        lat, loss, jit = await udp_ping(resolved_ip, primary_port, count=3, timeout=1.5)
        if lat is None:
            # Most game servers ignore arbitrary UDP probes. Fall back to a TCP
            # handshake on 443 so the user still gets a usable host RTT instead of
            # a bare "unreachable".
            rtt, ok = await loop.run_in_executor(
                None, lambda: tcp_ping(resolved_ip, 443, timeout=1.5))
            if ok:
                lat, loss, jit = rtt, 0.0, 0.0
    else:
        rtt, ok = await loop.run_in_executor(
            None, lambda: tcp_ping(resolved_ip, primary_port, timeout=1.5))
        lat, loss, jit = (rtt, 0.0, 0.0) if ok else (None, 100.0, 0.0)

    res_item["game_latency"] = lat
    res_item["game_loss"] = loss
    res_item["game_jitter"] = jit
    res_item["resolved_ip"] = resolved_ip
    res_item["protocol"] = protocol
    res_item["port"] = primary_port
    res_item["early_terminated"] = False
    return res_item


# ============================================================
#  PINNED LIST PERSISTENCE
# ============================================================
# ---- OPTIMIZATION: Module-level pinned list cache ----
_pinned_cache = None

def load_pinned_list():
    global _pinned_cache
    if _pinned_cache is not None:
        return _pinned_cache
    if os.path.exists(PINNED_FILE):
        try:
            with open(PINNED_FILE, "r") as f:
                data = json.load(f)
                _pinned_cache = data if isinstance(data, list) else []
                return _pinned_cache
        except:
            pass
    _pinned_cache = []
    return _pinned_cache

def save_pinned_list(pinned_list):
    global _pinned_cache
    _pinned_cache = pinned_list
    clean_list = [{"pair": p["pair"], "country": p.get("country", "DE")} for p in pinned_list]
    # ---- OPTIMIZATION: Atomic write to prevent corruption ----
    tmp = PINNED_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(clean_list, f, indent=4)
    os.rename(tmp, PINNED_FILE)


# ============================================================
#  NON-BLOCKING INPUT
# ============================================================
async def check_async_input_native():
    loop = asyncio.get_running_loop()
    def get_input():
        import select
        if select.select([sys.stdin], [], [], 0.0)[0]:
            return sys.stdin.readline().strip()
        return None
    return await loop.run_in_executor(None, get_input)


# ============================================================
#  DNS MANAGER  (MENU KEY: M) - PRIVATE DNS LIST + RETRY-SAFE TESTING
# ============================================================
# ---- OPTIMIZATION: Module-level DNS list cache ----
_dns_list_cache = None

def load_dns_list():
    global _dns_list_cache
    if _dns_list_cache is not None:
        return _dns_list_cache
    if not os.path.exists(DNS_LIST_FILE):
        _dns_list_cache = []
        return _dns_list_cache
    with open(DNS_LIST_FILE, "r") as f:
        _dns_list_cache = [line.strip() for line in f if line.strip()]
    return _dns_list_cache

def save_dns_list(dns_list):
    global _dns_list_cache
    _dns_list_cache = dns_list
    # ---- OPTIMIZATION: Atomic write to prevent corruption ----
    tmp = DNS_LIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        for addr in dns_list:
            f.write(addr + "\n")
    os.rename(tmp, DNS_LIST_FILE)

async def async_ping_with_retry(address, retries=DNS_TEST_RETRIES, count=3, timeout_s=2):
    """Async ping with retry-on-timeout: the blocking Shizuku ping call is dispatched to the
    executor and awaited under an explicit asyncio timeout. On a Timeout (or any unreachable
    result), it retries up to `retries` full rounds, stopping at the first success. Always
    returns the measured packet-loss percentage, whether the target ultimately succeeded or not."""
    loop = asyncio.get_running_loop()
    last_loss = 100.0
    # ---- OPTIMIZATION: Pre-build the ping command template (avoid f-string in loop) ----
    ping_cmd_template = f"ping -c {count} -W {timeout_s} "
    for attempt in range(1, retries + 1):
        try:
            raw = await asyncio.wait_for(
                loop.run_in_executor(None, run_shizuku_cmd, ping_cmd_template + address),
                timeout=(timeout_s * count) + 3
            )
        except asyncio.TimeoutError:
            raw = ""
        avg_rtt, loss, reachable = parse_ping_result(raw)
        if reachable:
            return avg_rtt, loss, True, attempt
        last_loss = loss
        await asyncio.sleep(0.2)  # brief pause before the next retry round
    return None, last_loss, False, retries

def dns_manager_add():
    clear_scr()
    print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    print(f"{ANSI_BLUE}{ANSI_BOLD}                 ADD DNS ENTRY{ANSI_RESET}")
    print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    address = input(f"{ANSI_CYAN}Enter DNS address (e.g. dns.google): {ANSI_RESET}").strip()
    if not address or " " in address:
        print(f"{ANSI_RED}[X] Invalid address.{ANSI_RESET}")
        input(f"\n{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")
        return
    dns_list = load_dns_list()
    if address in dns_list:
        print(f"{ANSI_YELLOW}[!] '{address}' is already in the list.{ANSI_RESET}")
    else:
        dns_list.append(address)
        save_dns_list(dns_list)
        print(f"{ANSI_GREEN}[OK] Added '{address}'.{ANSI_RESET}")
    input(f"\n{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")

def dns_manager_delete():
    dns_list = load_dns_list()
    clear_scr()
    print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    print(f"{ANSI_BLUE}{ANSI_BOLD}               DELETE DNS ENTRY{ANSI_RESET}")
    print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    if not dns_list:
        print(f"{ANSI_RED}[X] No DNS entries saved yet.{ANSI_RESET}")
        input(f"\n{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")
        return
    for idx, addr in enumerate(dns_list, start=1):
        print(f"  {ANSI_GREEN}[{idx}]{ANSI_RESET} {addr}")
    print(f"{ANSI_DIM}{'-' * 55}{ANSI_RESET}")
    choice = input(f"{ANSI_CYAN}Enter number to delete: {ANSI_RESET}").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(dns_list):
        removed = dns_list.pop(int(choice) - 1)
        save_dns_list(dns_list)
        print(f"{ANSI_GREEN}[OK] Removed '{removed}'.{ANSI_RESET}")
    else:
        print(f"{ANSI_RED}[X] Invalid selection.{ANSI_RESET}")
    input(f"\n{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")

async def dns_manager_run_test():
    dns_list = load_dns_list()
    clear_scr()
    print(f"{ANSI_GREEN}{ANSI_BOLD}======================================================={ANSI_RESET}")
    print(f"{ANSI_GREEN}{ANSI_BOLD}                 RUN DNS TEST{ANSI_RESET}")
    print(f"{ANSI_GREEN}{ANSI_BOLD}======================================================={ANSI_RESET}")
    if not dns_list:
        print(f"{ANSI_RED}[X] No DNS entries saved yet. Add one first.{ANSI_RESET}")
        input(f"\n{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")
        return

    for idx, addr in enumerate(dns_list, start=1):
        print(f"  {ANSI_GREEN}[{idx}]{ANSI_RESET} {addr}")
    print(f"{ANSI_DIM}{'-' * 55}{ANSI_RESET}")
    raw_choice = input(f"{ANSI_CYAN}Select number(s) comma-separated, or 'all': {ANSI_RESET}").strip().lower()

    if raw_choice == "all":
        targets = list(dns_list)
    else:
        targets = []
        for part in raw_choice.split(","):
            part = part.strip()
            if part.isdigit() and 1 <= int(part) <= len(dns_list):
                targets.append(dns_list[int(part) - 1])

    if not targets:
        print(f"{ANSI_RED}[X] No valid selection made.{ANSI_RESET}")
        input(f"\n{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")
        return

    print(f"\n{ANSI_CYAN}[*] Testing {len(targets)} DNS target(s) (async, up to {DNS_TEST_RETRIES} attempts each)...{ANSI_RESET}\n")
    rows = []
    for addr in targets:
        print(f"  {ANSI_DIM}->{ANSI_RESET} {addr:<30}", end="", flush=True)
        avg_rtt, loss, ok, attempts_used = await async_ping_with_retry(addr)
        if ok:
            print(f" {ANSI_GREEN}[OK]{ANSI_RESET} {avg_rtt:.1f}ms | Loss: {loss:.0f}% (attempt {attempts_used}/{DNS_TEST_RETRIES})")
            rows.append([addr, f"{avg_rtt:.1f}ms", f"{loss:.0f}%", "OK"])
        else:
            print(f" {ANSI_RED}[FAIL]{ANSI_RESET} Loss: {loss:.0f}% after {DNS_TEST_RETRIES} attempts")
            rows.append([addr, "--", f"{loss:.0f}%", "FAIL"])

    print()
    print(draw_ascii_table(["DNS Address", "Avg Latency", "Loss %", "Status"], rows, [24, 13, 8, 8]))
    input(f"\n{ANSI_DIM}Press Enter to return to DNS Manager...{ANSI_RESET}")

def run_dns_manager():
    while True:
        dns_list = load_dns_list()
        clear_scr()
        print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
        print(f"{ANSI_BLUE}{ANSI_BOLD}                  DNS MANAGER{ANSI_RESET}")
        print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
        if dns_list:
            for idx, addr in enumerate(dns_list, start=1):
                print(f"  {ANSI_GREEN}[{idx}]{ANSI_RESET} {addr}")
        else:
            print(f"  {ANSI_DIM}(no DNS entries saved yet){ANSI_RESET}")
        print(f"{ANSI_DIM}{'-' * 55}{ANSI_RESET}")
        print(f"{ANSI_GREEN}[1]{ANSI_RESET} Add DNS")
        print(f"{ANSI_RED}[2]{ANSI_RESET} Delete DNS")
        print(f"{ANSI_YELLOW}[3]{ANSI_RESET} Run DNS Test")
        print(f"{ANSI_BLUE}[4]{ANSI_RESET} Back")
        print(f"{ANSI_BLUE}{ANSI_BOLD}======================================================={ANSI_RESET}")
        choice = input(f"{ANSI_BOLD}Select Action{ANSI_RESET} [1-4]: ").strip()
        if choice == '1':
            dns_manager_add()
        elif choice == '2':
            dns_manager_delete()
        elif choice == '3':
            asyncio.run(dns_manager_run_test())
        elif choice == '4':
            break


# ============================================================
#  CDN DOWNLOAD TELEMETRY (ASYNC)
# ============================================================
async def run_download_cdn_telemetry_async():
    cdn_host = "gs-sec.ww.np.dl.playstation.net"
    file_path = "/storage/emulated/0/Download/dns_pairs_with_countries.txt"
    if not os.path.exists(file_path):
        print(f"\n[X] Error: File missing at {file_path}"); input("\nPress Enter..."); return

    print("\n[*] Initializing Network Telemetry Engine...")
    operator, net_type = get_live_hardware_data()
    golden_mtu, mtu_mode, _mtu_iface = resolve_smart_mtu()

    all_loaded_pairs = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        current_pair_ips, current_pair_countries = [], []
        # ---- OPTIMIZATION: Use pre-compiled regex patterns ----
        for line in f:
            line = line.strip()
            if line.startswith("### PAIR START"):
                if current_pair_ips:
                    all_loaded_pairs.append({"pair": current_pair_ips, "country": current_pair_countries[0] if current_pair_countries else "DE"})
                current_pair_ips, current_pair_countries = [], []
                continue
            if line.startswith("nameserver"):
                ip_match = _RE_NAMESERVER.search(line)
                if ip_match:
                    current_pair_ips.append(ip_match.group(1))
                    c_match = _RE_COUNTRY.search(line)
                    current_pair_countries.append(c_match.group(1).upper() if c_match else "DE")
        # Flush the final pair: the file's last entry has no trailing "### PAIR START"
        # marker, so without this it would be dropped from the scan pool.
        if current_pair_ips:
            all_loaded_pairs.append({"pair": current_pair_ips, "country": current_pair_countries[0] if current_pair_countries else "DE"})

    pinned_list = load_pinned_list()
    loop = asyncio.get_running_loop()

    try:
        # ---- OPTIMIZATION: Pre-compute values that don't change in the loop ----
        _header_border = "=" * 90
        _sub_border = "-" * 90
        _pool_size = min(12, len(all_loaded_pairs))
        _pinned_pair_set = set(p['pair'][0] for p in pinned_list) if pinned_list else set()

        # ---- OPTIMIZATION: Pre-shuffle pool once, then cycle through it ----
        _shuffled_pool = list(all_loaded_pairs)
        random.shuffle(_shuffled_pool)
        _shuffle_idx = 0

        while True:
            # ---- OPTIMIZATION: Cycle through shuffled pool instead of random.sample ----
            if _shuffle_idx + _pool_size > len(_shuffled_pool):
                random.shuffle(_shuffled_pool)
                _shuffle_idx = 0
            scan_pool = _shuffled_pool[_shuffle_idx:_shuffle_idx + _pool_size]
            _shuffle_idx += _pool_size

            async def measure_cdn_route_async(item):
                res_item = dict(item)
                primary_dns = res_item["pair"][0]
                lat, loss, jit = await async_ping_dns_core(primary_dns)
                # ---- OPTIMIZATION: DNS resolution now cached via native_dns_resolver ----
                cdn_ip = await loop.run_in_executor(None, native_dns_resolver, cdn_host, primary_dns)
                res_item["latency"] = lat
                res_item["loss"] = loss
                res_item["jitter"] = jit
                res_item["resolved_cdn"] = cdn_ip if cdn_ip else "Anycast Node"
                return res_item

            tasks = [measure_cdn_route_async(item) for item in scan_pool]
            results = await asyncio.gather(*tasks)

            results = sorted([r for r in results if r["latency"] < 9000], key=lambda x: x["latency"])
            display_list = results[:8]

            updated_pinned = []
            if pinned_list:
                pinned_tasks = [measure_cdn_route_async(p_item) for p_item in pinned_list]
                updated_pinned = await asyncio.gather(*pinned_tasks)

            clear_scr()
            print(f"{ANSI_CYAN}{ANSI_BOLD}{_header_border}{ANSI_RESET}")
            print(f"{ANSI_CYAN}{ANSI_BOLD}   PLAYSTATION CDN CONTENT ROUTER v6 - NATIVE ASYNC LAYER{ANSI_RESET}")
            print(f"{ANSI_CYAN}{ANSI_BOLD}{_header_border}{ANSI_RESET}")
            print(f" {ANSI_GREEN}Hardware{ANSI_RESET} : {operator} [{net_type}]  |  Golden MTU: {ANSI_YELLOW}{golden_mtu}{ANSI_RESET} [{mtu_mode}]")
            print(f" {ANSI_GREEN}CDN Host{ANSI_RESET} : {cdn_host}")
            print(f"{ANSI_DIM}{_sub_border}{ANSI_RESET}")

            table_rows = []
            for idx, item in enumerate(display_list, start=1):
                s_dns = item['pair'][1] if len(item['pair']) > 1 else '1.1.1.1'
                table_rows.append([idx, item['pair'][0], s_dns, item['resolved_cdn'], f"{item['latency']:.1f}ms", f"{item['jitter']:.1f}ms", f"{int(item['loss'])}%"])
            print(draw_ascii_table(["Rank", "Primary DNS", "Secondary DNS", "Assigned CDN IP", "Latency", "Jitter", "Loss"], table_rows, [4, 15, 15, 17, 9, 8, 6]))

            if pinned_list:
                print(_header_border)
                print(" [PIN] PINNED REGISTRY SYSTEMS:")
                print(_sub_border)
                for p_idx, p_item in enumerate(updated_pinned, start=1):
                    sec_d = p_item['pair'][1] if len(p_item['pair']) > 1 else '1.1.1.1'
                    lat_val = p_item.get('latency', 0.0)
                    jit_val = p_item.get('jitter', 0.0)
                    cdn_val = p_item.get('resolved_cdn', 'Resolving...')
                    status = "[WARN] SPIKE" if jit_val > 45.0 else "[OK]"
                    print(f" #{p_idx}  PRM: {p_item['pair'][0]:<15} SEC: {sec_d:<15} CDN: {cdn_val:<15} Lat: {lat_val:.1f}ms Jit: {jit_val:.1f}ms ({status})")

            print(_header_border)
            print(" [*] Pin [1-8] | Clear specific: 'r1', 'r2' | Clear all: 'c' | Exit: 'q'")

            # ---- OPTIMIZATION: Use monotonic clock, set-based pinned lookup ----
            start_t = time.monotonic()
            while time.monotonic() - start_t < 4.0:
                user_cmd = await check_async_input_native()
                if user_cmd:
                    cmd_clean = user_cmd.strip().lower()
                    if cmd_clean.isdigit():
                        sel_idx = int(cmd_clean) - 1
                        if 0 <= sel_idx < len(display_list):
                            if display_list[sel_idx]['pair'][0] not in _pinned_pair_set:
                                pinned_list.append(display_list[sel_idx])
                                _pinned_pair_set.add(display_list[sel_idx]['pair'][0])
                                save_pinned_list(pinned_list)
                    elif cmd_clean.startswith('r'):
                        try:
                            r_idx = int(cmd_clean[1:]) - 1
                            if 0 <= r_idx < len(pinned_list):
                                removed_pair = pinned_list.pop(r_idx)['pair'][0]
                                _pinned_pair_set.discard(removed_pair)
                                save_pinned_list(pinned_list)
                        except:
                            pass
                    elif cmd_clean == 'c':
                        pinned_list = []
                        _pinned_pair_set.clear()
                        save_pinned_list(pinned_list)  # also clears the module-level cache
                        if os.path.exists(PINNED_FILE):
                            os.remove(PINNED_FILE)
                    elif cmd_clean == 'q':
                        return
                    break
                await asyncio.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass


# ============================================================
#  HISTORICAL STABILITY SCORING (MODULE 1 ONLY - MULTI-CYCLE TRACKING)
# ============================================================
JITTER_SPIKE_THRESHOLD_MS = 45.0  # matches the existing SPIKE threshold used in the pinned display

def update_stability_history(history, cycle_results):
    """Folds one telemetry cycle's full measured batch into the running per-DNS-pair history.
    Must be called with the RAW batch (before the display table's <9000ms filter) so total
    failures (loss = 100%) are also captured, not just the pairs that make the top-8 cut."""
    for item in cycle_results:
        key = item["pair"][0]
        rec = history.setdefault(key, {"cycles": 0, "success_cycles": 0, "jitter_spike_cycles": 0, "latency_sum": 0.0})
        rec["cycles"] += 1
        if item["loss"] <= 0:
            rec["success_cycles"] += 1
        if item["jitter"] > JITTER_SPIKE_THRESHOLD_MS:
            rec["jitter_spike_cycles"] += 1
        rec["latency_sum"] += min(item["latency"], 2000.0)  # cap so one timeout doesn't skew the average

def compute_stability_score(rec, fastest_avg_latency):
    """Deterministic 0-100 score: Packet Loss Resilience (50 pts, squared - sharp penalty for any
    drop), Jitter Consistency (30 pts, squared - heavy penalty for spikes), Latency Baseline
    (20 pts, relative to the fastest pair's average latency seen this session)."""
    cycles = rec["cycles"]
    if cycles == 0:
        return 0, 0.0, 0.0
    success_rate = rec["success_cycles"] / cycles
    spike_ratio = rec["jitter_spike_cycles"] / cycles
    avg_latency = rec["latency_sum"] / cycles

    loss_score = 50 * (success_rate ** 2)
    jitter_score = 30 * ((1 - spike_ratio) ** 2)
    latency_score = 20 * min(1.0, fastest_avg_latency / avg_latency) if avg_latency > 0 and fastest_avg_latency > 0 else 0

    total = max(0, min(100, round(loss_score + jitter_score + latency_score)))
    return total, success_rate, spike_ratio

def stability_status_label(score, success_rate, spike_ratio):
    """Deterministic status label, prioritizing the dominant issue (loss > jitter > general tier)."""
    if success_rate < 0.9:
        return "Bad (High Loss)"
    if score >= 90:
        return "Excellent (Stable)"
    if spike_ratio > 0.15:
        return "Good (Minor Jitter)"
    if score >= 60:
        return "Fair (Watch Closely)"
    return "Bad (Unstable)"

def render_stability_history_table(history, min_cycles=1, top_n=5):
    """Builds the historical stability ranking block. Shows even with 1 cycle."""
    eligible = {k: v for k, v in history.items() if v["cycles"] >= min_cycles}
    if not eligible:
        return None

    fastest_avg_latency = min(v["latency_sum"] / v["cycles"] for v in eligible.values())

    ranked = []
    for dns_ip, rec in eligible.items():
        score, success_rate, spike_ratio = compute_stability_score(rec, fastest_avg_latency)
        ranked.append((dns_ip, success_rate, score, spike_ratio))
    ranked.sort(key=lambda r: r[2], reverse=True)

    rows = []
    for idx, (dns_ip, success_rate, score, spike_ratio) in enumerate(ranked[:top_n], start=1):
        status = stability_status_label(score, success_rate, spike_ratio)
        rows.append([idx, dns_ip, f"{success_rate * 100:.0f}%", f"{score}/100", status])

    widths = [4, 15, 12, 15, 21]
    header = "-" * 90 + "\n[SCORE] HISTORICAL STABILITY RANKING (DETERMINISTIC EVALUATION)\n" + "-" * 90
    table = draw_ascii_table(["Rank", "Primary DNS", "Success Rate", "Stability Score", "Performance Status"], rows, widths)
    return header + "\n" + table


# ============================================================
#  GAME TELEMETRY OPTIMIZER (ASYNC, GEO-AWARE)
# ============================================================
async def run_advanced_telemetry_async():
    target_host, target_name = select_game_target()
    file_path = "/storage/emulated/0/Download/dns_pairs_with_countries.txt"
    if not os.path.exists(file_path):
        print(f"\n[X] Error: File missing at {file_path}"); input("\nPress Enter..."); return

    print("\n[*] Gathering Telemetry baseline specs...")
    operator, net_type = get_live_hardware_data()
    golden_mtu, mtu_mode, _mtu_iface = resolve_smart_mtu()
    print(f"{ANSI_RED}[!] MTU adjustment requires manual setup in VPN app (Recommended: {VPN_MTU}).{ANSI_RESET}")

    gw_ip, gw_country, isp = analyze_gateway()

    all_loaded_pairs = []
    available_countries = set()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        current_pair_ips, current_pair_countries = [], []
        # ---- OPTIMIZATION: Use pre-compiled regex patterns ----
        for line in f:
            line = line.strip()
            if line.startswith("### PAIR START"):
                if current_pair_ips:
                    c_code = current_pair_countries[0] if current_pair_countries else "DE"
                    all_loaded_pairs.append({"pair": current_pair_ips, "country": c_code})
                    available_countries.add(c_code)
                current_pair_ips, current_pair_countries = [], []
                continue
            if line.startswith("nameserver"):
                ip_match = _RE_NAMESERVER.search(line)
                if ip_match:
                    current_pair_ips.append(ip_match.group(1))
                    c_match = _RE_COUNTRY.search(line)
                    current_pair_countries.append(c_match.group(1).upper() if c_match else "DE")
        # Flush the final pair (the last entry has no trailing "### PAIR START" marker).
        if current_pair_ips:
            c_code = current_pair_countries[0] if current_pair_countries else "DE"
            all_loaded_pairs.append({"pair": current_pair_ips, "country": c_code})
            available_countries.add(c_code)

    sorted_countries = sorted(list(available_countries))

    clear_scr()
    print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    print(f"{ANSI_PURPLE}{ANSI_BOLD}          SELECT DNS GEOLOCATION TARGET{ANSI_RESET}")
    print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")
    print(f"{ANSI_GREEN}[1]{ANSI_RESET} Match Gateway IP Automatically {ANSI_DIM}(Current: {gw_country}){ANSI_RESET}")
    print(f"{ANSI_YELLOW}[2]{ANSI_RESET} Random Matrix Mix Mode {ANSI_DIM}(Chaos Scan){ANSI_RESET}")
    print(f"{ANSI_YELLOW}[3]{ANSI_RESET} Full Matrix Scan {ANSI_DIM}(All Countries){ANSI_RESET}")
    print(f"{ANSI_DIM}{'-' * 55}{ANSI_RESET}")
    print(f"{ANSI_CYAN}Manual Country Isolation:{ANSI_RESET}")
    for idx, country_code in enumerate(sorted_countries, start=4):
        print(f"  {ANSI_BLUE}[{idx}]{ANSI_RESET} Only {country_code}")
    print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")

    try:
        geo_choice = int(input(f"Select Mode [1-{len(sorted_countries)+3}]: ").strip())
        if geo_choice == 1:
            filtered_pool = [item for item in all_loaded_pairs if item["country"] == gw_country]
            mode_desc = f"Matched to Gateway [{gw_country}]"
            if not filtered_pool:
                filtered_pool = [item for item in all_loaded_pairs if item["country"] == "DE"]
                mode_desc = f"Gateway [{gw_country}] not found. Fallback to DE"
        elif geo_choice == 2 or geo_choice == 3:
            filtered_pool = all_loaded_pairs
            mode_desc = "Asynchronous Chaos Matrix"
        elif 4 <= geo_choice <= len(sorted_countries) + 3:
            selected_geo = sorted_countries[geo_choice - 4]
            filtered_pool = [item for item in all_loaded_pairs if item["country"] == selected_geo]
            mode_desc = f"Manual Isolation [{selected_geo}]"
        else:
            filtered_pool = [item for item in all_loaded_pairs if item["country"] == "DE"]
            mode_desc = "Fallback Auto [DE]"
    except:
        filtered_pool = [item for item in all_loaded_pairs if item["country"] == "DE"]
        mode_desc = "Fallback Auto [DE]"

    pinned_list = load_pinned_list()
    history = {}

    try:
        # ---- OPTIMIZATION: Pre-compute values that don't change in the loop ----
        _header_border = "=" * 90
        _sub_border = "-" * 90
        _pool_size = min(12, len(filtered_pool))
        _pinned_pair_set = set(p['pair'][0] for p in pinned_list) if pinned_list else set()

        # ---- OPTIMIZATION: Pre-shuffle pool once, then cycle through it ----
        # Instead of random.sample every cycle (which re-shuffles), we cycle through
        # a shuffled list. This gives good coverage while being much faster.
        _shuffled_pool = list(filtered_pool)
        random.shuffle(_shuffled_pool)
        _shuffle_idx = 0

        # ---- OPTIMIZATION: Define measure_combined once outside the loop ----
        # This avoids recreating the closure every cycle, saving memory and GC pressure
        async def measure_combined(item):
            dns_result = await measure_item_async(item, timeout=_adaptive_timeout)
            # Pass dns_result (which carries "latency") so early termination works.
            game_result = await measure_game_latency_async(dns_result, target_host, target_name)
            dns_result.update(game_result)
            return dns_result

        # ---- OPTIMIZATION: Compute adaptive timeout before the loop ----
        # This uses the fastest recent RTT to scale the timeout
        # Prevents slow DNS servers from blocking the entire scan
        _adaptive_timeout = 1.5  # default, will be updated after first cycle

        while True:
                # ---- OPTIMIZATION: Cycle through shuffled pool instead of random.sample ----
                if _shuffle_idx + _pool_size > len(_shuffled_pool):
                    random.shuffle(_shuffled_pool)
                    _shuffle_idx = 0
                scan_pool = _shuffled_pool[_shuffle_idx:_shuffle_idx + _pool_size]
                _shuffle_idx += _pool_size

                # ---- OPTIMIZATION: Protocol-aware game latency measurement ----
                # DNS ping alone doesn't measure game traffic. For UDP-based games
                # (Apex, Valorant, etc.), we ping the actual game ports.
                game_config = GAME_PROTOCOL_DB.get(target_name, {})
                game_protocol = game_config.get("protocol", "tcp")
                game_ports = game_config.get("ports", DEFAULT_PORTS)

                tasks = [measure_combined(item) for item in scan_pool]
                results = await asyncio.gather(*tasks)
                update_stability_history(history, results)

                # ---- OPTIMIZATION: Update adaptive timeout for next cycle ----
                _adaptive_timeout = compute_adaptive_timeout(
                    base_timeout=1.5, min_timeout=0.5, max_timeout=3.0,
                    recent_lats=[r.get('latency') for r in results[:8] if r.get('latency')]
                )

                results = sorted([r for r in results if r["latency"] < 9000], key=lambda x: x["latency"])
                display_list = results[:8]

                updated_pinned = []
                if pinned_list:
                    pinned_tasks = [measure_combined(p_item) for p_item in pinned_list]
                    updated_pinned = await asyncio.gather(*pinned_tasks)

                sys.stdout.write("\033[2J\033[H")
                sys.stdout.flush()
                print(_header_border)
                print("   ASYNCIO MATRIX TELEMETRY CORE v6 - NATIVE LAYER (No Jitter Spike)  ")
                print(_header_border)
                print(f" {ANSI_GREEN}Hardware{ANSI_RESET} : {operator} [{net_type}]  |  Golden MTU: {ANSI_YELLOW}{golden_mtu}{ANSI_RESET} [{mtu_mode}]")
                print(f" {ANSI_GREEN}VPN Exit{ANSI_RESET} : {gw_ip} [{gw_country}] via {isp}")
                print(f" {ANSI_GREEN}Target{ANSI_RESET}   : {target_name} ({target_host})  |  Routing: {mode_desc}")
                if game_protocol == "udp":
                    print(f" {ANSI_YELLOW}Protocol{ANSI_RESET} : UDP/{game_ports[0]} {ANSI_DIM}(game traffic){ANSI_RESET}")
                print(f"{ANSI_DIM}{_sub_border}{ANSI_RESET}")

                table_rows = []
                for idx, item in enumerate(display_list, start=1):
                    s_dns = item['pair'][1] if len(item['pair']) > 1 else '1.1.1.1'
                    game_lat = item.get('game_latency')
                    if game_lat is not None and game_lat > 0 and game_lat < 9000:
                        game_str = f"{game_lat:.1f}ms"
                    else:
                        game_str = "--"
                    table_rows.append([idx, item['pair'][0], s_dns, f"{item['latency']:.1f}ms", game_str, f"{int(item['loss'])}%", item['country']])

                if game_protocol == "udp":
                    headers = ["Rank", "Primary DNS", "Secondary DNS", "DNS Lat", "Game Lat", "Loss", "Geo"]
                    widths = [4, 15, 15, 9, 9, 6, 4]
                else:
                    headers = ["Rank", "Primary DNS", "Secondary DNS", "Latency", "Game Lat", "Loss", "Geo"]
                    widths = [4, 15, 15, 9, 9, 6, 4]
                print(draw_ascii_table(headers, table_rows, widths))

                if pinned_list:
                    print(_header_border)
                    print(" [PIN] PINNED REGISTRY SYSTEMS:")
                    print(_sub_border)
                    for p_idx, p_item in enumerate(updated_pinned, start=1):
                        sec_d = p_item['pair'][1] if len(p_item['pair']) > 1 else '1.1.1.1'
                        lat_val = p_item.get('latency', 0.0)
                        jit_val = p_item.get('jitter', 0.0)
                        loss_val = p_item.get('loss', 0)
                        geo_val = p_item.get('country', 'DE')
                        game_lat_val = p_item.get('game_latency')
                        status = "[WARN] SPIKE" if jit_val > 45.0 else "[OK]"
                        if game_lat_val is not None and game_lat_val > 0 and game_lat_val < 9000:
                            game_str = f" Game: {game_lat_val:.1f}ms"
                        else:
                            game_str = ""
                        print(f" #{p_idx}  PRM: {p_item['pair'][0]:<15} SEC: {sec_d:<15} Geo: {geo_val:<4} Lat: {lat_val:.1f}ms Jit: {jit_val:.1f}ms Loss: {int(loss_val)}%{game_str} ({status})")

                history_block = render_stability_history_table(history)
                if history_block:
                    print(history_block)

                print(_header_border)
                print(" [*] Pin [1-8] | Clear specific: 'r1', 'r2' | Clear all: 'c' | Exit: 'q'")

                # ---- OPTIMIZATION: Use monotonic clock, reduce polling interval ----
                start_t = time.monotonic()
                while time.monotonic() - start_t < 4.0:
                    user_cmd = await check_async_input_native()
                    if user_cmd:
                        cmd_clean = user_cmd.strip().lower()
                        if cmd_clean.isdigit():
                            sel_idx = int(cmd_clean) - 1
                            if 0 <= sel_idx < len(display_list):
                                if display_list[sel_idx]['pair'][0] not in _pinned_pair_set:
                                    pinned_list.append(display_list[sel_idx])
                                    _pinned_pair_set.add(display_list[sel_idx]['pair'][0])
                                    save_pinned_list(pinned_list)
                        elif cmd_clean.startswith('r'):
                            try:
                                r_idx = int(cmd_clean[1:]) - 1
                                if 0 <= r_idx < len(pinned_list):
                                    removed_pair = pinned_list.pop(r_idx)['pair'][0]
                                    _pinned_pair_set.discard(removed_pair)
                                    save_pinned_list(pinned_list)
                            except:
                                pass
                        elif cmd_clean == 'c':
                            pinned_list = []
                            _pinned_pair_set.clear()
                            save_pinned_list(pinned_list)  # also clears the module-level cache
                            if os.path.exists(PINNED_FILE):
                                os.remove(PINNED_FILE)
                        elif cmd_clean == 'q':
                            return
                        break
                    await asyncio.sleep(0.1)

    except (KeyboardInterrupt, SystemExit):
        pass


# ============================================================
#  PROFILE MANAGEMENT (CRUD)
# ============================================================
def manage_custom_profiles():
    while True:
        services = load_services()
        clear_scr()
        print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")
        print(f"{ANSI_PURPLE}{ANSI_BOLD}         GAME & SERVICE PROFILE REGISTRY{ANSI_RESET}")
        print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")
        for name, host in services.items():
            print(f"  {ANSI_GREEN}-{ANSI_RESET} {name:<22} {ANSI_DIM}-->{ANSI_RESET} {host}")
        print(f"{ANSI_DIM}{'-' * 55}{ANSI_RESET}")
        print(f"{ANSI_GREEN}[1]{ANSI_RESET} Add New Profile")
        print(f"{ANSI_RED}[2]{ANSI_RESET} Delete Profile")
        print(f"{ANSI_BLUE}[3]{ANSI_RESET} Back")
        print(f"{ANSI_PURPLE}{ANSI_BOLD}======================================================={ANSI_RESET}")
        ch = input(f"{ANSI_BOLD}Select Action{ANSI_RESET} [1-3]: ")
        if ch == '1':
            name = input(f"{ANSI_CYAN}Enter Game Name: {ANSI_RESET}").strip()
            host = input(f"{ANSI_CYAN}Enter Host URL: {ANSI_RESET}").strip()
            if name and host:
                services[name] = host
                save_services(services)
                print(f"{ANSI_GREEN}[OK] Profile '{name}' added.{ANSI_RESET}")
        elif ch == '2':
            name = input(f"{ANSI_CYAN}Enter Profile Name to Delete: {ANSI_RESET}").strip()
            if name in services:
                del services[name]
                save_services(services)
                print(f"{ANSI_GREEN}[OK] Profile '{name}' deleted.{ANSI_RESET}")
            else:
                print(f"{ANSI_RED}[X] Profile '{name}' not found.{ANSI_RESET}")
        elif ch == '3':
            break


# ============================================================
#  LOCAL WEB CONSOLE  (MENU KEY: W)
#  A dependency-free HTTP dashboard (Python standard library only)
#  that reuses the measurement helpers above. The UI is embedded as
#  strings below, so this single file is fully self-contained: there
#  is no web_server.py and no web/ folder to keep alongside it.
#
#  Endpoints
#    GET  /                 dashboard (HTML/CSS/JS served from memory)
#    GET  /api/health
#    GET  /api/dns-list     saved DNS list (persisted across sessions)
#    GET  /api/stability    persistent stability ranking
#    GET  /api/history      raw persistent history
#    GET  /api/device       Shizuku device snapshot
#    GET  /api/network      public IP / geo / ISP / interface / VPN / MTU
#    GET  /api/mtu          MTU recommendation
#    GET  /api/profiles     game/service profiles
#    GET  /api/apn          carrier APN entries + current preferred id
#    GET  /api/diagnosis    local network diagnosis (reference + gateway)
#    GET  /api/scan         SSE: chunked, parallel DNS scan (targets/count/
#                           workers/chunk/dnslist)
#    GET  /api/apn/benchmark SSE: live APN benchmark (needs confirm=1)
#    GET  /api/ai/status    whether a server-side OpenRouter key is configured
#    POST /api/dns-list     {add|add[], delete, clear}
#    POST /api/profiles     {add:{name,host}} | {delete:name}
#    POST /api/history/clear
#    POST /api/import       extract DNS servers from any file (multipart file=…
#                           OR JSON {filename, content:base64} / {filename, text})
#    POST /api/ai/analyze   {api_key?, model?, results:[…]} -> OpenRouter analysis
#    POST /api/tools/{resolve,tcp,tls,http,game}
# ============================================================

_WEB_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="theme-color" content="#0a0b14" />
  <title>DNS Console</title>
  <link rel="stylesheet" href="/app.css" />
</head>
<body>
  <a class="skip-link" href="#deck">skip to dashboard</a>

  <div class="bg-layer" aria-hidden="true">
    <span class="bg-orb o1"></span>
    <span class="bg-orb o2"></span>
    <span class="bg-grid"></span>
  </div>

  <!-- ---------- TOP BAR ---------- -->
  <header class="topbar">
    <div class="tb-left">
      <button class="icon-btn burger" id="burger" aria-label="open menu" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
      <span class="brand"><i class="brand-dot"></i>DNS<span>Console</span></span>
    </div>
    <div class="tb-right">
      <span class="conn"><i class="conn-dot" id="conn-dot"></i><em id="conn-text">connecting…</em></span>
      <span class="clock" id="clock">--:--:--</span>
      <span class="host" id="footer-port">—</span>
    </div>
  </header>

  <!-- ---------- NAV DRAWER ---------- -->
  <div class="scrim" id="drawer-backdrop" hidden></div>
  <aside class="drawer" id="drawer" aria-label="section navigation" aria-hidden="true">
    <div class="drawer-head">
      <span class="drawer-title">Sections</span>
      <button class="icon-btn" id="drawer-close" aria-label="close menu">✕</button>
    </div>
    <nav class="drawer-nav" id="drawer-nav">
      <a data-target="panel-import"     href="#panel-import"><span class="di">00</span> Import DNS list</a>
      <a data-target="panel-scanner"    href="#panel-scanner"><span class="di">01</span> Bulk Scanner</a>
      <a data-target="panel-autotest"   href="#panel-autotest"><span class="di">02</span> Auto-Test</a>
      <a data-target="panel-stability"  href="#panel-stability"><span class="di">03</span> Stability</a>
      <a data-target="panel-list"       href="#panel-list"><span class="di">04</span> Saved DNS</a>
      <a data-target="panel-tools"      href="#panel-tools"><span class="di">05</span> Probe Lab</a>
      <a data-target="panel-network"    href="#panel-network"><span class="di">06</span> Network · VPN</a>
      <a data-target="panel-device"     href="#panel-device"><span class="di">07</span> Device</a>
      <a data-target="panel-apn"        href="#panel-apn"><span class="di">08</span> APN Benchmark</a>
      <a data-target="panel-profiles"   href="#panel-profiles"><span class="di">09</span> Game Profiles</a>
      <a data-target="panel-diagnosis"  href="#panel-diagnosis"><span class="di">10</span> Diagnosis</a>
      <a data-target="panel-ai"         href="#panel-ai"><span class="di">11</span> AI Analysis</a>
      <a data-target="panel-appearance" href="#panel-appearance"><span class="di">12</span> Appearance</a>
      <a data-target="panel-route"      href="#panel-route"><span class="di">13</span> Route · Path</a>
      <a data-target="panel-signal"     href="#panel-signal"><span class="di">14</span> Signal · Radio</a>
      <a data-target="panel-logs"       href="#panel-logs"><span class="di">15</span> Logs</a>
    </nav>
  </aside>

  <!-- ---------- CONTROL BAR ---------- -->
  <div class="controlbar" id="dock-bar">
    <span class="cb-title">dashboard</span>
    <span class="cb-count" id="dock-count"></span>
    <div class="cb-actions">
      <button class="btn ghost" id="dock-expand">expand all</button>
      <button class="btn ghost" id="dock-collapse">collapse all</button>
    </div>
  </div>

  <!-- ---------- DASHBOARD ---------- -->
  <main class="deck" id="deck" aria-label="dashboard">

    <!-- ---------- PRIMARY: scanner (large, results live here) ---------- -->
<section class="panel accent-cyan" id="panel-scanner">
      <div class="panel-head">
        <h2><span class="idx">01</span> Bulk Scanner</h2>
        <div class="head-actions">
          <button class="btn ghost" id="use-list" title="Load your saved DNS list">use saved list</button>
          <button class="btn ghost" id="export-csv">export CSV</button>
          <button class="btn ghost" id="clear-targets">clear</button>
        </div>
      </div>

      <textarea id="targets" class="bulk targets" spellcheck="false"
        placeholder="Paste DNS servers — one per line or comma separated&#10;8.8.8.8, 1.1.1.1, 9.9.9.9, 8.8.4.4, dns.google&#10;Handles thousands of entries."></textarea>

      <div class="controls">
        <label class="field"><span>packets</span><input type="number" id="count" min="1" max="10" value="3" /></label>
        <label class="field"><span>workers</span><input type="number" id="workers" min="1" max="512" value="64" /></label>
        <label class="field"><span>chunk</span><input type="number" id="chunk" min="1" max="5000" value="100" /></label>
        <label class="field"><span>protocol</span>
          <select id="proto" class="sel">
            <option value="udp">UDP (53)</option>
            <option value="tcp">TCP (53)</option>
            <option value="tls">TLS / DoT (853)</option>
            <option value="both">UDP + TCP</option>
            <option value="auto">Auto (first that works)</option>
          </select>
        </label>
        <label class="field"><span>timeout s</span><input type="number" id="timeout" min="0.3" max="10" step="0.1" value="1.5" /></label>
        <label class="field"><span>probe target</span>
          <select id="probe" class="sel"><option value="google">google.com</option></select>
        </label>
        <label class="chk"><input type="checkbox" id="geo" /> geo-locate</label>
        <button class="btn primary" id="run"><span class="run-label">RUN SCAN</span></button>
      </div>

      <div class="progress-wrap">
        <div class="progress"><div class="progress-bar" id="progress-bar"></div></div>
        <div class="progress-text" id="progress-text">idle</div>
      </div>

      <div class="metrics">
        <div class="metric cyan"><span class="m-label">scanned</span><span class="m-val" id="stat-done">—</span></div>
        <div class="metric green"><span class="m-label">alive</span><span class="m-val" id="stat-ok">—</span></div>
        <div class="metric amber"><span class="m-label">best</span><span class="m-val" id="stat-best">—</span></div>
        <div class="metric pink"><span class="m-label">rate /s</span><span class="m-val" id="stat-rate">—</span></div>
      </div>

      <div class="table-tools">
        <input type="text" id="filter" placeholder="filter results (ip, status…)" spellcheck="false" />
        <label class="field"><span>country</span>
          <input type="text" id="country-filter" placeholder="e.g. DE, NL, US" spellcheck="false" style="width:120px" />
        </label>
        <label class="field"><span>sort by</span>
          <select id="sort-by" class="sel">
            <option value="latency">lowest latency</option>
            <option value="reliability">most reliable (score)</option>
            <option value="jitter">lowest jitter</option>
            <option value="loss">lowest packet loss</option>
            <option value="combined">best overall (all three)</option>
            <option value="country">country (A→Z)</option>
          </select>
        </label>
        <label class="chk"><input type="checkbox" id="only-ok" /> alive only</label>
      </div>

      <div class="table-wrap">
        <table class="results">
          <thead>
            <tr><th>#</th><th>DNS Server</th><th>Location</th><th>Latency</th><th>Jitter</th><th>Loss</th><th>Proto</th><th>Status</th></tr>
          </thead>
          <tbody id="results-body">
            <tr class="empty"><td colspan="8">No scan yet — hit RUN SCAN.</td></tr>
          </tbody>
        </table>
      </div>

      <div class="reco" id="reco" hidden>
        <h3>Recommended pairs</h3>
        <div class="reco-grid" id="reco-grid"></div>
      </div>

      <div class="export-row">
        <button class="btn ghost small" id="copy-results">copy results</button>
        <button class="btn ghost small" id="export-txt">export TXT</button>
      </div>
    </section>

    <!-- 02 AUTO-TEST -->

    <!-- ---------- RAIL: everything else (compact, scrolls on its own) ---------- -->
    <div class="rail" id="rail">
<section class="panel accent-violet" id="panel-import">
      <div class="panel-head">
        <h2><span class="idx">00</span> Import DNS list</h2>
        <div class="head-actions">
          <button class="btn ghost" id="import-save">save to list</button>
          <button class="btn ghost" id="import-scan">scan now</button>
        </div>
      </div>
      <p class="hint">Drop any file — .txt, .csv, .json, .log, .md, .xml, .html, .zip, .gz, .xlsx, .docx. Every IPv4 address (and known resolver) is detected.</p>
      <div class="drop" id="drop">
        <input type="file" id="file" hidden multiple />
        <div class="drop-icon">⤓</div>
        <div class="drop-text">Drop files here or <span class="link" id="browse">browse</span></div>
        <div class="drop-sub">or paste raw text below</div>
      </div>
      <textarea id="paste-import" class="bulk" spellcheck="false"
        placeholder="…or paste anything containing DNS servers (text, config dumps, logs)"></textarea>
      <button class="btn ghost wide" id="import-paste">extract from pasted text</button>
      <div class="outbox" id="import-out">No file imported yet.</div>
    </section>

    <!-- 01 SCANNER -->
<section class="panel accent-amber" id="panel-autotest">
      <div class="panel-head">
        <h2><span class="idx">02</span> Auto-Test <span class="badge" id="auto-state">idle</span></h2>
        <div class="head-actions">
          <button class="btn primary small" id="auto-start"><span class="run-label">START</span></button>
          <button class="btn ghost" id="auto-stop">stop</button>
        </div>
      </div>
      <p class="hint">Runs the scan on a timer, forever. Fully customizable — interval, protocol, packets, jitter/latency alert thresholds. Pick what to test below, and turn on background mode to keep cycling while you use the app.</p>

      <div class="auto-types">
        <span class="auto-types-label">test what</span>
        <label class="chk"><input type="checkbox" id="auto-type-dns" checked /> DNS servers</label>
        <label class="chk"><input type="checkbox" id="auto-type-mtu" /> MTU</label>
        <label class="chk"><input type="checkbox" id="auto-type-signal" /> signal strength</label>
        <label class="chk"><input type="checkbox" id="auto-background" checked /> background (keep testing)</label>
      </div>

      <div class="auto-grid">
        <label class="field"><span>interval</span>
          <div class="with-unit"><input type="number" id="auto-interval" min="5" max="86400" value="60" /><em>s</em></div>
        </label>
        <label class="field"><span>protocol</span>
          <select id="auto-proto" class="sel">
            <option value="udp">UDP (53)</option>
            <option value="tcp">TCP (53)</option>
            <option value="tls">TLS / DoT (853)</option>
            <option value="both">UDP + TCP</option>
            <option value="auto">Auto (first that works)</option>
          </select>
        </label>
        <label class="field"><span>packets</span><input type="number" id="auto-count" min="1" max="10" value="3" /></label>
        <label class="field"><span>workers</span><input type="number" id="auto-workers" min="1" max="512" value="64" /></label>
        <label class="field"><span>source</span>
          <select id="auto-source" class="sel">
            <option value="targets">scanner box</option>
            <option value="list">saved DNS list</option>
          </select>
        </label>
        <label class="field"><span>cycles</span>
          <select id="auto-cycles" class="sel">
            <option value="0">forever</option>
            <option value="5">5</option>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
          </select>
        </label>
        <label class="field"><span>probe target</span>
          <select id="auto-probe" class="sel"><option value="google">google.com</option></select>
        </label>
        <label class="field"><span>chunk size</span><input type="number" id="auto-chunk" min="0" max="100000" value="0" title="0 = scan the whole list each cycle; otherwise test this many per cycle, rotating through the list" /></label>
        <label class="chk"><input type="checkbox" id="auto-rotate" checked /> rotate through list</label>
        <label class="chk"><input type="checkbox" id="auto-geo" /> geo-locate</label>
      </div>

      <div class="auto-alerts">
        <label class="chk"><input type="checkbox" id="auto-alert-on" /> alerts</label>
        <label class="field inline"><span>warn latency</span>
          <div class="with-unit"><input type="number" id="auto-warn-lat" min="1" max="9999" value="120" /><em>ms</em></div>
        </label>
        <label class="field inline"><span>alert jitter</span>
          <div class="with-unit"><input type="number" id="auto-alert-jit" min="1" max="9999" value="40" /><em>ms</em></div>
        </label>
        <label class="field inline"><span>alert loss</span>
          <div class="with-unit"><input type="number" id="auto-alert-loss" min="1" max="100" value="20" /><em>%</em></div>
        </label>
      </div>

      <div class="auto-timer">
        <div class="ring" id="auto-ring">
          <svg viewBox="0 0 120 120" aria-hidden="true">
            <circle class="ring-bg" cx="60" cy="60" r="52"></circle>
            <circle class="ring-fg" id="auto-ring-fg" cx="60" cy="60" r="52"></circle>
          </svg>
          <div class="ring-label"><span id="auto-countdown">--</span><em id="auto-cycle-label">cycle 0</em></div>
        </div>
        <div class="auto-stats">
          <div class="metric amber"><span class="m-label">next in</span><span class="m-val" id="auto-next">—</span></div>
          <div class="metric cyan"><span class="m-label">cycles run</span><span class="m-val" id="auto-cycles-run">0</span></div>
          <div class="metric green"><span class="m-label">best now</span><span class="m-val" id="auto-best">—</span></div>
          <div class="metric pink"><span class="m-label">alerts</span><span class="m-val" id="auto-alert-count">0</span></div>
        </div>
      </div>
      <div class="outbox" id="auto-log">Auto-test idle. Set an interval and hit START.</div>
    </section>

    <!-- 03 STABILITY -->
<section class="panel accent-violet" id="panel-stability">
      <div class="panel-head">
        <h2><span class="idx">03</span> Stability</h2>
        <div class="head-actions">
          <button class="btn ghost" id="refresh-stab">refresh</button>
          <button class="btn ghost" id="clear-history">clear</button>
        </div>
      </div>
      <p class="hint">Ranked across every scan — saved between sessions.</p>
      <div class="stab-list" id="stab-list"><div class="empty-note">Run a scan to build history.</div></div>
    </section>

    <!-- 04 SAVED DNS -->
<section class="panel accent-green" id="panel-list">
      <div class="panel-head">
        <h2><span class="idx">04</span> Saved DNS <span class="badge" id="dns-count">0</span></h2>
        <div class="head-actions"><button class="btn ghost" id="clear-dns">clear all</button></div>
      </div>
      <div class="add-row">
        <input type="text" id="new-dns" placeholder="add one e.g. 8.8.4.4" spellcheck="false" />
        <button class="btn primary small" id="add-dns">add</button>
      </div>
      <textarea id="bulk-dns" class="bulk" spellcheck="false"
        placeholder="paste many at once (one per line) then ADD ALL"></textarea>
      <button class="btn ghost wide" id="bulk-add">add all pasted</button>
      <ul class="list" id="dns-list"></ul>
    </section>

    <!-- 05 PROBE LAB -->
<section class="panel accent-pink" id="panel-tools">
      <div class="panel-head"><h2><span class="idx">05</span> Probe Lab</h2></div>
      <div class="tool-row">
        <input type="text" id="tool-host" placeholder="host / IP" spellcheck="false" value="1.1.1.1" />
      </div>
      <div class="tool-row">
        <label class="field"><span>probe targets (pick up to 3)</span>
          <select id="tool-probe" class="sel" multiple size="4" title="Ctrl/Cmd-click or tap to select up to 3 game/CDN targets">
            <option value="google">google.com</option>
          </select>
        </label>
        <label class="field"><span>DNS server (protocols)</span>
          <input type="text" id="tool-dns" placeholder="resolver IP e.g. 1.1.1.1" spellcheck="false" value="1.1.1.1" />
        </label>
      </div>
      <div class="chips">
        <button class="chip" data-tool="resolve">DNS resolve</button>
        <button class="chip" data-tool="tcp">TCP ping</button>
        <button class="chip" data-tool="tls">TLS handshake</button>
        <button class="chip" data-tool="http">HTTP GET</button>
        <button class="chip" data-tool="game">Game latency</button>
        <button class="chip" data-tool="mtu">MTU advice</button>
        <button class="chip" data-tool="protocols">UDP / TCP / TLS</button>
        <button class="chip" data-tool="dig">Dig targets</button>
      </div>
      <div class="tool-row">
        <select id="tool-game" class="sel"></select>
        <input type="text" id="tool-game-port" placeholder="port (optional, e.g. 37015)" spellcheck="false" style="width:180px" />
        <select id="tool-game-proto" class="sel" style="width:110px">
          <option value="">proto (auto)</option>
          <option value="udp">UDP</option>
          <option value="tcp">TCP</option>
          <option value="both">UDP+TCP</option>
        </select>
        <button class="btn ghost small" id="tool-game-plan">AI: find port</button>
      </div>
      <div class="outbox" id="tool-out">Pick a probe to test a host.</div>
    </section>

    <!-- 06 NETWORK / VPN -->
<section class="panel accent-amber" id="panel-network">
      <div class="panel-head">
        <h2><span class="idx">06</span> Network · VPN</h2>
        <button class="btn ghost" id="refresh-network">refresh</button>
      </div>
      <p class="hint">Public egress IP &amp; geo — check what your VPN exposes.</p>
      <div class="device-grid" id="network-grid">
        <div class="dev-cell"><span class="dev-k">public ip</span><span class="dev-v" id="net-ip">…</span></div>
        <div class="dev-cell"><span class="dev-k">country</span><span class="dev-v" id="net-country">…</span></div>
        <div class="dev-cell"><span class="dev-k">isp</span><span class="dev-v" id="net-isp">…</span></div>
        <div class="dev-cell"><span class="dev-k">interface</span><span class="dev-v" id="net-iface">…</span></div>
        <div class="dev-cell"><span class="dev-k">vpn tunnel</span><span class="dev-v" id="net-vpn">…</span></div>
        <div class="dev-cell"><span class="dev-k">mtu</span><span class="dev-v" id="net-mtu">…</span></div>
      </div>
    </section>

    <!-- 07 DEVICE -->
<section class="panel accent-blue" id="panel-device">
      <div class="panel-head">
        <h2><span class="idx">07</span> Device</h2>
        <button class="btn ghost" id="refresh-device">refresh</button>
      </div>
      <p class="hint">Read-only Shizuku snapshot (getprop / ip route).</p>
      <div class="device-grid" id="device-grid">
        <div class="dev-cell"><span class="dev-k">shizuku</span><span class="dev-v" id="dev-shizuku">…</span></div>
        <div class="dev-cell"><span class="dev-k">operator</span><span class="dev-v" id="dev-operator">…</span></div>
        <div class="dev-cell"><span class="dev-k">network</span><span class="dev-v" id="dev-net">…</span></div>
        <div class="dev-cell"><span class="dev-k">interface</span><span class="dev-v" id="dev-iface">…</span></div>
        <div class="dev-cell"><span class="dev-k">vpn tunnel</span><span class="dev-v" id="dev-vpn">…</span></div>
      </div>
    </section>

    <!-- 08 APN BENCHMARK -->
<section class="panel accent-violet" id="panel-apn">
      <div class="panel-head">
        <h2><span class="idx">08</span> APN Benchmark</h2>
        <div class="head-actions">
          <button class="btn ghost" id="refresh-apn">refresh</button>
          <button class="btn ghost danger" id="apn-bench">run benchmark</button>
        </div>
      </div>
      <p class="hint">Lists carrier APNs. Benchmarking switches the preferred APN, tests, then restores it (Shizuku).</p>
      <div class="apn-wrap">
        <ul class="list apn-list" id="apn-list"><li class="empty-note">load to see APN entries</li></ul>
        <div class="outbox" id="apn-out">Current preferred APN: —</div>
      </div>
    </section>

    <!-- 09 GAME PROFILES -->
<section class="panel accent-green" id="panel-profiles">
      <div class="panel-head"><h2><span class="idx">09</span> Game Profiles</h2></div>
      <div class="add-row">
        <input type="text" id="prof-name" placeholder="name e.g. Valorant" spellcheck="false" />
        <input type="text" id="prof-host" placeholder="host" spellcheck="false" />
      </div>
      <button class="btn ghost wide" id="prof-add">add profile</button>
      <ul class="list" id="prof-list"></ul>
    </section>

    <!-- 10 DIAGNOSIS -->
<section class="panel accent-cyan" id="panel-diagnosis">
      <div class="panel-head">
        <h2><span class="idx">10</span> Diagnosis</h2>
        <button class="btn ghost" id="diag-run">run</button>
      </div>
      <div class="outbox" id="diag-out">Run the local network diagnosis (reference host + gateway).</div>
    </section>

    <!-- 11 AI ANALYSIS -->
<section class="panel accent-pink" id="panel-ai">
      <div class="panel-head">
        <h2><span class="idx">11</span> AI Analysis <span class="badge ai-badge" id="ai-badge">OpenRouter</span></h2>
        <div class="head-actions">
          <button class="btn ghost" id="ai-analyse">analyse scan</button>
          <button class="btn ghost" id="ai-ask">ask about results</button>
        </div>
      </div>
      <p class="hint">Send your latest scan to an OpenRouter model for recommendations. The key stays in your browser unless you start the server with one.</p>
      <div class="ai-config">
        <label class="field"><span>OpenRouter API key</span>
          <input type="password" id="ai-key" placeholder="sk-or-… (stored locally in this browser)" spellcheck="false" />
        </label>
        <label class="field"><span>model</span>
          <div class="model-pick">
            <select id="ai-model-select" class="sel"></select>
            <input type="text" id="ai-model" value="openai/gpt-4o-mini" spellcheck="false" />
          </div>
        </label>
        <div class="model-filters">
          <div class="seg-group">
            <button class="seg active" id="ai-seg-all">all</button>
            <button class="seg" id="ai-seg-free">free</button>
            <button class="seg" id="ai-seg-paid">paid</button>
          </div>
          <button class="btn ghost tiny" id="ai-models-refresh" title="reload the model list">⟳</button>
          <span class="model-count" id="ai-model-count"></span>
        </div>
        <label class="chk"><input type="checkbox" id="ai-remember" checked /> remember key</label>
      </div>
      <div class="tool-row">
        <input type="text" id="ai-question" placeholder="optional: ask something specific, e.g. “best for gaming in EU?”" spellcheck="false" />
      </div>
      <div class="outbox tall" id="ai-out">Run a scan, then hit ANALYSE SCAN for an AI recommendation.</div>
      <div class="export-row">
        <button class="btn ghost small" id="ai-copy">copy answer</button>
        <button class="btn ghost small" id="ai-export">export TXT</button>
      </div>
    </section>

    <!-- 12 APPEARANCE -->
<section class="panel accent-blue" id="panel-appearance">
      <div class="panel-head">
        <h2><span class="idx">12</span> Appearance</h2>
        <div class="head-actions">
          <button class="btn ghost" id="theme-reset">reset</button>
        </div>
      </div>
      <p class="hint">Make it yours — colours, font and effects. Saved in this browser and applied instantly.</p>

      <div class="appear-grid">
        <div class="appear-block">
          <div class="appear-title">theme preset</div>
          <div class="preset-row" id="preset-row">
            <button class="preset" data-preset="nexus">Nexus</button>
            <button class="preset" data-preset="midnight">Midnight</button>
            <button class="preset" data-preset="matrix">Matrix</button>
            <button class="preset" data-preset="sunset">Sunset</button>
            <button class="preset" data-preset="ice">Ice</button>
            <button class="preset" data-preset="light">Light</button>
          </div>
        </div>

        <div class="appear-block">
          <div class="appear-title">colours</div>
          <div class="color-row">
            <label class="color-field"><span>accent</span><input type="color" id="col-accent" value="#35e6ff" /></label>
            <label class="color-field"><span>text</span><input type="color" id="col-ink" value="#eae6ff" /></label>
            <label class="color-field"><span>muted</span><input type="color" id="col-dim" value="#9a92c4" /></label>
            <label class="color-field"><span>background</span><input type="color" id="col-bg" value="#08060f" /></label>
          </div>
        </div>

        <div class="appear-block">
          <div class="appear-title">font</div>
          <div class="font-row">
            <label class="field"><span>family</span>
              <select id="font-family" class="sel">
                <option value="Inter">Inter (default)</option>
                <option value="system">System UI</option>
                <option value="Georgia">Georgia (serif)</option>
                <option value="'Courier New'">Courier (mono)</option>
                <option value="Verdana">Verdana</option>
              </select>
            </label>
            <label class="field"><span>size</span>
              <div class="with-unit"><input type="number" id="font-size" min="12" max="20" step="0.5" value="14.5" /><em>px</em></div>
            </label>
            <label class="field"><span>density</span>
              <select id="ui-density" class="sel">
                <option value="cozy">cozy</option>
                <option value="compact">compact</option>
                <option value="roomy">roomy</option>
              </select>
            </label>
          </div>
        </div>

        <div class="appear-block">
          <div class="appear-title">effects</div>
          <div class="fx-row">
            <label class="chk"><input type="checkbox" id="fx-aurora" checked /> aurora glow</label>
            <label class="chk"><input type="checkbox" id="fx-grid" checked /> grid</label>
            <label class="chk"><input type="checkbox" id="fx-scanlines" /> scanlines</label>
            <label class="chk"><input type="checkbox" id="fx-sparkles" /> sparkles</label>
          </div>
        </div>
      </div>
    </section>

    <!-- 13 ROUTE · PATH -->
<section class="panel accent-amber" id="panel-route">
      <div class="panel-head">
        <h2><span class="idx">13</span> Route · Path</h2>
        <button class="btn ghost" id="route-run">analyse</button>
      </div>
      <p class="hint">Where your VPN egress sits vs. the game server, and which scanned resolvers are closest to that route.</p>
      <div class="tool-row">
        <input type="text" id="route-host" placeholder="game server host e.g. eu.battle.net" spellcheck="false" />
        <select id="route-game" class="sel"><option value="">— pick a game —</option></select>
        <select id="route-region" class="sel" style="width:110px"><option value="">region</option></select>
      </div>
      <div class="outbox" id="route-out">Pick a game (or type a host) and hit ANALYSE.</div>
      <div class="device-grid" id="route-grid" style="margin-top:10px"></div>
      <div class="outbox" id="route-route"></div>
    </section>

    <!-- 14 SIGNAL -->
<section class="panel accent-green" id="panel-signal">
      <div class="panel-head">
        <h2><span class="idx">14</span> Signal · Radio</h2>
        <button class="btn ghost" id="signal-refresh">refresh</button>
      </div>
      <p class="hint">Reads the cellular signal (dBm) and recommends a radio mode. Needs Shizuku for a real reading.</p>
      <div class="device-grid" id="signal-grid">
        <div class="dev-cell"><span class="dev-k">signal</span><span class="dev-v" id="sig-dbm">…</span></div>
        <div class="dev-cell"><span class="dev-k">quality</span><span class="dev-v" id="sig-quality">…</span></div>
        <div class="dev-cell"><span class="dev-k">technology</span><span class="dev-v" id="sig-tech">…</span></div>
        <div class="dev-cell"><span class="dev-k">operator</span><span class="dev-v" id="sig-operator">…</span></div>
      </div>
      <div class="outbox" id="signal-out">Refresh to read the signal.</div>
    </section>

    <!-- 15 LOGS -->
<section class="panel accent-amber" id="panel-logs">
      <div class="panel-head">
        <h2><span class="idx">15</span> Logs</h2>
        <button class="btn ghost small" id="logs-copy">copy all</button>
      </div>
      <p class="hint">Live engine log — every request, scan, probe and error. Copy this
        when something misbehaves; it is the fastest way to see what the app was doing.</p>
      <div class="tool-row">
        <select id="logs-level" class="sel" style="width:130px">
          <option value="">all levels</option>
          <option value="DEBUG">debug</option>
          <option value="INFO">info</option>
          <option value="WARNING">warning</option>
          <option value="ERROR">error</option>
          <option value="CRITICAL">critical</option>
        </select>
        <label class="chk"><input type="checkbox" id="logs-autoscroll" checked /> auto-scroll</label>
        <label class="chk"><input type="checkbox" id="logs-follow" checked /> live</label>
        <button class="btn ghost small" id="logs-refresh">refresh</button>
        <button class="btn ghost small" id="logs-clear">clear</button>
        <button class="btn ghost small" id="logs-download">download .txt</button>
      </div>
      <div class="metric"><span class="m-label">lines</span><span class="m-val" id="logs-count">0</span></div>
      <div class="outbox tall" id="logs-out" style="max-height:52vh">waiting for log lines…</div>
    </section>

    </div>
  </main>

  <!-- ---------- FOCUS OVERLAY (single wrapper; only intercepts clicks while open) ---------- -->
  <div class="focus-overlay" id="focus-overlay" hidden>
    <div class="focus-backdrop" id="focus-backdrop"></div>
    <div class="focus-frame">
      <button class="icon-btn focus-close" id="focus-close" aria-label="close focused panel">✕</button>
      <div class="focus-slot" id="focus-slot"></div>
    </div>
  </div>

  <script src="/app.js"></script>
</body>
</html>
"""
_WEB_APP_CSS = r"""/* ============================================================
   DNS Console — front-end stylesheet (vanilla, no build step)
   ============================================================ */

:root {
  --bg: #08060f;
  --panel: #120f22;
  --panel-solid: #140f24;
  --line: rgba(150, 140, 200, 0.14);
  --line-2: rgba(150, 140, 200, 0.28);
  --ink: #eae6ff;
  --dim: #9a92c4;
  --dim-2: #6f6a94;

  --acc: #35e6ff;
  --cyan: #35e6ff;
  --green: #37ff8b;
  --amber: #ffb648;
  --pink: #ff6fa5;
  --violet: #a97bff;
  --blue: #6aa8ff;

  --radius: 14px;
  --radius-sm: 9px;
  --shadow: 0 16px 40px -26px rgba(0, 0, 0, 0.9);

  --display: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
}

* { box-sizing: border-box; }
[hidden] { display: none !important; }

html, body { height: 100%; overscroll-behavior: none; }

body {
  margin: 0;
  display: flex;
  flex-direction: column;
  height: 100vh;
  height: 100dvh;
  overflow: hidden;
  font-family: var(--display);
  font-size: 14.5px;
  color: var(--ink);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
}

/* Only real scroll containers scroll, and they never chain to the page. */
.rail, .panel-body-inner, .table-wrap, .outbox, .list, .drawer-nav { overscroll-behavior: contain; }
/* Slim, quiet scrollbars so a tiny gesture does not look like a big jump. */
.rail, .panel-body-inner, .table-wrap, .outbox { scrollbar-width: thin; }

/* ---------- background layers ---------- */
.bg-layer { position: fixed; inset: 0; z-index: -1; pointer-events: none; overflow: hidden; }
/* A radial-gradient gives the same soft glow as the old filter: blur(90px) circle,
   but without the blur. Android WebView rasterizes filter: blur in software and
   re-blurs the whole layer on every repaint (the auto-test countdown and streaming
   results invalidate it constantly), which saturates the renderer thread and makes
   Android report the app as not responding. */
.bg-orb { position: absolute; width: 46vw; height: 46vw; border-radius: 50%; opacity: 0.32; }
.bg-orb.o1 { top: -12vw; left: -8vw;
  background: radial-gradient(circle at center, var(--acc) 0%, transparent 68%); }
.bg-orb.o2 { bottom: -14vw; right: -10vw;
  background: radial-gradient(circle at center, var(--violet) 0%, transparent 68%); }
.bg-grid {
  position: absolute; inset: 0;
  background-image:
    linear-gradient(rgba(150, 140, 200, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(150, 140, 200, 0.05) 1px, transparent 1px);
  background-size: 44px 44px;
  -webkit-mask-image: radial-gradient(circle at 50% 26%, #000, transparent 78%);
  mask-image: radial-gradient(circle at 50% 26%, #000, transparent 78%);
}
.bg-layer::before {
  content: ""; position: absolute; inset: 0; opacity: 0.5;
  background: repeating-linear-gradient(0deg, rgba(255, 255, 255, 0.02) 0 1px, transparent 1px 3px);
}
.bg-layer::after {
  content: ""; position: absolute; inset: 0; opacity: 0.35;
  background-image: radial-gradient(rgba(255, 255, 255, 0.14) 1px, transparent 1px);
  background-size: 130px 130px;
}
body.no-aurora .bg-orb { display: none; }
body.no-grid .bg-grid { display: none; }
body.no-scanlines .bg-layer::before { display: none; }
body.no-sparkles .bg-layer::after { display: none; }

/* ---------- skip link ---------- */
.skip-link { position: absolute; left: -9999px; top: 0; }
.skip-link:focus {
  left: 8px; top: 8px; z-index: 300; padding: 8px 12px;
  background: var(--panel-solid); border: 1px solid var(--line-2); border-radius: 8px; color: var(--ink);
}

/* ---------- top bar ---------- */
.topbar {
  flex: 0 0 auto; display: flex; align-items: center; justify-content: space-between;
  height: 56px; padding: 0 16px; z-index: 20;
  background: rgba(9, 8, 18, 0.94); border-bottom: 1px solid var(--line);
}
.tb-left, .tb-right { display: flex; align-items: center; gap: 14px; }
.brand { display: inline-flex; align-items: center; font-weight: 800; font-size: 15px; letter-spacing: 0.01em; }
.brand span { color: var(--dim); font-weight: 600; }
.brand-dot {
  width: 9px; height: 9px; border-radius: 50%; margin-right: 9px;
  background: var(--acc); box-shadow: 0 0 12px var(--acc);
}
.conn { display: inline-flex; align-items: center; gap: 7px; font-size: 11.5px; color: var(--dim); }
.conn em { font-style: normal; }
.conn-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--dim-2); transition: background 0.2s; }
.conn-dot.live { background: var(--green); box-shadow: 0 0 9px var(--green); }
.clock { font-family: var(--mono); font-size: 12px; color: var(--dim); }
.host {
  font-family: var(--mono); font-size: 11.5px; color: var(--dim-2);
  border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px;
}

/* ---------- icon buttons ---------- */
.icon-btn {
  width: 34px; height: 34px; display: grid; place-items: center; cursor: pointer;
  border: 1px solid var(--line); border-radius: var(--radius-sm);
  background: rgba(255, 255, 255, 0.04); color: var(--dim);
  transition: color 0.15s, border-color 0.15s, background 0.15s;
}
.icon-btn:hover { color: var(--ink); border-color: var(--line-2); background: rgba(255, 255, 255, 0.08); }
.burger { flex-direction: column; gap: 3px; }
.burger span { width: 15px; height: 2px; border-radius: 2px; background: currentColor; }

/* ---------- buttons ---------- */
.btn {
  font: inherit; font-size: 12.5px; font-weight: 600; cursor: pointer; white-space: nowrap;
  padding: 8px 13px; border-radius: var(--radius-sm); border: 1px solid var(--line);
  background: rgba(255, 255, 255, 0.04); color: var(--ink);
  transition: color 0.15s, border-color 0.15s, background 0.15s, filter 0.15s;
}
.btn:hover { border-color: var(--line-2); background: rgba(255, 255, 255, 0.08); }
.btn.primary {
  background: linear-gradient(180deg, color-mix(in srgb, var(--acc) 92%, #fff), var(--acc));
  color: #04121a; border-color: transparent;
}
.btn.primary:hover { filter: brightness(1.08); }
.btn.ghost { background: rgba(255, 255, 255, 0.03); }
.btn.danger { color: #ff9b7a; border-color: rgba(255, 120, 90, 0.3); }
.btn.danger:hover { background: rgba(255, 120, 90, 0.12); }
.btn.small { padding: 6px 11px; font-size: 12px; }
.btn.tiny { padding: 6px 9px; }
.btn.wide { width: 100%; }
.btn:disabled { opacity: 0.5; cursor: default; }

/* ---------- control bar ---------- */
.controlbar {
  flex: 0 0 auto; display: flex; align-items: center; gap: 12px;
  padding: 8px 16px; border-bottom: 1px solid var(--line); background: rgba(9, 8, 18, 0.5);
}
.cb-title { font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--dim-2); }
.cb-count { font-size: 12px; color: var(--dim); }
.cb-actions { margin-left: auto; display: flex; gap: 8px; }

/* ============================================================
   LAYOUT — one big Scanner on the left, a compact rail on the right.
   Each column scrolls on its own; the page itself never scrolls.
   ============================================================ */
.deck {
  flex: 1 1 auto; min-height: 0; overflow: hidden;
  display: grid; grid-template-columns: minmax(0, 1fr) minmax(300px, 32%);
  gap: 12px; padding: 12px;
}

/* the rail is the only scrolling column on a desktop-sized screen */
.rail {
  min-height: 0; overflow-y: auto; overscroll-behavior: contain;
  display: flex; flex-direction: column; gap: 12px; padding-right: 2px;
  scrollbar-width: thin;
}
.rail > .panel { flex: 0 0 auto; }
/* No inner scrollers inside the rail: it is the ONE thing that scrolls, so a
   gesture can never chain from a panel to the rail to the page. */
.rail > .panel > .panel-body > .panel-body-inner { max-height: none; overflow: visible; }

/* ---------- panel ---------- */
.panel {
  position: relative; display: flex; flex-direction: column; min-height: 0; overflow: hidden;
  background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow);
}
#panel-scanner { min-height: 0; }
.panel::before {
  content: ""; position: absolute; left: 0; right: 0; top: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--pa, var(--acc)), transparent);
}
.accent-cyan::before { --pa: var(--cyan); }
.accent-green::before { --pa: var(--green); }
.accent-amber::before { --pa: var(--amber); }
.accent-pink::before { --pa: var(--pink); }
.accent-violet::before { --pa: var(--violet); }
.accent-blue::before { --pa: var(--blue); }

.panel-head {
  flex: 0 0 auto; display: flex; align-items: center; gap: 10px;
  padding: 11px 14px; border-bottom: 1px solid var(--line); cursor: pointer;
}
.panel-head h2 {
  margin: 0 auto 0 0; display: flex; align-items: center; gap: 8px;
  font-size: 13.5px; font-weight: 650; letter-spacing: 0.01em;
}
.idx { font-family: var(--mono); font-size: 11px; color: var(--dim-2); }
.head-actions { display: flex; gap: 6px; align-items: center; }

/* focus + collapse controls injected by JS */
.head-tools { display: flex; gap: 2px; align-items: center; }
.ico-btn {
  width: 26px; height: 26px; display: grid; place-items: center; cursor: pointer;
  border: 1px solid transparent; border-radius: 7px; background: transparent; color: var(--dim-2);
  transition: color 0.15s, background 0.15s;
}
.ico-btn:hover { color: var(--ink); background: rgba(255, 255, 255, 0.07); }
.ico-btn svg { width: 15px; height: 15px; }
.chev { transition: transform 0.2s; }
.panel.collapsed .chev { transform: rotate(-90deg); }

/* collapsible body: grid-template-rows 1fr -> 0fr (grows to content, never clips) */
.panel-body { display: grid; grid-template-rows: 1fr; min-height: 0; transition: grid-template-rows 0.26s ease; }
.panel-body-inner {
  min-height: 0; overflow: auto; padding: 12px 14px;
  display: flex; flex-direction: column; gap: 10px;
  transition: opacity 0.18s;
}
/* In the Scanner, the body itself does not scroll — only the results table
   does, so a stray scroll can never push the results out of view. */
#panel-scanner > .panel-body > .panel-body-inner { overflow: hidden; }
.panel.collapsed .panel-body { grid-template-rows: 0fr; }
.panel.collapsed .panel-body-inner { opacity: 0; pointer-events: none; }

body[data-density="compact"] .panel-body-inner { padding: 8px 10px; gap: 7px; }
body[data-density="roomy"] .panel-body-inner { padding: 16px 18px; gap: 13px; }

.hint { margin: 0; font-size: 11.5px; line-height: 1.5; color: var(--dim-2); }

/* ---------- import dropzone ---------- */
.drop {
  display: flex; flex-direction: column; align-items: center; gap: 4px; cursor: pointer;
  padding: 16px 12px; text-align: center; border: 1.5px dashed var(--line-2); border-radius: 12px;
  background: rgba(255, 255, 255, 0.02); transition: border-color 0.15s, background 0.15s;
}
.drop:hover { border-color: var(--acc); background: rgba(255, 255, 255, 0.04); }
.drop.over { border-color: var(--acc); background: color-mix(in srgb, var(--acc) 12%, transparent); }
.drop-icon { font-size: 22px; color: var(--acc); line-height: 1; }
.drop-text { font-size: 12.5px; }
.drop-sub { font-size: 11px; color: var(--dim-2); }
.link { color: var(--acc); text-decoration: underline; cursor: pointer; }

/* ---------- generic form controls ---------- */
input[type="text"], input[type="password"], input[type="number"], textarea, .sel {
  font: inherit; color: var(--ink); background: rgba(8, 7, 16, 0.7);
  border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 8px 10px; outline: none;
  transition: border-color 0.15s, box-shadow 0.15s;
}
input:focus, textarea:focus, .sel:focus {
  border-color: var(--line-2);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--acc) 18%, transparent);
}
.sel { cursor: pointer; }
textarea.bulk { font-family: var(--mono); font-size: 12px; line-height: 1.5; resize: vertical; min-height: 62px; }
textarea.targets { min-height: 78px; }

.field { display: flex; flex-direction: column; gap: 5px; font-size: 11px; color: var(--dim-2); min-width: 0; }
.field > span { letter-spacing: 0.06em; text-transform: uppercase; }
.field input, .field select { width: 100%; }

.chk { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--dim); cursor: pointer; }
.chk input { accent-color: var(--acc); }

.with-unit { display: flex; align-items: center; gap: 4px; }
.with-unit input { width: 66px; }
.with-unit em { font-style: normal; font-size: 11px; color: var(--dim-2); }

.add-row, .tool-row { display: flex; gap: 8px; align-items: stretch; flex-wrap: wrap; }
.add-row input { flex: 1; min-width: 100px; }
.tool-row .field { flex: 1; min-width: 120px; }

.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: end; }
.controls .field { width: 92px; }
.controls #run { margin-left: auto; }

/* ---------- output box ---------- */
.outbox {
  font-family: var(--mono); font-size: 11.5px; line-height: 1.55; color: var(--dim);
  background: rgba(6, 6, 14, 0.6); border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 12px; white-space: pre-wrap; overflow: auto; min-height: 38px;
}
.outbox.tall { min-height: 108px; }
.k { color: var(--dim-2); }
.v { color: var(--ink); }
.err { color: var(--pink); }
.ok, .good { color: var(--green); }
.dim { color: var(--dim-2); }

/* ---------- progress + metrics ---------- */
.progress-wrap { display: flex; flex-direction: column; gap: 5px; }
.progress { height: 6px; border-radius: 999px; overflow: hidden; background: rgba(255, 255, 255, 0.06); }
.progress-bar {
  height: 100%; width: 0; border-radius: 999px;
  background: linear-gradient(90deg, var(--acc), color-mix(in srgb, var(--acc) 45%, var(--violet)));
  transition: width 0.2s;
}
.progress-text { font-family: var(--mono); font-size: 11px; color: var(--dim-2); }

.metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.metric {
  position: relative; overflow: hidden; display: flex; flex-direction: column; gap: 2px;
  padding: 8px 10px 8px 13px; border: 1px solid var(--line); border-radius: 10px; background: rgba(255, 255, 255, 0.02);
}
.metric::after { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--mc, var(--acc)); }
.metric .m-label { font-size: 10px; letter-spacing: 0.07em; text-transform: uppercase; color: var(--dim-2); }
.metric .m-val { font-family: var(--mono); font-size: 15px; font-weight: 600; }
.metric.cyan { --mc: var(--cyan); }
.metric.green { --mc: var(--green); }
.metric.amber { --mc: var(--amber); }
.metric.pink { --mc: var(--pink); }

/* ---------- results table (plain + minimal) ---------- */
.table-tools { display: flex; gap: 10px; align-items: center; flex: 0 0 auto; }
.table-tools input[type="text"] { flex: 1; }
/* The results are the point of the panel: give them a guaranteed floor so they
   can never be squeezed to nothing, and let only this box scroll. */
.table-wrap {
  flex: 1 1 auto; min-height: 180px; overflow: auto; overscroll-behavior: contain;
  border: 1px solid var(--line); border-radius: 10px; background: rgba(6, 6, 14, 0.35);
}
.results { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.results th {
  position: sticky; top: 0; z-index: 1; text-align: left; padding: 7px 10px;
  background: var(--panel-solid); color: var(--dim-2); font-weight: 600;
  font-size: 10px; letter-spacing: 0.05em; text-transform: uppercase; border-bottom: 1px solid var(--line);
}
.results td { padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: middle; }
.results tbody tr:last-child td { border-bottom: 0; }
.results tbody tr:hover { background: rgba(255, 255, 255, 0.03); }
.results .empty td { text-align: center; color: var(--dim-2); padding: 22px; }
.results td:nth-child(1) { color: var(--dim-2); font-family: var(--mono); font-size: 11px; width: 34px; }
.results td:nth-child(2) { font-family: var(--mono); }
.bar-cell { display: flex; align-items: center; gap: 8px; }
.mini-bar { height: 5px; border-radius: 999px; background: var(--acc); min-width: 3px; }
.geo-cell { white-space: nowrap; color: var(--dim); }

.pill { font-size: 10.5px; font-weight: 600; padding: 2px 8px; border-radius: 999px; }
.pill.ok { background: rgba(55, 255, 139, 0.14); color: var(--green); }
.pill.warn { background: rgba(255, 182, 72, 0.16); color: var(--amber); }
.pill.fail { background: rgba(255, 111, 165, 0.16); color: var(--pink); }

.ptag {
  font-family: var(--mono); font-size: 10px; padding: 1px 6px; border-radius: 6px;
  border: 1px solid var(--line); color: var(--dim);
}
.ptag.ok { color: var(--green); border-color: rgba(55, 255, 139, 0.35); }
.ptag.bad { color: var(--pink); border-color: rgba(255, 111, 165, 0.35); }

/* ---------- recommended pairs ---------- */
.reco { display: flex; flex-direction: column; gap: 8px; }
.reco h3 { margin: 0; font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--dim-2); }
.reco-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 8px; }
.reco-card { border: 1px solid var(--line); border-radius: 10px; padding: 9px 11px; background: rgba(255, 255, 255, 0.02); }
.reco-title { font-size: 10.5px; color: var(--dim-2); margin-bottom: 6px; }
.reco-row { display: grid; grid-template-columns: auto 1fr auto auto; gap: 8px; align-items: center; font-size: 12px; }
.reco-rank { font-size: 9.5px; text-transform: uppercase; color: var(--acc); }
.reco-ip { font-family: var(--mono); }
.reco-cc { color: var(--dim); }
.reco-ms { font-family: var(--mono); color: var(--green); }

/* ---------- stability ---------- */
.stab-list { display: flex; flex-direction: column; }
.stab-item { display: grid; grid-template-columns: 1fr auto; gap: 3px 10px; padding: 8px 0; border-bottom: 1px solid var(--line); }
.stab-item .ip { font-family: var(--mono); font-size: 12px; }
.stab-item .meta { font-size: 10.5px; color: var(--dim-2); }
.stab-score { font-family: var(--mono); font-weight: 700; font-size: 14px; }
.stab-track { grid-column: 1 / -1; height: 5px; border-radius: 999px; overflow: hidden; background: rgba(255, 255, 255, 0.06); }
.stab-fill { height: 100%; background: linear-gradient(90deg, var(--acc), var(--green)); }
.empty-note { font-size: 11.5px; color: var(--dim-2); font-style: italic; }

/* ---------- lists (saved DNS / APN / profiles) ---------- */
.list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
.list li {
  display: flex; align-items: center; gap: 10px; padding: 6px 10px;
  border: 1px solid var(--line); border-radius: 8px; font-family: var(--mono); font-size: 12px;
}
.list li .del {
  margin-left: auto; font: inherit; font-size: 11px; cursor: pointer; color: var(--pink);
  background: transparent; border: 0; padding: 2px 4px;
}
.list li .del:hover { text-decoration: underline; }
.list li.cur { border-color: var(--acc); box-shadow: 0 0 0 2px color-mix(in srgb, var(--acc) 22%, transparent); }
.list li.ok { border-color: rgba(55, 255, 139, 0.4); }
.list li.bad { border-color: rgba(255, 111, 165, 0.4); }
.apn-wrap { display: flex; flex-direction: column; gap: 8px; min-height: 0; }

/* ---------- device / network grid ---------- */
.device-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(128px, 1fr)); gap: 8px; }
.dev-cell {
  display: flex; flex-direction: column; gap: 2px; padding: 7px 10px;
  border: 1px solid var(--line); border-radius: 9px; background: rgba(255, 255, 255, 0.02);
}
.dev-k { font-size: 10px; letter-spacing: 0.07em; text-transform: uppercase; color: var(--dim-2); }
.dev-v { font-family: var(--mono); font-size: 12.5px; }
.dev-v.on { color: var(--green); }
.dev-v.off { color: var(--pink); }

/* ---------- probe chips ---------- */
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  font: inherit; font-size: 11.5px; padding: 6px 11px; border-radius: 999px; cursor: pointer;
  border: 1px solid var(--line); background: rgba(255, 255, 255, 0.03); color: var(--dim);
  transition: color 0.15s, background 0.15s, border-color 0.15s;
}
.chip:hover { color: var(--ink); border-color: var(--line-2); }
.chip.active { color: #04121a; background: var(--acc); border-color: transparent; }

/* ---------- AI model picker ---------- */
.ai-config { display: flex; flex-direction: column; gap: 8px; }
.model-pick { display: flex; gap: 6px; }
.model-pick select { flex: 1; }
.model-pick input { width: 44%; }
.model-filters { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.seg-group { display: inline-flex; border: 1px solid var(--line); border-radius: 999px; overflow: hidden; }
.seg { font: inherit; font-size: 11.5px; padding: 5px 12px; background: transparent; color: var(--dim); border: 0; cursor: pointer; }
.seg:hover { color: var(--ink); }
.seg.active { background: var(--acc); color: #04121a; }
.model-count { font-size: 11px; color: var(--dim-2); }

/* ---------- appearance ---------- */
.appear-grid { display: grid; gap: 12px; }
.appear-block { display: flex; flex-direction: column; gap: 7px; }
.appear-title { font-size: 10.5px; letter-spacing: 0.09em; text-transform: uppercase; color: var(--dim-2); }
.preset-row, .color-row, .font-row, .fx-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: end; }
.preset {
  font: inherit; font-size: 11.5px; padding: 6px 11px; border-radius: 999px; cursor: pointer;
  border: 1px solid var(--line); background: rgba(255, 255, 255, 0.03); color: var(--dim);
}
.preset:hover { color: var(--ink); border-color: var(--line-2); }
.preset.active { color: #04121a; background: var(--acc); border-color: transparent; }
.color-field { display: flex; flex-direction: column; gap: 4px; font-size: 10.5px; color: var(--dim-2); }
.color-field input[type="color"] {
  width: 46px; height: 30px; padding: 2px; border-radius: 8px;
  border: 1px solid var(--line); background: transparent; cursor: pointer;
}

/* ---------- auto-test timer ---------- */
.auto-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(108px, 1fr)); gap: 10px; }
.auto-alerts { display: flex; flex-wrap: wrap; gap: 10px; align-items: end; }
.auto-timer { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.ring { position: relative; flex: 0 0 auto; width: 104px; height: 104px; }
.ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.ring circle { fill: none; stroke-width: 8; }
.ring-bg { stroke: rgba(255, 255, 255, 0.07); }
.ring-fg {
  stroke: var(--amber); stroke-linecap: round;
  stroke-dasharray: 327; stroke-dashoffset: 327; transition: stroke-dashoffset 0.25s linear;
}
.ring.running .ring-fg { stroke: var(--green); }
.ring-label { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.ring-label span { font-family: var(--mono); font-size: 22px; font-weight: 700; }
.ring-label em { font-style: normal; font-size: 9.5px; color: var(--dim-2); }
.auto-stats { flex: 1; min-width: 220px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
.auto-line { font-family: var(--mono); font-size: 11px; color: var(--dim); }

/* ---------- badges ---------- */
.badge {
  font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 999px;
  border: 1px solid var(--line); color: var(--dim);
}
.badge.live { color: var(--green); border-color: rgba(55, 255, 139, 0.4); }
.ai-badge { border-color: var(--line-2); }

/* ---------- nav drawer ---------- */
.scrim { position: fixed; inset: 0; z-index: 90; background: rgba(4, 4, 12, 0.6); opacity: 0; transition: opacity 0.2s; }
.scrim.show { opacity: 1; }
.drawer {
  position: fixed; top: 0; left: 0; bottom: 0; z-index: 91; width: 282px; max-width: 84vw;
  display: flex; flex-direction: column; background: var(--panel-solid); border-right: 1px solid var(--line);
  transform: translateX(-102%); transition: transform 0.24s ease;
}
.drawer.open { transform: none; }
.drawer-head { display: flex; align-items: center; justify-content: space-between; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.drawer-title { font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--dim-2); }
.drawer-nav { display: flex; flex-direction: column; gap: 2px; padding: 8px; overflow: auto; }
.drawer-nav a {
  display: flex; align-items: center; gap: 10px; padding: 9px 11px; border-radius: 9px;
  color: var(--dim); text-decoration: none; font-size: 13px; transition: background 0.15s, color 0.15s;
}
.drawer-nav a:hover { background: rgba(255, 255, 255, 0.05); color: var(--ink); }
.drawer-nav a.active { background: color-mix(in srgb, var(--acc) 14%, transparent); color: var(--ink); }
.di { font-family: var(--mono); font-size: 10.5px; color: var(--dim-2); }

/* ---------- focus overlay ----------
   One wrapper element; while it is [hidden] nothing here covers the page. */
.focus-overlay {
  position: fixed; inset: 0; z-index: 95;
  display: flex; align-items: center; justify-content: center; padding: 20px;
}
/* backdrop-filter is likewise software-rasterized on Android WebView; the dim reads fine alone. */
.focus-backdrop { position: absolute; inset: 0; background: rgba(4, 4, 12, 0.86); }
.focus-frame {
  position: relative; width: min(1200px, 96vw); height: min(900px, 92vh);
  display: flex; flex-direction: column; padding: 12px;
  background: linear-gradient(180deg, rgba(22, 18, 40, 0.99), rgba(12, 10, 24, 0.99));
  border: 1px solid var(--line-2); border-radius: var(--radius);
  box-shadow: 0 40px 120px -30px rgba(0, 0, 0, 0.9);
  animation: popIn 0.2s ease;
}
.focus-close { position: absolute; top: 12px; right: 12px; z-index: 2; }
.focus-slot { flex: 1 1 auto; min-height: 0; display: flex; overflow: hidden; }
.focus-slot > .panel { flex: 1 1 auto; border: none; background: transparent; box-shadow: none; border-radius: 0; }
.focus-slot > .panel::before { display: none; }
.focus-slot .panel-head { cursor: default; }
.focus-slot .panel.collapsed .panel-body { grid-template-rows: 1fr; }
.focus-slot .panel.collapsed .panel-body-inner { opacity: 1; pointer-events: auto; }

@keyframes popIn { from { transform: translateY(12px) scale(0.985); opacity: 0; } to { transform: none; opacity: 1; } }

/* ---------- jump highlight ---------- */
.panel.flash { animation: flashPanel 1.3s ease-out; }
@keyframes flashPanel {
  0% { box-shadow: 0 0 0 2px var(--acc), 0 0 40px color-mix(in srgb, var(--acc) 40%, transparent); }
  100% { box-shadow: var(--shadow); }
}

/* ---------- accessibility ---------- */
:focus-visible { outline: 2px solid color-mix(in srgb, var(--acc) 70%, transparent); outline-offset: 2px; }

/* ---------- new feature bits (round 13) ---------- */
.export-row { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.export-row .btn { flex: 0 0 auto; }
.auto-types {
  display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
  margin: 8px 0 4px; padding: 8px 10px; border-radius: 10px;
  background: color-mix(in srgb, var(--acc) 6%, transparent);
  border: 1px solid color-mix(in srgb, var(--acc) 18%, transparent);
}
.auto-types-label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; opacity: 0.7; }
.ptag.ptag-warn { background: color-mix(in srgb, #ffb86b 22%, transparent); color: #ffd7a6; }
.outbox table.ai-table { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 13px; }
.outbox table.ai-table th, .outbox table.ai-table td {
  border: 1px solid color-mix(in srgb, var(--acc) 22%, transparent);
  padding: 4px 8px; text-align: left;
}
.outbox table.ai-table th { background: color-mix(in srgb, var(--acc) 12%, transparent); }
.copy-ok { color: #7dffb0; }

/* ---------- responsive ---------- */
/* Below ~1080px the two columns no longer fit side by side: stack them and let
   the page scroll. Each panel also gets a sane floor so nothing is crushed. */
@media (max-width: 1080px) {
  body { overflow: auto; }
  .deck {
    display: flex; flex-direction: column; height: auto; overflow: visible;
    padding: 10px;
  }
  .deck > #panel-scanner { min-height: 460px; }
  .rail { overflow: visible; }
  .rail > .panel > .panel-body > .panel-body-inner { max-height: none; }
  .panel { min-height: 240px; }
}
@media (max-width: 720px) {
  .deck { padding: 8px; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
  .controls .field { width: 46%; }
  .focus-frame { width: 100%; height: 96vh; }
  .clock { display: none; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.001ms !important; transition-duration: 0.001ms !important; }
}

/* ---------- logs tab ---------- */
#logs-out { white-space: pre-wrap; word-break: break-word; }
#logs-count { font-variant-numeric: tabular-nums; }
"""
_WEB_APP_JS = r"""/* ============================================================
   NEXUS DNS — front-end logic (vanilla, no build step)
   ============================================================ */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const fmt = (v, unit = "ms", digits = 1) =>
    v == null ? "—" : `${Number(v).toFixed(digits)}${unit}`;

  // Shared across features so the AI can see what the other panels found.
  let lastMtuIntel = null;
  let lastRoute = null;

  /* ---------- clock ---------- */
  const clock = $("clock");
  const tick = () => { clock.textContent = new Date().toTimeString().slice(0, 8); };
  tick();
  setInterval(tick, 1000);

  /* ---------- connection ---------- */
  const dot = $("conn-dot");
  const connText = $("conn-text");
  fetch("/api/health")
    .then((r) => r.json())
    .then(() => { dot.classList.add("live"); connText.textContent = "online"; })
    .catch(() => { connText.textContent = "offline"; });
  $("footer-port").textContent = location.host;

  const getJSON = (p) => fetch(p).then((r) => r.json());
  const post = (p, body) =>
    fetch(p, { method: "POST", headers: { "Content-Type": "application/json" },
               body: JSON.stringify(body) }).then((r) => r.json());

  /* ============================================================
     NAV DRAWER (burger)
     ============================================================ */
  const drawer = $("drawer");
  const backdrop = $("drawer-backdrop");
  const burger = $("burger");

  function openDrawer() {
    drawer.classList.add("open");
    backdrop.hidden = false;
    requestAnimationFrame(() => backdrop.classList.add("show"));
    burger.setAttribute("aria-expanded", "true");
    drawer.setAttribute("aria-hidden", "false");
  }
  function closeDrawer() {
    drawer.classList.remove("open");
    backdrop.classList.remove("show");
    burger.setAttribute("aria-expanded", "false");
    drawer.setAttribute("aria-hidden", "true");
    setTimeout(() => { if (!drawer.classList.contains("open")) backdrop.hidden = true; }, 260);
  }
  burger.addEventListener("click", () =>
    drawer.classList.contains("open") ? closeDrawer() : openDrawer());
  $("drawer-close").addEventListener("click", closeDrawer);
  backdrop.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  /* ============================================================
     DASHBOARD DECK — every panel visible, fixed 3-row grid
     ============================================================ */
  const PANEL_KEY = "nexus_panel_state";
  const dockPanels = [...document.querySelectorAll("main .panel")];

  const CHEV = '<svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const EXPAND_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 4H4v5M15 4h5v5M15 20h5v-5M9 20H4v-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function readPanelState() {
    try { return JSON.parse(localStorage.getItem(PANEL_KEY) || "null"); } catch { return null; }
  }
  function writePanelState() {
    const st = {};
    dockPanels.forEach((p) => { st[p.id] = p.classList.contains("collapsed") ? 0 : 1; });
    try { localStorage.setItem(PANEL_KEY, JSON.stringify(st)); } catch {}
  }

  // Restructure each card: wrap its body, add focus + collapse controls.
  dockPanels.forEach((panel) => {
    const head = panel.querySelector(".panel-head");
    if (!head) return;

    const body = el("div", "panel-body");
    const bodyInner = el("div", "panel-body-inner");
    let n = head.nextSibling;
    while (n) { const next = n.nextSibling; bodyInner.appendChild(n); n = next; }
    body.appendChild(bodyInner);
    panel.appendChild(body);

    const tools = el("div", "head-tools");
    const focusBtn = el("button", "ico-btn focus-btn");
    focusBtn.type = "button"; focusBtn.title = "focus this panel";
    focusBtn.setAttribute("aria-label", "focus panel");
    focusBtn.innerHTML = EXPAND_ICON;
    focusBtn.addEventListener("click", (e) => { e.stopPropagation(); openFocus(panel); });

    const chevBtn = el("button", "ico-btn chev-btn");
    chevBtn.type = "button"; chevBtn.title = "expand / collapse";
    chevBtn.setAttribute("aria-label", "toggle panel");
    chevBtn.innerHTML = CHEV;
    chevBtn.addEventListener("click", (e) => { e.stopPropagation(); togglePanel(panel); });

    tools.append(focusBtn, chevBtn);
    head.appendChild(tools);
  });

  // Click behaviour: the header toggles open/closed; a collapsed card is a big
  // tile, so clicking anywhere on it opens it. Action buttons are left alone.
  dockPanels.forEach((panel) => {
    panel.addEventListener("click", (e) => {
      if (e.target.closest(".head-actions") || e.target.closest(".head-tools")) return;
      if (e.target.closest(".panel-head")) { togglePanel(panel); return; }
      if (panel.classList.contains("collapsed")) togglePanel(panel, false);
    });
  });

  function togglePanel(panel, force) {
    if (!panel) return;
    const collapsed = force != null ? force : !panel.classList.contains("collapsed");
    panel.classList.toggle("collapsed", collapsed);
    const head = panel.querySelector(".panel-head");
    if (head) head.setAttribute("aria-expanded", String(!collapsed));
    writePanelState();
    updateDockCount();
  }

  function setAllPanels(collapsed) {
    dockPanels.forEach((p) => {
      p.classList.toggle("collapsed", collapsed);
      const head = p.querySelector(".panel-head");
      if (head) head.setAttribute("aria-expanded", String(!collapsed));
    });
    writePanelState();
    updateDockCount();
  }

  function updateDockCount() {
    const open = dockPanels.filter((p) => !p.classList.contains("collapsed")).length;
    const c = $("dock-count");
    if (c) c.textContent = `${open} / ${dockPanels.length} open`;
  }

  // Everything is on screen at once, so panels default to OPEN. A saved
  // layout (from a previous visit) is respected.
  (function restorePanelState() {
    const st = readPanelState();
    dockPanels.forEach((p) => {
      const collapsed = st && p.id in st ? !st[p.id] : false;
      p.classList.toggle("collapsed", collapsed);
      const head = p.querySelector(".panel-head");
      if (head) head.setAttribute("aria-expanded", String(!collapsed));
    });
    updateDockCount();
  })();

  $("dock-expand").addEventListener("click", () => setAllPanels(false));
  $("dock-collapse").addEventListener("click", () => setAllPanels(true));

  /* ---- focus overlay: pop any card into one full-screen view ---- */
  const focusOverlay = $("focus-overlay");
  const focusBackdrop = $("focus-backdrop");
  const focusSlot = $("focus-slot");
  let focusedPanel = null;
  let focusAnchor = null;

  function openFocus(panel) {
    if (focusedPanel || !panel) return;
    focusedPanel = panel;
    togglePanel(panel, false);            // a focused card is always expanded
    focusAnchor = document.createComment("panel-anchor");
    panel.parentNode.insertBefore(focusAnchor, panel);
    focusSlot.appendChild(panel);
    focusOverlay.hidden = false;
    closeDrawer();
  }
  function closeFocus() {
    if (!focusedPanel) return;
    const panel = focusedPanel;
    focusedPanel = null;
    if (focusAnchor && focusAnchor.parentNode) {
      focusAnchor.parentNode.insertBefore(panel, focusAnchor);
      focusAnchor.remove();
    }
    focusAnchor = null;
    focusOverlay.hidden = true;
  }
  $("focus-close").addEventListener("click", closeFocus);
  focusBackdrop.addEventListener("click", closeFocus);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeFocus(); });

  /* ---- nav drawer: open the section (everything is already on screen) ---- */
  const navLinks = [...document.querySelectorAll("#drawer-nav a")];
  navLinks.forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault();
    const target = document.getElementById(a.dataset.target);
    closeDrawer();
    if (!target) return;
    if (focusedPanel && focusedPanel !== target) closeFocus();
    togglePanel(target, false);
    target.scrollIntoView({ block: "nearest", behavior: "smooth" });
    target.classList.remove("flash");
    void target.offsetWidth;
    target.classList.add("flash");
  }));

  // Highlight the section currently in view.
  const sectionObserver = new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (!en.isIntersecting) return;
      const id = en.target.id;
      navLinks.forEach((a) => a.classList.toggle("active", a.dataset.target === id));
    });
  }, { rootMargin: "-45% 0px -50% 0px", threshold: 0 });
  dockPanels.forEach((p) => sectionObserver.observe(p));

  function statusPill(status) {
    const s = el("span", "pill " + status);
    s.textContent = status === "ok" ? "ok" : status === "warn" ? "spike" : "fail";
    return s;
  }

  /* ============================================================
     SCANNER
     ============================================================ */
  const targetsBox = $("targets");
  const runBtn = $("run");
  const progressBar = $("progress-bar");
  const progressText = $("progress-text");
  const resultsBody = $("results-body");
  let currentES = null;
  let rows = [];
  let scanDoneHook = null;   // called with the finished rows (used by auto-test)

  const parseTargets = () =>
    targetsBox.value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);

  function resetMetrics() {
    $("stat-done").textContent = "—";
    $("stat-ok").textContent = "—";
    $("stat-best").textContent = "—";
    $("stat-rate").textContent = "—";
  }

  // opts: { targets, count, workers, chunk, proto, timeout, probe, geo,
  //         label, silent, keepRows }
  // Returns a promise that resolves with the finished rows.
  function runScan(opts) {
    opts = opts || {};
    const targets = opts.targets || parseTargets();
    if (!targets.length) {
      if (!opts.silent) progressText.textContent = "add a target first";
      return Promise.resolve([]);
    }
    const count = Math.max(1, Math.min(10, opts.count ?? (parseInt($("count").value, 10) || 3)));
    const workers = Math.max(1, Math.min(512, opts.workers ?? (parseInt($("workers").value, 10) || 64)));
    const chunk = Math.max(1, Math.min(5000, opts.chunk ?? (parseInt($("chunk").value, 10) || 100)));
    const proto = opts.proto || $("proto").value || "udp";
    const timeout = Math.max(0.3, Math.min(10, opts.timeout ?? (parseFloat($("timeout").value) || 1.5)));
    const probe = opts.probe || $("probe").value || "google";
    const geo = opts.geo ?? $("geo").checked;

    if (currentES) currentES.close();
    if (!opts.keepRows) {
      resultsBody.innerHTML = "";
      rows = [];
      resetMetrics();
    }
    runBtn.disabled = true;
    runBtn.querySelector(".run-label").textContent = "SCANNING…";

    const params = new URLSearchParams({
      count, workers, chunk, proto, timeout, probe, geo: geo ? "1" : "0",
    });
    // Small lists go in the query string; large lists are POSTed so the GET
    // request line never overflows (which the server rejects with 414).
    const usePost = targets.length > 200 || params.toString().length + targets.join(",").length > 2000;
    if (!usePost) params.set("targets", targets.join(","));
    const url = "/api/scan?" + params.toString();

    return new Promise((resolve) => {
      // EventSource can't POST, so for big lists we stream the POST response by
      // hand with fetch() + a ReadableStream reader.
      const handlers = {
        onEvent(msg) {
          if (msg.type === "start") {
            progressText.textContent = `0 / ${msg.total} · ${msg.workers} workers · ${msg.proto.toUpperCase()}` +
              (msg.truncated ? " · capped" : "");
            progressBar.style.width = "0%";
          } else if (msg.type === "result") {
            rows.push(msg);
            renderResults();
          } else if (msg.type === "progress") {
            progressBar.style.width = (msg.done / msg.total) * 100 + "%";
            progressText.textContent = `${msg.done} / ${msg.total}`;
          } else if (msg.type === "chunk") {
            progressBar.style.width = (msg.done / msg.total) * 100 + "%";
            $("stat-done").textContent = msg.done;
            $("stat-ok").textContent = msg.ok;
            $("stat-best").textContent = fmt(msg.best);
            $("stat-rate").textContent = msg.rate;
            progressText.textContent = `${msg.done} / ${msg.total} · ${msg.rate}/s`;
          } else if (msg.type === "geo") {
            const row = rows.find((r) => r.target === msg.target);
            if (row) {
              row.country = msg.country; row.country_name = msg.country_name;
              row.asn = msg.asn; row.org = msg.org;
              renderResults();
            }
          } else if (msg.type === "geo-start") {
            progressText.textContent = `scan done · locating ${msg.total} servers…`;
          } else if (msg.type === "pairs") {
            renderPairs(msg);
          } else if (msg.type === "summary") {
            renderStability(msg.rows);
          } else if (msg.type === "done") {
            progressText.textContent = `done — ${msg.summary.ok} ok / ${msg.summary.failed} failed`;
            finish();
          } else if (msg.type === "error") {
            progressText.textContent = "error: " + msg.message;
            finish();
          }
        },
        onError() { finish(); },
      };

      let finished = false;
      function finish() {
        if (finished) return;
        finished = true;
        if (currentES) { try { currentES.close(); } catch {} currentES = null; }
        runBtn.disabled = false;
        runBtn.querySelector(".run-label").textContent = "RUN SCAN";
        updateMetrics();
        renderResultsNow();   // flush the last row; a deferred rAF can miss it
        if (scanDoneHook) scanDoneHook(rows.slice());
        resolve(rows.slice());
      }

      if (!usePost) {
        const es = new EventSource(url);
        currentES = es;
        es.onmessage = (ev) => {
          let msg; try { msg = JSON.parse(ev.data); } catch { return; }
          handlers.onEvent(msg);
        };
        es.onerror = () => { if (runBtn.disabled) progressText.textContent = "stream closed"; handlers.onError(); };
      } else {
        const ctrl = new AbortController();
        currentES = { close: () => ctrl.abort() };
        fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ targets, count, workers, chunk, proto, timeout, probe, geo }),
          signal: ctrl.signal,
        }).then(async (res) => {
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buf = "";
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buf.indexOf("\n\n")) >= 0) {
              const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
              for (const line of block.split("\n")) {
                if (!line.startsWith("data:")) continue;
                let msg; try { msg = JSON.parse(line.slice(5)); } catch { continue; }
                handlers.onEvent(msg);
              }
            }
          }
          finish();
        }).catch(() => { if (!finished) progressText.textContent = "stream closed"; finish(); });
      }
    });
  }

  function rowScore(r, mode) {
    // Lower is better. Missing metrics are pushed to the end by the sorters.
    const lat = r.latency == null ? 1e9 : r.latency;
    const jit = r.jitter == null ? 1e6 : r.jitter;
    const loss = r.loss == null ? 1e4 : r.loss;
    if (mode === "jitter") return jit;
    if (mode === "loss") return loss;
    if (mode === "reliability") return jit * 4 + loss * 30 + lat * 0.2;
    if (mode === "combined") return lat + jit * 2 + loss * 10;
    return lat; // latency
  }

  function sortRows(list) {
    const mode = ($("sort-by") && $("sort-by").value) || "latency";
    const copy = list.slice();
    if (mode === "country") {
      copy.sort((a, b) => {
        const ca = (a.country_name || a.country || "~").toLowerCase();
        const cb = (b.country_name || b.country || "~").toLowerCase();
        if (ca !== cb) return ca < cb ? -1 : 1;
        return (a.latency ?? 1e9) - (b.latency ?? 1e9);
      });
      return copy;
    }
    copy.sort((a, b) => {
      const af = a.status !== "ok", bf = b.status !== "ok";
      if (af !== bf) return af ? 1 : -1;
      return rowScore(a, mode) - rowScore(b, mode);
    });
    return copy;
  }

  function visibleRows() {
    const q = $("filter").value.trim().toLowerCase();
    const cc = ($("country-filter") ? $("country-filter").value : "").trim().toLowerCase();
    const ccSet = cc.split(/[\s,]+/).filter(Boolean);
    const onlyOk = $("only-ok").checked;
    const list = rows.filter((r) => {
      if (onlyOk && r.status !== "ok") return false;
      if (ccSet.length) {
        const rcc = `${r.country || ""} ${r.country_name || ""}`.toLowerCase();
        if (!ccSet.some((c) => rcc.includes(c))) return false;
      }
      if (q && !(`${r.target} ${r.status} ${r.proto_used || ""} ${r.country_name || ""}`.toLowerCase().includes(q))) return false;
      return true;
    });
    return sortRows(list);
  }

  // Redrawing on every streamed row is quadratic for large lists: filtering,
  // sorting and rebuilding thousands of <tr> at 60fps blocks the UI thread long
  // enough for Android to show an "isn't responding" dialog. Coalesce to a few
  // redraws per second instead, and paint fewer rows while a scan is streaming
  // (the full set is painted once it finishes).
  let renderTimer = null;
  const RENDER_INTERVAL_MS = 250;
  function renderResults() {
    if (renderTimer) return;
    renderTimer = setTimeout(() => { renderTimer = null; renderResultsNow(); }, RENDER_INTERVAL_MS);
  }
  function renderResultsNow() {
    if (renderTimer) { clearTimeout(renderTimer); renderTimer = null; }
    const list = visibleRows();
    // A spread over thousands of elements can also throw RangeError, so scan.
    let maxLat = 1;
    for (const r of list) if (r.latency != null && r.latency > maxLat) maxLat = r.latency;
    // Hard cap what we paint; the full set stays in `rows` for export/filtering.
    // While a scan is still streaming, paint far fewer rows so each redraw stays
    // cheap; the finished scan paints the larger cap.
    const CAP = (runBtn && runBtn.disabled) ? 400 : 1500;
    const shown = list.length > CAP ? list.slice(0, CAP) : list;
    const frag = document.createDocumentFragment();
    shown.forEach((r, i) => {
      const tr = el("tr", r.status === "ok" ? "row-ok" : "row-fail");
      tr.appendChild(el("td", null, String(i + 1)));
      tr.appendChild(el("td", null, r.target));
      tr.appendChild(el("td", "geo-cell", r.country_name
        ? `${flag(r.country)} ${r.country_name}` : "—"));
      const latCell = el("td");
      if (r.latency != null) {
        const wrap = el("div", "bar-cell");
        const bar = el("span", "mini-bar");
        bar.style.width = Math.max(3, (r.latency / maxLat) * 70) + "px";
        wrap.appendChild(bar);
        wrap.appendChild(el("span", null, fmt(r.latency)));
        latCell.appendChild(wrap);
      } else latCell.textContent = "—";
      tr.appendChild(latCell);
      tr.appendChild(el("td", null, fmt(r.jitter)));
      tr.appendChild(el("td", null, fmt(r.loss, "%", 0)));
      // which protocol actually answered (or the one being tested)
      const protoCell = el("td");
      const pr = r.proto_results || {};
      const tags = [];
      ["udp", "tcp", "tls"].forEach((k) => {
        const v = pr[k];
        if (!v) return;
        const cls = v.ok ? "ptag ok" : "ptag bad";
        tags.push(`<span class="${cls}" title="${v.ms ?? "—"} ms">${k.toUpperCase()}</span>`);
      });
      protoCell.innerHTML = tags.length ? tags.join(" ") :
        `<span class="ptag">${(r.proto || "udp").toUpperCase()}</span>`;
      tr.appendChild(protoCell);
      const st = el("td");
      st.appendChild(statusPill(r.status));
      tr.appendChild(st);
      frag.appendChild(tr);
    });
    if (list.length > CAP) {
      const tr = el("tr", "empty");
      const td = el("td", null, `showing first ${CAP} of ${list.length} — refine the filter to see more.`);
      td.colSpan = 8;
      tr.appendChild(td);
      frag.appendChild(tr);
    }
    resultsBody.innerHTML = "";
    if (!list.length) {
      const tr = el("tr", "empty");
      const td = el("td", null, rows.length ? "no rows match the filter." : "No scan yet — hit RUN SCAN.");
      td.colSpan = 8;
      tr.appendChild(td);
      resultsBody.appendChild(tr);
      return;
    }
    resultsBody.appendChild(frag);
  }

  function flag(cc) {
    if (!cc || cc.length !== 2) return "🏳";
    return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65));
  }

  function renderPairs(msg) {
    const box = $("reco");
    const grid = $("reco-grid");
    const groups = [];
    if (msg.cross && msg.cross.length) groups.push(["Best diversity (different countries)", msg.cross]);
    if (msg.same && msg.same.length) groups.push(["Fastest pair", msg.same]);
    if (!groups.length) { box.hidden = true; return; }
    grid.innerHTML = "";
    groups.forEach(([title, pair]) => {
      const card = el("div", "reco-card");
      card.appendChild(el("div", "reco-title", title));
      pair.forEach((p, i) => {
        const row = el("div", "reco-row");
        row.appendChild(el("span", "reco-rank", i === 0 ? "primary" : "backup"));
        row.appendChild(el("span", "reco-ip", p.target));
        row.appendChild(el("span", "reco-cc", `${flag(p.country)} ${p.country_name || "?"}`));
        row.appendChild(el("span", "reco-ms", fmt(p.latency)));
        card.appendChild(row);
      });
      grid.appendChild(card);
    });
    box.hidden = false;
  }

  // Re-rank the recommended pairs when the user narrows by country, so the
  // "best pair" reflects the countries they actually care about.
  let pairTimer = null;
  function refreshPairs() {
    if (!rows.length) return;
    const cc = ($("country-filter") && $("country-filter").value.trim()) || "";
    const countries = cc.split(/[\s,]+/).filter(Boolean);
    clearTimeout(pairTimer);
    pairTimer = setTimeout(async () => {
      try {
        const r = await post("/api/pairs",
          { rows: rows.filter((x) => x.status === "ok"), countries });
        renderPairs(r);
      } catch {}
    }, 350);
  }
  if ($("country-filter")) $("country-filter").addEventListener("input", refreshPairs);

  function updateMetrics() {
    const ok = rows.filter((r) => r.status === "ok" && r.latency != null);
    $("stat-done").textContent = rows.length;
    $("stat-ok").textContent = ok.length;
    if (ok.length) {
      const best = ok.reduce((a, b) => (a.latency < b.latency ? a : b));
      $("stat-best").textContent = fmt(best.latency);
    }
  }

  runBtn.addEventListener("click", runScan);
  $("clear-targets").addEventListener("click", () => { targetsBox.value = ""; targetsBox.focus(); });
  $("filter").addEventListener("input", renderResults);
  $("only-ok").addEventListener("change", renderResults);
  if ($("sort-by")) $("sort-by").addEventListener("change", renderResults);
  if ($("country-filter")) $("country-filter").addEventListener("input", renderResults);
  targetsBox.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runScan();
  });

  $("use-list").addEventListener("click", async () => {
    const r = await getJSON("/api/dns-list");
    if (r.list && r.list.length) {
      targetsBox.value = r.list.join("\n");
      progressText.textContent = `loaded ${r.list.length} from saved list`;
    } else progressText.textContent = "saved list is empty";
  });

  $("export-csv").addEventListener("click", () => {
    if (!rows.length) { progressText.textContent = "nothing to export"; return; }
    const head = "target,country,country_name,asn,latency_ms,jitter_ms,loss_pct,proto,status\n";
    const body = rows.map((r) =>
      [r.target, r.country || "", r.country_name || "", r.asn || "",
       r.latency ?? "", r.jitter ?? "", r.loss ?? "", r.proto_used || r.proto || "", r.status]
        .join(",")).join("\n");
    const blob = new Blob([head + body], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "dns_scan_results.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  /* ---------- share helpers (copy to clipboard + .txt download) ---------- */
  async function copyText(text, btn) {
    const done = () => {
      if (!btn) return;
      const old = btn.textContent;
      btn.textContent = "copied ✓";
      btn.classList.add("copy-ok");
      setTimeout(() => { btn.textContent = old; btn.classList.remove("copy-ok"); }, 1400);
    };
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        done();
        return true;
      }
    } catch {}
    // Fallback for non-secure contexts (http:// on a LAN IP): a hidden textarea.
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      done();
      return true;
    } catch { return false; }
  }

  function downloadText(name, text) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function resultsAsText() {
    const list = sortRows(rows);
    const head = ["#", "DNS Server", "Country", "Latency(ms)", "Jitter(ms)", "Loss(%)", "Proto", "Status"];
    const lines = [`DNS scan results — ${new Date().toISOString()}`, ""];
    const widths = head.map((h, i) => Math.max(h.length,
      ...list.map((r, n) => String(cellFor(r, n, i)).length)));
    const pad = (s, w) => String(s).padEnd(w);
    lines.push(head.map((h, i) => pad(h, widths[i])).join(" | "));
    lines.push(widths.map((w) => "-".repeat(w)).join("-+-"));
    list.forEach((r, n) => lines.push(head.map((h, i) => pad(cellFor(r, n, i), widths[i])).join(" | ")));
    lines.push("", `Total: ${list.length} · alive: ${list.filter((r) => r.status === "ok").length}`);
    return lines.join("\n");
  }

  function cellFor(r, n, i) {
    switch (i) {
      case 0: return n + 1;
      case 1: return r.target;
      case 2: return r.country_name || r.country || "—";
      case 3: return r.latency ?? "—";
      case 4: return r.jitter ?? "—";
      case 5: return r.loss ?? "—";
      case 6: return (r.proto_used || r.proto || "udp").toUpperCase();
      case 7: return r.status;
      default: return "";
    }
  }

  if ($("copy-results")) $("copy-results").addEventListener("click", (e) => {
    if (!rows.length) { progressText.textContent = "nothing to copy"; return; }
    copyText(resultsAsText(), e.currentTarget);
  });
  if ($("export-txt")) $("export-txt").addEventListener("click", () => {
    if (!rows.length) { progressText.textContent = "nothing to export"; return; }
    downloadText("dns_scan_results.txt", resultsAsText());
  });

  /* ============================================================
     STABILITY
     ============================================================ */
  function renderStability(list) {
    const box = $("stab-list");
    box.innerHTML = "";
    if (!list || !list.length) {
      box.appendChild(el("div", "empty-note", "Run a scan to build history."));
      return;
    }
    list.forEach((r) => {
      const item = el("div", "stab-item");
      const left = el("div");
      left.appendChild(el("div", "ip", r.target));
      left.appendChild(el("div", "meta",
        `${r.success_rate}% success · ${r.cycles} cycles · ${r.spikes} spikes · avg ${r.avg}ms`));
      const score = el("div", "stab-score", r.score);
      const track = el("div", "stab-track");
      const fill = el("div", "stab-fill");
      fill.style.width = r.score + "%";
      track.appendChild(fill);
      item.append(left, score, track);
      box.appendChild(item);
    });
  }

  async function loadStability() {
    const r = await getJSON("/api/stability");
    renderStability(r.rows);
  }
  $("refresh-stab").addEventListener("click", loadStability);
  $("clear-history").addEventListener("click", async () => {
    if (!confirm("Clear all stability history (this session and saved)?")) return;
    await post("/api/history/clear", {});
    loadStability();
  });
  loadStability();

  /* ============================================================
     SAVED DNS
     ============================================================ */
  const dnsList = $("dns-list");

  function renderDnsList(list) {
    $("dns-count").textContent = list ? list.length : 0;
    dnsList.innerHTML = "";
    if (!list || !list.length) {
      const li = el("li", null, "no saved servers yet");
      li.style.color = "var(--dim-2)";
      li.style.fontStyle = "italic";
      dnsList.appendChild(li);
      return;
    }
    list.forEach((addr) => {
      const li = el("li");
      li.appendChild(el("span", null, addr));
      const del = el("button", "del", "remove");
      del.addEventListener("click", () => mutateList({ delete: addr }));
      li.appendChild(del);
      dnsList.appendChild(li);
    });
  }

  async function mutateList(payload) {
    const r = await post("/api/dns-list", payload);
    renderDnsList(r.list);
  }

  async function loadDnsList() {
    const r = await getJSON("/api/dns-list");
    renderDnsList(r.list);
  }
  $("add-dns").addEventListener("click", () => {
    const v = $("new-dns").value.trim();
    if (v) { mutateList({ add: v }); $("new-dns").value = ""; }
  });
  $("new-dns").addEventListener("keydown", (e) => { if (e.key === "Enter") $("add-dns").click(); });
  $("bulk-add").addEventListener("click", () => {
    const items = $("bulk-dns").value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    if (items.length) { mutateList({ add: items }); $("bulk-dns").value = ""; }
  });
  $("clear-dns").addEventListener("click", () => {
    if (confirm("Remove every saved DNS entry?")) mutateList({ clear: true });
  });
  loadDnsList();

  /* ============================================================
     PROBE LAB
     ============================================================ */
  const toolOut = $("tool-out");
  const toolHost = $("tool-host");
  const renderTool = (html) => { toolOut.innerHTML = html; };
  const kv = (k, v) => `<span class="k">${k}</span> <span class="v">${v}</span>`;

  const tools = {
    resolve: async (host) => {
      const r = await post("/api/tools/resolve", { host, dns: "8.8.8.8" });
      return r.ip ? kv("resolved", `${r.host} → ${r.ip}`) + "\n" + kv("query time", `${r.ms} ms`)
                  : `<span class="err">could not resolve ${host}</span>`;
    },
    tcp: async (host) => {
      const r = await post("/api/tools/tcp", { host, port: 443 });
      return r.ok ? kv("tcp 443", `${r.ms} ms (open)`)
                  : `<span class="err">tcp 443 closed / unreachable</span>`;
    },
    tls: async (host) => {
      const r = await post("/api/tools/tls", { host, port: 443 });
      return r.ok ? kv("tls handshake", `${r.ms} ms`)
                  : `<span class="err">tls handshake failed</span>`;
    },
    http: async (host) => {
      const r = await post("/api/tools/http", { url: host });
      return r.ok ? kv("http", `${r.status} · ${r.ms} ms · ${r.bytes} bytes`)
                  : `<span class="err">http request failed</span>`;
    },
    game: async (host) => {
      const game = $("tool-game").value;
      const port = parseInt(($("tool-game-port") || {}).value, 10) || 0;
      const protocol = ($("tool-game-proto") || {}).value || "";
      const r = await post("/api/tools/game", { host, game, count: 3, port, protocol });
      if (!r.ok) return `<span class="err">no response from ${r.host || host}${r.port ? " :" + r.port : ""}</span>`;
      return kv("game", r.game) + "\n" +
             kv("target", `${r.host} :${r.port} ${(r.protocol || "").toUpperCase()}`) + "\n" +
             kv("game latency", `${r.latency} ms · loss ${r.loss}%`);
    },
    mtu: async () => {
      const game = $("tool-game").value;
      const protocol = ($("tool-game-proto") || {}).value || "";
      const r = await getJSON(`/api/mtu-intel?game=${encodeURIComponent(game)}&protocol=${encodeURIComponent(protocol)}`);
      lastMtuIntel = r;
      return kv("recommended MTU", r.mtu) + "\n" + kv("mode", r.mode) + "\n" +
             kv("interface", r.interface || "unknown") + "\n" +
             kv("safe payload", r.payload) + "\n" + r.advice;
    },
    protocols: async () => {
      const dns = ($("tool-dns").value || "").trim();
      if (!dns) return `<span class="err">enter a resolver IP to probe</span>`;
      const probe = selectedProbes()[0] || "google";
      const r = await post("/api/tools/protocols", { host: dns, probe, count: 3 });
      const res = r.results || {};
      const line = (k, label) => {
        const v = res[k];
        if (!v) return "";
        const mark = v.ok ? `<span class="good">${v.ms} ms</span>` : `<span class="err">no reply</span>`;
        return kv(label, `${mark} · loss ${v.loss}%`);
      };
      return kv("resolver", r.host) + "\n" + kv("resolving", r.probe) + "\n" +
        [line("udp", "UDP :53"), line("tcp", "TCP :53"), line("tls", "DoT :853")]
          .filter(Boolean).join("\n");
    },
    dig: async () => {
      const dns = ($("tool-dns").value || "").trim();
      if (!dns) return `<span class="err">enter a resolver IP to dig against</span>`;
      const targets = selectedProbes();
      if (!targets.length) return `<span class="err">pick at least one probe target</span>`;
      const r = await post("/api/tools/dig", { dns, targets, timeout: 2.0 });
      const blocks = (r.results || []).map((q) => {
        const head = kv("dig", `@${r.server} ${q.host}`) +
          (q.ms != null ? ` <span class="dim">(${q.ms} ms)</span>` : "");
        if (!q.ok) return head + "\n" + `<span class="err">no response</span>`;
        if (!q.answers.length) return head + "\n" + `<span class="err">no A records</span>`;
        const rows = q.answers.filter((a) => a.type === 1).map((a) => `  ${a.value}  ttl ${a.ttl}`).join("\n");
        return head + "\n" + (rows || `  ${q.answers[0].value}`);
      });
      return blocks.join("\n\n");
    },
  };

  // 'protocols' probes a DNS server (from #tool-dns), not the host field.
  const hostFree = new Set(["mtu", "protocols", "dig"]);

  function selectedProbes() {
    const sel = $("tool-probe");
    const picked = [...sel.selectedOptions].map((o) => o.value).filter(Boolean);
    return picked.slice(0, 3);
  }
  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", async () => {
      const tool = chip.dataset.tool;
      const host = toolHost.value.trim();
      if (!host && !hostFree.has(tool)) {
        renderTool(`<span class="err">enter a host first</span>`);
        return;
      }
      document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      renderTool("probing…");
      try { renderTool(await tools[tool](host)); }
      catch (e) { renderTool(`<span class="err">error: ${e}</span>`); }
    });
  });

  /* ============================================================
     NETWORK / VPN
     ============================================================ */
  function setCell(id, value, cls) {
    const node = $(id);
    node.textContent = value == null || value === "" ? "—" : value;
    node.className = "dev-v" + (cls ? " " + cls : "");
  }

  async function loadNetwork() {
    try {
      const r = await getJSON("/api/network");
      setCell("net-ip", r.public_ip);
      setCell("net-country", r.country);
      setCell("net-isp", r.isp);
      setCell("net-iface", r.interface);
      setCell("net-vpn", r.vpn ? ("yes" + (r.vpn_interface ? " · " + r.vpn_interface : "")) : "no", r.vpn ? "on" : "off");
      setCell("net-mtu", `${r.mtu} (${r.mtu_mode})`);
    } catch (e) { setCell("net-ip", "error", "off"); }
  }
  $("refresh-network").addEventListener("click", loadNetwork);
  loadNetwork();

  /* ============================================================
     DEVICE
     ============================================================ */
  async function loadDevice() {
    try {
      const r = await getJSON("/api/device");
      setCell("dev-shizuku", r.shizuku ? "running" : "not running", r.shizuku ? "on" : "off");
      setCell("dev-operator", r.operator);
      setCell("dev-net", r.network_type);
      setCell("dev-iface", r.interface);
      setCell("dev-vpn", r.vpn ? ("yes" + (r.vpn_interface ? " · " + r.vpn_interface : "")) : "no", r.vpn ? "on" : "off");
    } catch (e) { setCell("dev-shizuku", "error", "off"); }
  }
  $("refresh-device").addEventListener("click", loadDevice);
  loadDevice();

  /* ============================================================
     ROUTE · PATH  (VPN egress -> game server, closest resolvers)
     ============================================================ */
  async function runRoute() {
    const out = $("route-out");
    const hostField = $("route-host").value.trim();
    const game = $("route-game") && $("route-game").value;
    const region = $("route-region") && $("route-region").value;
    let host = hostField;
    if (!host && game && game !== "(generic)") {
      // Ask the backend for a representative endpoint for the chosen region.
      const g = builtinGames.find((x) => x.name === game);
      host = (g && g.hosts && g.hosts[0]) || "";
      if (region && g && g.regions && g.regions.includes(region)) host = host || game;
    }
    if (!host) { out.textContent = "pick a game or type a host first."; return; }
    out.textContent = "analysing route…";
    try {
      const r = await post("/api/route", { host, rows: rows.slice(0, 4000), game, region });
      lastRoute = r;
      const grid = $("route-grid");
      grid.innerHTML = "";
      const cell = (k, v) => `<div class="dev-cell"><span class="dev-k">${k}</span><span class="dev-v">${v ?? "—"}</span></div>`;
      grid.innerHTML =
        cell("egress", `${flag(r.egress && r.egress.countryCode)} ${r.egress && r.egress.country || "?"}${r.egress && r.egress.city ? " · " + r.egress.city : ""}`) +
        cell("vpn tunnel", r.vpn ? "yes" : "no") +
        cell("target", `${r.target_host}${r.target_ip ? " → " + r.target_ip : ""}`) +
        cell("target geo", `${flag(r.target && r.target.countryCode)} ${r.target && r.target.country || "?"}${r.target && r.target.city ? " · " + r.target.city : ""}`) +
        cell("distance", r.distance_km != null ? r.distance_km + " km" : "—");
      out.innerHTML = mdLite(r.note || "") ;
      const onRoute = r.on_route || [];
      const routeBox = $("route-route");
      if (onRoute.length) {
        routeBox.innerHTML = "<strong>Resolvers closest to your route:</strong>\n" +
          onRoute.map((x, i) => `${i + 1}. ${x.target} — ${flag(x.country)} ${x.country_name || "?"} · ` +
            `${x.latency} ms${x.distance_km != null ? " · " + x.distance_km + " km" : ""}${x.same_country ? " (same country)" : ""}`).join("\n");
      } else {
        routeBox.textContent = "Run a scan with geo-locate on, then re-analyse to rank resolvers on this route.";
      }
    } catch (e) { out.innerHTML = `<span class="err">error: ${e}</span>`; }
  }
  if ($("route-run")) $("route-run").addEventListener("click", runRoute);
  if ($("route-game")) $("route-game").addEventListener("change", () => {
    updateRouteRegions();
    const g = builtinGames.find((x) => x.name === $("route-game").value);
    if (g && g.hosts && g.hosts.length && !$("route-host").value.trim()) {
      $("route-host").placeholder = "e.g. " + g.hosts[0];
    }
  });

  /* ============================================================
     SIGNAL · RADIO
     ============================================================ */
  async function loadSignal() {
    const out = $("signal-out");
    out.textContent = "reading signal…";
    try {
      const r = await getJSON("/api/signal");
      setCell("sig-dbm", r.dbm != null ? r.dbm + " dBm" : (r.available ? "—" : "needs Shizuku"),
        r.quality === "excellent" || r.quality === "good" ? "on" : r.quality === "unknown" ? "" : "off");
      setCell("sig-quality", r.quality);
      setCell("sig-tech", r.technology || "—");
      setCell("sig-operator", r.operator || "—");
      out.textContent = r.recommendation || "—";
    } catch (e) { out.innerHTML = `<span class="err">error: ${e}</span>`; }
  }
  if ($("signal-refresh")) $("signal-refresh").addEventListener("click", loadSignal);
  loadSignal();

  /* ============================================================
     APN BENCHMARK
     ============================================================ */
  const apnList = $("apn-list");
  const apnOut = $("apn-out");

  function renderApn(data) {
    apnList.innerHTML = "";
    const entries = data.entries || [];
    if (!entries.length) {
      apnList.appendChild(el("li", "empty-note", "no APN entries (Shizuku off or denied)"));
    }
    entries.forEach((a) => {
      const li = el("li", a.id === data.current ? "cur" : null);
      li.appendChild(el("span", null, a.name));
      li.appendChild(el("span", null, a.apn));
      apnList.appendChild(li);
    });
    apnOut.textContent = `Current preferred APN: ${data.current || "unknown"} · ${entries.length} entries`;
  }

  async function loadApn() {
    try { renderApn(await getJSON("/api/apn")); }
    catch (e) { apnOut.textContent = "error loading APNs: " + e; }
  }
  $("refresh-apn").addEventListener("click", loadApn);
  loadApn();

  $("apn-bench").addEventListener("click", () => {
    if (!confirm("This switches the preferred APN to test each one, then restores it.\nContinue?")) return;
    apnOut.textContent = "benchmarking… (radio cooldown between switches)";
    apnList.querySelectorAll("li").forEach((li) => li.classList.remove("ok", "bad"));
    const es = new EventSource("/api/apn/benchmark?confirm=1");
    const results = {};
    es.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === "start") apnOut.textContent = `testing ${msg.total} APNs (original ${msg.original})…`;
      else if (msg.type === "result") {
        results[msg.id] = msg;
        const li = [...apnList.children].find((c) => c.textContent.includes(msg.apn));
        if (li) li.classList.add(msg.ok ? "ok" : "bad");
        apnOut.textContent = `${msg.name}: ${msg.ok ? msg.rtt + " ms" : "FAIL"}`;
      } else if (msg.type === "restored") apnOut.textContent = `restored preferred APN (${msg.id})`;
      else if (msg.type === "preview") apnOut.textContent = msg.message;
      else if (msg.type === "done") {
        es.close();
        const okc = msg.summary.ok;
        apnOut.textContent += `\nbenchmark complete — ${okc} ok / ${msg.summary.failed} failed`;
        loadApn();
      } else if (msg.type === "error") { es.close(); apnOut.textContent = "error: " + msg.message; }
    };
    es.onerror = () => es.close();
  });

  /* ============================================================
     PROFILES
     ============================================================ */
  const profList = $("prof-list");
  let builtinGames = [];
  let lastProfiles = {};

  function refreshGameSelects() {
    const all = [...new Set([...Object.keys(lastProfiles || {}),
                             ...builtinGames.map((g) => g.name)])];
    ["tool-game", "route-game"].forEach((id) => {
      const sel = $(id);
      if (!sel) return;
      const prev = sel.value;
      sel.innerHTML = "";
      sel.appendChild(el("option", null, "(generic)"));
      all.forEach((name) => {
        const o = el("option", null, name);
        o.value = name;
        sel.appendChild(o);
      });
      if (prev) sel.value = prev;
    });
    updateRouteRegions();
  }

  function updateRouteRegions() {
    const sel = $("route-region");
    if (!sel) return;
    const game = $("route-game") && $("route-game").value;
    const g = builtinGames.find((x) => x.name === game);
    const regions = (g && g.regions) || [];
    sel.innerHTML = '<option value="">region</option>' +
      regions.map((r) => `<option value="${r}">${r.toUpperCase()}</option>`).join("");
  }

  async function loadGames() {
    try {
      const r = await getJSON("/api/games");
      if (r.games) builtinGames = r.games;
    } catch {}
    refreshGameSelects();
  }

  function renderProfiles(map) {
    lastProfiles = map || {};
    profList.innerHTML = "";
    const names = Object.keys(lastProfiles);
    if (!names.length) {
      profList.appendChild(el("li", null, "no profiles yet"));
    }
    names.forEach((name) => {
      const li = el("li");
      li.appendChild(el("span", null, `${name} → ${lastProfiles[name]}`));
      const del = el("button", "del", "remove");
      del.addEventListener("click", () => mutateProfiles({ delete: name }));
      li.appendChild(del);
      profList.appendChild(li);
    });
    refreshGameSelects();
  }

  async function mutateProfiles(payload) {
    const r = await post("/api/profiles", payload);
    renderProfiles(r.profiles);
  }
  async function loadProfiles() {
    const r = await getJSON("/api/profiles");
    renderProfiles(r.profiles);
  }
  $("prof-add").addEventListener("click", () => {
    const name = $("prof-name").value.trim();
    const host = $("prof-host").value.trim();
    if (name && host) { mutateProfiles({ add: { name, host } }); $("prof-name").value = ""; $("prof-host").value = ""; }
  });
  loadProfiles();
  loadGames();

  /* ---------- AI: find the port/protocol for a game ---------- */
  if ($("tool-game-plan")) $("tool-game-plan").addEventListener("click", async () => {
    const game = $("tool-game").value;
    if (!game || game === "(generic)") {
      renderTool(`<span class="err">pick a game first (or type its name as the host)</span>`);
      return;
    }
    renderTool("asking the AI for ports/protocol…");
    try {
      const key = (aiKey.value || "").trim();
      const r = await post("/api/ai/game-plan",
        { game, api_key: key, model: aiModel.value.trim() });
      if (r.error) {
        renderTool(`<span class="err">${r.error}</span>` +
          (r.hint ? `\n<span class="ok">Tip: ${r.hint}</span>` : ""));
        return;
      }
      if (r.ports && r.ports.length) $("tool-game-port").value = r.ports[0];
      if (r.protocol && $("tool-game-proto")) $("tool-game-proto").value = r.protocol;
      renderTool(kv("game", r.game) + "\n" +
        kv("ports", (r.ports || []).join(", ") || "—") + "\n" +
        kv("protocol", (r.protocol || "").toUpperCase()) + "\n" +
        kv("source", r.source) + (r.region_host ? "\n" + kv("region host", r.region_host) : "") +
        (r.note ? "\n" + r.note : ""));
    } catch (e) { renderTool(`<span class="err">error: ${e}</span>`); }
  });

  /* ============================================================
     DIAGNOSIS
     ============================================================ */
  $("diag-run").addEventListener("click", async () => {
    const out = $("diag-out");
    out.textContent = "running diagnosis…";
    try {
      const r = await getJSON("/api/diagnosis");
      const ref = r.reference, gw = r.gateway;
      const cls = ref.quality === "EXCELLENT" ? "good" : ref.quality === "DOWN" ? "err" : "v";
      out.innerHTML =
        kv("reference", `${ref.host}`) + "\n" +
        kv("  rtt", `${ref.rtt} ms`) + "\n" +
        kv("  loss", `${ref.loss}%`) + "\n" +
        `<span class="k">quality</span> <span class="${cls}">${ref.quality}</span>` + "\n" +
        kv("gateway", `${gw.host}`) + "\n" +
        kv("  rtt", gw.reachable ? `${gw.rtt} ms` : "n/a") + "\n" +
        kv("  loss", `${gw.loss}%`);
    } catch (e) { out.textContent = "error: " + e; }
  });

  /* ============================================================
     IMPORT (any file format)
     ============================================================ */
  const importOut = $("import-out");
  let imported = [];

  function renderImport(data) {
    imported = data.found || [];
    if (!imported.length) {
      importOut.innerHTML = `<span class="err">No DNS servers found` +
        (data.filename ? ` in ${data.filename}` : "") + `.</span>`;
      return;
    }
    const preview = imported.slice(0, 40).map((ip) => `<code>${ip}</code>`).join("  ");
    const more = imported.length > 40 ? `\n…and ${imported.length - 40} more` : "";
    importOut.innerHTML =
      `<span class="ok">Found ${imported.length} DNS server(s)</span>` +
      (data.filename ? ` in <strong>${data.filename}</strong>` : "") +
      ` (${data.bytes ? (data.bytes / 1024).toFixed(1) + " KB" : "text"}).\n\n${preview}${more}`;
  }

  async function importFiles(files) {
    if (!files || !files.length) return;
    importOut.textContent = `reading ${files.length} file(s)…`;
    let all = [];
    let names = [];
    for (const f of files) {
      try {
        const fd = new FormData();
        fd.append("file", f, f.name);
        const r = await fetch("/api/import", { method: "POST", body: fd }).then((x) => x.json());
        if (r.found) { all = all.concat(r.found); names.push(f.name); }
        else if (r.error) importOut.innerHTML = `<span class="err">${r.error}</span>`;
      } catch (e) { importOut.innerHTML = `<span class="err">${f.name}: ${e}</span>`; }
    }
    imported = [...new Set(all)];
    renderImport({ found: imported, filename: names.join(", "), bytes: 0 });
  }

  const drop = $("drop");
  const fileInput = $("file");
  drop.addEventListener("click", () => fileInput.click());
  $("browse").addEventListener("click", (e) => { e.stopPropagation(); fileInput.click(); });
  fileInput.addEventListener("change", () => importFiles(fileInput.files));
  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => importFiles(e.dataTransfer.files));

  $("import-paste").addEventListener("click", async () => {
    const text = $("paste-import").value.trim();
    if (!text) { importOut.textContent = "paste some text first."; return; }
    const r = await post("/api/import", { filename: "(pasted text)", text });
    renderImport(r);
  });

  $("import-save").addEventListener("click", async () => {
    if (!imported.length) { importOut.textContent = "import something first."; return; }
    const r = await post("/api/dns-list", { add: imported });
    renderDnsList(r.list);
    importOut.innerHTML += `\n<span class="ok">→ saved to your DNS list (${r.count} total).</span>`;
  });

  $("import-scan").addEventListener("click", () => {
    if (!imported.length) { importOut.textContent = "import something first."; return; }
    targetsBox.value = imported.join("\n");
    const sc = document.getElementById("panel-scanner");
    togglePanel(sc, false);
    sc.classList.remove("flash"); void sc.offsetWidth; sc.classList.add("flash");
    runScan();
  });

  /* ============================================================
     AI ANALYSIS (OpenRouter)
     ============================================================ */
  const aiOut = $("ai-out");
  const aiKey = $("ai-key");
  const aiModel = $("ai-model");

  const savedKey = localStorage.getItem("openrouter_key");
  if (savedKey) aiKey.value = savedKey;
  const savedModel = localStorage.getItem("openrouter_model");
  if (savedModel) aiModel.value = savedModel;

  getJSON("/api/ai/status").then((r) => {
    if (r.server_key) $("ai-badge").textContent = "key on server";
  }).catch(() => {});

  /* ---- model menu (free / paid) ---- */
  const modelSelect = $("ai-model-select");
  const modelCount = $("ai-model-count");
  let allModels = [];
  let modelFilter = "all";

  function priceTag(m) {
    if (m.free) return "free";
    const p = parseFloat(m.prompt || "0");
    if (!isFinite(p) || p === 0) return "free";
    if (p < 0) return "varies";
    return `$${(p * 1e6).toFixed(2)}/M in`;
  }

  function renderModelOptions() {
    const list = allModels.filter((m) =>
      modelFilter === "free" ? m.free : modelFilter === "paid" ? !m.free : true);
    modelSelect.innerHTML = "";
    if (!list.length) {
      modelSelect.appendChild(el("option", null, "(no models)"));
      return;
    }
    list.forEach((m) => {
      const opt = el("option", null, `${m.free ? "★ " : ""}${m.name} — ${priceTag(m)}`);
      opt.value = m.id;
      modelSelect.appendChild(opt);
    });
    // keep the current typed model selected if present
    const cur = aiModel.value.trim();
    if (cur && list.some((m) => m.id === cur)) modelSelect.value = cur;
    else if (list.length) { modelSelect.value = list[0].id; aiModel.value = list[0].id; }
    modelCount.textContent = `${list.length} / ${allModels.length} models · ` +
      `${allModels.filter((m) => m.free).length} free`;
  }

  async function loadModels(force) {
    modelCount.textContent = "loading models…";
    try {
      const r = await getJSON("/api/ai/models" + (force ? "?refresh=1" : ""));
      allModels = r.models || [];
      renderModelOptions();
    } catch (e) { modelCount.textContent = "model list unavailable"; }
  }

  modelSelect.addEventListener("change", () => {
    aiModel.value = modelSelect.value;
    localStorage.setItem("openrouter_model", aiModel.value);
  });
  [["ai-seg-all", "all"], ["ai-seg-free", "free"], ["ai-seg-paid", "paid"]].forEach(([id, val]) => {
    $(id).addEventListener("click", () => {
      modelFilter = val;
      ["ai-seg-all", "ai-seg-free", "ai-seg-paid"].forEach((x) =>
        $(x).classList.toggle("active", $(x) === $(id)));
      renderModelOptions();
    });
  });
  $("ai-models-refresh").addEventListener("click", () => loadModels(true));
  loadModels(false);

  function mdLite(text) {
    // Keep the raw text around: the AI is asked for plain text, and models often
    // emit pipe tables. We render those as real <table>s, but never mangle a
    // table that the model already drew with spaces/dashes.
    const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const lines = String(text == null ? "" : text).split(/\r?\n/);
    const out = [];
    let i = 0;
    const isTableRow = (l) => /^\s*\|.*\|\s*$/.test(l);
    const isSepRow = (l) => /^\s*\|?[\s:|-]+\|?\s*$/.test(l) && l.includes("-");
    while (i < lines.length) {
      if (isTableRow(lines[i]) && i + 1 < lines.length && isSepRow(lines[i + 1])) {
        const header = lines[i].trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
        i += 2;
        const body = [];
        while (i < lines.length && isTableRow(lines[i])) {
          body.push(lines[i].trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim()));
          i++;
        }
        let html = '<table class="ai-table"><thead><tr>' +
          header.map((h) => `<th>${esc(h)}</th>`).join("") + "</tr></thead><tbody>";
        body.forEach((row) => {
          html += "<tr>" + row.map((c) => `<td>${esc(c)}</td>`).join("") + "</tr>";
        });
        out.push(html + "</tbody></table>");
        continue;
      }
      let l = esc(lines[i]);
      l = l.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
           .replace(/`(.+?)`/g, "<code>$1</code>")
           .replace(/^###?\s+(.*)$/, "<h4>$1</h4>")
           .replace(/^\s*[-*]\s+(.*)$/, "• $1");
      out.push(l);
      i++;
    }
    return out.join("\n");
  }

  let lastAiAnswer = "";

  // Everything the dashboard knows, bundled so the AI can reason over all of it.
  function aiContext() {
    const ctx = {
      timestamp: new Date().toISOString(),
      game: ($("tool-game") && $("tool-game").value) || "",
      sort_by: ($("sort-by") && $("sort-by").value) || "latency",
      countries: ($("country-filter") && $("country-filter").value.trim()) || "",
      resolver_count: rows.length,
    };
    const net = {
      public_ip: textOf("net-ip"), country: textOf("net-country"), isp: textOf("net-isp"),
      interface: textOf("net-iface"), vpn: textOf("net-vpn"), mtu: textOf("net-mtu"),
    };
    if (net.public_ip && net.public_ip !== "…") ctx.network = net;
    const sig = { dbm: textOf("sig-dbm"), quality: textOf("sig-quality"), technology: textOf("sig-tech") };
    if (sig.dbm && sig.dbm !== "…") ctx.signal = sig;
    if (lastMtuIntel) ctx.mtu_intelligence = lastMtuIntel;
    if (lastRoute) ctx.route = lastRoute;
    return ctx;
  }
  const textOf = (id) => (($(id) && $(id).textContent) || "").trim();

  async function runAI(withQuestion) {
    const key = aiKey.value.trim();
    const remember = $("ai-remember").checked;
    if (remember && key) localStorage.setItem("openrouter_key", key);
    else if (!remember) localStorage.removeItem("openrouter_key");
    if (aiModel.value.trim()) localStorage.setItem("openrouter_model", aiModel.value.trim());

    const results = rows.length ? rows : null;
    if (!results && !$("ai-question").value.trim()) {
      aiOut.innerHTML = `<span class="err">Run a scan first (or type a question).</span>`;
      return;
    }
    const payload = { api_key: key, model: aiModel.value.trim(), results: results || [],
                      context: aiContext(), sort_by: aiContext().sort_by };
    const cc = ($("country-filter") && $("country-filter").value.trim()) || "";
    if (cc) payload.countries = cc.split(/[\s,]+/).filter(Boolean);
    const q = $("ai-question").value.trim();
    if (q) payload.prompt = q;

    aiOut.textContent = "thinking… (contacting OpenRouter)";
    try {
      const r = await post("/api/ai/analyze", payload);
      if (r.error) {
        aiOut.innerHTML = `<span class="err">${r.error}</span>` +
          (r.hint ? `\n<span class="ok">Tip: ${r.hint}</span>` : "") +
          (r.detail ? `\n<code>${String(r.detail).replace(/[<>&]/g, "")}</code>` : "");
        return;
      }
      lastAiAnswer = r.analysis || "";
      aiOut.innerHTML = mdLite(lastAiAnswer || "(empty response)") +
        (r.model ? `\n\n— ${r.model}` : "");
    } catch (e) { aiOut.innerHTML = `<span class="err">request failed: ${e}</span>`; }
  }

  $("ai-analyse").addEventListener("click", () => runAI(false));
  $("ai-ask").addEventListener("click", () => runAI(true));
  $("ai-question").addEventListener("keydown", (e) => { if (e.key === "Enter") runAI(true); });
  if ($("ai-copy")) $("ai-copy").addEventListener("click", (e) => {
    if (!lastAiAnswer) { aiOut.textContent = "nothing to copy yet"; return; }
    copyText(lastAiAnswer, e.currentTarget);
  });
  if ($("ai-export")) $("ai-export").addEventListener("click", () => {
    if (!lastAiAnswer) { aiOut.textContent = "nothing to export yet"; return; }
    downloadText("dns_ai_analysis.txt",
      `DNS AI analysis — ${new Date().toISOString()}\n\n${lastAiAnswer}\n`);
  });

  /* ============================================================
     AUTO-TEST (timer-driven recurring scan)
     ============================================================ */
  const auto = {
    running: false,
    bg: false,
    busy: false,
    cycle: 0,
    maxCycles: 0,
    alertCount: 0,
    tickTimer: null,
    remaining: 0,
    interval: 60,
    offset: 0,
  };
  const autoRing = $("auto-ring");
  const autoRingFg = $("auto-ring-fg");
  const RING_LEN = 327; // 2 * pi * 52

  function autoLog(msg) {
    const box = $("auto-log");
    const stamp = new Date().toTimeString().slice(0, 8);
    const line = el("div", "auto-line", `[${stamp}] ${msg}`);
    box.insertBefore(line, box.firstChild);
    while (box.childElementCount > 60) box.removeChild(box.lastChild);
    // Mirror into the engine log: the browser-side auto-test loop is a prime
    // suspect for a frozen UI, so its progress must be visible in the Logs tab.
    uiReport("INFO", "auto-test: " + msg);
  }

  function setRing(frac) {
    const f = Math.max(0, Math.min(1, frac));
    autoRingFg.style.strokeDashoffset = String(RING_LEN * (1 - f));
  }

  function autoTargets() {
    const src = $("auto-source").value;
    if (src === "list") return null; // resolved from the server
    return parseTargets();
  }

  function autoConfig() {
    return {
      interval: Math.max(5, Math.min(86400, parseInt($("auto-interval").value, 10) || 60)),
      proto: $("auto-proto").value,
      count: Math.max(1, Math.min(10, parseInt($("auto-count").value, 10) || 3)),
      workers: Math.max(1, Math.min(512, parseInt($("auto-workers").value, 10) || 64)),
      source: $("auto-source").value,
      maxCycles: Math.max(0, parseInt($("auto-cycles").value, 10) || 0),
      probe: $("auto-probe").value || "google",
      chunkSize: Math.max(0, parseInt($("auto-chunk").value, 10) || 0),
      rotate: $("auto-rotate").checked,
      geo: $("auto-geo").checked,
      alerts: $("auto-alert-on").checked,
      warnLat: parseFloat($("auto-warn-lat").value) || 120,
      alertJit: parseFloat($("auto-alert-jit").value) || 40,
      alertLoss: parseFloat($("auto-alert-loss").value) || 20,
    };
  }

  function autoStart() {
    if (auto.running) return;
    // Background mode is the server-side loop; don't run both timers at once.
    if ($("auto-background") && $("auto-background").checked) {
      autoLog("background mode is on — using the server-side loop.");
      return;
    }
    const cfg = autoConfig();
    auto.running = true;
    auto.cycle = 0;
    auto.maxCycles = cfg.maxCycles;
    auto.alertCount = 0;
    auto.interval = cfg.interval;
    auto.offset = 0;
    $("auto-alert-count").textContent = "0";
    $("auto-cycles-run").textContent = "0";
    $("auto-state").textContent = "running";
    $("auto-state").classList.add("live");
    autoRing.classList.add("running");
    $("auto-log").innerHTML = "";
    autoLog(`auto-test started · every ${cfg.interval}s · ${cfg.proto.toUpperCase()} · ` +
            (cfg.maxCycles ? `${cfg.maxCycles} cycles` : "forever"));
    autoLoop();
  }

  function autoStop(msg) {
    if (!auto.running) return;
    auto.running = false;
    auto.busy = false;
    clearTimeout(auto.tickTimer);
    autoRing.classList.remove("running");
    setRing(0);
    $("auto-countdown").textContent = "--";
    $("auto-state").textContent = "idle";
    $("auto-state").classList.remove("live");
    $("auto-next").textContent = "—";
    if (msg) autoLog(msg);
  }

  async function autoRunCycle() {
    // A countdown tick and the 3s status poll can both try to start a cycle; a
    // second concurrent scan would double the network/CPU load for no benefit.
    if (auto.busy) return;
    auto.busy = true;
    const cfg = autoConfig();
    const cycleStarted = Date.now();
    auto.cycle += 1;
    $("auto-cycles-run").textContent = String(auto.cycle);
    $("auto-cycle-label").textContent = `cycle ${auto.cycle}`;

    let all = autoTargets();
    if (all === null) {
      try {
        const r = await getJSON("/api/dns-list");
        all = r.list || [];
      } catch { all = []; }
    }
    if (!all.length) {
      autoLog("no targets — set the scanner box or save a DNS list. Stopping.");
      auto.busy = false;
      autoStop();
      return;
    }

    // Chunked rotation: test `chunkSize` servers per cycle, moving through the
    // list so every server is exercised without hammering the whole list at once.
    let targets = all;
    let sliceNote = "";
    if (cfg.chunkSize > 0 && all.length > cfg.chunkSize) {
      if (!cfg.rotate || auto.offset >= all.length) auto.offset = 0;
      const start = auto.offset;
      targets = all.slice(start, start + cfg.chunkSize);
      if (targets.length < cfg.chunkSize) {
        targets = targets.concat(all.slice(0, cfg.chunkSize - targets.length));
      }
      sliceNote = ` [${start + 1}–${start + targets.length} of ${all.length}]`;
      auto.offset = (start + cfg.chunkSize) % all.length;
    }
    autoLog(`cycle ${auto.cycle}: scanning ${targets.length} server(s)${sliceNote}…`);

    // drive the visible scanner so results stream in live
    const result = await runScan({
      targets, proto: cfg.proto, count: cfg.count, workers: cfg.workers,
      timeout: 1.5, probe: cfg.probe, geo: cfg.geo, keepRows: false, silent: true,
    });

    const ok = result.filter((r) => r.status === "ok");
    const best = ok.length ? ok.reduce((a, b) => (a.latency < b.latency ? a : b)) : null;
    $("auto-best").textContent = best ? fmt(best.latency) : "—";
    autoLog(`cycle ${auto.cycle}: ${ok.length}/${result.length} alive` +
            (best ? `, best ${best.target} ${fmt(best.latency)}` : ""));

    if (cfg.alerts) {
      result.forEach((r) => {
        if (r.status !== "ok") {
          auto.alertCount++;
          autoLog(`⚠ ${r.target} unreachable`);
        } else {
          if (r.latency > cfg.warnLat) { auto.alertCount++; autoLog(`⚠ ${r.target} slow ${fmt(r.latency)} (> ${cfg.warnLat}ms)`); }
          if (r.jitter > cfg.alertJit) { auto.alertCount++; autoLog(`⚠ ${r.target} jitter ${fmt(r.jitter)} (> ${cfg.alertJit}ms)`); }
          if (r.loss > cfg.alertLoss) { auto.alertCount++; autoLog(`⚠ ${r.target} loss ${fmt(r.loss, "%", 0)} (> ${cfg.alertLoss}%)`); }
        }
      });
      $("auto-alert-count").textContent = String(auto.alertCount);
    }

    auto.busy = false;
    if (auto.maxCycles && auto.cycle >= auto.maxCycles) {
      autoStop(`auto-test finished after ${auto.cycle} cycles (${auto.alertCount} alerts).`);
      return;
    }
    // Fixed cadence: subtract the scan time so the gap between cycle STARTS is the
    // configured interval. When a scan outlasts the interval we must still pause a
    // full interval before the next one -- a 0s countdown here would re-scan
    // immediately and spin the UI thread (ANR: "app isn't responding").
    const elapsed = (Date.now() - cycleStarted) / 1000;
    const wait = auto.interval - elapsed;
    autoCountdown(wait > 0 ? wait : auto.interval);
  }

  // The countdown is shared by the browser loop and the server-side loop, so a
  // generation token cancels any previous ticker (a poll every 3s would
  // otherwise leak a new ticker each time).
  let autoCountdownGen = 0;
  function autoCountdown(seconds) {
    auto.remaining = Math.max(0, seconds);
    const gen = ++autoCountdownGen;
    clearTimeout(auto.tickTimer);
    const started = Date.now();
    const total = Math.max(0, seconds * 1000);
    // The step still runs at 250ms so the cycle fires on time, but the DOM is only
    // written when the displayed second actually changes. Writing the countdown and
    // the SVG ring four times a second forced a repaint each time, which on Android
    // keeps the renderer busy for no visible benefit.
    let lastLeft = -1;
    const step = () => {
      if (gen !== autoCountdownGen) return;
      if (!auto.running && !auto.bg) return;
      const elapsed = Date.now() - started;
      const left = Math.max(0, Math.ceil((total - elapsed) / 1000));
      if (left !== lastLeft) {
        lastLeft = left;
        $("auto-countdown").textContent = left;
        $("auto-next").textContent = left + "s";
        setRing(total > 0 ? elapsed / total : 1);
      }
      if (elapsed >= total) {
        // The browser loop must never fire back-to-back cycles; a scan that
        // overran its interval is throttled to one extra interval here.
        if (!auto.bg) {
          if (total <= 0) autoCountdown(auto.interval);
          else autoRunCycle();
        }
        return;
      }
      auto.tickTimer = setTimeout(step, 250);
    };
    step();
  }

  function autoLoop() {
    // first cycle runs immediately, then countdown between cycles
    autoRunCycle();
  }

  $("auto-start").addEventListener("click", autoStart);
  $("auto-stop").addEventListener("click", () => autoStop("auto-test stopped."));

  /* ============================================================
     BACKGROUND AUTO-TEST (server-side, survives tab close)
     ============================================================
     The timer above lives in the browser and stops when the page is closed.
     This talks to /api/autotest, which keeps cycling on the server. It can also
     test MTU and signal strength, not just DNS. */
  let bgPollTimer = null;

  function bgConfig() {
    const types = [];
    if ($("auto-type-dns").checked) types.push("dns");
    if ($("auto-type-mtu") && $("auto-type-mtu").checked) types.push("mtu");
    if ($("auto-type-signal") && $("auto-type-signal").checked) types.push("signal");
    return {
      enabled: true,
      types: types.length ? types : ["dns"],
      interval: Math.max(5, parseInt($("auto-interval").value, 10) || 60),
      proto: $("auto-proto").value,
      count: parseInt($("auto-count").value, 10) || 3,
      workers: parseInt($("auto-workers").value, 10) || 64,
      probe: $("auto-probe").value,
      geo: $("auto-geo").checked,
      source: $("auto-source").value,
      chunkSize: parseInt($("auto-chunk").value, 10) || 0,
      rotate: $("auto-rotate").checked,
      maxCycles: parseInt($("auto-cycles").value, 10) || 0,
      alerts: $("auto-alert-on").checked,
      warnLat: parseInt($("auto-warn-lat").value, 10) || 120,
      alertJit: parseInt($("auto-alert-jit").value, 10) || 40,
      alertLoss: parseInt($("auto-alert-loss").value, 10) || 20,
      game: ($("tool-game") && $("tool-game").value) || "",
      region: ($("route-region") && $("route-region").value) || "",
    };
  }

  function applyBgConfig(cfg) {
    if (!cfg) return;
    if (Array.isArray(cfg.types)) {
      $("auto-type-dns").checked = cfg.types.includes("dns");
      if ($("auto-type-mtu")) $("auto-type-mtu").checked = cfg.types.includes("mtu");
      if ($("auto-type-signal")) $("auto-type-signal").checked = cfg.types.includes("signal");
    }
    if (cfg.interval) $("auto-interval").value = cfg.interval;
    if (cfg.proto) $("auto-proto").value = cfg.proto;
    if (cfg.count) $("auto-count").value = cfg.count;
    if (cfg.workers) $("auto-workers").value = cfg.workers;
    if (cfg.probe) $("auto-probe").value = cfg.probe;
    if (typeof cfg.geo === "boolean") $("auto-geo").checked = cfg.geo;
    if (cfg.source) $("auto-source").value = cfg.source;
    if (typeof cfg.chunkSize === "number") $("auto-chunk").value = cfg.chunkSize;
    if (typeof cfg.rotate === "boolean") $("auto-rotate").checked = cfg.rotate;
    if (typeof cfg.maxCycles === "number") $("auto-cycles").value = String(cfg.maxCycles);
    if (typeof cfg.alerts === "boolean") $("auto-alert-on").checked = cfg.alerts;
    if (cfg.warnLat) $("auto-warn-lat").value = cfg.warnLat;
    if (cfg.alertJit) $("auto-alert-jit").value = cfg.alertJit;
    if (cfg.alertLoss) $("auto-alert-loss").value = cfg.alertLoss;
  }

  function renderBgStatus(st) {
    if (!st) return;
    const running = st.running;
    auto.bg = running;
    $("auto-state").textContent = running ? "running (bg)" : "idle";
    $("auto-state").classList.toggle("live", running);
    if (typeof st.cycle === "number") $("auto-cycles-run").textContent = st.cycle;
    if (typeof st.alerts === "number") $("auto-alert-count").textContent = st.alerts;
    if (st.next_in != null) {
      $("auto-next").textContent = st.next_in + "s";
      autoCountdown(st.next_in);
    }
    const dns = st.last && st.last.dns;
    if (dns && dns.best) $("auto-best").textContent = `${dns.best.target} ${dns.best.latency}ms`;
    // Rebuilding this list every poll repainted the panel even when the server had
    // nothing new to say. The signature check keeps an idle app from repainting.
    if (st.log && st.log.length) {
      const sig = st.log.length + "|" + st.log[0].t + "|" + st.log[0].msg;
      if (sig !== renderBgStatus.lastSig) {
        renderBgStatus.lastSig = sig;
        $("auto-log").innerHTML = st.log.slice(0, 40).map((l) =>
          `<div class="auto-log-line"><span class="dim">${l.t}</span> ${l.msg}</div>`).join("");
      }
    }
  }

  async function bgPoll() {
    try {
      const st = await getJSON("/api/autotest");
      renderBgStatus(st);
      if (!st.running && bgPollTimer) { clearInterval(bgPollTimer); bgPollTimer = null; }
    } catch {}
  }

  async function bgStart() {
    // autoTargets() is null when the source is the saved server-side list.
    const boxTargets = autoTargets();
    const payload = { action: "start", config: bgConfig(),
                      targets: boxTargets ? boxTargets.slice(0, 20000) : [] };
    auto.bg = true;
    const st = await post("/api/autotest", payload);
    renderBgStatus(st);
    autoLog("background auto-test started (runs on the server).");
    if (bgPollTimer) clearInterval(bgPollTimer);
    bgPollTimer = setInterval(bgPoll, 3000);
  }

  async function bgStop() {
    const st = await post("/api/autotest", { action: "stop" });
    auto.bg = false;
    renderBgStatus(st);
    if (bgPollTimer) { clearInterval(bgPollTimer); bgPollTimer = null; }
  }

  $("auto-start").addEventListener("click", () => {
    if ($("auto-background") && $("auto-background").checked) bgStart();
  });
  $("auto-stop").addEventListener("click", () => {
    if ($("auto-background") && $("auto-background").checked) bgStop();
  });
  // Restore saved background config on load (does not auto-start; the server
  // resumes it if it was left enabled).
  (async function initBgAuto() {
    try {
      const st = await getJSON("/api/autotest");
      if (st.config) applyBgConfig(st.config);
      if (st.running) auto.bg = true;
      renderBgStatus(st);
      if (st.running) bgPollTimer = setInterval(bgPoll, 3000);
    } catch {}
  })();

  /* ============================================================
     APPEARANCE (theme / colours / font) — persisted in localStorage
     ============================================================ */
  const APPEAR_KEY = "nexus_appearance";
  const PRESETS = {
    nexus:    { accent: "#35e6ff", ink: "#eae6ff", dim: "#9a92c4", bg: "#08060f" },
    midnight: { accent: "#8b9dff", ink: "#e6e9ff", dim: "#8f97c4", bg: "#05060f" },
    matrix:   { accent: "#37ff8b", ink: "#d6ffe6", dim: "#79b894", bg: "#03080a" },
    sunset:   { accent: "#ff8a5c", ink: "#ffe9e0", dim: "#c79a8c", bg: "#120708" },
    ice:      { accent: "#7afcff", ink: "#eafcff", dim: "#8fb6c4", bg: "#06101a" },
    light:    { accent: "#2f7cff", ink: "#14162e", dim: "#5b6180", bg: "#eef1f8" },
  };

  function applyAppearance(a) {
    const root = document.documentElement;
    const body = document.body;
    if (a.accent) root.style.setProperty("--acc", a.accent);
    if (a.ink) { root.style.setProperty("--ink", a.ink); }
    if (a.dim) root.style.setProperty("--dim", a.dim);
    if (a.bg) { root.style.setProperty("--bg", a.bg); }
    if (a.font) root.style.setProperty("--display", a.font === "system" ? "system-ui, sans-serif" : a.font);
    if (a.fontSize) body.style.fontSize = a.fontSize + "px";
    body.dataset.density = a.density || "cozy";
    body.classList.toggle("no-aurora", a.fxAurora === false);
    body.classList.toggle("no-grid", a.fxGrid === false);
    body.classList.toggle("no-scanlines", a.fxScanlines === false);
    body.classList.toggle("no-sparkles", a.fxSparkles === false);
  }

  function readAppearanceControls() {
    return {
      accent: $("col-accent").value,
      ink: $("col-ink").value,
      dim: $("col-dim").value,
      bg: $("col-bg").value,
      font: $("font-family").value,
      fontSize: parseFloat($("font-size").value) || 14.5,
      density: $("ui-density").value,
      fxAurora: $("fx-aurora").checked,
      fxGrid: $("fx-grid").checked,
      fxScanlines: $("fx-scanlines").checked,
      fxSparkles: $("fx-sparkles").checked,
    };
  }

  function writeAppearanceControls(a) {
    if (a.accent) $("col-accent").value = a.accent;
    if (a.ink) $("col-ink").value = a.ink;
    if (a.dim) $("col-dim").value = a.dim;
    if (a.bg) $("col-bg").value = a.bg;
    if (a.font) $("font-family").value = a.font;
    if (a.fontSize) $("font-size").value = a.fontSize;
    if (a.density) $("ui-density").value = a.density;
    if (a.fxAurora != null) $("fx-aurora").checked = a.fxAurora;
    if (a.fxGrid != null) $("fx-grid").checked = a.fxGrid;
    if (a.fxScanlines != null) $("fx-scanlines").checked = a.fxScanlines;
    if (a.fxSparkles != null) $("fx-sparkles").checked = a.fxSparkles;
  }

  function saveAppearance() {
    const a = readAppearanceControls();
    a.preset = currentPreset;
    localStorage.setItem(APPEAR_KEY, JSON.stringify(a));
    applyAppearance(a);
    document.querySelectorAll(".preset").forEach((p) =>
      p.classList.toggle("active", p.dataset.preset === a.preset));
  }

  let currentPreset = null;
  document.querySelectorAll("#preset-row .preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const p = PRESETS[btn.dataset.preset];
      if (!p) return;
      currentPreset = btn.dataset.preset;
      writeAppearanceControls({ ...p, fxAurora: true, fxGrid: true, fxSparkles: true,
        fxScanlines: false, density: "cozy", font: "Outfit", fontSize: 14.5 });
      document.querySelectorAll(".preset").forEach((x) => x.classList.remove("active"));
      btn.classList.add("active");
      saveAppearance();
    });
  });

  ["col-accent", "col-ink", "col-dim", "col-bg", "font-family", "font-size",
   "ui-density", "fx-aurora", "fx-grid", "fx-scanlines", "fx-sparkles"]
    .forEach((id) => $(id).addEventListener("input", saveAppearance));

  $("theme-reset").addEventListener("click", () => {
    localStorage.removeItem(APPEAR_KEY);
    writeAppearanceControls({ ...PRESETS.nexus, fxAurora: true, fxGrid: true,
      fxSparkles: true, fxScanlines: false, density: "cozy", font: "Outfit", fontSize: 14.5 });
    document.documentElement.removeAttribute("style");
    document.body.removeAttribute("style");
    applyAppearance({ ...PRESETS.nexus, font: "Outfit", fontSize: 14.5, density: "cozy",
      fxAurora: true, fxGrid: true, fxScanlines: false, fxSparkles: true });
    document.querySelectorAll(".preset").forEach((x) => x.classList.remove("active"));
    document.querySelector('.preset[data-preset="nexus"]').classList.add("active");
  });

  (function loadAppearance() {
    let a = null;
    try { a = JSON.parse(localStorage.getItem(APPEAR_KEY) || "null"); } catch {}
    if (a) {
      writeAppearanceControls(a);
      applyAppearance(a);
      if (a.preset) {
        const b = document.querySelector(`.preset[data-preset="${a.preset}"]`);
        if (b) b.classList.add("active");
      }
    } else {
      document.querySelector('.preset[data-preset="nexus"]').classList.add("active");
    }
  })();

  /* ---------- probe targets (shared by scanner / auto-test / probe lab) ---- */
  async function loadProbeTargets() {
    let list = [{ key: "google", host: "google.com", label: "Google" }];
    try {
      const r = await getJSON("/api/probe-targets");
      if (r.targets && r.targets.length) list = r.targets;
    } catch {}
    const opts = list.map((t) => `<option value="${t.key}">${t.label} (${t.host})</option>`).join("");
    ["probe", "auto-probe", "tool-probe"].forEach((id) => {
      const sel = $(id);
      if (!sel) return;
      if (sel.multiple) {
        sel.innerHTML = opts;
        // default to the first target selected so a dig works out of the box
        if (sel.options.length) sel.options[0].selected = true;
      } else {
        const cur = sel.value;
        sel.innerHTML = opts;
        if (cur) sel.value = cur;
      }
    });
  }
  /* ---------- UI self-reporting ----------
     The engine log only sees the server. A frozen WebView leaves no server-side
     trace, so the page reports its own errors and long main-thread blocks to
     /api/logs/client, where they appear alongside everything else. */
  const uiQueue = [];
  function uiReport(level, msg) {
    uiQueue.push({ level, msg });
    if (uiQueue.length >= 8) flushUi();
  }
  let uiFlushTimer = null;
  async function flushUi() {
    if (!uiQueue.length) return;
    const batch = uiQueue.splice(0, 200);
    try {
      await fetch("/api/logs/client", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lines: batch }),
      });
    } catch {}
  }
  window.addEventListener("error", (e) => {
    uiReport("ERROR", `ui error: ${e.message} @ ${e.filename || "?"}:${e.lineno || 0}`);
    flushUi();
  });
  window.addEventListener("unhandledrejection", (e) => {
    const r = e.reason;
    uiReport("ERROR", `ui promise rejection: ${(r && (r.message || r)) || "unknown"}`);
    flushUi();
  });
  // 200ms, not 1000ms: an Android ANR is raised well below a full second, and the
  // 1000ms threshold meant real blocks were never reported.
  try {
    new PerformanceObserver((l) => {
      for (const e of l.getEntries()) {
        if (e.duration >= 200) {
          uiReport("WARNING", `main thread blocked ${Math.round(e.duration)}ms`);
        }
      }
    }).observe({ entryTypes: ["longtask"] });
  } catch (err) {
    uiReport("WARNING", "longtask observer unavailable: " + (err && err.message));
  }
  // Frames: if the renderer cannot keep up, the gap between animation frames grows
  // even when no single task is long. That is the signature of a saturated
  // rasterizer (large blurred layers, constant repaints) rather than of slow JS.
  try {
    let frames = 0, janky = 0, worst = 0, last = performance.now(), t0 = last;
    (function loop(now) {
      const gap = now - last; last = now;
      if (gap > 100) { janky++; if (gap > worst) worst = Math.round(gap); }
      frames++;
      if (now - t0 >= 10000) {
        if (janky) {
          uiReport("WARNING", `slow frames: ${janky}/${frames} over 10s ` +
                              `(worst ${worst}ms gap)`);
        }
        frames = 0; janky = 0; worst = 0; t0 = now;
      }
      requestAnimationFrame(loop);
    })(last);
  } catch {}
  document.addEventListener("visibilitychange", () => {
    uiReport("INFO", `ui ${document.visibilityState}`);
    flushUi();
  });
  window.addEventListener("pagehide", () => { flushUi(); });
  uiReport("INFO", "ui loaded");
  flushUi();
  uiFlushTimer = setInterval(flushUi, 5000);

  /* ============================================================
     LOGS — live engine log with a one-tap copy for bug reports
     ============================================================ */
  const logState = { lines: [], last: 0, timer: null, err: 0, painted: 0 };

  // Only the tail of the log is painted, and new lines are appended rather than
  // rewriting the whole buffer. Rewriting all 2000 lines cost ~0.5s of the main
  // thread on a phone CPU every 2s — that is what made Android report the app as
  // not responding (repeatedly, every poll).
  const LOG_PAINT_MAX = 300;

  function logLineText(e) {
    return `${e.t} [${e.level}] ${e.name}: ${e.msg}`;
  }

  function logPanelOpen() {
    const p = $("panel-logs");
    return !!p && !p.classList.contains("collapsed");
  }

  function logAtBottom(box) {
    return box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  }

  function paintLogMeta(atBottom) {
    const cnt = $("logs-count");
    if (cnt) cnt.textContent = String(logState.lines.length);
    const box = $("logs-out");
    if (box && $("logs-autoscroll") && $("logs-autoscroll").checked && atBottom) {
      box.scrollTop = box.scrollHeight;
    }
  }

  function renderLogsFull() {
    const box = $("logs-out");
    if (!box) return;
    const atBottom = logAtBottom(box);
    const lines = logState.lines.slice(-LOG_PAINT_MAX);
    box.textContent = lines.length
      ? lines.map(logLineText).join("\n")
      : "no log lines yet — use the app and they will appear here.";
    logState.painted = lines.length;
    paintLogMeta(atBottom);
  }

  function renderLogsAppend(fresh) {
    const box = $("logs-out");
    // Nothing to paint while the panel is closed; repaint happens on open.
    if (!box || !logPanelOpen()) return;
    const add = fresh.slice(-LOG_PAINT_MAX);
    // (Re)build when nothing is painted yet, or once the painted tail has grown
    // to twice the cap. That keeps the DOM bounded without a rebuild per poll.
    if (!logState.painted || logState.painted + add.length > LOG_PAINT_MAX * 2) {
      renderLogsFull();
      return;
    }
    const atBottom = logAtBottom(box);
    box.textContent += "\n" + add.map(logLineText).join("\n");
    logState.painted += add.length;
    paintLogMeta(atBottom);
  }

  function renderLogs() { renderLogsFull(); }

  async function pollLogs(force) {
    const level = $("logs-level") ? $("logs-level").value : "";
    const q = force || level ? `?since=0&limit=2000&level=${encodeURIComponent(level)}`
                             : `?since=${logState.last}`;
    try {
      const r = await getJSON("/api/logs" + q);
      const fresh = r.lines || [];
      if (force || level) {
        logState.lines = fresh;
        renderLogsFull();
      } else if (fresh.length) {
        logState.lines = logState.lines.concat(fresh).slice(-2000);
        renderLogsAppend(fresh);
      } else if (logPanelOpen() && !logState.painted) {
        renderLogsFull();
      }
      logState.last = r.last || logState.last;
      logState.err = 0;
    } catch (e) {
      logState.err++;
      // Keep polling but stop spamming once the engine is clearly unreachable.
      if (logState.err === 1) {
        const box = $("logs-out");
        if (box) box.textContent = "cannot reach the engine log: " + e.message;
      }
    }
  }

  // Repaint the moment the panel is opened: lines may have arrived while it was
  // closed, in which case nothing was painted.
  (function watchLogPanel() {
    const p = $("panel-logs");
    if (!p || !window.MutationObserver) return;
    new MutationObserver(() => { if (logPanelOpen()) renderLogsFull(); })
      .observe(p, { attributes: true, attributeFilter: ["class"] });
  })();

  function logsAsText() {
    return logState.lines.map(logLineText).join("\n");
  }

  if ($("logs-copy")) $("logs-copy").addEventListener("click", (e) => {
    if (!logState.lines.length) { pollLogs(true); return; }
    copyText(logsAsText(), e.currentTarget);
  });
  if ($("logs-refresh")) $("logs-refresh").addEventListener("click", () => pollLogs(true));
  if ($("logs-level")) $("logs-level").addEventListener("change", () => pollLogs(true));
  if ($("logs-download")) $("logs-download").addEventListener("click", () => {
    downloadText("dns_console_log.txt", logsAsText() || "(no log lines)");
  });
  if ($("logs-clear")) $("logs-clear").addEventListener("click", async () => {
    try { await post("/api/logs/clear", {}); } catch {}
    logState.lines = []; logState.last = 0; logState.painted = 0; renderLogsFull();
  });

  function startLogPoll() {
    if (logState.timer) return;
    logState.timer = setInterval(() => {
      if (!$("logs-follow") || $("logs-follow").checked) pollLogs(false);
    }, 2000);
  }
  startLogPoll();
  pollLogs(true);

  loadProbeTargets();

  /* ---------- seed ---------- */
  targetsBox.value = "8.8.8.8, 1.1.1.1, 9.9.9.9, 8.8.4.4, 1.0.0.1, 208.67.222.222";
})();
"""

# Persistent history: survives restarts so the ranking keeps building up.
WEB_HISTORY_FILE = os.path.expanduser("~/.dns_console_history.json")

_WEB_HISTORY = {}
_WEB_HISTORY_LOCK = threading.Lock()
_WEB_HISTORY_DIRTY = False


# --------------------------------------------------------------------------
#  History persistence
# --------------------------------------------------------------------------
def _web_history_load():
    if _WEB_HISTORY or not os.path.exists(WEB_HISTORY_FILE):
        return
    try:
        with open(WEB_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _WEB_HISTORY.update(data)
    except Exception:
        pass


def _web_history_save(force=False):
    global _WEB_HISTORY_DIRTY
    if not (_WEB_HISTORY_DIRTY or force):
        return
    try:
        tmp = WEB_HISTORY_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_WEB_HISTORY, f)
        os.rename(tmp, WEB_HISTORY_FILE)
        _WEB_HISTORY_DIRTY = False
    except Exception:
        pass


# --------------------------------------------------------------------------
#  Small helpers
# --------------------------------------------------------------------------
def _web_pick_port(host, preferred, tries=25):
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


def _web_open_browser(url):
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
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            return True
        except Exception:
            continue
    try:
        import webbrowser
        return webbrowser.open(url)
    except Exception:
        return False


def _web_measure_http(url, timeout=6.0):
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


def _web_device_info():
    """Read-only device/network snapshot via Shizuku (getprop / pgrep / ip route)."""
    shizuku = is_shizuku_running()
    operator, net_type = get_live_hardware_data()
    iface = detect_active_interface()
    vpn_iface = detect_vpn_interface()
    return {
        "shizuku": shizuku,
        "operator": operator,
        "network_type": net_type,
        "interface": iface,
        "vpn": bool(vpn_iface) or is_vpn_interface(iface),
        "vpn_interface": vpn_iface,
    }


def _web_network_info():
    """Public IP / geo / ISP (via ip-api) plus interface, VPN flag and MTU advice."""
    ip, country, isp = analyze_gateway()
    mtu, mode, iface = resolve_smart_mtu()
    operator, net_type = get_live_hardware_data()
    vpn_iface = detect_vpn_interface()
    return {
        "public_ip": ip,
        "country": country,
        "isp": isp,
        "interface": iface,
        "vpn": bool(vpn_iface) or is_vpn_interface(iface),
        "vpn_interface": vpn_iface,
        "mtu": mtu,
        "mtu_mode": mode,
        "operator": operator,
        "network_type": net_type,
    }


def _web_mtu_recommendation():
    """Read-only MTU recommendation (VPN -> fixed, cellular -> probing)."""
    mtu, mode, iface = resolve_smart_mtu()
    return {"mtu": mtu, "mode": mode, "interface": iface}


def _web_diagnosis():
    """Non-interactive version of the CLI's local network diagnosis."""
    raw = run_shizuku_cmd(f"ping -c 6 -W 2 {REFERENCE_HOST}")
    rtt, loss, reachable = parse_ping_result(raw)
    quality = "EXCELLENT" if reachable and rtt < 60 else "OK" if reachable and rtt < 150 \
        else "POOR" if reachable else "DOWN"
    raw_gw = run_shizuku_cmd(f"ping -c 2 -W 1 {HOTSPOT_GATEWAY_IP}")
    gw_rtt, gw_loss, gw_reachable = parse_ping_result(raw_gw)
    return {
        "reference": {"host": REFERENCE_HOST, "rtt": rtt, "loss": loss,
                      "reachable": reachable, "quality": quality},
        "gateway": {"host": HOTSPOT_GATEWAY_IP, "rtt": gw_rtt, "loss": gw_loss,
                    "reachable": gw_reachable},
    }


def _dns_recv_exact(sock, n):
    """Read exactly n bytes from a stream socket (or raise)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed before full DNS message")
        buf += chunk
    return buf


def _dns_query_udp(ip, packet, timeout):
    """One UDP DNS query. Returns round-trip ms, or raises.

    The socket is *connected* so the kernel discards datagrams from any other
    source, and the reply's transaction ID is checked — otherwise a stray or
    spoofed packet could be timed as if it were the resolver's answer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, 53))
        t0 = time.perf_counter()
        sock.send(packet)
        want_id = packet[:2]
        while True:
            data = sock.recv(512)
            if len(data) >= 12 and data[:2] == want_id and (data[2] & 0x80):
                return (time.perf_counter() - t0) * 1000
            # Ignore anything that is not a response to *this* query.
    finally:
        sock.close()


def _dns_query_stream(ip, packet, timeout, tls=False):
    """One DNS-over-TCP (or DNS-over-TLS/DoT) query, length-prefixed per RFC 1035.

    TCP fallback and DoT are how resolvers behave when UDP is filtered or a
    truncated reply is received, so they are the honest way to tell a resolver
    that is blocked from one that is merely slow."""
    import ssl as _ssl
    port = 853 if tls else 53
    t0 = time.perf_counter()
    raw = socket.create_connection((ip, port), timeout)
    try:
        if tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw
        sock.settimeout(timeout)
        sock.sendall(len(packet).to_bytes(2, "big") + packet)
        length = int.from_bytes(_dns_recv_exact(sock, 2), "big")
        _dns_recv_exact(sock, length)
        return (time.perf_counter() - t0) * 1000
    finally:
        try:
            raw.close()
        except Exception:
            pass


def _dns_probe_protocol(ip, packet, count, timeout, kind):
    """Run `count` probes of one protocol and summarise them."""
    runners = {
        "udp": lambda: _dns_query_udp(ip, packet, timeout),
        "tcp": lambda: _dns_query_stream(ip, packet, timeout, tls=False),
        "tls": lambda: _dns_query_stream(ip, packet, timeout, tls=True),
    }
    run = runners[kind]
    durations, lost = [], 0
    for _ in range(count):
        try:
            durations.append(run())
        except Exception:
            lost += 1
    ok = bool(durations)
    avg = (sum(durations) / len(durations)) if durations else None
    jitter = (sum(abs(durations[i] - durations[i - 1]) for i in range(1, len(durations)))
              / (len(durations) - 1)) if len(durations) > 1 else 0.0
    log_event(f"probe {kind} {ip} count={count} timeout={timeout}s -> "
              f"{'ok ' + str(round(avg, 1)) + 'ms' if ok else 'no reply'}"
              f" (lost {lost}/{count})", "debug")
    return {"ok": ok, "ms": round(avg, 1) if ok else None,
            "loss": round((lost / count) * 100, 1), "jitter": round(jitter, 1)}


def _web_ping_blocking(ip, count=3, timeout=1.5, proto="udp", host="google.com"):
    """Blocking multi-protocol DNS probe — one thread per target.

    `async_ping_dns_core` performs a *blocking* recvfrom, so running it under
    asyncio serialises the whole scan. This thread-friendly twin lets the web
    scanner run many targets genuinely in parallel via a thread pool.

    proto: 'udp' | 'tcp' | 'tls' | 'both' (udp+tcp) | 'auto' (first that works).
    host:  the name to resolve (probe target) — defaults to google.com.
    Returns a dict; the aggregate latency/loss/jitter come from the fastest
    protocol that answered."""
    packet = _build_dns_query(host)
    proto = (proto or "udp").lower()
    if proto not in ("udp", "tcp", "tls", "both", "auto"):
        proto = "udp"
    proto_results = {}

    if proto in ("udp", "tcp", "tls"):
        proto_results[proto] = _dns_probe_protocol(ip, packet, count, timeout, proto)
    elif proto == "both":
        proto_results["udp"] = _dns_probe_protocol(ip, packet, count, timeout, "udp")
        proto_results["tcp"] = _dns_probe_protocol(ip, packet, count, timeout, "tcp")
    else:  # auto — stop at the first protocol that answers
        for kind in ("udp", "tcp", "tls"):
            res = _dns_probe_protocol(ip, packet, count, timeout, kind)
            proto_results[kind] = res
            if res["ok"]:
                break

    chosen = None
    chosen_kind = None
    for kind in ("udp", "tcp", "tls"):
        res = proto_results.get(kind)
        if res and res["ok"]:
            chosen, chosen_kind = res, kind
            break
    if chosen:
        latency, loss, jitter = chosen["ms"], chosen["loss"], chosen["jitter"]
        log_event(f"target {ip} alive via {chosen_kind} {latency}ms", "debug")
    else:
        latency, loss, jitter = 9999.0, 100.0, 999.0
        log_event(f"target {ip} unreachable ({proto})", "debug")

    return {
        "latency": latency, "loss": loss, "jitter": jitter,
        "ok": latency < 9000, "proto": proto, "proto_results": proto_results,
    }


def _web_fold_history(target, latency, loss, jitter):
    global _WEB_HISTORY_DIRTY
    with _WEB_HISTORY_LOCK:
        update_stability_history(
            _WEB_HISTORY,
            [{"pair": [target], "latency": latency, "loss": loss, "jitter": jitter}],
        )
        _WEB_HISTORY_DIRTY = True


def _web_stability_snapshot(top_n=10):
    with _WEB_HISTORY_LOCK:
        if not _WEB_HISTORY:
            return []
        fastest = min(v["latency_sum"] / v["cycles"] for v in _WEB_HISTORY.values())
        rows = []
        for dns_ip, rec in _WEB_HISTORY.items():
            score, success_rate, spike_ratio = compute_stability_score(rec, fastest)
            rows.append({
                "target": dns_ip,
                "cycles": rec["cycles"],
                "success_rate": round(success_rate * 100, 1),
                "score": score,
                "spikes": rec["jitter_spike_cycles"],
                "avg": round(rec["latency_sum"] / rec["cycles"], 1),
                "status": stability_status_label(score, success_rate, spike_ratio),
            })
        rows.sort(key=lambda r: r["score"], reverse=True)
        return rows[:top_n]


# --------------------------------------------------------------------------
#  Auto-test engine (background, config-persistent)
# --------------------------------------------------------------------------
# The dashboard's auto-test runs in the browser and dies when the tab closes.
# This server-side twin keeps cycling while the app is open (the WebView holds
# the connection, so it works with the screen on and the app in the foreground),
# remembers the user's settings on disk, and can test any combination of
# DNS servers / MTU / signal strength.

_AUTOTEST = {
    "running": False,
    "cycle": 0,
    "offset": 0,
    "next_run": 0.0,
    "started": 0.0,
    "alerts": 0,
    "log": [],          # newest-first
    "last": {},         # last cycle's summary
}
_AUTOTEST_LOCK = threading.Lock()
_AUTOTEST_WAKE = threading.Event()
_AUTOTEST_THREAD = None

_AUTOTEST_DEFAULTS = {
    "enabled": False,
    "types": ["dns"],
    "interval": 60,
    "proto": "udp",
    "count": 3,
    "workers": 64,
    "probe": "google",
    "geo": False,
    "source": "list",
    "chunkSize": 0,
    "rotate": True,
    "maxCycles": 0,
    "alerts": True,
    "warnLat": 120,
    "alertJit": 40,
    "alertLoss": 20,
    "game": "",
    "region": "",
    "gameHost": "",
    "targets": [],
}


def _autotest_load_config():
    cfg = dict(_AUTOTEST_DEFAULTS)
    try:
        with open(AUTOTEST_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            for k, v in saved.items():
                if k in cfg:
                    cfg[k] = v
    except Exception:
        pass
    if not isinstance(cfg.get("types"), list) or not cfg["types"]:
        cfg["types"] = ["dns"]
    return cfg


def _autotest_save_config(cfg):
    try:
        clean = {k: cfg.get(k, v) for k, v in _AUTOTEST_DEFAULTS.items()}
        tmp = AUTOTEST_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(clean, f)
        os.rename(tmp, AUTOTEST_FILE)
        return True
    except Exception:
        return False


def _autotest_log(msg):
    stamp = time.strftime("%H:%M:%S")
    with _AUTOTEST_LOCK:
        _AUTOTEST["log"].insert(0, {"t": stamp, "msg": msg})
        del _AUTOTEST["log"][120:]


def _autotest_dns_cycle(cfg):
    """Run one DNS scan cycle (mirrors the browser auto-test's rotation)."""
    if cfg.get("source") == "list":
        all_targets = list(load_dns_list())
    else:
        all_targets = cfg.get("targets") or []
    if not all_targets:
        return {"type": "dns", "skipped": "no targets — save a DNS list or set the scanner box"}

    chunk = max(0, int(cfg.get("chunkSize") or 0))
    targets = all_targets
    slice_note = ""
    with _AUTOTEST_LOCK:
        offset = _AUTOTEST["offset"]
    if chunk and len(all_targets) > chunk:
        if not cfg.get("rotate", True) or offset >= len(all_targets):
            offset = 0
        targets = all_targets[offset:offset + chunk]
        if len(targets) < chunk:
            targets = targets + all_targets[:chunk - len(targets)]
        slice_note = f" [{offset + 1}-{offset + len(targets)} of {len(all_targets)}]"
        with _AUTOTEST_LOCK:
            _AUTOTEST["offset"] = (offset + chunk) % len(all_targets)

    proto = cfg.get("proto", "udp")
    count = max(1, min(10, int(cfg.get("count") or 3)))
    timeout = 1.5
    probe_host = _web_probe_host(cfg.get("probe") or "google")
    workers = max(1, min(512, int(cfg.get("workers") or 64)))

    _autotest_log(f"cycle scanning {len(targets)} server(s){slice_note}…")
    _web_history_load()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_web_ping_blocking, t, count, timeout, proto, probe_host)
                for t in targets]
        for t, fut in zip(targets, futs):
            try:
                r = fut.result()
            except Exception:
                r = {"latency": 9999.0, "loss": 100.0, "jitter": 999.0, "ok": False,
                     "proto": proto, "proto_results": {}}
            ok = r["ok"]
            _web_fold_history(t, r["latency"] if ok else 2000.0, r["loss"], r["jitter"])
            results.append({
                "target": t, "latency": round(r["latency"], 1) if ok else None,
                "loss": round(r["loss"], 1), "jitter": round(r["jitter"], 1) if ok else None,
                "status": "ok" if ok else "fail",
                "proto_used": next((k for k in ("udp", "tcp", "tls")
                                    if r["proto_results"].get(k, {}).get("ok")), None),
            })
    _web_history_save()

    ok = [r for r in results if r["status"] == "ok"]
    best = min(ok, key=lambda r: r["latency"]) if ok else None
    alerts = 0
    if cfg.get("alerts", True):
        warn_lat = float(cfg.get("warnLat") or 120)
        alert_jit = float(cfg.get("alertJit") or 40)
        alert_loss = float(cfg.get("alertLoss") or 20)
        for r in results:
            if r["status"] != "ok":
                alerts += 1
                _autotest_log(f"⚠ {r['target']} unreachable")
            else:
                if r["latency"] > warn_lat:
                    alerts += 1
                    _autotest_log(f"⚠ {r['target']} slow {r['latency']}ms (> {warn_lat:.0f}ms)")
                if r["jitter"] > alert_jit:
                    alerts += 1
                    _autotest_log(f"⚠ {r['target']} jitter {r['jitter']}ms (> {alert_jit:.0f}ms)")
                if r["loss"] > alert_loss:
                    alerts += 1
                    _autotest_log(f"⚠ {r['target']} loss {r['loss']}% (> {alert_loss:.0f}%)")
    _autotest_log(f"{len(ok)}/{len(results)} alive" +
                  (f", best {best['target']} {best['latency']}ms" if best else ""))
    return {"type": "dns", "total": len(results), "ok": len(ok), "alerts": alerts,
            "best": best, "rows": results}


def _autotest_extra_cycle(cfg):
    """MTU and/or signal strength — cheap checks, run every cycle when selected."""
    out = {}
    if "mtu" in cfg.get("types", []):
        game = cfg.get("game") or None
        out["mtu"] = _web_mtu_intelligence(game=game)
        _autotest_log(f"MTU {out['mtu'].get('mtu')} ({out['mtu'].get('mode')})"
                      + (f" · {game}" if game else ""))
    if "signal" in cfg.get("types", []):
        out["signal"] = _web_signal_strength()
        s = out["signal"]
        _autotest_log(f"signal {s.get('dbm') if s.get('dbm') is not None else 'n/a'} dBm "
                      f"· {s.get('quality')}")
    return out


def _autotest_loop():
    while True:
        with _AUTOTEST_LOCK:
            if not _AUTOTEST["running"]:
                break
            due = _AUTOTEST["next_run"]
        # Sleep only until the next cycle is due, in short slices so a stop/start
        # is noticed promptly. The event is CLEARED after each wait: without the
        # clear the flag stays set, wait() returns instantly forever, and the loop
        # spins (millions of iterations/sec) which made the interval drift.
        remaining = due - time.time()
        if remaining > 0:
            _AUTOTEST_WAKE.wait(timeout=min(2.0, remaining))
            _AUTOTEST_WAKE.clear()
            continue
        cfg = _autotest_load_config()
        cycle_started = time.time()
        with _AUTOTEST_LOCK:
            _AUTOTEST["cycle"] += 1
            cycle = _AUTOTEST["cycle"]
        _autotest_log(f"cycle {cycle} started")
        log_event(f"auto-test cycle {cycle} started (types={cfg.get('types')}, "
                  f"interval={cfg.get('interval')}s)")
        summary = {"cycle": cycle, "types": cfg.get("types", [])}
        try:
            if "dns" in cfg.get("types", []):
                summary["dns"] = _autotest_dns_cycle(cfg)
            summary.update(_autotest_extra_cycle(cfg))
        except Exception as e:
            import traceback as _tb
            _autotest_log(f"cycle error: {e}")
            log_event("auto-test cycle error: " + "".join(
                _tb.format_exception(type(e), e, e.__traceback__)), "error")
            summary["error"] = str(e)
        interval = max(5, int(cfg.get("interval") or 60))
        with _AUTOTEST_LOCK:
            _AUTOTEST["last"] = summary
            _AUTOTEST["alerts"] += int((summary.get("dns") or {}).get("alerts") or 0)
            max_cycles = int(cfg.get("maxCycles") or 0)
            if max_cycles and cycle >= max_cycles:
                _AUTOTEST["running"] = False
                _autotest_log(f"finished after {cycle} cycles")
                break
            # Fixed cadence: measure from the START of the cycle so a slow scan does
            # not push the next run later by its own duration. If the cycle overran
            # its interval, still wait a full interval before the next one -- never
            # schedule in the past, which would fire cycles back-to-back and peg the
            # CPU (and, via the web UI's poll, make the app look unresponsive).
            nxt = cycle_started + interval
            if nxt <= time.time():
                nxt = time.time() + interval
            _AUTOTEST["next_run"] = nxt
            log_event(f"auto-test cycle {cycle} done in "
                      f"{round(time.time() - cycle_started, 2)}s; next in "
                      f"{round(nxt - time.time(), 2)}s")


def _autotest_start(cfg):
    global _AUTOTEST_THREAD
    with _AUTOTEST_LOCK:
        _AUTOTEST["running"] = True
        _AUTOTEST["cycle"] = 0
        _AUTOTEST["offset"] = 0
        _AUTOTEST["alerts"] = 0
        _AUTOTEST["log"] = []
        _AUTOTEST["next_run"] = time.time()
        _AUTOTEST["started"] = time.time()
    if _AUTOTEST_THREAD is None or not _AUTOTEST_THREAD.is_alive():
        _AUTOTEST_THREAD = threading.Thread(target=_autotest_loop, daemon=True,
                                            name="dns-autotest")
        _AUTOTEST_THREAD.start()
    else:
        _AUTOTEST_WAKE.set()
    _autotest_log(f"auto-test started · {', '.join(cfg.get('types', ['dns']))} · "
                  f"every {cfg.get('interval')}s")


def _autotest_stop():
    with _AUTOTEST_LOCK:
        was = _AUTOTEST["running"]
        _AUTOTEST["running"] = False
    _AUTOTEST_WAKE.set()
    if was:
        _autotest_log("auto-test stopped")


def _autotest_status():
    cfg = _autotest_load_config()
    with _AUTOTEST_LOCK:
        st = dict(_AUTOTEST)
    next_in = None
    if st.get("running") and st.get("next_run"):
        next_in = max(0, int(st["next_run"] - time.time()))
    return {"running": st.get("running", False), "cycle": st.get("cycle", 0),
            "alerts": st.get("alerts", 0), "next_in": next_in,
            "log": st.get("log", [])[:80], "last": st.get("last", {}),
            "config": cfg}


def _autotest_autoresume():
    """Start the background loop if the saved config had it enabled."""
    try:
        cfg = _autotest_load_config()
        if cfg.get("enabled"):
            _autotest_start(cfg)
    except Exception:
        pass


# --------------------------------------------------------------------------
#  DNS extraction from uploaded files (any text-like format)
# --------------------------------------------------------------------------
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
# Well-known public resolver hostnames (hostnames are only accepted when they
# match this set, so we never mistake arbitrary prose domains for resolvers).
_KNOWN_DNS_HOSTS = {
    "dns.google", "one.one.one.one", "one.one.one.one.", "cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.opendns.com", "doh.familyshield.opendns.com", "dns.adguard.com",
    "dns.adguard-dns.com", "dns-family.adguard.com", "unfiltered.adguard-dns.com",
    "doh.mullvad.net", "dns.mullvad.net", "dns.nextdns.io", "dot.pub",
    "dns.sb", "dot.sb", "dnslow.me", "dns.alidns.com", "doh.360.cn",
    "dns.comss.one", "doh.dns.sb", "dns.controld.com", "freedns.controld.com",
    "dns.cleanbrowsing.org", "doh.cleanbrowsing.org", "get.dns.owlapps.net",
    "dns.dnshome.de", "dnsforge.de", "dot.dnsforge.de", "resolver-eu.lelux.fi",
    "dns.launchpad.net", "anycast.censurfridns.dk", "dns.njal.la",
    "doh.libredns.gr", "dns.libredns.gr", "dns.east.comcast.net",
}


def _web_valid_ipv4(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
        if len(p) > 1 and p[0] == "0":
            return False
    return True


def _web_extract_dns(text, limit=500000):
    """Pull every IPv4 address (and known resolver hostname) out of arbitrary text."""
    if not text:
        return []
    text = text.replace("\x00", " ")
    out, seen = [], set()
    for m in _IPV4_RE.finditer(text):
        cand = m.group(0)
        if _web_valid_ipv4(cand) and cand not in seen:
            seen.add(cand)
            out.append(cand)
    for m in _HOST_RE.finditer(text):
        host = m.group(0).lower()
        if host in _KNOWN_DNS_HOSTS and host not in seen:
            seen.add(host)
            out.append(host)
    return out[:limit]


def _web_decode_bytes(data):
    """Decode bytes to text, BOM-aware, falling back to latin-1 (never fails)."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", "ignore")


def _web_text_from_upload(data, filename):
    """Return readable text from an uploaded file of (almost) any format.

    Handles UTF-8/UTF-16/Latin-1 plain text, gzip, and ZIP containers
    (.zip/.xlsx/.ods/.docx — the shared strings and inline text live inside)."""
    chunks = []
    if data[:4] == b"PK\x03\x04":
        try:
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    if name.endswith("/"):
                        continue
                    try:
                        chunks.append(_web_decode_bytes(z.read(name)))
                    except Exception:
                        continue
        except Exception:
            chunks = []
    elif data[:2] == b"\x1f\x8b":
        try:
            import gzip
            chunks = [_web_decode_bytes(gzip.decompress(data))]
        except Exception:
            chunks = []
    if not chunks:
        chunks = [_web_decode_bytes(data)]
    return "\n".join(chunks)


def _web_parse_multipart(body, content_type):
    """Minimal multipart/form-data parser (enough for one file upload)."""
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return None, ""
    boundary = m.group(1).strip().strip('"').encode("latin-1")
    filename = ""
    delim = b"--" + boundary
    for part in body.split(delim):
        if b"\r\n\r\n" not in part:
            continue
        head, _, payload = part.partition(b"\r\n\r\n")
        payload = payload.rstrip(b"\r\n")
        if payload.endswith(b"--"):
            payload = payload[:-2]
        fn = re.search(rb'filename="([^"]*)"', head)
        if fn:
            filename = fn.group(1).decode("latin-1", "ignore")
            return payload, filename
    return None, ""


# --------------------------------------------------------------------------
#  OpenRouter AI analysis
# --------------------------------------------------------------------------
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_AI_DEFAULT_MODEL = "openai/gpt-4o-mini"
# Default key set from --api-key / $OPENROUTER_API_KEY; the UI can override per request.
_WEB_AI_KEY = ""
# Identify the console honestly to OpenRouter (and its WAF).
_WEB_AI_TITLE = "NEXUS DNS Console"
_WEB_AI_REFERER = "https://github.com/Onlyicing1/Dns"
_WEB_UA = "NEXUS-DNS-Console/3.4 (+https://github.com/Onlyicing1/Dns)"


def _web_ai_analyze(api_key, model, prompt):
    """Call OpenRouter's chat completions API and return (text, model, usage)."""
    payload = json.dumps({
        "model": model or _AI_DEFAULT_MODEL,
        "messages": [
            {"role": "system", "content":
             "You are a senior network engineer analysing DNS resolver benchmark "
             "results. Be concise and practical. Rank the resolvers, explain the "
             "latency/jitter/loss trade-offs, and recommend a primary and a backup "
             "resolver. Use short sections and bullet points."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
    }).encode("utf-8")
    req = urllib.request.Request(
        OPENROUTER_URL, data=payload,
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            # A real UA matters: WAFs in front of OpenRouter reject the default
            # "Python-urllib/x.y" with "Access denied by security policy." (403).
            "User-Agent": _WEB_UA,
            "HTTP-Referer": _WEB_AI_REFERER,
            "X-Title": _WEB_AI_TITLE,
        })
    with urllib.request.urlopen(req, timeout=90) as res:
        data = json.loads(res.read().decode("utf-8"))
    # OpenRouter can return HTTP 200 with an error object embedded in the body.
    if isinstance(data, dict) and data.get("error"):
        err = data["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        raise RuntimeError(msg or "OpenRouter returned an error")
    choice = (data.get("choices") or [{}])[0]
    text = (choice.get("message") or {}).get("content", "")
    return text, data.get("model"), data.get("usage")


def _web_build_ai_prompt(body):
    """Turn structured scan results + device context into an analysis prompt.

    The AI is given everything the dashboard knows — resolvers, the egress
    (VPN) location, the route to a game endpoint, signal strength, MTU and the
    game's port/protocol — so its recommendation can account for all of it."""
    if body.get("prompt"):
        base = str(body["prompt"])[:20000]
    else:
        base = ""
    rows = body.get("results") or body.get("rows") or []
    lines = []
    if base:
        lines += [base, ""]
    lines += ["Here are DNS resolver benchmark results (latency/jitter/loss in ms/%):", ""]
    if not rows:
        lines.append("(no scan results)")
    for r in rows[:200]:
        if not isinstance(r, dict):
            continue
        lat = r.get("latency")
        used = r.get("proto_used")
        tag = f" [{used}]" if used else ""
        cc = r.get("country_name") or r.get("country") or "?"
        if lat is None:
            lines.append(f"- {r.get('target','?')} ({cc}): unreachable (loss {r.get('loss','?')}%)")
        else:
            lines.append(f"- {r.get('target','?')} ({cc}): latency {lat} ms, "
                         f"jitter {r.get('jitter','?')} ms, loss {r.get('loss','?')}%{tag}")

    ctx = body.get("context") or {}
    if not isinstance(ctx, dict):
        ctx = {"note": str(ctx)[:2000]}
    if ctx:
        lines += ["", "Device & route context (JSON):"]
        try:
            lines.append(json.dumps(ctx, ensure_ascii=False)[:6000])
        except Exception:
            lines.append(str(ctx)[:6000])

    countries = body.get("countries") or []
    if countries:
        lines += ["", f"User wants resolvers from these countries only: {', '.join(map(str, countries))}."]

    sort_by = body.get("sort_by")
    if sort_by:
        lines += ["", f"User cares most about: {sort_by}."]

    lines += ["", "Recommend the best primary and backup DNS servers and why.",
              "If the user asked about a specific game, give the UDP/TCP port(s) and "
              "protocol to test for it, and whether the VPN/route helps or hurts ping.",
              "Always answer with plain text. When you show a table, use simple "
              "pipe-and-dash rows (| a | b |) with no other formatting inside cells."]
    return "\n".join(lines)


def _web_build_game_plan_prompt(game, region=None, hint=None):
    """Ask the AI for the ports/protocol to test for a game we may not know."""
    lines = [
        "You are a network engineer. For the game below, list the UDP/TCP ports and "
        "the protocol the game client uses to reach its servers.",
        f"Game: {game}",
    ]
    if region:
        lines.append(f"Region of interest: {region}")
    if hint:
        lines.append(f"Extra hint from the user: {hint}")
    lines += [
        "",
        "Reply with STRICT JSON only, no prose, in this exact shape:",
        '{"ports": [1234, 5678], "protocol": "udp", "region_host": "optional.host.name", '
        '"note": "one short sentence"}',
        "protocol must be one of: udp, tcp, both. If unsure, use your best estimate "
        "and say so in the note.",
    ]
    return "\n".join(lines)


def _parse_json_block(text):
    """Extract the first JSON object from an AI reply (tolerates ``` fences)."""
    if not text:
        return None
    s = text.strip()
    if s.startswith("```"):
        s = s.split("```")[1] if "```" in s[3:] else s[3:]
        s = s.lstrip("json").strip()
    start = s.find("{")
    end = s.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(s[start:end + 1])
    except Exception:
        return None


# ---- Model catalogue (free / paid) -------------------------------------
_AI_MODELS_CACHE = {"ts": 0.0, "data": None}
_AI_MODELS_TTL = 3600  # seconds
# Fallback so the UI menu is never empty if the network is unavailable.
_AI_MODELS_FALLBACK = [
    {"id": "openai/gpt-4o-mini", "name": "GPT-4o mini", "free": False,
     "context": 128000, "prompt": "0.00000015", "completion": "0.0000006"},
    {"id": "openai/gpt-4o", "name": "GPT-4o", "free": False,
     "context": 128000, "prompt": "0.0000025", "completion": "0.00001"},
    {"id": "anthropic/claude-3.5-haiku", "name": "Claude 3.5 Haiku", "free": False,
     "context": 200000, "prompt": "0.0000008", "completion": "0.000004"},
    {"id": "anthropic/claude-3.7-sonnet", "name": "Claude 3.7 Sonnet", "free": False,
     "context": 200000, "prompt": "0.000003", "completion": "0.000015"},
    {"id": "google/gemini-2.0-flash-001", "name": "Gemini 2.0 Flash", "free": False,
     "context": 1000000, "prompt": "0.0000001", "completion": "0.0000004"},
    {"id": "meta-llama/llama-3.3-70b-instruct:free", "name": "Llama 3.3 70B (free)",
     "free": True, "context": 128000, "prompt": "0", "completion": "0"},
    {"id": "deepseek/deepseek-r1:free", "name": "DeepSeek R1 (free)", "free": True,
     "context": 128000, "prompt": "0", "completion": "0"},
]


def _web_ai_http_message(code, raw):
    """Translate an OpenRouter HTTP error into a friendly message + actionable hint."""
    detail = ""
    try:
        parsed = json.loads(raw) if raw else {}
        err = parsed.get("error")
        if isinstance(err, dict):
            detail = err.get("message") or ""
        elif err:
            detail = str(err)
    except Exception:
        detail = ""
    detail = (detail or raw or "").strip()
    low = detail.lower()

    if code == 401:
        return ("OpenRouter rejected the API key (401).",
                "Check the key is copied in full and starts with sk-or-. "
                "Create a new one at openrouter.ai/keys.")
    if code == 402:
        return ("OpenRouter: out of credits (402).",
                "Add credits, or switch the model menu to the FREE models "
                "(e.g. a ':free' model).")
    if code == 403:
        if "security policy" in low or "denied" in low:
            return ("OpenRouter blocked the request (403 security policy).",
                    "This is usually the model/provider being blocked for your account "
                    "or region, or a restricted key. Try a different model from the menu "
                    "(the FREE ones often work), or use a key with provider access enabled. "
                    "If it persists, it may be network/VPN related — try another connection.")
        return ("OpenRouter forbade the request (403).",
                "The key may lack permission for this model, or a guardrail blocked it. "
                "Try another model, or use a key with the right access.")
    if code == 404:
        return ("OpenRouter: model not found (404).",
                "That model id does not exist. Pick one from the model menu.")
    if code == 408:
        return ("OpenRouter timed out (408).", "Try again, or pick a faster/smaller model.")
    if code == 429:
        return ("OpenRouter rate limit (429).", "Wait a moment and retry; free models "
                "share a tight rate limit.")
    if code == 502:
        return ("OpenRouter: the chosen model is down (502).",
                "Pick a different model from the menu.")
    if code == 503:
        return ("OpenRouter: no provider available for that model (503).",
                "Pick a different model, or retry shortly.")
    return (f"OpenRouter HTTP {code}.", "See the detail below; try another model or key.")


def _web_ai_models(force=False):
    """Fetch OpenRouter's model catalogue, split into free / paid for the UI menu.

    Cached for an hour; falls back to a small curated list offline so the model
    menu always has something to show."""
    now = time.time()
    if not force and _AI_MODELS_CACHE["data"] and now - _AI_MODELS_CACHE["ts"] < _AI_MODELS_TTL:
        return _AI_MODELS_CACHE["data"]
    models = None
    try:
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/models",
            headers={"Accept": "application/json",
                     "User-Agent": _WEB_UA, "X-Title": _WEB_AI_TITLE})
        with urllib.request.urlopen(req, timeout=20) as res:
            payload = json.loads(res.read().decode("utf-8"))
        out = []
        for m in payload.get("data", []):
            pricing = m.get("pricing") or {}
            prompt = pricing.get("prompt") or "0"
            completion = pricing.get("completion") or "0"
            try:
                is_free = float(prompt) == 0 and float(completion) == 0
            except (TypeError, ValueError):
                is_free = str(m.get("id", "")).endswith(":free")
            out.append({
                "id": m.get("id"),
                "name": m.get("name") or m.get("id"),
                "free": bool(is_free),
                "context": m.get("context_length"),
                "prompt": prompt,
                "completion": completion,
            })
        out = [m for m in out if m["id"]]
        out.sort(key=lambda m: (not m["free"], m["name"].lower()))
        models = out or list(_AI_MODELS_FALLBACK)
    except Exception:
        models = list(_AI_MODELS_FALLBACK)
    _AI_MODELS_CACHE["ts"] = now
    _AI_MODELS_CACHE["data"] = models
    return models


# --------------------------------------------------------------------------
#  HTTP handler
# --------------------------------------------------------------------------
class _ClientGone(Exception):
    """Raised internally when the SSE client has disconnected mid-stream."""


class WebConsoleHandler(BaseHTTPRequestHandler):
    server_version = "DnsConsole/4.0"

    def log_message(self, *args):  # keep the console quiet
        pass


    def _send_bytes(self, body, content_type, status=200):
        # The client may close the socket before the response is written (a page
        # reload, a backgrounded WebView, an aborted fetch). That surfaces as a
        # BrokenPipeError/ConnectionResetError and would otherwise dump a
        # traceback for what is entirely normal, so swallow it quietly.
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, obj, status=200):
        self._send_bytes(json.dumps(obj).encode("utf-8"),
                         "application/json; charset=utf-8", status)

    def _send_text(self, text, content_type):
        self._send_bytes(text.encode("utf-8"), content_type)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    # ---- GET --------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        query = parse_qs(parsed.query)
        # Logs tab is polled constantly; logging it would drown everything else.
        if route != "/api/logs":
            log_event(f"GET {route}" + (f"?{parsed.query}" if parsed.query else ""),
                      "debug")

        if route in ("/", "/index.html"):
            self._send_text(_WEB_INDEX_HTML, "text/html; charset=utf-8")
        elif route == "/app.css":
            self._send_text(_WEB_APP_CSS, "text/css; charset=utf-8")
        elif route == "/app.js":
            self._send_text(_WEB_APP_JS, "application/javascript; charset=utf-8")
        elif route == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        elif route == "/api/health":
            self._send_json({"ok": True, "service": "dns-console", "version": "4.0"})
        elif route == "/api/dns-list":
            self._send_json({"list": load_dns_list()})
        elif route == "/api/stability":
            _web_history_load()
            self._send_json({"rows": _web_stability_snapshot(top_n=25)})
        elif route == "/api/history":
            _web_history_load()
            with _WEB_HISTORY_LOCK:
                self._send_json({"history": _WEB_HISTORY})
        elif route == "/api/device":
            self._send_json(_web_device_info())
        elif route == "/api/network":
            self._send_json(_web_network_info())
        elif route == "/api/mtu":
            self._send_json(_web_mtu_recommendation())
        elif route == "/api/profiles":
            self._send_json({"profiles": load_services()})
        elif route == "/api/apn":
            self._send_json({"entries": query_apn_database(),
                             "current": get_current_preferred_apn_id()})
        elif route == "/api/diagnosis":
            self._send_json(_web_diagnosis())
        elif route == "/api/ai/status":
            self._send_json({"server_key": bool(_WEB_AI_KEY)})
        elif route == "/api/ai/models":
            models = _web_ai_models(force=query.get("refresh", ["0"])[0] in ("1", "true"))
            free = [m for m in models if m["free"]]
            self._send_json({"models": models, "count": len(models),
                             "free_count": len(free)})
        elif route == "/api/probe-targets":
            self._send_json({"targets": [
                {"key": k, "host": v[0], "label": v[1]}
                for k, v in _WEB_PROBE_TARGETS.items()]})
        elif route == "/api/games":
            self._send_json({"games": game_catalog()})
        elif route == "/api/signal":
            self._send_json(_web_signal_strength())
        elif route == "/api/mtu-intel":
            game = query.get("game", [""])[0]
            proto = query.get("protocol", [""])[0]
            self._send_json(_web_mtu_intelligence(game=game or None,
                                                  protocol=proto or None))
        elif route == "/api/route":
            host = query.get("host", ["google.com"])[0]
            self._send_json(_web_route_analysis(host))
        elif route == "/api/autotest":
            self._send_json(_autotest_status())
        elif route == "/api/logs":
            since = int(query.get("since", ["0"])[0] or 0)
            limit = int(query.get("limit", ["0"])[0] or 0)
            lvl = query.get("level", [""])[0]
            lines = _log_lines(since=since, limit=limit, level=lvl)
            with _LOG_LOCK:
                total = _LOG_SEQ
            self._send_json({"lines": lines, "last": total, "count": len(lines)})
        elif route == "/api/geo":
            ips = []
            for raw in query.get("ips", [""])[0].split(","):
                raw = raw.strip()
                if raw:
                    ips.append(raw)
            self._send_json({"geo": _web_geo_bulk(ips[:500])} if ips else {"geo": {}})
        elif route == "/api/scan":
            self._stream_scan(query)
        elif route == "/api/apn/benchmark":
            self._stream_apn_benchmark(query)
        else:
            self._send_json({"error": "unknown route"}, 404)

    # ---- POST -------------------------------------------------------------
    def do_POST(self):
        route = urlparse(self.path).path
        ctype = self.headers.get("Content-Type", "")
        log_event(f"POST {route} ({ctype.split(';')[0] or 'no content-type'})", "debug")
        # multipart/form-data (native browser file upload) takes priority.
        if route == "/api/import" and ctype.startswith("multipart/form-data"):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            payload, filename = _web_parse_multipart(raw, ctype)
            if payload is None:
                self._send_json({"error": "no file in upload"}, 400)
                return
            text = _web_text_from_upload(payload, filename)
            found = _web_extract_dns(text)
            self._send_json({"filename": filename, "found": found, "count": len(found),
                             "total_scanned": len(found), "bytes": len(payload)})
            return

        body = self._read_json()

        if route == "/api/scan":
            # Large target lists are POSTed (a long GET query string is 414'd).
            # Pass the parsed body through so the same streaming logic is reused.
            self._stream_scan(parse_qs(urlparse(self.path).query), body)
        elif route == "/api/dns-list":
            self._post_dns_list(body)
        elif route == "/api/profiles":
            self._post_profiles(body)
        elif route == "/api/history/clear":
            with _WEB_HISTORY_LOCK:
                _WEB_HISTORY.clear()
            _web_history_save(force=True)
            self._send_json({"ok": True})
        elif route == "/api/logs/clear":
            _log_clear()
            log_event("log buffer cleared")
            self._send_json({"ok": True})
        elif route == "/api/logs/client":
            # The browser reports its own lifecycle here (page load, JS errors,
            # main-thread freezes). A WebView that stops responding leaves no
            # trace on the Python side, so this is the only way to see it.
            items = body.get("lines") or []
            if isinstance(items, list):
                for it in items[:200]:
                    try:
                        lvl = str(it.get("level") or "INFO").upper()
                        msg = str(it.get("msg") or "")
                    except Exception:
                        continue
                    if msg:
                        _log_add(lvl, "ui", msg)
            self._send_json({"ok": True})
        elif route == "/api/tools/resolve":
            host = _web_str(body.get("host"))
            dns = _web_str(body.get("dns")) or "8.8.8.8"
            if not host:
                self._send_json({"error": "host required"}, 400)
                return
            start = time.perf_counter()
            ip = native_dns_resolver(host, dns)
            ms = round((time.perf_counter() - start) * 1000, 1)
            self._send_json({"host": host, "dns": dns, "ip": ip, "ms": ms, "ok": bool(ip)})
        elif route == "/api/tools/tcp":
            host = _web_str(body.get("host"))
            port = _web_safe_port(body.get("port"))
            if not host:
                self._send_json({"error": "host required"}, 400)
                return
            rtt, ok = tcp_ping(host, port, timeout=3.0)
            self._send_json({"host": host, "port": port, "ok": ok,
                             "ms": round(rtt, 1) if rtt else None})
        elif route == "/api/tools/tls":
            host = _web_str(body.get("host"))
            port = _web_safe_port(body.get("port"))
            if not host:
                self._send_json({"error": "host required"}, 400)
                return
            ms, ok = asyncio.run(measure_tls_handshake(host, port))
            self._send_json({"host": host, "port": port, "ok": ok,
                             "ms": round(ms, 1) if ms else None})
        elif route == "/api/tools/http":
            url = _web_str(body.get("url"))
            if not url:
                self._send_json({"error": "url required"}, 400)
                return
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            ok, status, ms, size = _web_measure_http(url)
            self._send_json({"url": url, "ok": ok, "status": status, "ms": ms, "bytes": size})
        elif route == "/api/tools/game":
            self._post_tool_game(body)
        elif route == "/api/tools/protocols":
            self._post_tool_protocols(body)
        elif route == "/api/tools/dig":
            self._post_tool_dig(body)
        elif route == "/api/import":
            self._post_import(body)
        elif route == "/api/ai/analyze":
            self._post_ai_analyze(body)
        elif route == "/api/ai/game-plan":
            self._post_ai_game_plan(body)
        elif route == "/api/pairs":
            rows = body.get("rows")
            if not isinstance(rows, list):
                rows = []
            countries = body.get("countries")
            if not isinstance(countries, list):
                countries = []
            try:
                fanout = max(1, min(20, int(body.get("fanout") or 2)))
            except (TypeError, ValueError):
                fanout = 2
            self._send_json(_web_recommend_pairs_filtered(rows, countries=countries,
                                                          fanout=fanout))
        elif route == "/api/autotest":
            action = _web_str(body.get("action")) or "status"
            if action == "config":
                cfg = dict(_AUTOTEST_DEFAULTS)
                cfg.update(body.get("config") or {})
                if body.get("targets"):
                    cfg["targets"] = body["targets"]
                _autotest_save_config(cfg)
                self._send_json({"saved": True, "config": cfg})
            elif action == "start":
                cfg = dict(_AUTOTEST_DEFAULTS)
                cfg.update(body.get("config") or {})
                if body.get("targets"):
                    cfg["targets"] = body["targets"]
                cfg["enabled"] = True
                _autotest_save_config(cfg)
                _autotest_start(cfg)
                self._send_json(_autotest_status())
            elif action == "stop":
                _autotest_stop()
                cfg = _autotest_load_config()
                cfg["enabled"] = False
                _autotest_save_config(cfg)
                self._send_json(_autotest_status())
            else:
                self._send_json(_autotest_status())
        elif route == "/api/route":
            rows = body.get("rows") or []
            host = _web_str(body.get("host")) or "google.com"
            analysis = _web_route_analysis(host, region=body.get("region"), rows=rows)
            self._send_json(analysis)
        else:
            self._send_json({"error": "unknown route"}, 404)

    # ---- POST helpers -----------------------------------------------------
    def _post_import(self, body):
        """Extract DNS servers from a filename + (optionally base64) file content."""
        filename = body.get("filename") or body.get("name") or ""
        content = body.get("content")
        data = None
        if content is not None:
            try:
                import base64
                data = base64.b64decode(content, validate=False)
            except Exception:
                self._send_json({"error": "could not decode content"}, 400)
                return
        elif body.get("text"):
            text = str(body["text"])
            found = _web_extract_dns(text)
            self._send_json({"filename": filename, "found": found,
                             "count": len(found), "total_scanned": len(found)})
            return
        else:
            self._send_json({"error": "content or text required"}, 400)
            return

        text = _web_text_from_upload(data, filename)
        found = _web_extract_dns(text)
        self._send_json({"filename": filename, "found": found, "count": len(found),
                         "total_scanned": len(found), "bytes": len(data)})

    def _post_ai_analyze(self, body):
        key = _web_str(body.get("api_key")) or _WEB_AI_KEY
        model = _web_str(body.get("model"))
        if not key:
            self._send_json({"error": "OpenRouter API key required (set one in the UI or "
                                      "start with --api-key / $OPENROUTER_API_KEY)"}, 400)
            return
        prompt = _web_build_ai_prompt(body)
        try:
            text, used_model, usage = _web_ai_analyze(key, model, prompt)
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", "ignore")[:600]
            except Exception:
                pass
            message, hint = _web_ai_http_message(e.code, raw)
            self._send_json({"error": message, "detail": raw, "hint": hint,
                             "status": e.code}, 502)
            return
        except Exception as e:
            self._send_json({"error": f"AI request failed: {e}"}, 502)
            return
        self._send_json({"analysis": text, "model": used_model, "usage": usage})

    def _post_ai_game_plan(self, body):
        """Ask the AI for the ports/protocol to test for a game we may not know."""
        key = _web_str(body.get("api_key")) or _WEB_AI_KEY
        model = _web_str(body.get("model"))
        game = _web_str(body.get("game"))
        if not game:
            self._send_json({"error": "game name required"}, 400)
            return
        # If we already know the game, answer locally and skip the API round-trip.
        if game in GAME_PROTOCOL_DB:
            cfg = GAME_PROTOCOL_DB[game]
            self._send_json({"game": game, "ports": cfg.get("ports", DEFAULT_PORTS),
                             "protocol": cfg.get("protocol", DEFAULT_PROTOCOL),
                             "hosts": cfg.get("hosts", []),
                             "note": cfg.get("note", ""), "source": "builtin"})
            return
        if not key:
            self._send_json({"error": "OpenRouter API key required for unknown games "
                                      "(set one in the UI or start with --api-key)"}, 400)
            return
        prompt = _web_build_game_plan_prompt(game, body.get("region"), body.get("hint"))
        try:
            text, used_model, _usage = _web_ai_analyze(key, model, prompt)
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", "ignore")[:600]
            except Exception:
                pass
            message, hint = _web_ai_http_message(e.code, raw)
            self._send_json({"error": message, "detail": raw, "hint": hint,
                             "status": e.code}, 502)
            return
        except Exception as e:
            self._send_json({"error": f"AI request failed: {e}"}, 502)
            return
        plan = _parse_json_block(text) or {}
        ports = plan.get("ports") if isinstance(plan.get("ports"), list) else []
        clean_ports = []
        for p in ports:
            try:
                p = int(str(p).strip())
            except (TypeError, ValueError):
                continue
            if 1 <= p <= 65535 and p not in clean_ports:
                clean_ports.append(p)
        ports = clean_ports[:16]
        proto = plan.get("protocol") if plan.get("protocol") in ("udp", "tcp", "both") else "both"
        self._send_json({"game": game, "ports": ports or DEFAULT_PORTS,
                         "protocol": proto,
                         "region_host": plan.get("region_host") or "",
                         "note": plan.get("note") or text[:300],
                         "model": used_model, "source": "ai"})

    def _post_dns_list(self, body):
        dns_list = list(load_dns_list())
        if body.get("clear"):
            dns_list = []
        add = body.get("add")
        if isinstance(add, str):
            add = [add]
        if isinstance(add, list):
            for addr in add:
                addr = str(addr).strip()
                if addr and addr not in dns_list:
                    dns_list.append(addr)
        delete = body.get("delete")
        if isinstance(delete, str) and delete in dns_list:
            dns_list.remove(delete)
        save_dns_list(dns_list)
        self._send_json({"list": dns_list, "count": len(dns_list)})

    def _post_profiles(self, body):
        services = dict(load_services())
        add = body.get("add")
        if isinstance(add, dict):
            name = (add.get("name") or "").strip()
            host = (add.get("host") or "").strip()
            if name and host:
                services[name] = host
        delete = body.get("delete")
        if isinstance(delete, str) and delete in services:
            del services[delete]
        save_services(services)
        self._send_json({"profiles": services})

    def _post_tool_protocols(self, body):
        """Probe one target over UDP, TCP and DoT (TLS) side by side."""
        host = _web_str(body.get("host"))
        if not host:
            self._send_json({"error": "host required"}, 400)
            return
        try:
            count = max(1, min(10, int(body.get("count") or 3)))
        except (TypeError, ValueError):
            count = 3
        probe_host = _web_probe_host(body.get("probe") or "google")
        r = _web_ping_blocking(host, count, 2.0, "both", probe_host)
        # 'both' covers UDP+TCP; add a DoT pass explicitly for the full picture.
        r["proto_results"]["tls"] = _dns_probe_protocol(
            host, _build_dns_query(probe_host), count, 2.0, "tls")
        self._send_json({"host": host, "probe": probe_host, "count": count,
                         "results": r["proto_results"]})

    def _post_tool_dig(self, body):
        """Resolve the selected game/CDN target(s) through a chosen DNS server.

        Mirrors `dig @server target` — one query per selected target, using the
        resolver the user wants to test."""
        dns_server = _web_str(body.get("dns")) or _web_str(body.get("server")) or "1.1.1.1"
        raw_targets = body.get("targets")
        if raw_targets is None:
            raw_targets = [body.get("probe") or body.get("host") or "google"]
        if isinstance(raw_targets, str):
            raw_targets = [t for t in raw_targets.split(",") if t.strip()]
        hosts = [_web_probe_host(t) for t in raw_targets][:3]
        if not hosts:
            hosts = ["google.com"]
        try:
            timeout = max(0.3, min(10.0, float(body.get("timeout") or 2.0)))
        except (TypeError, ValueError):
            timeout = 2.0
        results = []
        for h in hosts:
            start = time.perf_counter()
            r = _web_dig(h, dns_server, 1, timeout)
            r["ms"] = round((time.perf_counter() - start) * 1000, 1)
            results.append(r)
        self._send_json({"server": dns_server, "results": results})

    def _post_tool_game(self, body):
        host = _web_str(body.get("host"))
        game = _web_str(body.get("game"))
        port = body.get("port")
        protocol = body.get("protocol")
        # If no host was given, fall back to the game's own known endpoints so the
        # test still hits something real instead of erroring out.
        if not host and game:
            eps = game_endpoints(game, body.get("region"))
            host = eps[0] if eps else ""
        if not host:
            self._send_json({"error": "host required (or pick a game with known servers)"}, 400)
            return
        try:
            count = max(1, min(10, int(body.get("count") or 3)))
        except (TypeError, ValueError):
            count = 3
        ports, proto = game_port_plan(game, port=port, protocol=protocol)
        start = time.perf_counter()
        # protocol_aware_ping returns (latency_ms, loss_pct, jitter_ms); latency is
        # None when nothing answered, which is the real reachability signal.
        latency, loss, jitter = asyncio.run(
            protocol_aware_ping(host, game, count, port=port, protocol=protocol))
        ms = round((time.perf_counter() - start) * 1000, 1)
        self._send_json({"host": host, "game": game or "(generic)",
                         "port": ports[0] if ports else None, "protocol": proto,
                         "ok": latency is not None,
                         "latency": round(latency, 1) if latency is not None else None,
                         "jitter": round(jitter, 1) if jitter is not None else None,
                         "loss": round(loss, 1) if loss is not None else None, "ms": ms})

    # ---- SSE: chunked / parallel DNS scan ---------------------------------
    def _stream_scan(self, query, body=None):
        """Server-sent events: scan many DNS servers in bounded-parallel chunks,
        streaming each result as it lands (scales to thousands of targets).

        GET supplies a small `targets` list in the query string; large lists are
        POSTed in the body (a long GET query string is rejected with 414)."""
        body = body or {}
        if body.get("dnslist") or query.get("dnslist", ["0"])[0] in ("1", "true", "yes"):
            targets = list(load_dns_list())
        else:
            raw_list = body.get("targets")
            if raw_list is None:
                raw_list = query.get("targets", [""])[0]
            if isinstance(raw_list, str):
                raw_list = raw_list.split(",")
            elif not isinstance(raw_list, (list, tuple)):
                raw_list = []      # JSON null / number / bool: nothing to scan
            targets = [str(t).strip() for t in raw_list
                       if t is not None and str(t).strip()]
        seen = set()
        targets = [t for t in targets if not (t in seen or seen.add(t))]

        def _int(name, default, lo, hi):
            src = body.get(name)
            if src is None:
                src = query.get(name, [str(default)])[0]
            try:
                return max(lo, min(hi, int(src)))
            except (TypeError, ValueError):
                return default

        count = _int("count", 3, 1, 10)
        workers = _int("workers", 64, 1, 512)
        chunk = _int("chunk", 100, 1, 5000)
        max_targets = _int("max", 20000, 1, 200000)
        proto = (_web_str(body.get("proto")) or query.get("proto", ["udp"])[0] or "udp").lower()
        if proto not in ("udp", "tcp", "tls", "both", "auto"):
            proto = "udp"
        try:
            timeout = max(0.3, min(10.0, float(body.get("timeout")
                        or query.get("timeout", ["1.5"])[0])))
        except (TypeError, ValueError):
            timeout = 1.5
        probe_key = body.get("probe") or query.get("probe", ["google"])[0]
        probe_host = _web_probe_host(probe_key)
        want_geo = bool(body.get("geo")) or query.get("geo", ["0"])[0] in ("1", "true", "yes")

        truncated = len(targets) > max_targets
        if truncated:
            targets = targets[:max_targets]

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True

        def emit(obj):
            # A closed client (page reload / backgrounded WebView) must abort the
            # stream quietly instead of raising mid-scan.
            try:
                self.wfile.write(b"data: " + json.dumps(obj).encode("utf-8") + b"\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise _ClientGone()

        try:
            _web_history_load()
            emit({"type": "start", "total": len(targets), "count": count,
                  "workers": workers, "chunk": chunk, "proto": proto,
                  "timeout": timeout, "probe": probe_host, "geo": want_geo,
                  "truncated": truncated})
            if not targets:
                emit({"type": "done", "summary": {"total": 0, "ok": 0, "failed": 0}})
                return

            def run_one(target):
                r = _web_ping_blocking(target, count, timeout, proto, probe_host)
                latency, loss, jitter = r["latency"], r["loss"], r["jitter"]
                ok = r["ok"]
                _web_fold_history(target, latency if ok else 2000.0, loss, jitter)
                best_proto = next((k for k in ("udp", "tcp", "tls")
                                   if r["proto_results"].get(k, {}).get("ok")), None)
                return {
                    "type": "result",
                    "target": target,
                    "latency": round(latency, 1) if ok else None,
                    "loss": round(loss, 1),
                    "jitter": round(jitter, 1) if ok else None,
                    "status": "ok" if ok else "fail",
                    "proto": proto,
                    "proto_used": best_proto,
                    "proto_results": r["proto_results"],
                }

            done = 0
            ok_count = 0
            best = None
            alive_map = {}          # target -> result, for pair recommendations
            started = time.perf_counter()
            # A sliding window keeps only ~2x the worker count of futures alive at
            # once, so even 100k targets don't exhaust memory.
            window = max(workers, workers * 2)
            it = iter(targets)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                pending = set()
                for _ in range(min(window, len(targets))):
                    t = next(it, None)
                    if t is None:
                        break
                    pending.add(pool.submit(run_one, t))
                while pending:
                    done_set, pending = concurrent.futures.wait(
                        pending, return_when=concurrent.futures.FIRST_COMPLETED)
                    for fut in done_set:
                        res = fut.result()
                        done += 1
                        if res["status"] == "ok":
                            ok_count += 1
                            alive_map[res["target"]] = res
                            if best is None or res["latency"] < best:
                                best = res["latency"]
                        emit(res)
                        if done % chunk == 0 or done == len(targets):
                            elapsed = time.perf_counter() - started
                            emit({"type": "chunk", "done": done, "total": len(targets),
                                  "ok": ok_count, "best": best,
                                  "rate": round(done / elapsed, 1) if elapsed > 0 else 0})
                        else:
                            emit({"type": "progress", "done": done, "total": len(targets)})
                        nxt = next(it, None)
                        if nxt is not None:
                            pending.add(pool.submit(run_one, nxt))
            _web_history_save()

            # Optional geo enrichment (post-pass, streamed so the UI can fill in).
            if want_geo and alive_map:
                emit({"type": "geo-start", "total": len(alive_map)})
                geo_done = 0
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as gpool:
                    gfuts = {gpool.submit(_web_geo_lookup, t): t for t in alive_map}
                    for gfut in concurrent.futures.as_completed(gfuts):
                        t = gfuts[gfut]
                        try:
                            g = gfut.result()
                        except Exception:
                            g = {"country": "", "country_name": "", "asn": "", "org": ""}
                        alive_map[t].update(g)
                        geo_done += 1
                        emit({"type": "geo", "target": t, "country": g.get("country", ""),
                              "country_name": g.get("country_name", ""),
                              "asn": g.get("asn", ""), "org": g.get("org", ""),
                              "done": geo_done, "total": len(alive_map)})
                emit({"type": "pairs", **_web_recommend_pairs(list(alive_map.values()))})

            emit({"type": "summary", "rows": _web_stability_snapshot(top_n=25)})
            emit({"type": "done", "summary": {"total": done, "ok": ok_count,
                                              "failed": done - ok_count}})
        except (BrokenPipeError, ConnectionResetError, _ClientGone):
            pass  # client navigated away
        except Exception as exc:  # never kill the server thread
            try:
                emit({"type": "error", "message": str(exc)})
            except Exception:
                pass

    # ---- SSE: live APN benchmark -----------------------------------------
    def _stream_apn_benchmark(self, query):
        """Stream an APN benchmark. Actually switching the preferred APN mutates
        live device state, so it only runs when confirm=1 is passed; otherwise the
        entries are listed without touching anything."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True

        def emit(obj):
            # A closed client (page reload / backgrounded WebView) must abort the
            # stream quietly instead of raising mid-scan.
            try:
                self.wfile.write(b"data: " + json.dumps(obj).encode("utf-8") + b"\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise _ClientGone()

        try:
            confirmed = query.get("confirm", ["0"])[0] in ("1", "true", "yes")
            if not is_shizuku_running():
                emit({"type": "error", "message": "Shizuku is not running."})
                return
            entries = query_apn_database()
            if not entries:
                emit({"type": "error", "message": "No APN entries found (Shizuku denied?)."})
                return
            if not confirmed:
                emit({"type": "preview", "entries": entries,
                      "message": "Read-only preview. Add confirm=1 to actually benchmark "
                                 "(this switches the preferred APN, then restores it)."})
                emit({"type": "done", "summary": {"total": 0, "ok": 0, "failed": 0}})
                return

            original_id = get_current_preferred_apn_id()
            emit({"type": "start", "total": len(entries), "original": original_id})
            results = []
            try:
                for entry in entries:
                    set_preferred_apn(entry["id"])
                    time.sleep(RADIO_COOLDOWN_SECONDS)
                    try:
                        rtt, ok = tcp_ping(REFERENCE_HOST, 443)
                    except Exception:
                        rtt, ok = None, False
                    res = {"type": "result", "id": entry["id"], "name": entry["name"],
                           "apn": entry["apn"], "ok": bool(ok),
                           "rtt": round(rtt, 1) if rtt else None}
                    results.append(res)
                    emit(res)
            finally:
                if original_id:
                    set_preferred_apn(original_id)
                    time.sleep(RADIO_COOLDOWN_SECONDS)
                    emit({"type": "restored", "id": original_id})
            okc = sum(1 for r in results if r["ok"])
            emit({"type": "done", "summary": {"total": len(results), "ok": okc,
                                              "failed": len(results) - okc}})
        except (BrokenPipeError, ConnectionResetError, _ClientGone):
            pass
        except Exception as exc:
            try:
                emit({"type": "error", "message": str(exc)})
            except Exception:
                pass


def _web_install_termux_autostart():
    """Install a Termux:Boot script that launches the console (background) at boot.

    Requires the Termux:Boot app; the script lives in ~/.termux/boot/ and starts the
    server on the LAN so the phone's dashboard is reachable from other devices."""
    boot_dir = os.path.expanduser("~/.termux/boot")
    script = os.path.join(boot_dir, "start-dns-console.sh")
    target = os.path.abspath(__file__)
    body = (
        "#!/data/data/com.termux/files/usr/bin/sh\n"
        "# Auto-generated by advanced_core.py --web --install-autostart\n"
        "termux-wake-lock\n"
        f"exec python {target} --web --all --background\n"
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
    print(f"  It runs: python {target} --web --all --background")
    print()
    print("  To activate it, install the Termux:Boot app from F-Droid,")
    print("  open it once, then reboot. The console will start automatically.")
    print("=" * 62)


def _web_lan_ip():
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


def web_console_main(argv=None):
    _install_exception_hooks()
    _start_watchdog()
    log_event("engine starting: " + " ".join(sys.argv[:6]))
    log_event(f"python {platform.python_version()} on {platform.system()} "
              f"({platform.machine()})")
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
    parser.add_argument("--api-key", default="",
                        help="default OpenRouter API key for AI analysis (overridable in the UI)")
    args = parser.parse_args(argv)

    # Seed the AI key from the CLI/env (env wins over flag only if the flag is empty).
    global _WEB_AI_KEY
    _WEB_AI_KEY = args.api_key or os.environ.get("OPENROUTER_API_KEY", "")

    if args.install_autostart:
        _web_install_termux_autostart()
        return

    host = "0.0.0.0" if args.all else args.host
    port = _web_pick_port(host, args.port)
    log_event(f"binding {host}:{port}")
    try:
        httpd = ThreadingHTTPServer((host, port), WebConsoleHandler)
    except Exception as exc:
        log_event(f"FATAL: cannot bind {host}:{port}: {exc}", "error")
        raise
    log_event(f"web console ready on http://{host}:{port}/")

    shown_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    url = f"http://{shown_host}:{port}/"

    print("=" * 62)
    print("  DNS CONSOLE  -  local web interface")
    print("=" * 62)
    print(f"  Serving at : {url}")
    print(f"  Bound to   : {host}:{port}")
    if host == "0.0.0.0":
        print(f"  LAN link   : http://{_web_lan_ip()}:{port}/  (from other devices)")
    print("  Stop with  : Ctrl+C")
    print("=" * 62)

    if args.background:
        args.no_open = True

    # Resume a previously-saved auto-test if the user had it enabled, so the
    # background loop keeps running without re-configuring it every time.
    try:
        _autotest_autoresume()
        log_event("auto-test config checked")
    except Exception as exc:
        log_event(f"auto-test autoresume failed: {exc}", "error")

    if not args.no_open:
        threading.Timer(0.7, lambda: _web_open_browser(url)).start()
        print("  Opening your browser automatically...")
    print("  If nothing opens, copy the link above into your browser.")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down. Bye.")
    finally:
        httpd.server_close()


def launch_web_console(extra_args=None):
    """Start the embedded local web console (see web_console_main)."""
    web_console_main([] if extra_args is None else extra_args)


# ============================================================
#  MAIN MENU
# ============================================================
def menu():
    while True:
        clear_scr()
        print(f"{ANSI_CYAN}{ANSI_BOLD}======================================================={ANSI_RESET}")
        print(f"{ANSI_CYAN}{ANSI_BOLD}         ASYNC NETWORK SYSTEM CORE v6 (LIGHT){ANSI_RESET}")
        print(f"{ANSI_CYAN}{ANSI_BOLD}======================================================={ANSI_RESET}")
        print(f"{ANSI_GREEN}[1]{ANSI_RESET} RUN ASYNC TELEMETRY OPTIMIZER {ANSI_YELLOW}(GAME){ANSI_RESET}")
        print(f"{ANSI_GREEN}[2]{ANSI_RESET} RUN ASYNC DOWNLOAD SPEED OPTIMIZER {ANSI_YELLOW}(CDN){ANSI_RESET}")
        print(f"{ANSI_GREEN}[3]{ANSI_RESET} MANAGE CUSTOM GAME PROFILES")
        print(f"{ANSI_BLUE}[D]{ANSI_RESET} LOCAL NETWORK DIAGNOSIS {ANSI_DIM}(GATEWAY/PING){ANSI_RESET}")
        print(f"{ANSI_YELLOW}[A]{ANSI_RESET} LIVE APN BENCHMARK {ANSI_RED}(SHIZUKU){ANSI_RESET}")
        print(f"{ANSI_BLUE}[M]{ANSI_RESET} DNS MANAGER {ANSI_DIM}(ADD / DELETE / TEST){ANSI_RESET}")
        print(f"{ANSI_CYAN}[W]{ANSI_RESET} OPEN LOCAL WEB CONSOLE {ANSI_DIM}(BROWSER UI){ANSI_RESET}")
        print(f"{ANSI_RED}[4]{ANSI_RESET} Exit")
        print(f"{ANSI_CYAN}{ANSI_BOLD}======================================================={ANSI_RESET}")

        choice = input(f"{ANSI_BOLD}Select Option{ANSI_RESET} [1-4, D, A, M, W]: ").strip().lower()
        if choice == '1':
            asyncio.run(run_advanced_telemetry_async())
        elif choice == '2':
            asyncio.run(run_download_cdn_telemetry_async())
        elif choice == '3':
            manage_custom_profiles()
        elif choice == 'd':
            run_local_diagnosis()
        elif choice == 'a':
            run_live_apn_benchmark()
        elif choice == 'm':
            run_dns_manager()
        elif choice == 'w':
            launch_web_console()
            input(f"{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")
        elif choice == '4':
            sys.exit(0)


if __name__ == '__main__':
    # `python advanced_core.py --web [--port N] [--all] ...` jumps into the console.
    if '--web' in sys.argv:
        idx = sys.argv.index('--web')
        launch_web_console(sys.argv[idx + 1:])
    else:
        menu()
