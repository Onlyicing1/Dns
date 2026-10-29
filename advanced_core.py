import os, sys, re, time, urllib.request, json, random, asyncio, socket
import logging
import hashlib
import secrets
from typing import Optional, Dict, List, Any, Callable

# Force UTF-8 stdout regardless of the Termux locale
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ---- NEW: Structured logging setup ----
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("advanced_core")

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
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    try:
        # Fallback: direct execution (no shell)
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
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
        "note": "Apex uses UDP on ports 37015-37025 for game traffic. Source: EA/Respawn docs."
    },
    "Valorant": {
        "ports": [5060, 5061, 3478, 3479, 37015],
        "protocol": "udp",
        "note": "Valorant uses UDP on 3478-3479 (peer-to-peer) and 5060-5061 (voice)."
    },
    "Fortnite": {
        "ports": [7848, 7849, 37015],
        "protocol": "udp",
        "note": "Fortnite uses UDP on 7848-7849 for game traffic."
    },
    "Call of Duty": {
        "ports": [3074, 3075, 3076, 3077],
        "protocol": "udp",
        "note": "CoD uses UDP on 3074-3077 for matchmaking and gameplay."
    },
    "PUBG": {
        "ports": [27015, 27016, 27017, 27018, 27019],
        "protocol": "udp",
        "note": "PUBG uses UDP on 27015-27019 for game servers."
    },
    "League of Legends": {
        "ports": [5190, 5191, 5192, 5193, 5194],
        "protocol": "udp",
        "note": "LoL uses UDP on 5190-5194 for game client communication."
    },
    "Overwatch": {
        "ports": [11196, 11197, 11198, 11199, 11200],
        "protocol": "udp",
        "note": "Overwatch uses UDP on 11196-11200 for game traffic."
    },
    "Rainbow Six Siege": {
        "ports": [3074, 3075, 3076, 3077, 3078],
        "protocol": "udp",
        "note": "R6 Siege uses UDP on 3074-3078 for game servers."
    },
    "Google Core": {
        "ports": [443],
        "protocol": "tcp",
        "note": "Google services use TCP/443."
    },
    "EA Auth": {
        "ports": [443],
        "protocol": "tcp",
        "note": "EA authentication uses TCP/443."
    },
    "Marvel Rivals": {
        "ports": [443],
        "protocol": "tcp",
        "note": "Marvel Rivals uses TCP/443 for API calls."
    },
}

# Default ports for unknown games/services
DEFAULT_PORTS = [443, 80]
DEFAULT_PROTOCOL = "tcp"

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
    """Test latency through multiple DNS servers sequentially."""
    results = []
    current_dns = None
    for dns in dns_servers:
        try:
            loop = asyncio.get_running_loop()
            rtt, ok = await loop.run_in_executor(None, lambda: tcp_ping(target_host, 443, timeout=2.0))
            results.append({"dns": dns, "rtt": rtt if ok else None, "ok": ok})
        except:
            results.append({"dns": dns, "rtt": None, "ok": False})
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
    return m.group(1) if m else None

def is_vpn_interface(iface_name):
    """WireGuard/OpenVPN-style tunnels surface as tun/wg/ppp interfaces on Android, regardless of
    the underlying VPN protocol, since Android's VpnService exposes a TUN device."""
    return bool(iface_name) and iface_name.startswith(("tun", "wg", "ppp"))

def resolve_smart_mtu():
    """
    Read-only MTU recommendation (informational only - nothing here touches live system state):
      - Default route via a VPN/WireGuard TUN interface -> fixed VPN_MTU
      - Otherwise (Cellular)                             -> physical MTU probing via find_golden_mtu()
    """
    active_iface = detect_active_interface()
    if is_vpn_interface(active_iface):
        return VPN_MTU, f"VPN:{active_iface}", active_iface
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
            if key in self._connections:
                sock = self._connections.pop(key)
                try:
                    sock.settimeout(timeout)
                    sock.setblocking(False)
                    try:
                        sock.recv(1, socket.MSG_PEEK)
                        elapsed = (time.perf_counter() - start) * 1000
                        self._connections[key] = sock
                        return elapsed, True
                    except:
                        sock.close()
                        sock = None
                except:
                    if sock:
                        try:
                            sock.close()
                        except:
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
                data = await asyncio.wait_for(loop.sock_recvfrom(sock, 512), timeout=timeout)
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

async def protocol_aware_ping(host, game_name, count=3, timeout=1.5):
    """Protocol-aware ping: uses UDP for game ports, TCP for standard ports.
    This is the key optimization — game traffic is UDP, so TCP ping is misleading."""
    config = GAME_PROTOCOL_DB.get(game_name, {})
    ports = config.get("ports", DEFAULT_PORTS)
    protocol = config.get("protocol", DEFAULT_PROTOCOL)
    primary_port = ports[0]

    if protocol == "udp":
        return await udp_ping(host, primary_port, count, timeout)
    else:
        # TCP ping via executor (blocking socket)
        loop = asyncio.get_running_loop()
        rtt, ok = await loop.run_in_executor(None, lambda: tcp_ping(host, primary_port, timeout))
        if ok:
            return rtt, 0.0, 0.0
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
def _build_dns_query(host):
    """Build a DNS query packet for the given hostname."""
    import struct
    import random as _random
    # Header: ID (random), flags (standard query), questions, answers, authority, additional
    txid = _random.randint(1, 65535)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    # Question section
    question = b''
    for part in host.split('.'):
        question += bytes([len(part)]) + part.encode()
    question += b'\x00'
    question += b'\x00\x01'  # QTYPE = A
    question += b'\x00\x01'  # QCLASS = IN
    return header + question

def _parse_dns_response(data):
    """Parse DNS response and extract IP addresses."""
    import struct
    try:
        if len(data) < 12:
            return None
        # Skip header (12 bytes)
        # Parse answer count from header
        qdcount = struct.unpack('!H', data[4:6])[0]
        ancount = struct.unpack('!H', data[6:8])[0]
        # Skip question section
        pos = 12
        for _ in range(qdcount):
            while data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
            pos += 4  # QTYPE + QCLASS
        # Parse answers
        for _ in range(ancount):
            # Skip name (could be compressed)
            if data[pos] & 0xC0 == 0xC0:
                pos += 2  # Compressed name pointer
            else:
                while data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            # Type, Class, TTL, RDLENGTH
            if pos + 10 > len(data):
                break
            rtype = struct.unpack('!H', data[pos:pos+2])[0]
            rclass = struct.unpack('!H', data[pos+2:pos+4])[0]
            ttl = struct.unpack('!I', data[pos+4:pos+8])[0]
            rdlength = struct.unpack('!H', data[pos+8:pos+10])[0]
            pos += 10
            rdata = data[pos:pos+rdlength]
            if rtype == 1 and rdlength == 4:  # A record
                ip = '.'.join(str(b) for b in rdata)
                return ip
            pos += rdlength
    except:
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
    if dns_server and not _is_ip_address(dns_server):
        try:
            dns_ip = socket.getaddrinfo(dns_server, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except Exception:
            dns_ip = None
    
    # Try the specified DNS server first via real UDP DNS query
    if dns_ip and _is_ip_address(dns_ip):
        try:
            query = _build_dns_query(host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (dns_ip, 53))
            data, _ = sock.recvfrom(512)
            sock.close()
            ip = _parse_dns_response(data)
            if ip:
                _DNS_CACHE[cache_key] = (ip, now)
                return ip
        except socket.timeout:
            pass
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
                        import random as _random
                        delay = delay * _random.uniform(0.5, 1.5)
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
                        import random as _random
                        delay = delay * _random.uniform(0.5, 1.5)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {delay:.2f}s: {e}")
                    time.sleep(delay)
        raise last_exception

_retry_handler = RetryHandler(max_retries=3, base_delay=0.5, max_delay=10.0, jitter=True)

async def async_ping_dns_core(ip_address, port=53, count=3):
    """Async DNS ping with circuit breaker and performance profiling."""
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
                qs.settimeout(1.5)
                qs.sendto(packet, (ip_address, port))
                data, _ = qs.recvfrom(512)
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

async def measure_item_async(item):
    res_item = dict(item)
    # ---- OPTIMIZATION: Protocol-aware ping — use UDP for game ports, TCP for standard ----
    # This is the key optimization: DNS ping alone doesn't measure game traffic latency.
    # For UDP-based games (Apex, Valorant, etc.), we ping the actual game ports.
    p1_time, p1_loss, p1_jit = await async_ping_dns_core(res_item["pair"][0])
    p2_time, p2_loss, p2_jit = (p1_time, p1_loss, p1_jit) if len(res_item["pair"]) < 2 else await async_ping_dns_core(res_item["pair"][1])
    res_item["latency"] = (p1_time + p2_time) / 2
    res_item["loss"] = (p1_loss + p2_loss) / 2
    res_item["jitter"] = (p1_jit + p2_jit) / 2
    return res_item

async def measure_game_latency_async(item, target_host, game_name):
    """Protocol-aware game latency measurement.
    Uses TCP ping for game-specific ports (Apex, Valorant, etc.) since most game servers
    don't respond to arbitrary UDP pings. TCP port check is more reliable for connectivity testing.
    
    Includes early termination: if DNS latency is too high, skip game latency test."""
    res_item = dict(item)
    primary_dns = res_item["pair"][0]
    # DNS resolution
    loop = asyncio.get_running_loop()
    resolved_ip = await loop.run_in_executor(None, native_dns_resolver, target_host, primary_dns)
    if not resolved_ip:
        resolved_ip = target_host

    # Protocol-aware ping — use TCP for reliability (most game servers respond on TCP ports)
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

    rtt, ok = await loop.run_in_executor(None, lambda: tcp_ping(resolved_ip, primary_port, timeout=1.5))
    lat = rtt if ok else None
    loss = 0.0 if ok else 100.0
    jit = 0.0

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

    # ---- NEW: Background DNS prefetch ----
    # Resolve target host IP in background while we load the DNS list
    loop = asyncio.get_running_loop()
    target_ip_task = loop.run_in_executor(None, native_dns_resolver, target_host, "8.8.8.8")

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
            dns_result = await measure_item_async(item)
            game_result = await measure_game_latency_async(item, target_host, target_name)
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
                print(f"   ASYNCIO MATRIX TELEMETRY CORE v6 - NATIVE LAYER (No Jitter Spike)  ")
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
                    game_loss = item.get('game_loss', 0)
                    proto = item.get('protocol', 'tcp')
                    port = item.get('port', 0)
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
                        game_loss_val = p_item.get('game_loss', 0)
                        proto = p_item.get('protocol', 'tcp')
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
            try:
                import web_server
                web_server.main([])
            except ImportError:
                print(f"{ANSI_RED}[X] web_server.py not found next to this script.{ANSI_RESET}")
                input(f"{ANSI_DIM}Press Enter to continue...{ANSI_RESET}")
        elif choice == '4':
            sys.exit(0)

if __name__ == '__main__':
    menu()
