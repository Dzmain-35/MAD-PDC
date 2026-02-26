"""
HTTP Traffic Monitor
Captures HTTP/HTTPS connection-level traffic per process and flags
suspicious patterns.  Designed to provide a Fiddler-like view without
requiring packet capture — uses psutil connection polling + hostname
resolution + heuristic alerting.

Data captured per session:
    #, Time, PID, Process, Protocol, Method, Host, URL, Status,
    Remote IP:Port, Alert level
"""

import threading
import time
import socket
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set
from collections import deque, defaultdict

try:
    import psutil
except ImportError:
    psutil = None

# ── Ports treated as HTTP/HTTPS traffic ──────────────────────────────
HTTP_PORTS = {80, 8080, 8000, 8008, 3128}
HTTPS_PORTS = {443, 8443, 9443}
WEB_PORTS = HTTP_PORTS | HTTPS_PORTS

# ── Suspicious TLDs and patterns ─────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",        # Free TLDs abused by malware
    ".top", ".xyz", ".buzz", ".icu",           # Cheap TLDs popular in phishing
    ".onion",                                   # Tor
}

SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "notepad.exe",
}


class HttpSession:
    """One observed HTTP/HTTPS connection."""

    __slots__ = (
        "id", "timestamp", "time_full", "pid", "process_name",
        "protocol", "host", "remote_ip", "remote_port",
        "local_port", "status", "alert", "alert_reasons",
        "first_seen", "last_seen", "hit_count",
    )

    def __init__(self, *, id: int, pid: int, process_name: str,
                 remote_ip: str, remote_port: int, local_port: int,
                 status: str, host: str = ""):
        now = datetime.now()
        self.id = id
        self.timestamp = now.strftime("%H:%M:%S.%f")[:-3]
        self.time_full = now.isoformat()
        self.pid = pid
        self.process_name = process_name
        self.protocol = "HTTPS" if remote_port in HTTPS_PORTS else "HTTP"
        self.host = host
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.local_port = local_port
        self.status = status
        self.alert = ""          # "", "low", "medium", "high"
        self.alert_reasons: list = []
        self.first_seen = now
        self.last_seen = now
        self.hit_count = 1

    # Unique key for deduplication (same process → same remote endpoint)
    @property
    def key(self) -> str:
        return f"{self.pid}|{self.remote_ip}:{self.remote_port}"

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "process_name": self.process_name,
            "protocol": self.protocol,
            "host": self.host,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "local_port": self.local_port,
            "status": self.status,
            "alert": self.alert,
            "alert_reasons": self.alert_reasons,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "hit_count": self.hit_count,
        }


class HttpTrafficMonitor:
    """
    Monitors HTTP/HTTPS traffic at the connection level.

    Usage:
        mon = HttpTrafficMonitor()
        mon.register_callback(my_handler)  # called with HttpSession
        mon.start_monitoring()
    """

    def __init__(self, max_sessions: int = 10000, poll_interval: float = 1.5):
        self.max_sessions = max_sessions
        self.poll_interval = poll_interval
        self.is_monitoring = False
        self._thread: Optional[threading.Thread] = None

        # Session storage
        self.sessions: deque = deque(maxlen=max_sessions)
        self._active: Dict[str, HttpSession] = {}   # key -> session
        self._session_counter = 0

        # Callbacks
        self.callbacks: List[Callable] = []

        # Hostname cache (shared with MAD's resolve_hostname when possible)
        self._hostname_cache: Dict[str, str] = {}

        # Stats
        self.stats = {
            "total_sessions": 0,
            "active_sessions": 0,
            "alerts": 0,
            "http_sessions": 0,
            "https_sessions": 0,
        }

        # Beaconing detection: pid -> list of timestamps
        self._beacon_tracker: Dict[int, list] = defaultdict(list)

    # ── public API ───────────────────────────────────────────────────
    def register_callback(self, callback: Callable):
        """Register callback(HttpSession) for new sessions."""
        self.callbacks.append(callback)

    def start_monitoring(self) -> bool:
        if self.is_monitoring:
            return False
        self.is_monitoring = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="HttpTrafficMonitor"
        )
        self._thread.start()
        return True

    def stop_monitoring(self) -> bool:
        if not self.is_monitoring:
            return False
        self.is_monitoring = False
        if self._thread:
            self._thread.join(timeout=3)
        return True

    def get_sessions(self, pid_filter: Optional[int] = None,
                     alert_only: bool = False) -> List[HttpSession]:
        """Return sessions, optionally filtered."""
        out = list(self.sessions)
        if pid_filter is not None:
            out = [s for s in out if s.pid == pid_filter]
        if alert_only:
            out = [s for s in out if s.alert]
        return out

    def clear(self):
        self.sessions.clear()
        self._active.clear()
        self._session_counter = 0
        self.stats = {k: 0 for k in self.stats}

    # ── internal ─────────────────────────────────────────────────────
    def _monitor_loop(self):
        while self.is_monitoring:
            try:
                self._poll_connections()
            except Exception as e:
                print(f"[HttpTrafficMonitor] Error: {e}")
            time.sleep(self.poll_interval)

    def _poll_connections(self):
        if psutil is None:
            return
        seen_keys: Set[str] = set()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = proc.info.get("name", "")
                for conn in psutil.Process(pid).net_connections(kind="inet"):
                    if not conn.raddr:
                        continue
                    rport = conn.raddr.port
                    if rport not in WEB_PORTS:
                        continue

                    key = f"{pid}|{conn.raddr.ip}:{rport}"
                    seen_keys.add(key)

                    if key in self._active:
                        # Update existing session
                        sess = self._active[key]
                        sess.last_seen = datetime.now()
                        sess.status = conn.status
                        sess.hit_count += 1
                        continue

                    # New HTTP/HTTPS session
                    self._session_counter += 1
                    host = self._resolve(conn.raddr.ip)
                    sess = HttpSession(
                        id=self._session_counter,
                        pid=pid,
                        process_name=pname,
                        remote_ip=conn.raddr.ip,
                        remote_port=rport,
                        local_port=conn.laddr.port if conn.laddr else 0,
                        status=conn.status,
                        host=host,
                    )

                    # Run alert heuristics
                    self._evaluate_alerts(sess)

                    self._active[key] = sess
                    self.sessions.append(sess)
                    self.stats["total_sessions"] += 1
                    if sess.protocol == "HTTPS":
                        self.stats["https_sessions"] += 1
                    else:
                        self.stats["http_sessions"] += 1
                    if sess.alert:
                        self.stats["alerts"] += 1

                    for cb in self.callbacks:
                        try:
                            cb(sess)
                        except Exception as e:
                            print(f"[HttpTrafficMonitor] Callback error: {e}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Prune closed connections
        closed = set(self._active.keys()) - seen_keys
        for key in closed:
            del self._active[key]
        self.stats["active_sessions"] = len(self._active)

    # ── hostname resolution ──────────────────────────────────────────
    def _resolve(self, ip: str) -> str:
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        if ip in ("", "0.0.0.0", "127.0.0.1", "::1", "::"):
            self._hostname_cache[ip] = ip
            return ip
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            host = ""
        self._hostname_cache[ip] = host
        return host

    # ── alert heuristics ─────────────────────────────────────────────
    def _evaluate_alerts(self, sess: HttpSession):
        """Score a session for suspiciousness."""
        reasons: List[str] = []

        # 1. Suspicious process making HTTP calls
        if sess.process_name.lower() in SUSPICIOUS_PROCESSES:
            reasons.append(f"Suspicious process: {sess.process_name}")

        # 2. No hostname resolved (direct IP connection — possible C2)
        if not sess.host:
            reasons.append("Direct IP connection (no hostname)")

        # 3. Suspicious TLD
        host_lower = sess.host.lower() if sess.host else ""
        for tld in SUSPICIOUS_TLDS:
            if host_lower.endswith(tld):
                reasons.append(f"Suspicious TLD: {tld}")
                break

        # 4. Non-standard HTTP port
        if sess.remote_port not in (80, 443):
            reasons.append(f"Non-standard web port: {sess.remote_port}")

        # 5. Beaconing detection (>5 new connections from same PID in 60s)
        now = time.time()
        tracker = self._beacon_tracker[sess.pid]
        tracker.append(now)
        # Keep only last 60 seconds
        self._beacon_tracker[sess.pid] = [t for t in tracker if now - t < 60]
        if len(self._beacon_tracker[sess.pid]) > 5:
            reasons.append("Possible beaconing (high-frequency connections)")

        # 6. HTTP (not HTTPS) from a modern process
        if sess.protocol == "HTTP" and sess.remote_port == 80:
            reasons.append("Unencrypted HTTP (unusual for modern apps)")

        # Assign severity
        if reasons:
            sess.alert_reasons = reasons
            if any("beaconing" in r.lower() or "suspicious process" in r.lower() for r in reasons):
                sess.alert = "high"
            elif any("direct ip" in r.lower() or "suspicious tld" in r.lower() for r in reasons):
                sess.alert = "medium"
            else:
                sess.alert = "low"
