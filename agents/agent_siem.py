#!/usr/bin/env python3
"""
SecOS v6.0 — SIEM Agent
Real log ingestion · Correlation rules · Alert publishing
"""

import asyncio, json, logging, os, re, time, hashlib
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
import redis
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIEM] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/secos/siem.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("secos.siem")

# ── CONFIG ─────────────────────────────────────────────────────────────────────
REDIS_URL   = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LOG_SOURCES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/nginx/access.log",
    "/var/log/secos/",
]

# ── CORRELATION RULES ──────────────────────────────────────────────────────────
class SlidingWindow:
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.events = deque()

    def add(self, key: str) -> int:
        now = time.time()
        self.events.append((now, key))
        cutoff = now - self.window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        return sum(1 for _, k in self.events if k == key)


class CorrelationEngine:
    def __init__(self):
        self.windows = {
            "ssh_fail":   SlidingWindow(60),
            "port_scan":  SlidingWindow(10),
            "lateral":    SlidingWindow(300),
            "dns_query":  SlidingWindow(60),
            "file_access": SlidingWindow(30),
        }
        self.seen_hashes = set()
        self.host_connections: dict = defaultdict(set)
        self.user_ips: dict = defaultdict(set)

    def dedup(self, alert: dict) -> bool:
        """Return True if this is a new unique alert."""
        key = f"{alert['rule']}:{alert.get('host','')}:{alert.get('src_ip','')}"
        h = hashlib.md5(key.encode()).hexdigest()
        if h in self.seen_hashes:
            return False
        self.seen_hashes.add(h)
        if len(self.seen_hashes) > 10000:
            self.seen_hashes.clear()
        return True

    def check_ssh_brute(self, line: str, src_ip: str) -> dict | None:
        count = self.windows["ssh_fail"].add(src_ip)
        if count >= 5:
            return {
                "rule": "SSH Brute Force",
                "severity": "HIGH",
                "mitre_id": "T1110.001",
                "tactic": "Credential Access",
                "src_ip": src_ip,
                "score": min(100, 50 + count * 3),
                "detail": f"{count} SSH failures in 60s from {src_ip}",
            }
        return None

    def check_port_scan(self, src_ip: str, dst_port: int, host: str) -> dict | None:
        key = f"{src_ip}:{host}"
        self.host_connections[key].add(dst_port)
        count = len(self.host_connections[key])
        if count >= 20:
            return {
                "rule": "Port Scan",
                "severity": "MEDIUM",
                "mitre_id": "T1046",
                "tactic": "Discovery",
                "src_ip": src_ip,
                "host": host,
                "score": min(100, 30 + count),
                "detail": f"Port scan: {count} ports from {src_ip} to {host}",
            }
        return None

    def check_impossible_travel(self, user: str, src_ip: str) -> dict | None:
        self.user_ips[user].add(src_ip)
        if len(self.user_ips[user]) >= 3:
            return {
                "rule": "Impossible Travel",
                "severity": "HIGH",
                "mitre_id": "T1621",
                "tactic": "Credential Access",
                "user_name": user,
                "src_ip": src_ip,
                "score": 85,
                "detail": f"User {user} from {len(self.user_ips[user])} IPs: {list(self.user_ips[user])}",
            }
        return None

    def check_lateral_movement(self, user: str, host: str) -> dict | None:
        key = f"lateral:{user}"
        self.host_connections[key].add(host)
        count = len(self.host_connections[key])
        if count >= 3:
            return {
                "rule": "Lateral Movement SMB",
                "severity": "HIGH",
                "mitre_id": "T1021.002",
                "tactic": "Lateral Movement",
                "user_name": user,
                "score": min(100, 60 + count * 5),
                "detail": f"{user} authenticated to {count} hosts: {list(self.host_connections[key])}",
            }
        return None


# ── LOG PARSERS ────────────────────────────────────────────────────────────────
class LogParser:
    SSH_FAIL = re.compile(r"Failed (password|publickey) for (\S+) from ([\d.]+) port (\d+)")
    SSH_ACCEPT = re.compile(r"Accepted (password|publickey) for (\S+) from ([\d.]+)")
    SUDO_CMD = re.compile(r"sudo:.*?(\w+).*?COMMAND=(.*)")
    NGINX_REQ = re.compile(r'([\d.]+) .* "(GET|POST|PUT|DELETE) (.+?) HTTP.*" (\d+)')
    KERNEL_MOD = re.compile(r"module (\S+) loaded")
    CRON_JOB = re.compile(r"CRON.*CMD \((.*)\)")

    @classmethod
    def parse_line(cls, line: str, source_file: str) -> dict | None:
        # SSH failures
        m = cls.SSH_FAIL.search(line)
        if m:
            return {"type": "ssh_fail", "user": m.group(2), "src_ip": m.group(3), "port": m.group(4)}

        # SSH success
        m = cls.SSH_ACCEPT.search(line)
        if m:
            return {"type": "ssh_accept", "user": m.group(2), "src_ip": m.group(3)}

        # Sudo
        m = cls.SUDO_CMD.search(line)
        if m:
            return {"type": "sudo_cmd", "user": m.group(1), "command": m.group(2)}

        # Nginx
        m = cls.NGINX_REQ.search(line)
        if m:
            return {"type": "http_req", "src_ip": m.group(1),
                    "method": m.group(2), "path": m.group(3), "status": m.group(4)}

        return None


# ── FILE TAIL ──────────────────────────────────────────────────────────────────
class FileTailer:
    def __init__(self, path: str):
        self.path = path
        self.pos = 0
        try:
            self.pos = Path(path).stat().st_size
        except Exception:
            pass

    def read_new(self) -> list[str]:
        lines = []
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self.pos)
                chunk = f.read(65536)
                self.pos = f.tell()
                lines = [l.strip() for l in chunk.splitlines() if l.strip()]
        except Exception:
            pass
        return lines


# ── SIEM ENGINE ────────────────────────────────────────────────────────────────
class SIEMAgent:
    def __init__(self):
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        self.engine = CorrelationEngine()
        self.tailers: dict[str, FileTailer] = {}
        self.alert_count = 0

        for src in LOG_SOURCES:
            p = Path(src)
            if p.is_file():
                self.tailers[src] = FileTailer(src)
            elif p.is_dir():
                for f in p.glob("*.log"):
                    self.tailers[str(f)] = FileTailer(str(f))

        log.info(f"SIEM: monitoring {len(self.tailers)} log files")

    def publish_alert(self, alert: dict):
        alert.setdefault("host", os.uname().nodename)
        alert.setdefault("source", "SIEM")
        alert.setdefault("timestamp", datetime.utcnow().isoformat())
        alert.setdefault("status", "NEW")

        if not self.engine.dedup(alert):
            return

        self.alert_count += 1
        alert["seq"] = self.alert_count

        log.warning(f"ALERT [{alert['severity']}] {alert['rule']} — {alert.get('detail','')}")

        # Push to Redis streams
        self.redis.publish("secos:alerts", json.dumps(alert))
        self.redis.lpush("secos:siem:alerts", json.dumps(alert))
        self.redis.ltrim("secos:siem:alerts", 0, 9999)

        # Send to API
        try:
            import urllib.request
            req = urllib.request.Request(
                "http://localhost:8000/api/alerts",
                data=json.dumps(alert).encode(),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass  # API may not be up yet

    def process_line(self, line: str, source_file: str):
        parsed = LogParser.parse_line(line, source_file)
        if not parsed:
            return

        t = parsed["type"]

        if t == "ssh_fail":
            alert = self.engine.check_ssh_brute(line, parsed["src_ip"])
            if alert:
                alert["user_name"] = parsed["user"]
                self.publish_alert(alert)

        elif t == "ssh_accept":
            alert = self.engine.check_impossible_travel(parsed["user"], parsed["src_ip"])
            if alert:
                self.publish_alert(alert)
            # Also check lateral movement
            alert2 = self.engine.check_lateral_movement(parsed["user"], os.uname().nodename)
            if alert2:
                self.publish_alert(alert2)

        elif t == "sudo_cmd":
            cmd = parsed.get("command", "")
            # Detect suspicious sudo commands
            for pattern, rule, sev, mitre in [
                (r"vssadmin.*delete|shadow", "Shadow Copy Delete", "CRITICAL", "T1490"),
                (r"passwd|shadow|credentials", "Credential File Access", "HIGH", "T1003"),
                (r"crontab|at\s+", "Persistence via Cron", "MEDIUM", "T1053"),
                (r"nc\s|ncat\s|netcat", "Reverse Shell Attempt", "CRITICAL", "T1059"),
            ]:
                if re.search(pattern, cmd, re.IGNORECASE):
                    self.publish_alert({
                        "rule": rule, "severity": sev,
                        "mitre_id": mitre, "tactic": "Execution",
                        "user_name": parsed["user"],
                        "score": 90 if sev == "CRITICAL" else 70,
                        "detail": f"Suspicious sudo: {cmd[:100]}",
                    })

    def run_once(self):
        for path, tailer in list(self.tailers.items()):
            for line in tailer.read_new():
                self.process_line(line, path)

        # Update heartbeat
        self.redis.setex("secos:siem:heartbeat", 30, datetime.utcnow().isoformat())

    def run(self):
        log.info("SIEM agent started")
        while True:
            try:
                self.run_once()
            except Exception as e:
                log.error(f"SIEM cycle error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    SIEMAgent().run()
