#!/usr/bin/env python3
"""
SecOS v6.0 — EDR Agent
Process monitoring · Behavioral detections · Endpoint response
"""

import json, logging, os, re, time, subprocess, hashlib
from datetime import datetime
from pathlib import Path
import psutil
import redis
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EDR] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/secos/edr.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("secos.edr")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ── BEHAVIORAL SIGNATURES ──────────────────────────────────────────────────────
SIGNATURES = [
    {
        "name": "LSASS Memory Access",
        "mitre": "T1003.001",
        "severity": "CRITICAL",
        "auto_block": True,
        "check": lambda p: (
            p.name().lower() in ["procdump.exe","mimikatz.exe","wce.exe","pwdump.exe"] or
            (p.name().lower() == "lsass.exe" and p.ppid() not in [0, 4] and
             p.username() not in ["NT AUTHORITY\\SYSTEM"])
        ),
    },
    {
        "name": "PowerShell Encoded Command",
        "mitre": "T1059.001",
        "severity": "HIGH",
        "auto_block": False,
        "check": lambda p: (
            "powershell" in p.name().lower() and
            any("-enc" in str(a).lower() or "-encodedcommand" in str(a).lower()
                for a in (p.cmdline() or []))
        ),
    },
    {
        "name": "Suspicious Parent-Child Chain",
        "mitre": "T1055.012",
        "severity": "HIGH",
        "auto_block": False,
        "check": lambda p: _check_parent_child(p),
    },
    {
        "name": "Network Scanner Process",
        "mitre": "T1046",
        "severity": "MEDIUM",
        "auto_block": False,
        "check": lambda p: p.name().lower() in ["nmap","masscan","zmap","portscan"],
    },
    {
        "name": "Crypto-Miner Process",
        "mitre": "T1496",
        "severity": "HIGH",
        "auto_block": True,
        "check": lambda p: p.name().lower() in ["xmrig","cpuminer","cgminer","bfgminer","ethminer"],
    },
    {
        "name": "Reverse Shell",
        "mitre": "T1059",
        "severity": "CRITICAL",
        "auto_block": True,
        "check": lambda p: _check_reverse_shell(p),
    },
]

def _check_parent_child(proc) -> bool:
    """Detect unexpected parent-child process chains."""
    suspicious_pairs = {
        "winword.exe":  ["cmd.exe","powershell.exe","wscript.exe","mshta.exe"],
        "excel.exe":    ["cmd.exe","powershell.exe","wscript.exe"],
        "outlook.exe":  ["cmd.exe","powershell.exe","wscript.exe"],
        "browser":      ["cmd.exe","powershell.exe"],
    }
    try:
        parent = psutil.Process(proc.ppid())
        parent_name = parent.name().lower()
        child_name = proc.name().lower()
        for sus_parent, sus_children in suspicious_pairs.items():
            if sus_parent in parent_name and child_name in sus_children:
                return True
    except Exception:
        pass
    return False

def _check_reverse_shell(proc) -> bool:
    """Detect reverse shell patterns in process cmdline."""
    cmd = " ".join(proc.cmdline() or []).lower()
    patterns = [
        r"bash\s+-i\s+>&",
        r"nc\s+-e\s+/bin",
        r"python.*socket.*exec",
        r"perl.*socket.*exec",
        r"/dev/tcp/",
    ]
    return any(re.search(p, cmd) for p in patterns)

# ── FILE INTEGRITY ─────────────────────────────────────────────────────────────
WATCHED_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/crontab", "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
]

class FileIntegrityMonitor:
    def __init__(self):
        self.baseline: dict = {}
        self._build_baseline()

    def _build_baseline(self):
        for path in WATCHED_FILES:
            if Path(path).exists():
                try:
                    with open(path, "rb") as f:
                        self.baseline[path] = hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    pass
        log.info(f"FIM baseline: {len(self.baseline)} files")

    def check(self) -> list[dict]:
        alerts = []
        for path, baseline_hash in self.baseline.items():
            try:
                with open(path, "rb") as f:
                    current = hashlib.sha256(f.read()).hexdigest()
                if current != baseline_hash:
                    alerts.append({
                        "rule": "File Integrity Violation",
                        "severity": "HIGH",
                        "mitre_id": "T1565.001",
                        "tactic": "Impact",
                        "score": 80,
                        "detail": f"Hash changed: {path}",
                        "host": os.uname().nodename,
                    })
                    self.baseline[path] = current  # Update to avoid spam
            except Exception:
                pass
        return alerts

# ── NETWORK CONNECTIONS ────────────────────────────────────────────────────────
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}
THREAT_INTEL_IPS = set()  # Loaded from Redis on startup

def check_suspicious_connections() -> list[dict]:
    alerts = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                rport = conn.raddr.port
                rip = conn.raddr.ip
                if rport in SUSPICIOUS_PORTS:
                    alerts.append({
                        "rule": "Suspicious Outbound Connection",
                        "severity": "HIGH",
                        "mitre_id": "T1071.001",
                        "tactic": "Command & Control",
                        "src_ip": rip,
                        "score": 75,
                        "detail": f"Outbound to suspicious port {rport} at {rip}",
                        "host": os.uname().nodename,
                    })
                if rip in THREAT_INTEL_IPS:
                    alerts.append({
                        "rule": "C2 Beacon Detected",
                        "severity": "CRITICAL",
                        "mitre_id": "T1071.001",
                        "tactic": "Command & Control",
                        "src_ip": rip,
                        "score": 98,
                        "detail": f"Connection to known C2 IP: {rip}:{rport}",
                        "host": os.uname().nodename,
                    })
    except Exception as e:
        log.debug(f"Connection check error: {e}")
    return alerts

# ── EDR AGENT ──────────────────────────────────────────────────────────────────
class EDRAgent:
    def __init__(self):
        self.r = redis.from_url(REDIS_URL, decode_responses=True)
        self.fim = FileIntegrityMonitor()
        self.known_pids: set = set()
        self.hostname = os.uname().nodename

        # Load threat intel IPs from Redis
        try:
            ioc_data = self.r.lrange("secos:tip:iocs", 0, -1)
            for item in ioc_data:
                try:
                    ioc = json.loads(item)
                    if ioc.get("type") == "ip":
                        THREAT_INTEL_IPS.add(ioc["value"])
                except Exception:
                    pass
        except Exception:
            pass

    def scan_processes(self) -> list[dict]:
        alerts = []
        current_pids = set()

        for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "ppid", "create_time"]):
            try:
                current_pids.add(proc.pid)

                for sig in SIGNATURES:
                    try:
                        if sig["check"](proc):
                            detail = {
                                "rule": sig["name"],
                                "severity": sig["severity"],
                                "mitre_id": sig["mitre"],
                                "tactic": "Execution",
                                "score": 95 if sig["severity"] == "CRITICAL" else 75,
                                "host": self.hostname,
                                "detail": f"PID:{proc.pid} {proc.name()} {' '.join((proc.cmdline() or [])[:3])}",
                                "source": "EDR",
                            }
                            alerts.append(detail)

                            if sig.get("auto_block") and os.geteuid() == 0:
                                log.warning(f"AUTO-BLOCKING: killing PID {proc.pid} ({proc.name()})")
                                try:
                                    proc.kill()
                                    self.r.lpush("secos:edr:actions", json.dumps({
                                        "action": "process_killed",
                                        "pid": proc.pid,
                                        "name": proc.name(),
                                        "reason": sig["name"],
                                        "ts": datetime.utcnow().isoformat(),
                                    }))
                                except Exception as e:
                                    log.error(f"Failed to kill PID {proc.pid}: {e}")
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        self.known_pids = current_pids
        return alerts

    def collect_telemetry(self) -> dict:
        """Collect system-wide endpoint telemetry."""
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            procs = [{"pid": p.pid, "name": p.name(), "cpu": p.cpu_percent(), "mem": p.memory_percent()}
                     for p in sorted(psutil.process_iter(["pid","name","cpu_percent","memory_percent"]),
                                     key=lambda x: x.info["cpu_percent"] or 0, reverse=True)[:10]]
            return {
                "hostname": self.hostname,
                "cpu_pct": cpu,
                "mem_pct": mem.percent,
                "disk_pct": disk.percent,
                "proc_count": len(psutil.pids()),
                "top_processes": procs,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            log.debug(f"Telemetry error: {e}")
            return {}

    def publish_alert(self, alert: dict):
        alert.setdefault("source", "EDR")
        alert.setdefault("timestamp", datetime.utcnow().isoformat())
        alert.setdefault("status", "NEW")
        self.r.publish("secos:alerts", json.dumps(alert))
        self.r.lpush("secos:edr:alerts", json.dumps(alert))
        self.r.ltrim("secos:edr:alerts", 0, 4999)
        log.warning(f"ALERT [{alert['severity']}] {alert['rule']} — {alert.get('detail','')}")

    def run(self):
        log.info(f"EDR agent started on {self.hostname}")
        cycle = 0
        while True:
            try:
                # Process scan every 15s
                for alert in self.scan_processes():
                    self.publish_alert(alert)

                # FIM check every 60s
                if cycle % 4 == 0:
                    for alert in self.fim.check():
                        self.publish_alert(alert)

                # Network connections every 30s
                if cycle % 2 == 0:
                    for alert in check_suspicious_connections():
                        self.publish_alert(alert)

                # Telemetry every 30s
                if cycle % 2 == 0:
                    telem = self.collect_telemetry()
                    if telem:
                        self.r.setex("secos:edr:telemetry", 60, json.dumps(telem))

                self.r.setex("secos:edr:heartbeat", 30, datetime.utcnow().isoformat())
                cycle += 1

            except Exception as e:
                log.error(f"EDR cycle error: {e}")

            time.sleep(15)


if __name__ == "__main__":
    EDRAgent().run()
