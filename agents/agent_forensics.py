#!/usr/bin/env python3
"""SecOS v6.0 — Forensics Agent: Artifact collection & preservation"""
import json, logging, os, subprocess, time, hashlib, gzip, shutil
from datetime import datetime
from pathlib import Path
import redis
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [FORENSICS] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/forensics.log"), logging.StreamHandler()])
log = logging.getLogger("secos.forensics")

REDIS_URL  = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ARTIFACT_DIR = Path(os.getenv("SECOS_DATA", "/var/lib/secos")) / "artifacts"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd: list, timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout[:65536]
    except Exception as e:
        return f"[ERROR: {e}]"

class ForensicsAgent:
    def __init__(self):
        self.r = redis.from_url(REDIS_URL, decode_responses=True)
        self.hostname = os.uname().nodename

    def collect_snapshot(self, trigger: str = "scheduled") -> dict:
        """Full forensic snapshot of the system."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        case_dir = ARTIFACT_DIR / f"snapshot_{self.hostname}_{ts}"
        case_dir.mkdir(parents=True, exist_ok=True)

        artifacts = {
            "hostname": self.hostname,
            "trigger": trigger,
            "collected_at": datetime.utcnow().isoformat(),
            "files": [],
        }

        collections = {
            "processes.txt":     ["ps", "auxf"],
            "network.txt":       ["ss", "-tunap"],
            "netstat.txt":       ["netstat", "-rn"],
            "connections.txt":   ["ss", "-s"],
            "users.txt":         ["who", "-a"],
            "logins.txt":        ["last", "-n", "50"],
            "crontabs.txt":      ["crontab", "-l"],
            "services.txt":      ["systemctl", "list-units", "--state=running", "--no-legend"],
            "mounts.txt":        ["mount"],
            "dmesg.txt":         ["dmesg", "-T"],
            "iptables.txt":      ["iptables", "-L", "-n", "-v"],
            "open_files.txt":    ["lsof", "-n", "-P", "+L1"],
            "listening.txt":     ["ss", "-tlnp"],
            "suid_files.txt":    ["find", "/", "-perm", "-4000", "-type", "f", "-maxdepth", "5"],
            "world_writable.txt":["find", "/tmp", "/var/tmp", "-perm", "-002", "-type", "f"],
            "bash_history.txt":  ["cat", "/root/.bash_history"],
            "auth_log.txt":      ["tail", "-n", "500", "/var/log/auth.log"],
            "syslog.txt":        ["tail", "-n", "500", "/var/log/syslog"],
        }

        for filename, cmd in collections.items():
            output = run_cmd(cmd)
            fpath = case_dir / filename
            fpath.write_text(output, errors="replace")
            artifacts["files"].append(str(fpath))

        # Hash all collected files
        hashes = {}
        for f in artifacts["files"]:
            try:
                h = hashlib.sha256(Path(f).read_bytes()).hexdigest()
                hashes[f] = h
            except Exception:
                pass
        artifacts["file_hashes"] = hashes

        # Save manifest
        manifest = case_dir / "manifest.json"
        manifest.write_text(json.dumps(artifacts, indent=2))

        # Compress
        archive = str(ARTIFACT_DIR / f"snapshot_{self.hostname}_{ts}.tar.gz")
        shutil.make_archive(archive.replace(".tar.gz", ""), "gztar", str(case_dir))
        shutil.rmtree(str(case_dir), ignore_errors=True)

        log.info(f"Forensic snapshot saved: {archive}")
        artifacts["archive"] = archive
        return artifacts

    def respond_to_alerts(self):
        """Watch for critical alerts requiring forensic collection."""
        pubsub = self.r.pubsub()
        pubsub.subscribe("secos:alerts")
        collected: set = set()

        for msg in pubsub.listen():
            if msg["type"] != "message":
                continue
            try:
                alert = json.loads(msg["data"])
                if alert.get("severity") != "CRITICAL":
                    continue
                host = alert.get("host", "")
                rule = alert.get("rule", "")
                key = f"{rule}:{host}"
                if key in collected:
                    continue
                collected.add(key)
                if len(collected) > 100:
                    collected.clear()

                log.info(f"Auto-collecting forensics for CRITICAL: {rule} on {host}")
                result = self.collect_snapshot(trigger=f"alert:{rule}")

                # Notify
                self.r.publish("secos:forensics:results", json.dumps({
                    "trigger": rule,
                    "host": host,
                    "archive": result.get("archive"),
                    "files_collected": len(result.get("files", [])),
                    "timestamp": datetime.utcnow().isoformat(),
                }))
                self.r.setex("secos:forensics:heartbeat", 30, datetime.utcnow().isoformat())
            except Exception as e:
                log.error(f"Forensics alert handler error: {e}")

    def run(self):
        log.info("Forensics agent started")
        # Initial snapshot on startup
        try:
            self.collect_snapshot(trigger="startup")
        except Exception as e:
            log.error(f"Startup snapshot failed: {e}")
        # Then respond to live alerts
        self.respond_to_alerts()

if __name__ == "__main__":
    ForensicsAgent().run()
