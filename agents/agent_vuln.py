#!/usr/bin/env python3
"""SecOS v6.0 — Vuln Agent: Vulnerability scanning & CVE tracking"""
import json, logging, os, subprocess, time, re
from datetime import datetime
from pathlib import Path
import redis
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [VULN] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/vuln.log"), logging.StreamHandler()])
log = logging.getLogger("secos.vuln")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Known critical CVEs with detection patterns (package name, version range)
KNOWN_CVES = [
    {"cve": "CVE-2021-44228", "name": "Log4Shell",        "pkg": "liblog4j",    "cvss": 10.0, "severity": "CRITICAL"},
    {"cve": "CVE-2021-45046", "name": "Log4Shell 2",      "pkg": "liblog4j",    "cvss": 9.0,  "severity": "CRITICAL"},
    {"cve": "CVE-2022-0847",  "name": "DirtyPipe",        "pkg": "linux",       "cvss": 7.8,  "severity": "HIGH"},
    {"cve": "CVE-2022-3786",  "name": "OpenSSL Overflow",  "pkg": "openssl",    "cvss": 7.5,  "severity": "HIGH"},
    {"cve": "CVE-2023-0464",  "name": "OpenSSL Chain",     "pkg": "openssl",    "cvss": 5.9,  "severity": "MEDIUM"},
    {"cve": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset","pkg": "nginx",      "cvss": 7.5,  "severity": "HIGH"},
    {"cve": "CVE-2024-3094",  "name": "XZ Utils Backdoor","pkg": "xz-utils",   "cvss": 10.0, "severity": "CRITICAL"},
    {"cve": "CVE-2023-4911",  "name": "Looney Tunables",  "pkg": "libc6",      "cvss": 7.8,  "severity": "HIGH"},
    {"cve": "CVE-2024-1086",  "name": "Linux Kernel nft",  "pkg": "linux",     "cvss": 7.8,  "severity": "HIGH"},
]

def run(cmd: list, timeout: int = 60) -> tuple[str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except Exception as e:
        return str(e), -1

class VulnAgent:
    def __init__(self):
        self.r = redis.from_url(REDIS_URL, decode_responses=True)
        self.hostname = os.uname().nodename
        self.findings: list = []

    def scan_packages(self) -> list[dict]:
        findings = []

        # Debian/Ubuntu: apt-get --just-print upgrade lists upgradeable packages
        out, rc = run(["apt-get", "--just-print", "upgrade"])
        upgradeable = []
        if rc == 0:
            upgradeable = re.findall(r"Inst (\S+) \[([^\]]+)\]", out)
        if upgradeable:
            findings.append({
                "type": "outdated_packages",
                "count": len(upgradeable),
                "packages": [f"{p[0]} ({p[1]})" for p in upgradeable[:20]],
                "severity": "MEDIUM" if len(upgradeable) < 20 else "HIGH",
            })

        # Check for known CVE-affected packages
        out, _ = run(["dpkg", "-l"])
        installed = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "ii":
                installed[parts[1]] = parts[2]

        for cve in KNOWN_CVES:
            pkg = cve["pkg"]
            # Check if installed
            matched = [name for name in installed if pkg in name.split("/")[0]]
            if matched:
                findings.append({
                    "cve": cve["cve"],
                    "name": cve["name"],
                    "package": matched[0],
                    "version": installed.get(matched[0], "unknown"),
                    "cvss": cve["cvss"],
                    "severity": cve["severity"],
                    "patch_available": pkg in [p[0] for p in upgradeable],
                    "host": self.hostname,
                })
                if cve["cvss"] >= 9.0:
                    log.warning(f"CRITICAL CVE: {cve['cve']} ({cve['name']}) — {matched[0]}")

        return findings

    def scan_configs(self) -> list[dict]:
        """Check for common misconfigurations."""
        findings = []

        checks = [
            ("/etc/ssh/sshd_config", r"PermitRootLogin\s+yes",
             "SSH Root Login Enabled", "HIGH", "T1078.003"),
            ("/etc/ssh/sshd_config", r"PasswordAuthentication\s+yes",
             "SSH Password Auth Enabled", "MEDIUM", "T1110"),
            ("/etc/passwd", r":\d+:\d+:.*:.*:/bin/(bash|sh)$",
             "Service Account with Shell", "LOW", "T1078"),
        ]

        for filepath, pattern, name, severity, mitre in checks:
            try:
                content = Path(filepath).read_text(errors="replace")
                if re.search(pattern, content, re.MULTILINE):
                    findings.append({
                        "type": "misconfiguration",
                        "name": name,
                        "file": filepath,
                        "severity": severity,
                        "mitre": mitre,
                        "host": self.hostname,
                    })
            except Exception:
                pass

        # World-writable files in sensitive paths
        out, _ = run(["find", "/etc", "-perm", "-002", "-type", "f"], timeout=15)
        ww_files = [f.strip() for f in out.splitlines() if f.strip()]
        if ww_files:
            findings.append({
                "type": "world_writable",
                "name": "World-Writable Files in /etc",
                "files": ww_files[:10],
                "severity": "HIGH",
                "mitre": "T1222",
                "host": self.hostname,
            })

        return findings

    def publish_findings(self, findings: list):
        self.r.setex("secos:vuln:findings", 3600, json.dumps(findings))
        self.r.setex("secos:vuln:last_scan", 3600, datetime.utcnow().isoformat())

        # Push critical findings as alerts
        for f in findings:
            if f.get("severity") in ("CRITICAL", "HIGH") and f.get("cve"):
                alert = {
                    "rule": f"CVE Detected: {f['cve']}",
                    "severity": f["severity"],
                    "mitre_id": "T1190",
                    "tactic": "Initial Access",
                    "host": self.hostname,
                    "score": int(f.get("cvss", 7) * 10),
                    "source": "VULN",
                    "detail": f"{f['name']} in {f.get('package','?')} — CVSS {f.get('cvss',0)}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "NEW",
                }
                self.r.publish("secos:alerts", json.dumps(alert))

        log.info(f"Vuln scan complete: {len(findings)} findings")

    def run(self):
        log.info("Vuln agent started")
        while True:
            try:
                findings = self.scan_packages() + self.scan_configs()
                self.publish_findings(findings)
                self.r.setex("secos:vuln:heartbeat", 30, datetime.utcnow().isoformat())
            except Exception as e:
                log.error(f"Vuln scan error: {e}")
            time.sleep(3600)  # Scan every hour

if __name__ == "__main__":
    VulnAgent().run()
