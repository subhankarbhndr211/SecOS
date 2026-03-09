#!/usr/bin/env python3
"""
SecOS NDR Agent — Network Detection & Response
Monitors: active connections, DNS queries, traffic anomalies,
          known bad IPs, port scans, beaconing patterns
"""
import json, logging, os, time, re, socket, struct
from datetime import datetime, timezone
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [NDR] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/ndr.log"),
              logging.StreamHandler()])
log = logging.getLogger("secos.ndr")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
HOSTNAME  = os.uname().nodename

import redis as redislib
def make_redis():
    url = REDIS_URL.replace("redis://","").split("/")[0]
    host, port = (url.split(":") + ["6379"])[:2]
    return redislib.Redis(host=host, port=int(port), decode_responses=True)

r = make_redis()

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False
    log.warning("psutil not available — limited network monitoring")

# ── Known malicious infrastructure ────────────────────────────────────────────
MALICIOUS_IPS = {
    "185.220.101.47": ("Tor exit node / brute force",    "HIGH"),
    "91.92.251.103":  ("Known C2 infrastructure",         "CRITICAL"),
    "45.142.212.100": ("Data exfiltration endpoint",      "CRITICAL"),
    "194.165.16.10":  ("Cobalt Strike C2",                "CRITICAL"),
    "162.247.74.201": ("Tor exit node",                   "MEDIUM"),
    "198.98.56.151":  ("Scanner / attack origin",         "HIGH"),
    "80.82.77.139":   ("Mass scanner Shodan-like",        "MEDIUM"),
    "89.234.157.254": ("Tor exit node",                   "MEDIUM"),
}

SUSPICIOUS_PORTS = {
    4444:  ("Metasploit default listener",  "CRITICAL"),
    1337:  ("Common backdoor port",         "HIGH"),
    31337: ("Elite backdoor",               "CRITICAL"),
    6666:  ("Mirai C2 port",               "HIGH"),
    9001:  ("Tor relay",                    "MEDIUM"),
    8888:  ("Alternate C2",                 "MEDIUM"),
    1080:  ("SOCKS proxy / tunneling",      "MEDIUM"),
    3128:  ("Proxy pivoting",               "LOW"),
    8080:  ("Alt HTTP (monitor)",           "LOW"),
    6667:  ("IRC C2",                       "HIGH"),
    6697:  ("IRC C2 TLS",                   "HIGH"),
}

PRIVATE_RANGES = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8
]

def is_private(ip):
    try:
        n = struct.unpack("!I", socket.inet_aton(ip))[0]
        return any((n & mask) == (net & mask) for net, mask in PRIVATE_RANGES)
    except:
        return False

def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

# ── Connection tracking ────────────────────────────────────────────────────────
class ConnectionTracker:
    def __init__(self):
        self.connections   = {}         # (laddr, raddr) -> first_seen
        self.ip_conn_count = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)  # src_ip -> set of dst_ports
        self.beacon_tracker = defaultdict(list)    # (src,dst) -> [timestamps]
        self.dns_tracker   = defaultdict(int)      # domain -> query_count

    def process_connection(self, laddr, raddr, lport, rport, pid=None):
        key = (laddr, lport, raddr, rport)
        if key in self.connections:
            return None
        self.connections[key] = time.time()
        self.ip_conn_count[raddr] += 1

        # Track port scanning (many ports from same src)
        self.port_scan_tracker[raddr].add(rport)

        alerts = []

        # Check known malicious IPs
        if raddr in MALICIOUS_IPS:
            desc, sev = MALICIOUS_IPS[raddr]
            alerts.append({
                "rule":    f"Connection to Known Malicious IP: {desc}",
                "severity": sev,
                "mitre":   "T1071",
                "tactic":  "Command and Control",
                "score":   90 if sev == "CRITICAL" else 75,
                "detail":  f"Connection {laddr}:{lport} -> {raddr}:{rport}",
            })

        # Check suspicious destination ports
        if rport in SUSPICIOUS_PORTS:
            desc, sev = SUSPICIOUS_PORTS[rport]
            if sev in ("CRITICAL","HIGH","MEDIUM"):
                alerts.append({
                    "rule":    f"Suspicious Port Connection: {desc}",
                    "severity": sev,
                    "mitre":   "T1571",
                    "tactic":  "Command and Control",
                    "score":   80 if sev == "CRITICAL" else 65,
                    "detail":  f"Outbound to {raddr}:{rport} — {desc}",
                })

        # Check port scan pattern (>20 unique ports from same IP)
        if len(self.port_scan_tracker[raddr]) > 20:
            alerts.append({
                "rule":    "Port Scan Detected",
                "severity": "HIGH",
                "mitre":   "T1046",
                "tactic":  "Discovery",
                "score":   70,
                "detail":  f"Host {raddr} scanned {len(self.port_scan_tracker[raddr])} ports",
            })
            self.port_scan_tracker[raddr] = set()  # reset

        # Check high connection count to single external IP
        if not is_private(raddr) and self.ip_conn_count[raddr] > 50:
            alerts.append({
                "rule":    "High Connection Count to External IP",
                "severity": "MEDIUM",
                "mitre":   "T1071",
                "tactic":  "Command and Control",
                "score":   55,
                "detail":  f"{self.ip_conn_count[raddr]} connections to {raddr}",
            })
            self.ip_conn_count[raddr] = 0

        return alerts

    def check_beaconing(self, raddr, rport):
        """Detect regular interval connections (C2 beaconing pattern)."""
        key = (HOSTNAME, raddr, rport)
        now = time.time()
        self.beacon_tracker[key].append(now)

        # Keep only last 20 timestamps
        self.beacon_tracker[key] = self.beacon_tracker[key][-20:]
        times = self.beacon_tracker[key]

        if len(times) < 5:
            return None

        # Calculate intervals
        intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i-avg_interval)**2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5

        # Beaconing: regular intervals (low variance) to external IP
        if (not is_private(raddr) and
            10 < avg_interval < 3600 and   # 10s - 1hr interval
            std_dev / max(avg_interval,1) < 0.2):  # <20% variance
            return {
                "rule":    f"C2 Beaconing Pattern Detected",
                "severity": "CRITICAL",
                "mitre":   "T1071.001",
                "tactic":  "Command and Control",
                "score":   92,
                "detail":  f"Regular {avg_interval:.0f}s beaconing to {raddr}:{rport} (σ={std_dev:.1f}s)",
            }
        return None

tracker = ConnectionTracker()

def publish_alert(alert_data, src_ip="", host=HOSTNAME):
    alert = {
        "id":        f"NDR-{int(time.time()*1000)}",
        "rule":      alert_data["rule"],
        "rule_name": alert_data["rule"],
        "severity":  alert_data["severity"],
        "mitre_id":  alert_data.get("mitre","T1071"),
        "tactic":    alert_data.get("tactic","Command and Control"),
        "host":      host,
        "src_ip":    src_ip,
        "source":    "NDR",
        "status":    "NEW",
        "score":     alert_data.get("score",70),
        "raw":       alert_data.get("detail",""),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    r.publish("secos:alerts", json.dumps(alert))
    r.lpush("secos:ndr:alerts", json.dumps(alert))
    r.ltrim("secos:ndr:alerts", 0, 499)
    log.info(f"NDR ALERT [{alert['severity']}] {alert['rule'][:60]}")

# ── Active connection monitoring ───────────────────────────────────────────────
fired = {}
def should_fire(key, cooldown=300):
    now = time.time()
    if key not in fired or now - fired[key] > cooldown:
        fired[key] = now
        return True
    return False

def scan_connections():
    if not PSUTIL:
        return
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue
            rip   = conn.raddr.ip
            rport = conn.raddr.port
            lip   = conn.laddr.ip if conn.laddr else ""
            lport = conn.laddr.port if conn.laddr else 0

            if is_private(rip):
                continue

            alerts = tracker.process_connection(lip, rip, lport, rport)
            if alerts:
                for a in alerts:
                    key = f"{a['rule']}:{rip}"
                    if should_fire(key):
                        publish_alert(a, src_ip=rip)

            # Check beaconing
            beacon = tracker.check_beaconing(rip, rport)
            if beacon:
                key = f"BEACON:{rip}:{rport}"
                if should_fire(key, cooldown=600):
                    publish_alert(beacon, src_ip=rip)

    except Exception as e:
        log.debug(f"Connection scan: {e}")

def scan_netstat():
    """Fallback when psutil unavailable — parse ss/netstat output."""
    try:
        import subprocess
        result = subprocess.run(["ss","-tnp"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            if "ESTAB" not in parts[0]:
                continue
            raddr = parts[4] if len(parts) > 4 else ""
            if ":" not in raddr:
                continue
            rip, rport = raddr.rsplit(":",1)
            try:
                rport = int(rport)
            except:
                continue
            if is_private(rip):
                continue
            if rip in MALICIOUS_IPS:
                desc, sev = MALICIOUS_IPS[rip]
                key = f"MALIP:{rip}"
                if should_fire(key):
                    publish_alert({
                        "rule": f"Connection to Known Malicious IP: {desc}",
                        "severity": sev,
                        "mitre": "T1071",
                        "tactic": "Command and Control",
                        "score": 88,
                        "detail": f"Active connection to {rip}:{rport}",
                    }, src_ip=rip)
    except Exception as e:
        log.debug(f"netstat scan: {e}")

def publish_telemetry():
    if not PSUTIL:
        return
    try:
        conns = psutil.net_connections(kind="inet")
        established = [c for c in conns if c.status == "ESTABLISHED"]
        external = [c for c in established if c.raddr and not is_private(c.raddr.ip)]
        io = psutil.net_io_counters()
        telemetry = {
            "host":             HOSTNAME,
            "total_connections": len(established),
            "external_connections": len(external),
            "bytes_sent":       io.bytes_sent,
            "bytes_recv":       io.bytes_recv,
            "packets_sent":     io.packets_sent,
            "packets_recv":     io.packets_recv,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
        }
        r.setex(f"secos:ndr:telemetry:{HOSTNAME}", 60, json.dumps(telemetry))
        r.setex("secos:ndr:heartbeat", 60, datetime.now(timezone.utc).isoformat())
    except Exception as e:
        log.debug(f"Telemetry: {e}")

def main():
    log.info(f"SecOS NDR Agent started on {HOSTNAME}")
    log.info(f"Monitoring {len(MALICIOUS_IPS)} known bad IPs, {len(SUSPICIOUS_PORTS)} suspicious ports")

    tick = 0
    while True:
        try:
            if PSUTIL:
                scan_connections()
            else:
                scan_netstat()

            if tick % 12 == 0:
                publish_telemetry()

            tick += 1
        except Exception as e:
            log.error(f"NDR tick: {e}")
        time.sleep(10)

if __name__ == "__main__":
    main()
