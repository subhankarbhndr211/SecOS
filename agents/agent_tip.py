#!/usr/bin/env python3
"""SecOS v6.0 — TIP Agent: Threat Intelligence Platform"""
import json, logging, os, time, ipaddress
from datetime import datetime
import redis
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [TIP] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/tip.log"), logging.StreamHandler()])
log = logging.getLogger("secos.tip")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
VT_KEY    = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_KEY   = os.getenv("ALIENTVAULT_API_KEY", "")

# Built-in seed intelligence (known C2/TOR/malicious CIDRs — public list)
SEED_MALICIOUS_IPS = [
    "185.220.101.0/24",   # TOR exit nodes
    "185.220.102.0/24",
    "91.92.251.0/24",     # Known scanning infrastructure
    "45.142.212.0/24",
    "194.165.16.0/24",
    "80.66.88.0/24",
    "23.106.160.0/24",
]

SEED_MALICIOUS_DOMAINS = [
    "evil-c2.ru", "malware-payload.cn", "ransomware-drop.cc",
    "cobaltstrike-teamserver.io", "emotet-c2.net",
]

class TIPAgent:
    def __init__(self):
        self.r = redis.from_url(REDIS_URL, decode_responses=True)
        self.hostname = os.uname().nodename
        self.ioc_cache: dict = {}
        self.learned_iocs: list = []

    def load_seed_intel(self):
        """Load built-in threat intelligence."""
        count = 0
        for cidr in SEED_MALICIOUS_IPS:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                for ip in list(net.hosts())[:10]:  # Sample first 10
                    ioc = {"value": str(ip), "type": "ip", "verdict": "MALICIOUS",
                           "confidence": 85, "source": "SECOS_SEED", "tags": ["malicious_infra"],
                           "first_seen": datetime.utcnow().isoformat()}
                    self.r.hset("secos:tip:ioc_index", str(ip), json.dumps(ioc))
                    count += 1
            except Exception:
                pass

        for domain in SEED_MALICIOUS_DOMAINS:
            ioc = {"value": domain, "type": "domain", "verdict": "MALICIOUS",
                   "confidence": 90, "source": "SECOS_SEED", "tags": ["c2", "malware"],
                   "first_seen": datetime.utcnow().isoformat()}
            self.r.hset("secos:tip:ioc_index", domain, json.dumps(ioc))
            count += 1

        log.info(f"Seed intel loaded: {count} IOCs")

    def lookup_ioc(self, value: str, ioc_type: str = "ip") -> dict:
        """Lookup IOC in local database first, then external APIs."""
        # Local cache
        cached = self.r.hget("secos:tip:ioc_index", value)
        if cached:
            return json.loads(cached)

        result = {"value": value, "type": ioc_type, "verdict": "UNKNOWN",
                  "confidence": 0, "source": "local", "tags": []}

        # VirusTotal
        if VT_KEY:
            try:
                import urllib.request
                url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if ioc_type == 'ip' else 'domains'}/{value}"
                req = urllib.request.Request(url, headers={"x-apikey": VT_KEY})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                    stats = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) or 1
                    if malicious > 3:
                        result.update({"verdict": "MALICIOUS", "confidence": int(malicious/total*100),
                                       "source": "VirusTotal"})
            except Exception as e:
                log.debug(f"VT lookup failed: {e}")

        # Cache result
        self.r.hset("secos:tip:ioc_index", value, json.dumps(result))
        self.r.expire("secos:tip:ioc_index", 86400 * 7)  # 7 days
        return result

    def learn_from_alerts(self):
        """Auto-learn IOCs from high-confidence detections."""
        feeds = ["secos:siem:alerts", "secos:edr:alerts", "secos:ndr:alerts"]
        for feed in feeds:
            try:
                for raw in self.r.lrange(feed, 0, 9):
                    ev = json.loads(raw)
                    if ev.get("score", 0) < 80:
                        continue
                    src_ip = ev.get("src_ip", "")
                    if src_ip and not ipaddress.ip_address(src_ip).is_private:
                        ioc = {
                            "value": src_ip, "type": "ip",
                            "verdict": "MALICIOUS", "confidence": ev["score"],
                            "source": "SECOS_LEARNED",
                            "tags": [ev.get("tactic",""), ev.get("mitre_id","")],
                            "first_seen": datetime.utcnow().isoformat(),
                            "alert_rule": ev.get("rule",""),
                        }
                        existing = self.r.hget("secos:tip:ioc_index", src_ip)
                        if not existing:
                            self.r.hset("secos:tip:ioc_index", src_ip, json.dumps(ioc))
                            self.learned_iocs.append(ioc)
                            log.info(f"Learned IOC: {src_ip} from {ev.get('rule','')}")
            except Exception:
                pass

        # Persist learned IOCs list
        if self.learned_iocs:
            self.r.setex("secos:tip:learned_iocs", 86400, json.dumps(self.learned_iocs[-100:]))

    def enrich_active_alerts(self):
        """Lookup IOCs from incoming alerts and flag malicious ones."""
        try:
            for raw in self.r.lrange("secos:siem:alerts", 0, 4):
                ev = json.loads(raw)
                src_ip = ev.get("src_ip","")
                if src_ip:
                    result = self.lookup_ioc(src_ip, "ip")
                    if result.get("verdict") == "MALICIOUS":
                        alert = {
                            "rule": "Threat Intel: Known Malicious IP",
                            "severity": "HIGH",
                            "mitre_id": "T1071",
                            "tactic": "Command & Control",
                            "src_ip": src_ip,
                            "host": ev.get("host", self.hostname),
                            "score": result.get("confidence", 85),
                            "source": "TIP",
                            "detail": f"IOC match: {src_ip} — {result.get('source')} (confidence: {result.get('confidence')}%)",
                            "timestamp": datetime.utcnow().isoformat(),
                            "status": "NEW",
                        }
                        self.r.publish("secos:alerts", json.dumps(alert))
        except Exception as e:
            log.debug(f"Enrichment error: {e}")

    def publish_stats(self):
        total = self.r.hlen("secos:tip:ioc_index")
        stats = {
            "total_iocs": total,
            "learned_iocs": len(self.learned_iocs),
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": self.hostname,
        }
        self.r.setex("secos:tip:stats", 300, json.dumps(stats))

    def run(self):
        log.info("TIP agent started")
        self.load_seed_intel()
        cycle = 0
        while True:
            try:
                if cycle % 4 == 0:
                    self.learn_from_alerts()
                if cycle % 2 == 0:
                    self.enrich_active_alerts()
                if cycle % 12 == 0:
                    self.publish_stats()
                self.r.setex("secos:tip:heartbeat", 30, datetime.utcnow().isoformat())
                cycle += 1
            except Exception as e:
                log.error(f"TIP cycle error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    TIPAgent().run()
