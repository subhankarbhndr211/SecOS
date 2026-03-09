#!/usr/bin/env python3
"""SecOS v6.0 — XDR Agent: Cross-layer Detection & Response Correlation"""
import json, logging, os, time, hashlib
from collections import defaultdict
from datetime import datetime
import redis
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [XDR] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/xdr.log"), logging.StreamHandler()])
log = logging.getLogger("secos.xdr")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

class XDRAgent:
    """Correlates events across SIEM, EDR, NDR, IAM into multi-layer incidents."""
    def __init__(self):
        self.r = redis.from_url(REDIS_URL, decode_responses=True)
        self.entity_events: dict = defaultdict(list)  # host/ip -> [events]
        self.user_events:   dict = defaultdict(list)  # user -> [events]
        self.incidents:     list = []
        self.hostname = os.uname().nodename
        self._seen: set = set()

    def publish(self, incident: dict):
        key = hashlib.md5(json.dumps(incident.get("events_summary",""), sort_keys=True).encode()).hexdigest()
        if key in self._seen:
            return
        self._seen.add(key)
        if len(self._seen) > 1000:
            self._seen.clear()
        incident.setdefault("source", "XDR")
        incident.setdefault("timestamp", datetime.utcnow().isoformat())
        self.r.publish("secos:alerts", json.dumps(incident))
        self.r.lpush("secos:xdr:incidents", json.dumps(incident))
        self.r.ltrim("secos:xdr:incidents", 0, 999)
        log.warning(f"XDR INCIDENT [{incident.get('severity')}] {incident.get('rule')}")

    def ingest_all_feeds(self):
        feeds = {
            "SIEM": "secos:siem:alerts",
            "EDR":  "secos:edr:alerts",
            "NDR":  "secos:ndr:alerts",
            "IAM":  "secos:iam:alerts",
            "UEBA": "secos:ueba:alerts",
        }
        events = []
        for source, key in feeds.items():
            try:
                raw_list = self.r.lrange(key, 0, 19)
                for raw in raw_list:
                    ev = json.loads(raw)
                    ev["_source_module"] = source
                    events.append(ev)
            except Exception:
                pass
        return events

    def correlate(self, events: list):
        # Group by host and user
        for ev in events:
            host = ev.get("host", "")
            user = ev.get("user_name", "")
            if host:
                self.entity_events[host].append(ev)
                self.entity_events[host] = self.entity_events[host][-50:]
            if user:
                self.user_events[user].append(ev)
                self.user_events[user] = self.user_events[user][-50:]

        # Pattern 1: Same host hit by multiple layers (EDR + SIEM + NDR)
        for host, host_evs in self.entity_events.items():
            sources = {e.get("_source_module") for e in host_evs[-10:]}
            if len(sources) >= 3:
                tactics = list({e.get("tactic","?") for e in host_evs[-5:]})
                self.publish({
                    "rule": "XDR: Multi-Layer Attack on Single Host",
                    "severity": "CRITICAL",
                    "mitre_id": "T1071",
                    "tactic": "Multiple",
                    "host": host,
                    "score": 96,
                    "detail": f"{host} hit across {len(sources)} layers: {','.join(sources)}. Tactics: {tactics}",
                    "events_summary": f"{host}:{len(sources)}:{len(host_evs)}",
                    "layers": list(sources),
                })

        # Pattern 2: Same user triggers IAM + EDR events = credential-based intrusion
        for user, user_evs in self.user_events.items():
            if not user or user in ("root","secos"):
                continue
            sources = {e.get("_source_module") for e in user_evs[-8:]}
            if "IAM" in sources and ("EDR" in sources or "SIEM" in sources):
                self.publish({
                    "rule": "XDR: User-Based Intrusion Chain",
                    "severity": "HIGH",
                    "mitre_id": "T1078",
                    "tactic": "Credential Access",
                    "user_name": user,
                    "score": 88,
                    "detail": f"User {user} implicated in {len(user_evs)} events across {','.join(sources)}",
                    "events_summary": f"{user}:{','.join(sources)}",
                })

    def run(self):
        log.info("XDR agent started")
        cycle = 0
        while True:
            try:
                events = self.ingest_all_feeds()
                if events:
                    self.correlate(events)
                self.r.setex("secos:xdr:heartbeat", 30, datetime.utcnow().isoformat())
                cycle += 1
            except Exception as e:
                log.error(f"XDR cycle error: {e}")
            time.sleep(15)

if __name__ == "__main__":
    XDRAgent().run()
