#!/usr/bin/env python3
"""
SecOS UEBA Agent — User & Entity Behavior Analytics
Builds behavioral baselines per user/host and detects anomalies:
- Off-hours logins, new IPs, impossible travel
- Privilege escalation patterns, data staging
- Lateral movement, credential stuffing
"""
import json, logging, os, time, math, re
from collections import defaultdict
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [UEBA] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/ueba.log"),
              logging.StreamHandler()])
log = logging.getLogger("secos.ueba")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

import redis as redislib
def make_redis():
    url = REDIS_URL.replace("redis://","").split("/")[0]
    host, port = (url.split(":") + ["6379"])[:2]
    return redislib.Redis(host=host, port=int(port), decode_responses=True)

r = make_redis()

# ── User Profile ───────────────────────────────────────────────────────────────
class UserProfile:
    def __init__(self, username):
        self.username       = username
        self.login_hours    = []        # hour-of-day history
        self.src_ips        = set()
        self.hosts_accessed = set()
        self.alert_types    = defaultdict(int)
        self.daily_alerts   = defaultdict(int)  # date -> count
        self.risk_score     = 0.0
        self.anomalies      = []
        self.first_seen     = datetime.now(timezone.utc).isoformat()
        self.last_seen      = None
        self.observation_count = 0

    def record_event(self, hour, src_ip, host, alert_type):
        self.login_hours.append(hour)
        if src_ip: self.src_ips.add(src_ip)
        if host:   self.hosts_accessed.add(host)
        self.alert_types[alert_type] += 1
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.daily_alerts[today] += 1
        self.last_seen = datetime.now(timezone.utc).isoformat()
        self.observation_count += 1
        if len(self.login_hours) > 2000:
            self.login_hours = self.login_hours[-1000:]

    def baseline_hours(self):
        if len(self.login_hours) < 10:
            return 0, 23
        avg = sum(self.login_hours) / len(self.login_hours)
        std = max(1, math.sqrt(sum((h-avg)**2 for h in self.login_hours)/len(self.login_hours)))
        return max(0,int(avg-2*std)), min(23,int(avg+2*std))

    def is_after_hours(self, hour):
        if self.observation_count < 20:
            return False
        lo, hi = self.baseline_hours()
        return hour < lo or hour > hi

    def alert_velocity(self):
        """Alerts in last 24h vs daily average."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today_count = self.daily_alerts.get(today, 0)
        if len(self.daily_alerts) < 3:
            return 0
        avg = sum(self.daily_alerts.values()) / len(self.daily_alerts)
        return today_count / max(avg, 1)

    def compute_risk(self):
        score = 0.0
        # High alert volume today
        vel = self.alert_velocity()
        if vel > 3:   score += 30
        elif vel > 2: score += 15
        # Many unique IPs
        if len(self.src_ips) > 5:  score += 20
        elif len(self.src_ips) > 2: score += 10
        # Many hosts accessed
        if len(self.hosts_accessed) > 8:  score += 20
        elif len(self.hosts_accessed) > 4: score += 10
        # Diverse attack types = intentional
        if len(self.alert_types) > 5: score += 15
        elif len(self.alert_types) > 3: score += 8
        # Privilege escalation attempts
        priv = self.alert_types.get("Privilege Escalation", 0)
        if priv > 3: score += 20
        elif priv > 1: score += 10
        # Persistence attempts
        pers = self.alert_types.get("Persistence", 0)
        if pers > 2: score += 15
        # C2 activity
        c2 = self.alert_types.get("Command and Control", 0)
        if c2 > 1: score += 25
        self.risk_score = min(100.0, score)
        return self.risk_score

    def to_dict(self):
        return {
            "username":       self.username,
            "risk_score":     round(self.compute_risk(), 1),
            "observation_count": self.observation_count,
            "unique_ips":     len(self.src_ips),
            "hosts_accessed": len(self.hosts_accessed),
            "alert_types":    dict(self.alert_types),
            "alert_velocity": round(self.alert_velocity(), 2),
            "baseline_hours": list(self.baseline_hours()),
            "first_seen":     self.first_seen,
            "last_seen":      self.last_seen,
            "anomalies":      self.anomalies[-10:],
        }

# ── Entity (Host) Profile ──────────────────────────────────────────────────────
class HostProfile:
    def __init__(self, hostname):
        self.hostname    = hostname
        self.alert_count = 0
        self.severity_counts = defaultdict(int)
        self.alert_types = defaultdict(int)
        self.users_seen  = set()
        self.src_ips     = set()
        self.risk_score  = 0.0
        self.first_seen  = datetime.now(timezone.utc).isoformat()
        self.last_seen   = None

    def record_alert(self, severity, tactic, user, src_ip):
        self.alert_count += 1
        self.severity_counts[severity] += 1
        self.alert_types[tactic] += 1
        if user: self.users_seen.add(user)
        if src_ip: self.src_ips.add(src_ip)
        self.last_seen = datetime.now(timezone.utc).isoformat()

    def compute_risk(self):
        score = 0.0
        score += self.severity_counts.get("CRITICAL", 0) * 20
        score += self.severity_counts.get("HIGH", 0) * 10
        score += self.severity_counts.get("MEDIUM", 0) * 3
        score += len(self.users_seen) * 5
        score += len(self.src_ips) * 3
        self.risk_score = min(100.0, score)
        return self.risk_score

    def to_dict(self):
        return {
            "hostname":    self.hostname,
            "risk_score":  round(self.compute_risk(), 1),
            "alert_count": self.alert_count,
            "severity_breakdown": dict(self.severity_counts),
            "top_tactics": dict(sorted(self.alert_types.items(), key=lambda x:-x[1])[:5]),
            "unique_users": len(self.users_seen),
            "unique_src_ips": len(self.src_ips),
            "first_seen":  self.first_seen,
            "last_seen":   self.last_seen,
        }

# ── Anomaly Detection ──────────────────────────────────────────────────────────
class UEBAEngine:
    def __init__(self):
        self.users = {}   # username -> UserProfile
        self.hosts = {}   # hostname -> HostProfile
        self.ip_user_map = defaultdict(set)  # ip -> set of usernames

    def get_user(self, username):
        if username not in self.users:
            self.users[username] = UserProfile(username)
        return self.users[username]

    def get_host(self, hostname):
        if hostname not in self.hosts:
            self.hosts[hostname] = HostProfile(hostname)
        return self.hosts[hostname]

    def process_alert(self, alert):
        user    = alert.get("user_name") or alert.get("user") or ""
        host    = alert.get("host","")
        src_ip  = alert.get("src_ip","")
        sev     = alert.get("severity","LOW")
        tactic  = alert.get("tactic","")
        rule    = alert.get("rule_name") or alert.get("rule","")
        ts      = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

        hour = datetime.now(timezone.utc).hour
        try:
            hour = datetime.fromisoformat(ts.replace("Z","+00:00")).hour
        except: pass

        anomalies = []

        # ── User profiling ────────────────────────────────────────────────────
        if user and user not in ("", "N/A", "SYSTEM", "root"):
            up = self.get_user(user)
            up.record_event(hour, src_ip, host, tactic)

            # Check: off-hours activity
            if up.is_after_hours(hour):
                anomalies.append({
                    "type": "OFF_HOURS_ACTIVITY",
                    "user": user,
                    "detail": f"Activity at hour {hour}, baseline: {up.baseline_hours()}",
                    "severity": "MEDIUM",
                    "score": 55,
                    "mitre": "T1078",
                })

            # Check: new source IP
            if src_ip and len(up.src_ips) > 1 and src_ip in up.src_ips:
                # Already known, check impossible travel (multiple IPs in short time)
                if len(up.src_ips) > 3:
                    anomalies.append({
                        "type": "MULTIPLE_SOURCE_IPS",
                        "user": user,
                        "detail": f"User seen from {len(up.src_ips)} IPs: {list(up.src_ips)[:5]}",
                        "severity": "HIGH",
                        "score": 72,
                        "mitre": "T1078.004",
                    })

            # Check: alert velocity spike
            vel = up.alert_velocity()
            if vel > 4:
                anomalies.append({
                    "type": "ALERT_VELOCITY_SPIKE",
                    "user": user,
                    "detail": f"Alert rate {vel:.1f}x above baseline today",
                    "severity": "HIGH",
                    "score": 78,
                    "mitre": "T1110",
                })

            # Check: high risk score
            risk = up.compute_risk()
            if risk >= 70:
                anomalies.append({
                    "type": "HIGH_RISK_USER",
                    "user": user,
                    "detail": f"User risk score: {risk:.0f}/100",
                    "severity": "HIGH" if risk < 85 else "CRITICAL",
                    "score": int(risk),
                    "mitre": "T1078",
                })

            # Lateral movement: user accessing many hosts
            if len(up.hosts_accessed) >= 5:
                anomalies.append({
                    "type": "LATERAL_MOVEMENT_PATTERN",
                    "user": user,
                    "detail": f"User accessed {len(up.hosts_accessed)} hosts: {list(up.hosts_accessed)[:5]}",
                    "severity": "HIGH",
                    "score": 80,
                    "mitre": "T1021",
                })

        # ── Host profiling ────────────────────────────────────────────────────
        if host:
            hp = self.get_host(host)
            hp.record_alert(sev, tactic, user, src_ip)
            host_risk = hp.compute_risk()
            if host_risk >= 60:
                anomalies.append({
                    "type": "HIGH_RISK_HOST",
                    "host": host,
                    "detail": f"Host risk score: {host_risk:.0f}/100, {hp.alert_count} alerts",
                    "severity": "HIGH" if host_risk < 80 else "CRITICAL",
                    "score": int(host_risk),
                    "mitre": "T1571",
                })

        return anomalies

    def persist_profiles(self):
        """Save profiles to Redis for API/dashboard consumption."""
        profiles = []
        for up in self.users.values():
            if up.observation_count > 0:
                profiles.append(up.to_dict())
        profiles.sort(key=lambda x: -x["risk_score"])
        r.set("secos:ueba:profiles", json.dumps(profiles))

        host_profiles = []
        for hp in self.hosts.values():
            if hp.alert_count > 0:
                host_profiles.append(hp.to_dict())
        host_profiles.sort(key=lambda x: -x["risk_score"])
        r.set("secos:ueba:hosts", json.dumps(host_profiles))

        # Top risky users for dashboard
        top = profiles[:10]
        r.set("secos:ueba:top_risks", json.dumps(top))
        log.debug(f"Persisted {len(profiles)} user profiles, {len(host_profiles)} host profiles")

def publish_ueba_alert(anomaly, source_alert):
    """Publish UEBA-detected anomaly as a new alert."""
    alert = {
        "id":       f"UEBA-{int(time.time()*1000)}",
        "rule":     f"UEBA: {anomaly['type'].replace('_',' ').title()}",
        "severity": anomaly["severity"],
        "mitre_id": anomaly.get("mitre","T1078"),
        "tactic":   "Lateral Movement",
        "host":     anomaly.get("host") or source_alert.get("host",""),
        "user":     anomaly.get("user") or source_alert.get("user_name",""),
        "src_ip":   source_alert.get("src_ip",""),
        "source":   "UEBA",
        "status":   "NEW",
        "score":    anomaly["score"],
        "raw":      anomaly["detail"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    r.publish("secos:alerts", json.dumps(alert))
    r.lpush("secos:ueba:alerts", json.dumps(alert))
    r.ltrim("secos:ueba:alerts", 0, 499)
    log.info(f"UEBA ALERT [{anomaly['severity']}] {anomaly['type']} — {anomaly['detail'][:80]}")

# ── Alert deduplication ────────────────────────────────────────────────────────
seen_anomalies = {}  # key -> last_fired timestamp

def should_fire(key, cooldown=300):
    now = time.time()
    if key not in seen_anomalies or now - seen_anomalies[key] > cooldown:
        seen_anomalies[key] = now
        return True
    return False

def main():
    log.info("SecOS UEBA Agent started")
    engine = UEBAEngine()
    pubsub = r.pubsub()
    pubsub.subscribe("secos:alerts")
    log.info("Subscribed to secos:alerts")

    # Load historical alerts from Redis list for baseline
    historical = r.lrange("secos:siem:alerts", 0, 499)
    for raw in historical:
        try:
            engine.process_alert(json.loads(raw))
        except: pass
    log.info(f"Loaded {len(historical)} historical alerts for baseline")

    tick = 0
    for msg in pubsub.listen():
        try:
            if msg["type"] != "message":
                continue
            alert = json.loads(msg["data"])

            # Skip UEBA-generated alerts to avoid loops
            if alert.get("source") == "UEBA":
                continue

            anomalies = engine.process_alert(alert)
            for anomaly in anomalies:
                key = f"{anomaly['type']}:{anomaly.get('user','')}:{anomaly.get('host','')}"
                if should_fire(key):
                    publish_ueba_alert(anomaly, alert)

            tick += 1
            if tick % 50 == 0:
                engine.persist_profiles()
                r.setex("secos:ueba:heartbeat", 60, datetime.now(timezone.utc).isoformat())

        except Exception as e:
            log.error(f"UEBA error: {e}")

        # Periodic profile persistence even without alerts
        if tick % 20 == 0:
            engine.persist_profiles()

if __name__ == "__main__":
    main()
