#!/usr/bin/env python3
"""
SecOS IAM Agent — Identity & Access Monitoring
Monitors: failed logins, account changes, privilege escalation,
          service accounts, sudo usage, SSH key changes
"""
import json, logging, os, re, time, pwd, grp
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [IAM] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/iam.log"),
              logging.StreamHandler()])
log = logging.getLogger("secos.iam")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
HOSTNAME  = os.uname().nodename

import redis as redislib
def make_redis():
    url = REDIS_URL.replace("redis://","").split("/")[0]
    host, port = (url.split(":") + ["6379"])[:2]
    return redislib.Redis(host=host, port=int(port), decode_responses=True)

r = make_redis()

# ── IAM Rules ──────────────────────────────────────────────────────────────────
IAM_RULES = [
    # Failed logins
    {
        "id": "IAM-001",
        "name": "SSH Brute Force",
        "pattern": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
        "severity": "HIGH",
        "mitre": "T1110.001",
        "tactic": "Credential Access",
        "score": 75,
        "threshold": 5,
        "window": 60,
        "extract": lambda m: {"user": m.group(1), "src_ip": m.group(2)},
    },
    # Root login
    {
        "id": "IAM-002",
        "name": "Root Login via SSH",
        "pattern": re.compile(r"Accepted .+ for root from (\S+)"),
        "severity": "CRITICAL",
        "mitre": "T1078.001",
        "tactic": "Privilege Escalation",
        "score": 90,
        "threshold": 1,
        "window": 3600,
        "extract": lambda m: {"user": "root", "src_ip": m.group(1)},
    },
    # Account creation
    {
        "id": "IAM-003",
        "name": "New User Account Created",
        "pattern": re.compile(r"new user: name=(\S+?)(?:,|$)"),
        "severity": "MEDIUM",
        "mitre": "T1136.001",
        "tactic": "Persistence",
        "score": 55,
        "threshold": 1,
        "window": 3600,
        "extract": lambda m: {"user": m.group(1)},
    },
    # Password change
    {
        "id": "IAM-004",
        "name": "Password Changed",
        "pattern": re.compile(r"password changed for (\S+)"),
        "severity": "MEDIUM",
        "mitre": "T1098",
        "tactic": "Account Manipulation",
        "score": 45,
        "threshold": 1,
        "window": 300,
        "extract": lambda m: {"user": m.group(1)},
    },
    # Sudo usage
    {
        "id": "IAM-005",
        "name": "Sudo Command Executed",
        "pattern": re.compile(r"sudo:\s+(\S+)\s+:.+COMMAND=(.+)"),
        "severity": "LOW",
        "mitre": "T1068",
        "tactic": "Privilege Escalation",
        "score": 20,
        "threshold": 10,
        "window": 300,
        "extract": lambda m: {"user": m.group(1), "command": m.group(2).strip()},
    },
    # Sudo failure
    {
        "id": "IAM-006",
        "name": "Sudo Authentication Failure",
        "pattern": re.compile(r"sudo:.+authentication failure.+user=(\S+)"),
        "severity": "MEDIUM",
        "mitre": "T1068",
        "tactic": "Privilege Escalation",
        "score": 55,
        "threshold": 3,
        "window": 300,
        "extract": lambda m: {"user": m.group(1)},
    },
    # Group change
    {
        "id": "IAM-007",
        "name": "User Added to Privileged Group",
        "pattern": re.compile(r"(group|usermod).+(sudo|wheel|admin|root)"),
        "severity": "HIGH",
        "mitre": "T1098.001",
        "tactic": "Privilege Escalation",
        "score": 80,
        "threshold": 1,
        "window": 3600,
        "extract": lambda m: {},
    },
    # Account deletion
    {
        "id": "IAM-008",
        "name": "User Account Deleted",
        "pattern": re.compile(r"delete user '?(\S+?)'?"),
        "severity": "MEDIUM",
        "mitre": "T1531",
        "tactic": "Impact",
        "score": 50,
        "threshold": 1,
        "window": 3600,
        "extract": lambda m: {"user": m.group(1)},
    },
    # SSH key added
    {
        "id": "IAM-009",
        "name": "SSH Authorized Key Modified",
        "pattern": re.compile(r"(authorized_keys|\.ssh/config)"),
        "severity": "HIGH",
        "mitre": "T1098.004",
        "tactic": "Persistence",
        "score": 80,
        "threshold": 1,
        "window": 3600,
        "extract": lambda m: {},
    },
    # Account locked
    {
        "id": "IAM-010",
        "name": "Account Locked Out",
        "pattern": re.compile(r"(account locked|pam_tally|faillock).+(\S+)"),
        "severity": "MEDIUM",
        "mitre": "T1110",
        "tactic": "Credential Access",
        "score": 50,
        "threshold": 1,
        "window": 300,
        "extract": lambda m: {},
    },
]

LOG_FILES = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
file_positions = {}
hit_tracker = defaultdict(list)

def uid():
    import hashlib
    return hashlib.md5(f"{time.time()}{HOSTNAME}".encode()).hexdigest()[:12].upper()

def publish_alert(rule, extras):
    alert = {
        "id":        uid(),
        "rule":      rule["name"],
        "rule_name": rule["name"],
        "severity":  rule["severity"],
        "mitre_id":  rule["mitre"],
        "tactic":    rule["tactic"],
        "host":      HOSTNAME,
        "src_ip":    extras.get("src_ip",""),
        "user_name": extras.get("user",""),
        "source":    "IAM",
        "status":    "NEW",
        "score":     rule["score"],
        "raw":       extras.get("raw",""),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    r.publish("secos:alerts", json.dumps(alert))
    r.lpush("secos:iam:alerts", json.dumps(alert))
    r.ltrim("secos:iam:alerts", 0, 499)
    log.info(f"IAM ALERT [{rule['severity']}] {rule['name']} user={extras.get('user','')} src={extras.get('src_ip','')}")

def check_threshold(rule_id, threshold, window):
    now = time.time()
    hits = [t for t in hit_tracker[rule_id] if now - t < window]
    hits.append(now)
    hit_tracker[rule_id] = hits
    return len(hits) >= threshold

def tail_log(path):
    try:
        if not Path(path).exists():
            return []
        size = Path(path).stat().st_size
        pos  = file_positions.get(path, size)
        if size < pos: pos = 0
        if size == pos: return []
        with open(path,"r",errors="ignore") as f:
            f.seek(pos)
            lines = f.readlines()
            file_positions[path] = f.tell()
        return lines
    except:
        return []

# ── User inventory ─────────────────────────────────────────────────────────────
user_baseline = {}

def build_user_inventory():
    users = {}
    try:
        for p in pwd.getpwall():
            groups = []
            try:
                for g in grp.getgrall():
                    if p.pw_name in g.gr_mem:
                        groups.append(g.gr_name)
            except: pass
            users[p.pw_name] = {
                "uid":        p.pw_uid,
                "gid":        p.pw_gid,
                "shell":      p.pw_shell,
                "home":       p.pw_dir,
                "groups":     groups,
                "privileged": p.pw_uid == 0 or "sudo" in groups or "wheel" in groups or "admin" in groups,
            }
    except Exception as e:
        log.debug(f"User inventory: {e}")
    return users

def check_user_changes(current_users):
    """Detect new/deleted/modified accounts."""
    global user_baseline
    if not user_baseline:
        user_baseline = current_users
        return

    # New users
    for u in set(current_users) - set(user_baseline):
        publish_alert({
            "name":"New User Account Detected","severity":"MEDIUM",
            "mitre":"T1136.001","tactic":"Persistence","score":55
        }, {"user":u,"raw":f"New user {u} uid={current_users[u]['uid']}"})

    # Deleted users
    for u in set(user_baseline) - set(current_users):
        publish_alert({
            "name":"User Account Removed","severity":"MEDIUM",
            "mitre":"T1531","tactic":"Impact","score":50
        }, {"user":u,"raw":f"User {u} deleted"})

    # Privilege changes
    for u in set(current_users) & set(user_baseline):
        was_priv = user_baseline[u].get("privileged",False)
        is_priv  = current_users[u].get("privileged",False)
        if not was_priv and is_priv:
            publish_alert({
                "name":"User Privilege Escalation Detected","severity":"HIGH",
                "mitre":"T1098.001","tactic":"Privilege Escalation","score":85
            }, {"user":u,"raw":f"User {u} granted privileged access — groups: {current_users[u]['groups']}"})

    user_baseline = current_users

def scan_logs():
    for log_file in LOG_FILES:
        for line in tail_log(log_file):
            line = line.strip()
            if not line: continue
            for rule in IAM_RULES:
                m = rule["pattern"].search(line)
                if m:
                    if check_threshold(rule["id"], rule["threshold"], rule["window"]):
                        try:
                            extras = rule["extract"](m)
                        except:
                            extras = {}
                        extras["raw"] = line[:300]
                        publish_alert(rule, extras)
                        hit_tracker[rule["id"]] = []

def main():
    log.info(f"SecOS IAM Agent started on {HOSTNAME}")

    # Initialize log positions
    for f in LOG_FILES:
        if Path(f).exists():
            file_positions[f] = Path(f).stat().st_size

    # Build initial user inventory
    user_baseline.update(build_user_inventory())
    log.info(f"User inventory: {len(user_baseline)} accounts, "
             f"{sum(1 for u in user_baseline.values() if u['privileged'])} privileged")

    # Persist inventory to Redis
    r.set("secos:iam:users", json.dumps({
        k: {**v, "groups": list(v.get("groups",[]))} 
        for k,v in user_baseline.items()
    }))

    tick = 0
    while True:
        try:
            scan_logs()
            if tick % 12 == 0:  # every 60s
                current = build_user_inventory()
                check_user_changes(current)
                r.set("secos:iam:users", json.dumps({
                    k: {**v, "groups": list(v.get("groups",[]))}
                    for k,v in current.items()
                }))
                r.setex("secos:iam:heartbeat", 60, datetime.now(timezone.utc).isoformat())
            tick += 1
        except Exception as e:
            log.error(f"IAM tick: {e}")
        time.sleep(5)

if __name__ == "__main__":
    main()
