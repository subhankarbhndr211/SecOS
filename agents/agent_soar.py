#!/usr/bin/env python3
"""
SecOS SOAR Agent — Security Orchestration, Automation & Response
- Listens for alerts and AEGIS decisions
- Executes playbooks (suggest mode: queues actions for human approval)
- Tracks case management and response history
"""
import json, logging, os, time, subprocess
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [SOAR] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/soar.log"),
              logging.StreamHandler()])
log = logging.getLogger("secos.soar")

REDIS_URL   = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SOAR_MODE   = os.getenv("SOAR_MODE", "suggest")   # suggest | auto
HOSTNAME    = os.uname().nodename

import redis as redislib
def make_redis():
    url = REDIS_URL.replace("redis://","").split("/")[0]
    host, port = (url.split(":") + ["6379"])[:2]
    return redislib.Redis(host=host, port=int(port), decode_responses=True)

r = make_redis()

# ── Playbook Library ───────────────────────────────────────────────────────────
PLAYBOOKS = {
    "SSH_BRUTE_FORCE": {
        "name": "SSH Brute Force Response",
        "triggers": ["SSH Brute Force", "Authentication Failure Spike"],
        "severity_threshold": "MEDIUM",
        "steps": [
            {"id": 1, "action": "block_ip",       "description": "Block source IP at firewall"},
            {"id": 2, "action": "alert_analyst",   "description": "Notify SOC analyst"},
            {"id": 3, "action": "add_ioc",         "description": "Add IP to threat intelligence"},
            {"id": 4, "action": "increase_logging","description": "Enable verbose auth logging"},
        ]
    },
    "CREDENTIAL_THEFT": {
        "name": "Credential Theft Response",
        "triggers": ["LSASS Dump", "Mimikatz Detected", "Credential Dumping"],
        "severity_threshold": "HIGH",
        "steps": [
            {"id": 1, "action": "isolate_host",    "description": "Network-isolate affected host"},
            {"id": 2, "action": "kill_process",    "description": "Terminate malicious process"},
            {"id": 3, "action": "snapshot_memory", "description": "Capture memory for forensics"},
            {"id": 4, "action": "reset_passwords", "description": "Force password reset for affected users"},
            {"id": 5, "action": "alert_analyst",   "description": "Escalate to senior analyst"},
        ]
    },
    "C2_BEACON": {
        "name": "C2 Beacon Response",
        "triggers": ["C2 Beacon", "C2 Beacon Detected", "DNS Exfiltration"],
        "severity_threshold": "HIGH",
        "steps": [
            {"id": 1, "action": "block_ip",        "description": "Block C2 IP at perimeter"},
            {"id": 2, "action": "block_domain",    "description": "Null-route C2 domain in DNS"},
            {"id": 3, "action": "isolate_host",    "description": "Quarantine beaconing host"},
            {"id": 4, "action": "capture_traffic", "description": "Enable full packet capture on host"},
            {"id": 5, "action": "create_case",     "description": "Open incident case in TheHive"},
        ]
    },
    "LATERAL_MOVEMENT": {
        "name": "Lateral Movement Response",
        "triggers": ["Lateral Movement SMB", "Lateral Movement", "UEBA: Lateral Movement Pattern"],
        "severity_threshold": "HIGH",
        "steps": [
            {"id": 1, "action": "map_movement",    "description": "Map lateral movement path"},
            {"id": 2, "action": "block_smb",       "description": "Block SMB between segments"},
            {"id": 3, "action": "disable_account", "description": "Temporarily disable compromised account"},
            {"id": 4, "action": "alert_analyst",   "description": "Escalate — potential breach in progress"},
        ]
    },
    "MALWARE_EXECUTION": {
        "name": "Malware Execution Response",
        "triggers": ["Suspicious Process", "Malicious Process", "Suspicious PowerShell Script"],
        "severity_threshold": "HIGH",
        "steps": [
            {"id": 1, "action": "kill_process",    "description": "Terminate malicious process"},
            {"id": 2, "action": "quarantine_file", "description": "Quarantine malicious file"},
            {"id": 3, "action": "scan_host",       "description": "Trigger full AV scan"},
            {"id": 4, "action": "collect_artifacts","description": "Collect execution artifacts"},
        ]
    },
    "UEBA_HIGH_RISK": {
        "name": "High Risk User Response",
        "triggers": ["UEBA: High Risk User", "UEBA: Alert Velocity Spike"],
        "severity_threshold": "HIGH",
        "steps": [
            {"id": 1, "action": "monitor_user",    "description": "Enable enhanced user monitoring"},
            {"id": 2, "action": "alert_analyst",   "description": "Notify analyst for review"},
            {"id": 3, "action": "request_mfa",     "description": "Force MFA re-authentication"},
        ]
    },
    "DEFAULT": {
        "name": "Default Alert Response",
        "triggers": [],
        "severity_threshold": "CRITICAL",
        "steps": [
            {"id": 1, "action": "alert_analyst",   "description": "Notify SOC analyst"},
            {"id": 2, "action": "add_ioc",         "description": "Extract and store IOCs"},
        ]
    }
}

# ── Action Executors ───────────────────────────────────────────────────────────
def execute_action(action_id, action_type, alert, case_id):
    """Execute or queue a SOAR action based on mode."""
    result = {
        "action_id":   action_id,
        "action_type": action_type,
        "case_id":     case_id,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "host":        alert.get("host",""),
        "src_ip":      alert.get("src_ip",""),
        "user":        alert.get("user_name") or alert.get("user",""),
        "status":      "PENDING",
        "result":      None,
    }

    if SOAR_MODE == "suggest":
        # Queue for human approval
        result["status"] = "AWAITING_APPROVAL"
        r.lpush("secos:soar:pending_actions", json.dumps(result))
        r.ltrim("secos:soar:pending_actions", 0, 199)
        log.info(f"ACTION QUEUED [{action_type}] for case {case_id} — awaiting approval")
        return result

    # Auto mode — actually execute
    try:
        if action_type == "block_ip" and alert.get("src_ip"):
            ip = alert["src_ip"]
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], timeout=5)
            subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], timeout=5)
            result["result"] = f"Blocked {ip}"
            result["status"] = "COMPLETED"
            log.info(f"BLOCKED IP: {ip}")

        elif action_type == "alert_analyst":
            r.publish("secos:analyst:alerts", json.dumps({
                "priority": alert.get("severity","HIGH"),
                "message": f"Analyst attention required: {alert.get('rule_name',alert.get('rule','Alert'))}",
                "case_id": case_id,
                "alert": alert,
            }))
            result["result"] = "Analyst notified"
            result["status"] = "COMPLETED"

        elif action_type == "add_ioc":
            ioc = {
                "type": "ip" if alert.get("src_ip") else "host",
                "value": alert.get("src_ip") or alert.get("host",""),
                "severity": alert.get("severity","HIGH"),
                "source": "SOAR",
                "case_id": case_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            r.lpush("secos:tip:iocs", json.dumps(ioc))
            result["result"] = f"IOC added: {ioc['value']}"
            result["status"] = "COMPLETED"

        elif action_type == "create_case":
            case = {
                "case_id":  case_id,
                "title":    alert.get("rule_name", alert.get("rule","Incident")),
                "severity": alert.get("severity","HIGH"),
                "host":     alert.get("host",""),
                "created":  datetime.now(timezone.utc).isoformat(),
                "status":   "OPEN",
                "alerts":   [alert],
            }
            r.hset("secos:soar:cases", case_id, json.dumps(case))
            result["result"] = f"Case {case_id} created"
            result["status"] = "COMPLETED"

        else:
            result["status"] = "SIMULATED"
            result["result"] = f"Action {action_type} logged (simulation)"

    except Exception as e:
        result["status"] = "FAILED"
        result["result"] = str(e)
        log.error(f"Action {action_type} failed: {e}")

    return result

# ── Case Management ────────────────────────────────────────────────────────────
def create_case(alert, playbook):
    case_id = f"CASE-{int(time.time())}"
    case = {
        "case_id":   case_id,
        "title":     alert.get("rule_name", alert.get("rule","Security Incident")),
        "severity":  alert.get("severity","HIGH"),
        "host":      alert.get("host",""),
        "user":      alert.get("user_name") or alert.get("user",""),
        "src_ip":    alert.get("src_ip",""),
        "playbook":  playbook["name"],
        "created":   datetime.now(timezone.utc).isoformat(),
        "status":    "OPEN",
        "mitre":     alert.get("mitre_id",""),
        "actions":   [],
        "timeline":  [{"time": datetime.now(timezone.utc).isoformat(),
                       "event": f"Case opened — {playbook['name']} triggered"}],
    }
    r.hset("secos:soar:cases", case_id, json.dumps(case))
    r.lpush("secos:soar:case_ids", case_id)
    r.ltrim("secos:soar:case_ids", 0, 499)
    log.info(f"Case opened: {case_id} — {playbook['name']}")
    return case_id

SEV_ORDER = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}

def match_playbook(alert):
    rule = alert.get("rule_name", alert.get("rule",""))
    sev  = alert.get("severity","LOW")
    for pb_key, pb in PLAYBOOKS.items():
        if pb_key == "DEFAULT":
            continue
        for trigger in pb["triggers"]:
            if trigger.lower() in rule.lower():
                threshold = pb["severity_threshold"]
                if SEV_ORDER.get(sev,0) >= SEV_ORDER.get(threshold,0):
                    return pb
    # Default for CRITICAL
    if sev == "CRITICAL":
        return PLAYBOOKS["DEFAULT"]
    return None

# ── Dedup ─────────────────────────────────────────────────────────────────────
processed = {}
def is_duplicate(alert_id, cooldown=600):
    now = time.time()
    if alert_id in processed and now - processed[alert_id] < cooldown:
        return True
    processed[alert_id] = now
    return False

def main():
    log.info(f"SecOS SOAR Agent started — mode: {SOAR_MODE}")
    pubsub = r.pubsub()
    pubsub.subscribe("secos:alerts", "secos:aegis:decisions")
    log.info("Subscribed to secos:alerts + secos:aegis:decisions")

    for msg in pubsub.listen():
        try:
            if msg["type"] != "message":
                continue

            channel = msg["channel"]
            data = json.loads(msg["data"])

            # ── Handle AEGIS decisions (approved actions) ──────────────────
            if channel == "secos:aegis:decisions":
                decision = data.get("decision","")
                alert    = data.get("alert",{})
                if decision in ("CONTAIN","BLOCK","ISOLATE"):
                    pb = match_playbook(alert) or PLAYBOOKS["DEFAULT"]
                    case_id = data.get("case_id") or create_case(alert, pb)
                    for step in pb["steps"]:
                        result = execute_action(step["id"], step["action"], alert, case_id)
                        log.info(f"  Step {step['id']}: {step['action']} → {result['status']}")
                continue

            # ── Handle incoming alerts ─────────────────────────────────────
            alert = data
            alert_id = str(alert.get("id",""))
            if not alert_id or is_duplicate(alert_id):
                continue

            # Skip low severity and SOAR-generated
            sev = alert.get("severity","LOW")
            if SEV_ORDER.get(sev,0) < SEV_ORDER.get("MEDIUM",0):
                continue

            pb = match_playbook(alert)
            if not pb:
                continue

            case_id = create_case(alert, pb)

            # Execute playbook steps
            action_results = []
            for step in pb["steps"]:
                result = execute_action(step["id"], step["action"], alert, case_id)
                action_results.append(result)

            # Publish playbook execution summary to dashboard
            summary = {
                "case_id":  case_id,
                "playbook": pb["name"],
                "alert":    alert.get("rule_name", alert.get("rule","")),
                "severity": sev,
                "host":     alert.get("host",""),
                "actions":  len(action_results),
                "pending":  sum(1 for a in action_results if a["status"]=="AWAITING_APPROVAL"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            r.lpush("secos:soar:executions", json.dumps(summary))
            r.ltrim("secos:soar:executions", 0, 199)
            r.setex("secos:soar:heartbeat", 60, datetime.now(timezone.utc).isoformat())

        except Exception as e:
            log.error(f"SOAR error: {e}")

if __name__ == "__main__":
    main()
