#!/usr/bin/env python3
"""
SecOS AEGIS Agent — Autonomous AI Triage Engine
Mode: SUGGEST — AI analyzes every alert and provides recommendations.
     Human approves all response actions.
Uses Groq (llama-3.3-70b-versatile) for reasoning.
"""
import json, logging, os, time, re
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [AEGIS] %(message)s",
    handlers=[logging.FileHandler("/var/log/secos/aegis.log"),
              logging.StreamHandler()])
log = logging.getLogger("secos.aegis")

REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379/0")
GROQ_API_KEY = os.getenv("GROQ_API_KEY","")
AEGIS_MODEL  = os.getenv("AEGIS_MODEL","llama-3.3-70b-versatile")
AEGIS_MODE   = "suggest"   # hardcoded — human approves all actions

import redis as redislib
def make_redis():
    url = REDIS_URL.replace("redis://","").split("/")[0]
    host, port = (url.split(":") + ["6379"])[:2]
    return redislib.Redis(host=host, port=int(port), decode_responses=True)

r = make_redis()

AI_AVAILABLE = bool(GROQ_API_KEY and GROQ_API_KEY != "your-groq-key-here")

if AI_AVAILABLE:
    try:
        import httpx
        log.info(f"AEGIS AI enabled — Groq model: {AEGIS_MODEL}")
    except ImportError:
        AI_AVAILABLE = False
        log.warning("httpx not installed — using rule-based triage")
else:
    log.warning("No Groq API key — using rule-based triage")

# ── Rule-based triage (fallback / supplement) ──────────────────────────────────
TRIAGE_RULES = {
    "CRITICAL": {
        "decision": "ESCALATE",
        "priority": "P1",
        "recommended_actions": ["ISOLATE_HOST","BLOCK_IP","ALERT_SOC_LEAD","CREATE_CASE"],
        "sla_minutes": 15,
    },
    "HIGH": {
        "decision": "INVESTIGATE",
        "priority": "P2",
        "recommended_actions": ["BLOCK_IP","MONITOR_USER","ALERT_ANALYST"],
        "sla_minutes": 60,
    },
    "MEDIUM": {
        "decision": "MONITOR",
        "priority": "P3",
        "recommended_actions": ["ADD_IOC","MONITOR_HOST"],
        "sla_minutes": 240,
    },
    "LOW": {
        "decision": "LOG",
        "priority": "P4",
        "recommended_actions": ["LOG_ONLY"],
        "sla_minutes": 1440,
    },
}

MITRE_CONTEXT = {
    "T1110":    "Brute Force — attacker attempting credential guessing",
    "T1078":    "Valid Accounts — legitimate credentials may be compromised",
    "T1003":    "OS Credential Dumping — credential theft in progress",
    "T1071":    "Application Layer Protocol — C2 communication detected",
    "T1048":    "Exfiltration Over Alternative Protocol — data leaving network",
    "T1021":    "Remote Services — lateral movement using remote access",
    "T1059":    "Command and Scripting Interpreter — code execution detected",
    "T1053":    "Scheduled Task — persistence mechanism installed",
    "T1543":    "Create or Modify System Process — service persistence",
    "T1136":    "Create Account — new account created",
    "T1098":    "Account Manipulation — privilege changes detected",
    "T1490":    "Inhibit System Recovery — ransomware precursor activity",
    "T1070":    "Indicator Removal — attacker covering tracks",
    "T1046":    "Network Service Scanning — reconnaissance in progress",
    "T1571":    "Non-Standard Port — suspicious network communication",
}

def rule_based_triage(alert):
    sev   = alert.get("severity","LOW")
    mitre = alert.get("mitre_id","")
    rule  = alert.get("rule_name", alert.get("rule",""))

    triage = TRIAGE_RULES.get(sev, TRIAGE_RULES["LOW"]).copy()
    mitre_base = mitre[:5] if mitre else ""
    context = MITRE_CONTEXT.get(mitre_base, MITRE_CONTEXT.get(mitre,"Unknown technique"))

    # Escalate certain high-value techniques
    if any(t in mitre for t in ["T1003","T1490","T1070.001"]):
        triage["decision"] = "ESCALATE"
        triage["priority"] = "P1"

    analysis = (
        f"Alert: {rule}\n"
        f"Severity: {sev} | MITRE: {mitre}\n"
        f"Context: {context}\n"
        f"Host: {alert.get('host','')} | User: {alert.get('user_name',alert.get('user',''))}\n"
        f"Source IP: {alert.get('src_ip','N/A')}\n"
        f"Triage Decision: {triage['decision']} (Priority {triage['priority']})\n"
        f"SLA: Respond within {triage['sla_minutes']} minutes\n"
        f"Recommended Actions: {', '.join(triage['recommended_actions'])}"
    )

    return {
        "decision":   triage["decision"],
        "priority":   triage["priority"],
        "sla_minutes": triage["sla_minutes"],
        "recommended_actions": triage["recommended_actions"],
        "analysis":   analysis,
        "confidence": 0.75,
        "source":     "rule-based",
    }

async def ai_triage(alert):
    """Call Groq API for AI-powered alert triage."""
    import httpx

    mitre = alert.get("mitre_id","")
    mitre_ctx = MITRE_CONTEXT.get(mitre[:5] if mitre else "", "")

    prompt = f"""You are AEGIS, an autonomous SOC AI triage engine. Analyze this security alert and provide a structured triage decision.

ALERT:
- Rule: {alert.get('rule_name', alert.get('rule',''))}
- Severity: {alert.get('severity','UNKNOWN')}
- MITRE ATT&CK: {mitre} — {mitre_ctx}
- Host: {alert.get('host','unknown')}
- User: {alert.get('user_name', alert.get('user','unknown'))}
- Source IP: {alert.get('src_ip','unknown')}
- Tactic: {alert.get('tactic','unknown')}
- Score: {alert.get('score',0)}/100
- Raw: {str(alert.get('raw',''))[:200]}

Provide your analysis in this exact JSON format (no markdown, just JSON):
{{
  "decision": "ESCALATE|INVESTIGATE|MONITOR|LOG|FALSE_POSITIVE",
  "priority": "P1|P2|P3|P4",
  "confidence": 0.0-1.0,
  "threat_summary": "2-3 sentence summary of the threat",
  "attack_stage": "Reconnaissance|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|C2|Exfiltration|Impact",
  "recommended_actions": ["action1","action2","action3"],
  "false_positive_likelihood": "LOW|MEDIUM|HIGH",
  "context": "Why this alert is significant and what the attacker may be attempting",
  "next_steps": "Specific investigation steps for the analyst"
}}"""

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                         "Content-Type": "application/json"},
                json={
                    "model": AEGIS_MODEL,
                    "messages": [{"role":"user","content":prompt}],
                    "max_tokens": 600,
                    "temperature": 0.1,
                }
            )
            data = resp.json()
            content = data["choices"][0]["message"]["content"].strip()

            # Strip markdown if present
            content = re.sub(r"```json\s*|\s*```","",content).strip()
            result = json.loads(content)
            result["source"] = "groq-ai"
            result["sla_minutes"] = {"P1":15,"P2":60,"P3":240,"P4":1440}.get(result.get("priority","P3"),240)
            return result

    except Exception as e:
        log.warning(f"Groq AI failed: {e} — falling back to rule-based")
        return None

def store_aegis_result(alert, triage):
    """Store AEGIS analysis in Redis for dashboard."""
    entry = {
        "alert_id":   str(alert.get("id","")),
        "rule":       alert.get("rule_name", alert.get("rule","")),
        "severity":   alert.get("severity",""),
        "host":       alert.get("host",""),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "decision":   triage["decision"],
        "priority":   triage["priority"],
        "confidence": triage.get("confidence",0.75),
        "analysis":   triage.get("analysis") or triage.get("threat_summary",""),
        "actions":    triage.get("recommended_actions",[]),
        "source":     triage.get("source","rule-based"),
        "false_positive_likelihood": triage.get("false_positive_likelihood","LOW"),
        "next_steps": triage.get("next_steps",""),
        "attack_stage": triage.get("attack_stage",""),
        "mode":       AEGIS_MODE,
    }
    r.lpush("secos:aegis:history", json.dumps(entry))
    r.ltrim("secos:aegis:history", 0, 499)
    r.set("secos:aegis:latest", json.dumps(entry))

    # Publish decision for SOAR
    if triage["decision"] in ("ESCALATE","INVESTIGATE") and triage.get("confidence",0) > 0.6:
        decision_msg = {
            "alert":    alert,
            "decision": "CONTAIN" if triage["decision"]=="ESCALATE" else "MONITOR",
            "priority": triage["priority"],
            "actions":  triage.get("recommended_actions",[]),
            "case_id":  f"CASE-{int(time.time())}",
        }
        r.publish("secos:aegis:decisions", json.dumps(decision_msg))

    log.info(f"AEGIS [{triage['source']}] {triage['decision']} (P{triage['priority'][-1]}) "
             f"conf:{triage.get('confidence',0.75):.0%} — {alert.get('rule_name',alert.get('rule',''))[:50]}")
    return entry

SEV_ORDER = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
processed = {}

def is_duplicate(alert_id, cooldown=300):
    now = time.time()
    if alert_id in processed and now - processed[alert_id] < cooldown:
        return True
    processed[alert_id] = now
    return False

def main():
    import asyncio

    log.info(f"SecOS AEGIS Agent started — mode: {AEGIS_MODE}, AI: {AI_AVAILABLE}")
    pubsub = r.pubsub()
    pubsub.subscribe("secos:alerts")

    async def process():
        for msg in pubsub.listen():
            try:
                if msg["type"] != "message":
                    continue

                alert    = json.loads(msg["data"])
                alert_id = str(alert.get("id",""))
                sev      = alert.get("severity","LOW")

                # Skip low severity and AEGIS-generated
                if SEV_ORDER.get(sev,0) < SEV_ORDER.get("MEDIUM",0):
                    continue
                if alert.get("source") == "AEGIS":
                    continue
                if alert_id and is_duplicate(alert_id):
                    continue

                # Try AI triage first, fall back to rule-based
                triage = None
                if AI_AVAILABLE:
                    triage = await ai_triage(alert)

                if not triage:
                    triage = rule_based_triage(alert)

                store_aegis_result(alert, triage)
                r.setex("secos:aegis:heartbeat", 60, datetime.now(timezone.utc).isoformat())

            except Exception as e:
                log.error(f"AEGIS error: {e}")

    asyncio.run(process())

if __name__ == "__main__":
    main()
