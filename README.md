# SecOS v6.0 — Autonomous Security Operating System

> AI-driven SOC platform · 8 autonomous agents · Groq LLaMA 3.3 triage · 16-module dashboard

![Python](https://img.shields.io/badge/python-3.12-00D4FF?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-latest-00FF88?style=flat-square)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF6B00?style=flat-square)
![AI](https://img.shields.io/badge/AI-Groq%20LLaMA%203.3-9B59B6?style=flat-square)

## Architecture
```
Endpoints (Windows/Linux)
        ↓ HTTP POST /api/ingest
FastAPI Gateway → PostgreSQL + Redis
        ↓ secos:alerts pub/sub
SIEM · EDR · NDR · IAM · UEBA · TIP
        ↓
AEGIS AI (Groq llama-3.3-70b) → P1/P2/P3/P4
        ↓
SOAR Playbooks → Pending Actions
        ↓
16-Module React Dashboard
```

## Quick Start
```bash
git clone https://github.com/YOUR_USERNAME/SecOS.git
cd SecOS
cp .env.example .env
nano .env  # Add GROQ_API_KEY
sudo bash start.sh
# Dashboard: http://localhost:8080
```

## Stack

| Layer | Tech |
|-------|------|
| API | FastAPI + Uvicorn |
| DB | PostgreSQL + asyncpg |
| Cache | Redis pub/sub |
| AI | Groq llama-3.3-70b-versatile |
| Frontend | React 18 + Babel |
| Proxy | Nginx |
| Agents | Python 3.12 |
| Windows Agent | PowerShell 5.1+ |

## Agents

| Agent | Detections |
|-------|-----------|
| SIEM | SSH brute force, privilege escalation, account changes |
| EDR | Malicious processes, FIM, network anomalies |
| NDR | C2 beaconing (variance analysis), port scans, malicious IPs |
| IAM | Account creation/deletion, privilege changes, lockouts |
| UEBA | Off-hours logins, lateral movement, velocity spikes |
| SOAR | 6 playbooks: SSH BF, C2, LM, Cred Theft, Malware, UEBA |
| AEGIS | Groq AI triage: decision, priority, confidence, recommendations |
| TIP | IOC management, indicator enrichment |

## AEGIS AI Output

Every HIGH/CRITICAL alert gets:
- **Decision**: ESCALATE / INVESTIGATE / MONITOR / FALSE_POSITIVE
- **Priority**: P1 (15min) → P4 (24hr)
- **Confidence**: 0.0–1.0
- **Attack stage**: MITRE tactic
- **Recommended actions**: Specific steps
- **Fallback**: Rule-based when API unavailable

## MITRE ATT&CK Coverage

Initial Access · Execution · Persistence · Privilege Escalation · Defense Evasion · Credential Access · Discovery · Lateral Movement · C&C · Exfiltration · Impact

## Default Credentials
```
admin   / Admin1234
analyst / Analyst123
soc     / SOCteam123
```

## Author

**Subhankar Bhandari** — SOC Analyst · Security Engineer
TryHackMe Top 4% · ISC2 CC · ArcSight Expert

---
*SecOS — Enterprise security without the enterprise budget.*
