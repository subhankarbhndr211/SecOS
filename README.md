# paste README content here
<div align="center">

```
███████╗███████╗ ██████╗ ██████╗ ███████╗
██╔════╝██╔════╝██╔════╝██╔═══██╗██╔════╝
███████╗█████╗  ██║     ██║   ██║███████╗
╚════██║██╔══╝  ██║     ██║   ██║╚════██║
███████║███████╗╚██████╗╚██████╔╝███████║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝
```

### Autonomous Security Operating System

[![License](https://img.shields.io/badge/license-MIT-00A3FF?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-v6.0.0-00FF88?style=flat-square)](https://github.com/subhankarbhndr211/SecOS/releases)
[![Status](https://img.shields.io/badge/status-Early%20Phase-FF6B00?style=flat-square)](#project-status)
[![Python](https://img.shields.io/badge/python-3.12-00D4FF?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-00FF88?style=flat-square)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square)](https://react.dev)
[![AI](https://img.shields.io/badge/AI-Groq%20LLaMA%203.3-9B59B6?style=flat-square)](https://groq.com)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF6B00?style=flat-square)](https://attack.mitre.org)

*An enterprise-grade, self-contained SOC platform powered by 8 autonomous detection agents and an AI triage engine — deployable on a single Linux machine.*

</div>

---

## ⚠️ Project Status — Early Phase

> **This project is in active early development. It is functional and deployable today, but represents the foundation of a much larger 2-year vision.**

SecOS v6.0 is a working autonomous SOC platform — all 8 agents run continuously, the AI triage engine is live, and endpoints can be connected from anywhere. However, many enterprise features are still being built.

**What works today:**
- ✅ 8 autonomous detection agents running 24/7
- ✅ AEGIS AI triage via Groq LLaMA 3.3-70b
- ✅ Windows + Linux endpoint agents with one-line installers
- ✅ 16-module React SOC dashboard with live WebSocket streaming
- ✅ Full MITRE ATT&CK mapping across 11 tactics
- ✅ Role-based access control (admin / analyst / soc_lead)
- ✅ SOAR suggest mode with 6 response playbooks
- ✅ ngrok support for remote endpoint connectivity

**What is being built (see [Roadmap](#roadmap)):**
- 🔨 Docker Compose single-command deployment
- 🔨 AEGIS agentic investigation chains
- 🔨 TheHive + MISP + Cortex integration
- 🔨 Multi-tenant MSSP support
- 🔨 Cloud workload monitoring (AWS/Azure/GCP)
- 🔨 Full autonomous SOAR response mode
- 🔨 Custom correlation rules engine

**Estimated timeline to full feature parity: ~2 years of active development.**

Contributions, feedback, and ideas are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## What is SecOS?

SecOS is a fully autonomous Security Operating System that replaces a traditional multi-vendor SOC stack with a single deployable platform. It collects telemetry from Windows and Linux endpoints, correlates events across 8 specialized detection engines, triages every alert using a Groq-powered LLM, and orchestrates response actions — without requiring cloud infrastructure, expensive licensing, or a large team.

> Built by a SOC analyst, for SOC analysts. Every design decision reflects real operational experience.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ENDPOINTS                            │
│   Windows Agent (PS)  ·  Linux Agent  ·  Log Sources        │
└──────────────────┬──────────────────────────────────────────┘
                   │ HTTP POST /api/ingest
┌──────────────────▼──────────────────────────────────────────┐
│                    INGESTION LAYER                           │
│         FastAPI Gateway  ·  PostgreSQL  ·  Redis            │
└──────────────────┬──────────────────────────────────────────┘
                   │ secos:alerts (pub/sub)
┌──────────────────▼──────────────────────────────────────────┐
│                   DETECTION LAYER                           │
│  SIEM · EDR · NDR · IAM · UEBA · SOAR · AEGIS AI · TIP     │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                  AEGIS AI ENGINE                            │
│       Groq · llama-3.3-70b-versatile · Suggest Mode         │
│   Triage · Priority · Attack Stage · Recommendations        │
└──────────────────┬──────────────────────────────────────────┘
                   │ WebSocket live stream
┌──────────────────▼──────────────────────────────────────────┐
│              16-MODULE REACT DASHBOARD                      │
│  http://localhost:8080  ·  Real-time alerts + AI decisions  │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Requirements
- Ubuntu 20.04+ / Debian / WSL2
- Python 3.10+, PostgreSQL 13+, Redis 6+
- 4GB RAM minimum

```bash
# 1. Clone
git clone https://github.com/subhankarbhndr211/SecOS.git
cd SecOS

# 2. Configure
cp .env.example .env
nano .env  # Add GROQ_API_KEY (free at console.groq.com)

# 3. Start
sudo bash start.sh
```

- Dashboard → `http://localhost:8080`
- API → `http://localhost:8000/api/health`

**Default credentials** *(change in production)*:
```
admin   / Admin1234
analyst / Analyst123
soc     / SOCteam123
```

---

## Connect an Endpoint

### Linux — one line
```bash
curl -s http://YOUR_SECOS_IP:8000/install.sh | sudo bash -s -- --server YOUR_SECOS_IP
```

### Windows — PowerShell as Administrator
```powershell
Invoke-WebRequest http://YOUR_SECOS_IP:8000/install-agent-windows.ps1 -OutFile install.ps1
.\install.ps1 -Server YOUR_SECOS_IP
```

### Remote machine (different network)
```bash
# On SecOS server — expose via ngrok
ngrok http 8000
# → https://abc123.ngrok-free.app

# On remote endpoint
curl -s https://abc123.ngrok-free.app/install.sh | sudo bash -s -- --server https://abc123.ngrok-free.app
```

📖 Full integration guide → [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md)

---

## Detection Agents

| Agent | Function | Key Detections | Status |
|-------|----------|---------------|--------|
| **SIEM** | Log correlation | SSH brute force, privilege escalation, account changes | ✅ Live |
| **EDR** | Endpoint detection | Malicious processes, FIM, network anomalies | ✅ Live |
| **NDR** | Network detection | C2 beaconing, port scans, malicious IPs | ✅ Live |
| **IAM** | Identity monitoring | Account creation, privilege changes, lockouts | ✅ Live |
| **UEBA** | Behavioral analytics | Off-hours activity, lateral movement, velocity spikes | ✅ Live |
| **SOAR** | Response orchestration | 6 playbooks, suggest/auto mode | ✅ Live |
| **AEGIS** | AI triage engine | LLM-powered P1–P4 prioritization | ✅ Live |
| **TIP** | Threat intelligence | IOC management, indicator enrichment | ✅ Live |

---

## AEGIS AI Triage

Every HIGH/CRITICAL alert is analyzed by `llama-3.3-70b-versatile`:

```json
{
  "decision": "ESCALATE",
  "priority": "P1",
  "confidence": 0.94,
  "attack_stage": "Credential Access",
  "mitre_technique": "T1110.001",
  "recommended_actions": [
    "Block source IP immediately",
    "Reset compromised account credentials",
    "Review auth logs for successful logins from same IP"
  ]
}
```

Rule-based fallback activates automatically when API is unavailable.

---

## Roadmap

> **Full autonomous SOC vision — estimated ~2 years to complete all phases.**
> This is an honest, long-term commitment to building something genuinely useful for the security community.

### ✅ Phase 1 — Foundation (Complete · v6.0 · March 2026)
- [x] Core ingestion pipeline (FastAPI + PostgreSQL + Redis pub/sub)
- [x] 8 autonomous detection agents running continuously
- [x] AEGIS AI triage engine (Groq LLaMA 3.3-70b-versatile)
- [x] Windows PowerShell endpoint agent
- [x] Linux Python endpoint agent
- [x] One-line installers for both platforms
- [x] 16-module React 18 dashboard with WebSocket live streaming
- [x] MITRE ATT&CK mapping across 11 tactics
- [x] Role-based access control
- [x] SOAR suggest mode with 6 playbooks
- [x] ngrok remote endpoint support
- [x] GitHub CI pipeline with secret scanning

### 🔨 Phase 2 — Hardening & Integration (Q2–Q3 2026)
- [ ] Docker Compose single-command deployment
- [ ] TLS/HTTPS for dashboard and API (Let's Encrypt)
- [ ] JWT-based API authentication
- [ ] TheHive integration (case management)
- [ ] MISP integration (threat intelligence feeds)
- [ ] Cortex integration (automated alert enrichment)
- [ ] Alert deduplication and suppression engine
- [ ] Agent heartbeat monitoring (offline alerts)
- [ ] Structured JSON logging with ELK/Grafana support
- [ ] Sigma rule import and execution
- [ ] YARA rule scanning on endpoints

### 🔮 Phase 3 — Autonomous Intelligence (Q4 2026 – Q1 2027)
- [ ] AEGIS agentic investigation chains (multi-step autonomous analysis)
- [ ] SOAR auto-mode (fully automated containment and response)
- [ ] Threat hunting query engine
- [ ] Attack simulation framework (validate detection coverage)
- [ ] Custom correlation rules builder (no-code UI)
- [ ] Forensics timeline reconstruction
- [ ] Automated IOC extraction and threat actor profiling
- [ ] ML-based anomaly detection (self-learning baselines)
- [ ] False positive feedback loop (AEGIS learns from analyst decisions)

### 🚀 Phase 4 — Enterprise Scale (Q2–Q4 2027)
- [ ] Multi-tenant MSSP support
- [ ] Cloud workload monitoring (AWS CloudTrail, Azure Sentinel, GCP)
- [ ] Kubernetes / container workload agents
- [ ] Active Directory / LDAP / SSO integration
- [ ] SLA tracking and management reporting
- [ ] Compliance reporting (ISO 27001, SOC 2, NIST CSF)
- [ ] Full REST API for external integrations
- [ ] High availability / clustered deployment
- [ ] Mobile dashboard (React Native)
- [ ] Marketplace for community detection packs

---

## Project Structure

```
SecOS/
├── agents/
│   ├── api.py                          # FastAPI gateway + WebSocket
│   ├── agent_siem.py                   # Log correlation
│   ├── agent_edr.py                    # Endpoint detection
│   ├── agent_ndr.py                    # Network detection
│   ├── agent_iam.py                    # Identity monitoring
│   ├── agent_ueba.py                   # Behavioral analytics
│   ├── agent_soar.py                   # Response orchestration
│   ├── agent_aegis.py                  # AI triage engine
│   ├── agent_tip.py                    # Threat intelligence
│   └── windows/
│       ├── SecOS-Agent.ps1             # Windows endpoint agent
│       └── install-agent-windows.ps1  # Windows installer
├── frontend/
│   └── index.html                      # React 18 dashboard
├── docs/
│   ├── AGENT-INTEGRATION.md            # Endpoint integration guide
│   └── SecOS-v6-Documentation.docx    # Full technical docs
├── .github/
│   ├── workflows/ci.yml               # GitHub Actions CI
│   └── ISSUE_TEMPLATE/
├── install-agent-linux.sh             # Linux one-line installer
├── start.sh                           # Full stack startup
├── .env.example                       # Environment template
├── CONTRIBUTING.md
├── SECURITY.md
└── CHANGELOG.md
```

---

## Author

**Subhankar Bhandari**
SOC Analyst · Security Engineer · Builder

8 years in IT · 4+ years in SOC operations

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%204%25-FF6B00?style=flat-square)](https://tryhackme.com)
[![ISC2](https://img.shields.io/badge/ISC2-CC%20Certified-00A3FF?style=flat-square)](https://isc2.org)
[![ArcSight](https://img.shields.io/badge/ArcSight-Expert-00D4FF?style=flat-square)](https://microfocus.com)

---

## Contributing

All contributions welcome — detection rules, new agents, bug fixes, documentation improvements.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

*"Enterprise security without the enterprise budget."*

**SecOS — Built by a SOC analyst. For SOC analysts.**

*Early phase · Active development · ~2 years to full vision*

⭐ Star this repo if you find it useful — it helps more people discover it.

</div>
