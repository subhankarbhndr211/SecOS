# Changelog

All notable changes to SecOS are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com).

## [6.0.0] — 2026-03-09

### Added
- 8 autonomous detection agents: SIEM, EDR, NDR, IAM, UEBA, SOAR, AEGIS, TIP
- AEGIS AI triage engine powered by Groq llama-3.3-70b-versatile
- P1–P4 priority system with SLA targets (15min → 24hr)
- Windows PowerShell endpoint agent with Security Event Log monitoring
- Linux endpoint agent with SSH brute force and process detection
- Auto-install Linux agent via `/agent/linux` API endpoint
- 16-module React 18 dashboard with WebSocket live streaming
- Role-based access control: admin, analyst, soc_lead
- Full MITRE ATT&CK mapping across 11 tactics
- SOAR playbooks: SSH BF, C2, Lateral Movement, Cred Theft, Malware, UEBA
- ngrok tunnel support for remote agent connectivity
- PostgreSQL persistent storage with rolling alert display
- Redis pub/sub alert pipeline

### Fixed
- Alert ordering (newest first in dashboard)
- Windows agent HTTP hang on GetResponse()
- Redis port parse error on agents
- DB password special character breaking systemd env
- Frontend credential mismatch

### Security
- Hardcoded credentials removed from source
- .env excluded from git via .gitignore
- .env.example provided for safe configuration sharing
