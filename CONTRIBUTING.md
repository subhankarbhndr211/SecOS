# Contributing to SecOS

## Ways to Contribute
- Bug reports via GitHub Issues
- New detection rules for agents
- New SOAR playbooks
- Dashboard module improvements
- Documentation improvements

## Development Setup
```bash
git clone https://github.com/subhankarbhndr211/SecOS.git
cd SecOS
cp .env.example .env
sudo bash start.sh
```

## Agent Development
Each agent lives in `agents/agent_*.py` and follows this pattern:
1. Subscribe to Redis `secos:alerts`
2. Analyze incoming events
3. Publish findings back to Redis or direct to API

## Pull Request Process
1. Fork the repo
2. Create feature branch: `git checkout -b feat/your-feature`
3. Commit with conventional commits: `feat:`, `fix:`, `docs:`
4. Push and open PR against `main`

## Detection Rule Format
```python
{
    "rule": "Rule Name",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "mitre_id": "T1234.001",
    "tactic": "Tactic Name",
    "score": 85
}
```
