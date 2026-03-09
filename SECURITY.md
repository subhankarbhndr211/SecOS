# Security Policy

## Supported Versions
| Version | Supported |
|---------|-----------|
| 6.x     | ✅ Active  |
| < 6.0   | ❌ EOL     |

## Reporting a Vulnerability
Please do NOT open public issues for security vulnerabilities.

Email: subhankarbhndr211@gmail.com
Subject: [SecOS Security] Brief description

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

Response time: within 48 hours.

## Security Best Practices for Deployment
- Always change default credentials before production use
- Generate a strong `SECOS_SECRET_KEY`
- Never expose port 8000 directly to the internet — use nginx + TLS
- Rotate API keys regularly
- Use ngrok or VPN for remote agent connectivity
