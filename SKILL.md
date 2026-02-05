---
name: security-monitor
description: Proactive security monitoring, threat scanning, and alerting for OpenClaw deployments
user-invocable: true
---

# Security Monitor

Real-time security monitoring with threat intelligence from ClawHavoc research, daily automated scans, web dashboard, and Telegram alerting for OpenClaw.

## Commands

### /security-scan
Run a comprehensive 16-point security scan:
1. Known C2 IPs (ClawHavoc: 91.92.242.x, 95.92.242.x, 54.91.154.110)
2. AMOS stealer / AuthTool markers
3. Reverse shells & backdoors (bash, python, perl, ruby, php, lua)
4. Credential exfiltration endpoints (webhook.site, pipedream, ngrok, etc.)
5. Crypto wallet targeting (seed phrases, private keys, exchange APIs)
6. Curl-pipe / download attacks
7. Sensitive file permission audit
8. Skill integrity hash verification
9. SKILL.md shell injection patterns (Prerequisites-based attacks)
10. Memory poisoning detection (SOUL.md, MEMORY.md, IDENTITY.md)
11. Base64 obfuscation detection (glot.io-style payloads)
12. External binary downloads (.exe, .dmg, .pkg, password-protected ZIPs)
13. Gateway security configuration audit
14. WebSocket origin validation (CVE-2026-25253)
15. Known malicious publisher detection (hightower6eu, etc.)
16. Sensitive environment/credential file leakage

```bash
bash ~/.openclaw/workspace/skills/security-monitor/scripts/scan.sh
```

Exit codes: 0=SECURE, 1=WARNINGS, 2=COMPROMISED

### /security-dashboard
Display a security overview with process trees via witr.

```bash
bash ~/.openclaw/workspace/skills/security-monitor/scripts/dashboard.sh
```

### /security-network
Monitor network connections and check against IOC database.

```bash
bash ~/.openclaw/workspace/skills/security-monitor/scripts/network-check.sh
```

### /security-setup-telegram
Register a Telegram chat for daily security alerts.

```bash
bash ~/.openclaw/workspace/skills/security-monitor/scripts/telegram-setup.sh [chat_id]
```

## Web Dashboard

**URL**: `http://<vm-ip>:18800`

Dark-themed browser dashboard with auto-refresh, on-demand scanning, donut charts, process tree visualization, network monitoring, and scan history timeline.

### Service Management
```bash
launchctl list | grep security-dashboard
launchctl unload ~/Library/LaunchAgents/com.openclaw.security-dashboard.plist
launchctl load ~/Library/LaunchAgents/com.openclaw.security-dashboard.plist
```

## IOC Database

Threat intelligence files in `ioc/`:
- `c2-ips.txt` - Known command & control IP addresses
- `malicious-domains.txt` - Payload hosting and exfiltration domains
- `file-hashes.txt` - Known malicious file SHA-256 hashes
- `malicious-publishers.txt` - Known malicious ClawHub publishers
- `malicious-skill-patterns.txt` - Malicious skill naming patterns

## Daily Automated Scan

Cron job at 06:00 UTC with Telegram alerts. Install:
```bash
crontab -l | { cat; echo "0 6 * * * $HOME/.openclaw/workspace/skills/security-monitor/scripts/daily-scan-cron.sh"; } | crontab -
```

## Threat Coverage

Based on research from:
- [ClawHavoc: 341 Malicious Skills](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) (Koi Security)
- [CVE-2026-25253: 1-Click RCE](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)
- [From SKILL.md to Shell Access](https://snyk.io/articles/skill-md-shell-access/) (Snyk)
- [VirusTotal: From Automation to Infection](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html)
