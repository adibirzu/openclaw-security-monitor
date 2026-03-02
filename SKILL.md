---
name: openclaw-security-monitor
description: Proactive security monitoring, threat scanning, and auto-remediation for OpenClaw deployments
tags: [security, scan, remediation, monitoring, threat-detection, hardening]
version: 3.4.0
author: Adrian Birzu
user-invocable: true
---
<!-- {"requires":{"bins":["bash","curl","node","lsof"],"optionalBins":["witr","docker","openclaw"],"env":{"OPENCLAW_TELEGRAM_TOKEN":"Optional: Telegram bot token for daily security alerts","OPENCLAW_HOME":"Optional: Override default ~/.openclaw directory"}}} -->

# Security Monitor

Real-time security monitoring with threat intelligence from ClawHavoc research, daily automated scans, web dashboard, and Telegram alerting for OpenClaw.

## Commands
Note: Replace `<skill-dir>` with the actual folder name where this skill is installed (commonly `openclaw-security-monitor` or `security-monitor`).

### /security-scan
Run a comprehensive 40-point security scan:
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
17. DM policy audit (open/wildcard channel access)
18. Tool policy / elevated tools audit
19. Sandbox configuration check
20. mDNS/Bonjour exposure detection
21. Session & credential file permissions
22. Persistence mechanism scan (LaunchAgents, crontabs, systemd)
23. Plugin/extension security audit
24. Log redaction settings audit
25. Reverse proxy localhost trust bypass detection
26. Exec-approvals configuration audit (CVE-2026-25253 exploit chain)
27. Docker container security (root, socket mount, privileged mode)
28. Node.js version / CVE-2026-21636 permission model bypass
29. Plaintext credential detection in config files
30. VS Code extension trojan detection (fake ClawdBot extensions)
31. Internet exposure detection (non-loopback gateway binding)
32. MCP server security audit (tool poisoning, prompt injection)
33. ClawJacked WebSocket brute-force protection (v2026.2.25+)
34. SSRF protection audit (CVE-2026-26322, CVE-2026-27488)
35. Exec safeBins validation bypass (CVE-2026-28363, CVSS 9.9)
36. ACP permission auto-approval audit (GHSA-7jx5)
37. PATH hijacking / command hijacking (GHSA-jqpq-mgvm-f9r6)
38. Skill env override host injection (GHSA-82g8-464f-2mv7)
39. macOS deep link truncation (CVE-2026-26320)
40. Log poisoning / WebSocket header injection

```bash
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/scan.sh
```

Exit codes: 0=SECURE, 1=WARNINGS, 2=COMPROMISED

### /security-dashboard
Display a security overview with process trees via witr.

```bash
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/dashboard.sh
```

### /security-network
Monitor network connections and check against IOC database.

```bash
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/network-check.sh
```

### /security-remediate
Scan-driven remediation: runs `scan.sh`, skips CLEAN checks, and executes per-check remediation scripts for each WARNING/CRITICAL finding. Includes 40 individual scripts covering file permissions, exfiltration domain blocking, tool deny lists, gateway hardening, sandbox configuration, credential auditing, ClawJacked protection, SSRF hardening, PATH hijacking cleanup, log poisoning remediation, and more.

```bash
# Full scan + remediate (interactive)
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/remediate.sh

# Auto-approve all fixes
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/remediate.sh --yes

# Dry run (preview)
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/remediate.sh --dry-run

# Remediate a single check
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/remediate.sh --check 7 --dry-run

# Run all 40 remediation scripts (skip scan)
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/remediate.sh --all
```

Flags:
- `--yes` / `-y` — Skip confirmation prompts (auto-approve all fixes)
- `--dry-run` — Show what would be fixed without making changes
- `--check N` — Run remediation for check N only (skip scan)
- `--all` — Run all 40 remediation scripts without scanning first

Exit codes: 0=fixes applied, 1=some fixes failed, 2=nothing to fix

### /security-setup-telegram
Register a Telegram chat for daily security alerts.

```bash
bash ~/.openclaw/workspace/skills/<skill-dir>/scripts/telegram-setup.sh [chat_id]
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
crontab -l | { cat; echo "0 6 * * * $HOME/.openclaw/workspace/skills/<skill-dir>/scripts/daily-scan-cron.sh"; } | crontab -
```

## Threat Coverage

Based on research from 40+ security sources including:
- [ClawHavoc: 341 Malicious Skills](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) (Koi Security)
- [CVE-2026-25253: 1-Click RCE](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)
- [From SKILL.md to Shell Access](https://snyk.io/articles/skill-md-shell-access/) (Snyk)
- [VirusTotal: From Automation to Infection](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html)
- [OpenClaw Official Security Docs](https://docs.openclaw.ai/gateway/security)
- [DefectDojo Hardening Checklist](https://defectdojo.com/blog/the-openclaw-hardening-checklist-in-depth-edition)
- [Vectra: Automation as Backdoor](https://www.vectra.ai/blog/clawdbot-to-moltbot-to-openclaw-when-automation-becomes-a-digital-backdoor)
- [Cisco: AI Agents Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare)
- [Bloom Security/JFrog: 37 Malicious Skills](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)
- [OpenSourceMalware: Skills Ganked Your Crypto](https://opensourcemalware.com/blog/clawdbot-skills-ganked-your-crypto)
- [Snyk: clawdhub Campaign Deep-Dive](https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CrowdStrike: OpenClaw AI Super Agent](https://www.crowdstrike.com/en-us/blog/what-security-teams-need-to-know-about-openclaw-ai-super-agent/)
- [Argus Security Audit (512 findings)](https://github.com/openclaw/openclaw/issues/1796)
- [ToxSec: OpenClaw Security Checklist](https://www.toxsec.com/p/openclaw-security-checklist)
- [Aikido.dev: Fake ClawdBot VS Code Extension](https://www.aikido.dev/blog/fake-clawdbot-vscode-extension-malware)
- [Prompt Security: Top 10 MCP Risks](https://prompt.security/blog/top-10-mcp-security-risks)
- [Oasis Security: ClawJacked](https://www.oasis.security/blog/openclaw-vulnerability) (Feb 26)
- [CVE-2026-28363: safeBins Bypass (CVSS 9.9)](https://advisories.gitlab.com/pkg/npm/openclaw/CVE-2026-28363/)
- [Flare: Widespread Exploitation](https://flare.io/learn/resources/blog/widespread-openclaw-exploitation) (Feb 25)

## Security & Transparency

**Why the scanner flags itself**: The ClawHub review scanner may report a `[ignore-previous-instructions]` finding for this skill. This is a **false positive** — the strings "ignore previous", "override instruction", etc. exist only within our **detection patterns** (grep regexes in scan.sh and remediation scripts). These patterns are how we *detect* prompt injection in other skills; they are not instructions to the agent.

**Environment variables**: This skill optionally uses `OPENCLAW_TELEGRAM_TOKEN` for daily scan alerts and `OPENCLAW_HOME` to override the default `~/.openclaw` directory. These are declared in the metadata above.

**Required binaries**: `bash`, `curl`, `node` (for dashboard), `lsof` (for network checks). Optional: `witr` (process trees), `docker` (container audits), `openclaw` CLI (config checks).

**What the scanner reads**: The scan inspects files within `~/.openclaw/` (configs, skills, credentials, logs) to detect threats. It reads `.env`, `.ssh`, and keychain paths only as **detection patterns** — it never exfiltrates or transmits this data.

**What remediation does**: Remediation scripts can modify file permissions, block domains in `/etc/hosts`, adjust OpenClaw config, and remove malicious skills. Always run `--dry-run` first to preview changes. The `--yes` flag auto-approves all fixes — use only after reviewing dry-run output.

**Persistence**: The daily cron job and LaunchAgent (dashboard) are both **optional** and manually installed by the user. The skill does not auto-install persistence.

**IOC updates**: `update-ioc.sh` fetches threat intelligence from this project's GitHub repository. Pin the upstream URL if you want to control the source.

**Dashboard binding**: The web dashboard defaults to `127.0.0.1:18800` (localhost only). Set `DASHBOARD_HOST=127.0.0.1` explicitly if concerned about LAN exposure.

## Installation

```bash
# From GitHub
git clone https://github.com/adibirzu/openclaw-security-monitor.git \
  ~/.openclaw/workspace/skills/<skill-dir>
chmod +x ~/.openclaw/workspace/skills/<skill-dir>/scripts/*.sh
```

The OpenClaw agent auto-discovers skills from `~/.openclaw/workspace/skills/` via SKILL.md frontmatter. After cloning, the `/security-scan`, `/security-remediate`, `/security-dashboard`, `/security-network`, and `/security-setup-telegram` commands will be available in the agent.
