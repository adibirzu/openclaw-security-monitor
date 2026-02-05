# OpenClaw Security Monitor

Proactive security monitoring, threat scanning, and real-time visibility for [OpenClaw](https://github.com/openclawai/openclaw) deployments. Detects threats from the **ClawHavoc** campaign, **AMOS stealer**, supply chain attacks, memory poisoning, and CVE-2026-25253 (1-Click RCE).

## Why This Exists

In late January 2026, security researchers found that **12% of all ClawHub skills were malicious** — 341 out of 2,857 skills across multiple campaigns. The primary campaign, ClawHavoc, delivered the Atomic Stealer (AMOS) macOS infostealer targeting crypto wallets, SSH credentials, and browser passwords.

Meanwhile, CVE-2026-25253 demonstrated that a single malicious link could achieve full remote code execution on any OpenClaw instance through WebSocket hijacking — even those bound to localhost.

This project provides defense-in-depth monitoring for self-hosted OpenClaw installations.

## Features

- **16-point security scan** covering C2 infrastructure, stealers, reverse shells, credential exfiltration, memory poisoning, SKILL.md injection, WebSocket hijacking, and more
- **IOC database** with known C2 IPs, malicious domains, file hashes, publisher blacklists, and skill name patterns
- **Auto-updating IOC feeds** that pull latest threat intelligence from upstream
- **Web dashboard** (dark-themed, zero dependencies) with real-time status, process trees, network monitoring, and scan history
- **Daily automated scans** with Telegram alerting
- **Process ancestry tracking** via [witr](https://github.com/pranshuparmar/witr) integration

## Quick Start

```bash
# Clone
git clone https://github.com/adibirzu/openclaw-security-monitor.git
cd openclaw-security-monitor

# Make scripts executable
chmod +x scripts/*.sh

# Run a scan
./scripts/scan.sh

# Start the web dashboard
node dashboard/server.js
# Open http://localhost:18800

# Update IOC database
./scripts/update-ioc.sh

# Install daily cron (06:00 UTC)
crontab -l | { cat; echo "0 6 * * * $(pwd)/scripts/daily-scan-cron.sh"; } | crontab -
```

## Architecture

```
openclaw-security-monitor/
  scripts/
    scan.sh              # 16-point threat scanner (v2.0)
    dashboard.sh         # CLI security dashboard with witr
    network-check.sh     # Network activity monitor
    daily-scan-cron.sh   # Cron wrapper + Telegram alerts
    telegram-setup.sh    # Telegram notification setup
    update-ioc.sh        # IOC database updater
  ioc/
    c2-ips.txt           # Known C2 IP addresses
    malicious-domains.txt # Payload/exfil domains
    file-hashes.txt      # Known malicious file hashes
    malicious-publishers.txt  # Blacklisted ClawHub accounts
    malicious-skill-patterns.txt  # Malicious skill naming patterns
  dashboard/
    server.js            # Node.js HTTP server (zero npm deps)
    index.html           # Single-file dark-themed SPA
  docs/
    threat-model.md      # Threat model and attack vectors
```

## Scan Checks (16)

| # | Check | Severity | Detects |
|---|-------|----------|---------|
| 1 | C2 Infrastructure | CRITICAL | Known C2 IPs (91.92.242.x, etc.) in skill code |
| 2 | AMOS Stealer | CRITICAL | AuthTool, Atomic Stealer, osascript credential theft |
| 3 | Reverse Shells | CRITICAL | bash/python/perl/ruby/php/lua reverse shells |
| 4 | Credential Exfiltration | CRITICAL | webhook.site, pipedream, ngrok, burpcollaborator |
| 5 | Crypto Wallet Targeting | WARNING | Seed phrases, private keys, exchange API keys |
| 6 | Curl-Pipe Attacks | WARNING | `curl\|sh`, `wget\|bash`, remote script execution |
| 7 | File Permissions | WARNING | Config files with permissions > 600 |
| 8 | Skill Integrity | WARNING | SKILL.md hash changes since last scan |
| 9 | SKILL.md Injection | WARNING | Shell commands in Prerequisites/install sections |
| 10 | Memory Poisoning | CRITICAL | Prompt injection in SOUL.md, MEMORY.md, IDENTITY.md |
| 11 | Base64 Obfuscation | WARNING | Encoded payloads (glot.io-style delivery) |
| 12 | Binary Downloads | WARNING | .exe, .dmg, .pkg references, password-protected ZIPs |
| 13 | Gateway Config | CRITICAL | Auth disabled, LAN exposure, version check |
| 14 | WebSocket Security | CRITICAL | CVE-2026-25253 origin validation bypass |
| 15 | Malicious Publishers | CRITICAL | Skills from known-bad ClawHub accounts |
| 16 | Environment Leakage | WARNING | Skills reading .env, .ssh, .aws, keychain files |

## IOC Database

### C2 IP Addresses
| IP | Campaign | Notes |
|----|----------|-------|
| `91.92.242.30` | ClawHavoc | Primary AMOS C2, used by 335 skills |
| `95.92.242.30` | ClawHavoc | Secondary C2 |
| `96.92.242.30` | ClawHavoc | Secondary C2 |
| `54.91.154.110` | ClawHavoc | Reverse shell endpoint (port 13338) |
| `202.161.50.59` | ClawHavoc | Payload staging |

### Malicious Domains
| Domain | Type | Notes |
|--------|------|-------|
| `install.app-distribution.net` | Payload | AMOS installer distribution |
| `glot.io` | Hosting | Base64-obfuscated shell scripts (legitimate service abused) |
| `webhook.site` | Exfiltration | Data exfil via webhooks |
| `pipedream.net` | Exfiltration | Data exfil |
| `ngrok.io` | Tunneling | Reverse tunnel for exfiltration |
| `github.com/hedefbari` | Payload | Attacker GitHub hosting openclaw-agent.zip |

### Known File Hashes (SHA-256)
| Hash | File | Platform |
|------|------|----------|
| `17703b3d...42283` | openclaw-agent.exe | Windows |
| `1e6d4b05...e2298` | x5ki60w1ih838sp7 | macOS (AMOS) |
| `0e52566c...4dd65` | unknown | macOS (AMOS variant) |
| `79e8f3f7...2bc1f2` | skill-archive | Any |

### Malicious Publisher Blacklist
| Publisher | Skills | Campaign |
|-----------|--------|----------|
| `hightower6eu` | 314 | ClawHavoc (crypto, finance, social lures) |

### Skill Name Patterns
Malicious skills mimic popular categories:
- **Typosquats** (28): `clawhub`, `clawhubb`, `clawwhub`, `cllawhub`, `clawhubcli`
- **Crypto** (111): `solana-wallet-*`, `phantom-wallet-*`, `bybit-agent`, `eth-gas-*`
- **Prediction markets** (34): `polymarket-*`, `better-polymarket`
- **YouTube** (57): `youtube-summarize-*`, `youtube-*-pro`
- **Auto-updaters** (28): `auto-updat*`
- **Finance** (51): `yahoo-finance`, `stock-track*`
- **Google Workspace** (17): `google-workspace-*`, `gmail-*`, `gdrive-*`

## IOC Auto-Updater

The `update-ioc.sh` script:
1. Checks upstream GitHub repo for IOC database updates
2. Scans active network connections against known C2 IPs
3. Validates installed skills against malicious publisher and pattern databases
4. Computes file hashes and checks against known malicious hashes

```bash
# Check for updates without applying
./scripts/update-ioc.sh --check-only

# Download and apply updates
./scripts/update-ioc.sh
```

## Web Dashboard

Zero-dependency Node.js server on port 18800 with:
- Scan summary donut chart
- 16 color-coded security check cards
- Gateway status and configuration audit
- Process tree via `witr` showing ancestry chains
- Network connections and listening ports
- File permissions and provider auth status
- Scan history timeline (last 30 scans)
- Auto-refresh every 30s + on-demand scan button

### API Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/api/scan` | GET | Last cached scan result |
| `/api/scan/run` | POST | Run scan on-demand |
| `/api/dashboard` | GET | CLI dashboard data |
| `/api/network` | GET | Network connections |
| `/api/process-tree` | GET | Process ancestry via witr |
| `/api/logs/scan` | GET | Scan log history |
| `/api/logs/cron` | GET | Cron log entries |
| `/api/status` | GET | Server uptime + gateway health |

### LaunchAgent (macOS)

The plist template in `docs/` uses `__HOME__` placeholders. Install with:

```bash
# Generate plist with your home directory and install
sed "s|__HOME__|$HOME|g" docs/com.openclaw.security-dashboard.plist \
  > ~/Library/LaunchAgents/com.openclaw.security-dashboard.plist

# Load the service
launchctl load ~/Library/LaunchAgents/com.openclaw.security-dashboard.plist

# Verify
curl -s http://localhost:18800/api/status | python3 -m json.tool
```

## CVE Coverage

| CVE | Description | Check |
|-----|-------------|-------|
| CVE-2026-25253 | 1-Click RCE via WebSocket hijacking | #14: WebSocket origin validation |
| CVE-2026-24763 | Command injection | #3: Reverse shell patterns |
| CVE-2026-25157 | Command injection | #6: Curl-pipe attacks |

## Threat Intelligence Sources

This project's detection patterns are built from published security research:

| Source | Report | What We Use |
|--------|--------|-------------|
| [Koi Security](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) | ClawHavoc: 341 Malicious Skills | C2 IPs, malicious publishers, skill patterns, AMOS indicators |
| [The Hacker News](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) | 341 Malicious ClawHub Skills | Campaign timeline, attack methodology |
| [VirusTotal](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html) | From Automation to Infection | File hashes, publisher identification, payload analysis |
| [Snyk](https://snyk.io/articles/skill-md-shell-access/) | From SKILL.md to Shell Access | SKILL.md injection patterns, memory poisoning techniques |
| [The Register](https://www.theregister.com/2026/02/02/openclaw_security_issues) | OpenClaw Security Issues | CVE details, ecosystem analysis |
| [SecurityWeek](https://www.securityweek.com/vulnerability-allows-hackers-to-hijack-openclaw-ai-assistant/) | Hijack OpenClaw AI Assistant | WebSocket hijacking details |
| [Cisco Blogs](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) | Personal AI Agents Security | Lethal trifecta analysis |
| [Tenable](https://www.tenable.com/blog/agentic-ai-security-how-to-mitigate-clawdbot-moltbot-openclaw-vulnerabilities) | Mitigate OpenClaw Vulnerabilities | Hardening recommendations |
| [1Password](https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface) | From Magic to Malware | Skill attack surface analysis |
| [SOCRadar](https://socradar.io/blog/cve-2026-25253-rce-openclaw-auth-token/) | CVE-2026-25253 Analysis | Exploit chain technical details |
| [SOCPrime](https://socprime.com/active-threats/openclaw-ai-agent-weaponized/) | OpenClaw Weaponized | Detection and response patterns |
| [CyberInsider](https://cyberinsider.com/341-openclaw-skills-distribute-macos-malware-via-clickfix-instructions/) | ClickFix Malware Distribution | macOS-specific attack vectors |
| [eSecurity Planet](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/) | Malicious Skills in ClawHub | Registry security analysis |
| [PointGuard AI](https://www.pointguardai.com/ai-security-incidents/openclaw-clawhub-malicious-skills-supply-chain-attack) | Supply Chain Attack Analysis | Attack timeline, scope |
| [SC Media](https://www.scworld.com/news/openclaw-agents-targeted-with-341-malicious-clawhub-skills) | 341 Malicious Skills | Technical indicators |
| [DepthFirst](https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys) | 1-Click RCE Exploit | CVE-2026-25253 original PoC research |

## Requirements

- macOS or Linux
- bash 4+
- Node.js 18+ (for web dashboard only)
- `curl` (for IOC updates and WebSocket check)
- Optional: [`witr`](https://github.com/pranshuparmar/witr) for process tree analysis
- Optional: `openclaw` for gateway configuration audit

### Install Prerequisites (macOS)

```bash
# Node.js (required for web dashboard)
brew install node@22

# witr - process ancestry tracer (optional but recommended)
brew install witr

# Verify
node --version   # v22.x
witr --version   # should print version
```

### Install Prerequisites (Linux)

```bash
# Node.js (via NodeSource or your package manager)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash -
sudo apt-get install -y nodejs

# witr (check https://github.com/pranshuparmar/witr for Linux install)
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENCLAW_HOME` | No | OpenClaw home directory (default: `~/.openclaw`) |
| `OPENCLAW_TELEGRAM_TOKEN` | For alerts | Telegram bot token for scan notifications |
| `DASHBOARD_HOST` | No | Dashboard bind address (default: `127.0.0.1`, use `0.0.0.0` for LAN access) |

## Contributing

IOC updates are welcome. To add new indicators:

1. Fork the repo
2. Add entries to the appropriate `ioc/*.txt` file following the existing format
3. Submit a PR with the source reference

## License

MIT
