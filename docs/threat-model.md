# OpenClaw Threat Model

**Last Updated**: 2026-02-18
**Version**: 2.0

## Attack Surface

OpenClaw AI agents have three critical properties that create what security researchers call the "lethal trifecta":

1. **Access to private data** — file system, credentials, configs, environment variables
2. **Exposure to untrusted content** — skills from ClawHub, external data, prompt injection
3. **Ability to communicate externally** — network access, shell execution, API calls

Combined with persistent memory (SOUL.md, MEMORY.md), these create compounding risk.

## Threat Landscape (Feb 2026)

- **135,000+ exposed instances** across 82 countries (SecurityScorecard STRIKE, Feb 9)
- **12,812 exploitable via RCE** from CVE-2026-25253
- **1,800 instances** leaking API keys and credentials
- **824+ confirmed malicious skills** in ClawHavoc (up from 341)
- **1,184 malicious packages** across 12 publisher accounts (Antiy CERT)
- **36% of all ClawHub skills** contain security flaws (Snyk ToxicSkills, 3,984 scanned)
- Major firms issued advisories: CrowdStrike, Bitdefender, Palo Alto, Cisco, Kaspersky, Trend Micro
- Meta banned OpenClaw from corporate devices

## Attack Vectors

### 1. Supply Chain (ClawHub Skills)
- **ClawHavoc campaign**: 824+ malicious skills (expanded from 341), now with 12 publisher accounts
- **Technique**: Social engineering via professional-looking SKILL.md
- **Payload**: AMOS stealer via Prerequisites section
- **Target**: macOS (osascript/glot.io) and Windows (openclaw-agent.exe)
- **New categories (Feb 2026)**: browser automation agents, coding agents, PDF tools, fake security scanners

### 2. WebSocket Hijacking (CVE-2026-25253)
- **Technique**: Cross-Site WebSocket Hijacking (CSWSH)
- **Vector**: Malicious link → gatewayUrl parameter → token exfiltration
- **Impact**: Full RCE even on localhost-bound instances
- **Kill chain**: Token steal → sandbox escape → arbitrary code execution

### 3. Memory Poisoning (Expanded)
- **Technique**: Skill modifies SOUL.md/MEMORY.md to alter future behavior
- **Impact**: Persistent backdoor across all future sessions
- **New finding**: Payloads fragmented across sessions, injected on one day, detonated when agent state aligns later
- **Detection**: Hash monitoring, content analysis for injection patterns

### 4. SKILL.md Shell Injection
- **Technique**: Embed shell commands in markdown that agents execute
- **Snyk finding**: Three lines of Markdown in SKILL.md can achieve full shell access
- **ClickFix variant**: Professional documentation tricks users into executing malicious commands in "Prerequisites" sections
- **Impact**: Arbitrary code execution with agent's permissions

### 5. Credential Harvesting
- **Technique**: Skills read .env, .ssh, .aws, keychain files
- **Exfiltration**: webhook.site, pipedream, ngrok tunnels
- **Target**: API keys, SSH keys, browser passwords, crypto wallets

### 6. Typosquatting
- **Technique**: Register skill names similar to popular tools
- **Examples**: clawhub → clawhubb, cllawhub, clawhubcli
- **Scale**: 28 typosquat variants in ClawHavoc alone

### 7. Log Poisoning (NEW - Feb 2026, Eye Security)
- **Technique**: WebSocket request headers (Origin, User-Agent) logged without sanitization
- **Vector**: Attacker injects crafted headers → poisoned logs → agent reads logs during troubleshooting
- **Impact**: Indirect prompt injection / time-shifted logic bomb
- **Patched in**: v2026.2.13

### 8. Infostealer Targeting Agent Identity (NEW - Feb 13, Hudson Rock)
- **Technique**: Vidar infostealer variant specifically harvests OpenClaw directories
- **Stolen files**: openclaw.json (gateway tokens, email), device.json (key pairs), soul.md, agents.md, memory.md
- **Impact**: First documented case of infostealers harvesting AI agent "souls and identities"
- **Significance**: Not a custom module — Vidar's broad file-grabbing routines now target AI config paths

### 9. Path Traversal & File Disclosure (NEW - CVE-2026-26329, CVE-2026-25475)
- **CVE-2026-26329**: Browser upload path traversal via Playwright setInputFiles() reads arbitrary files
- **CVE-2026-25475**: Local File Inclusion via MEDIA: path extraction reads /etc/passwd, ~/.ssh/id_rsa
- **Patched in**: v2026.2.14

### 10. Exec Allowlist Bypass (NEW - GHSA-3hcm, GHSA-qj77)
- **Technique**: Command substitution/backticks inside double quotes bypass exec allowlist
- **Windows variant**: cmd.exe parsing bypass of exec allowlist/approval gating
- **Patched in**: v2026.2.2

### 11. MCP Tool Poisoning
- **Technique**: MCP servers configured with enableAllProjectMcpServers=true enable tool poisoning and rug-pull attacks
- **Vector**: Prompt injection embedded in tool descriptions
- **Impact**: Even "official" MCP setups are vulnerable

### 12. Webhook Auth Bypass (NEW - CVE-2026-25474, CVE-2026-26319)
- **CVE-2026-25474**: Telegram webhook spoofing when webhookSecret is missing
- **CVE-2026-26319**: Telnyx voice-call webhook missing authentication
- **GHSA-xc7w**: Webhook auth bypass when gateway is behind reverse proxy (loopback trust)

### 13. Channel Policy Bypass (NEW)
- **GHSA-v773**: Slack dmPolicy=open allows any DM sender to run privileged slash commands
- **GHSA-rmxw**: Matrix allowlist bypass via displayName and cross-homeserver localpart matching
- **GHSA-4rj2**: Voice-call inbound allowlist bypass via empty caller ID + suffix matching

### 14. macOS Deep Link Truncation (NEW - CVE-2026-26320)
- **Technique**: Attackers conceal malicious payloads past 240-character preview in confirmation dialog
- **Impact**: Users approve actions without seeing full payload
- **Patched in**: v2026.2.14

## CVE Summary (as of 2026-02-18)

| CVE | Description | Severity | Patched |
|-----|-------------|----------|---------|
| CVE-2026-25253 | WebSocket hijacking 1-click RCE | Critical | v2026.1.29 |
| CVE-2026-25475 | Local File Inclusion via MEDIA: path | 6.5 | v2026.1.30 |
| CVE-2026-25474 | Telegram webhook request forgery | Medium | v2026.2.1 |
| CVE-2026-26319 | Telnyx voice-call webhook missing auth | Medium | v2026.2.14 |
| CVE-2026-26320 | macOS deep link confirmation truncation | Medium | v2026.2.14 |
| CVE-2026-26321 | Feishu/Lark local file disclosure | 3.1 | v2026.2.14 |
| CVE-2026-26325 | Node host system.run exec bypass | High | v2026.2.14 |
| CVE-2026-26326 | skills.status leaks secrets to operators | 3.1 | v2026.2.14 |
| CVE-2026-26327 | mDNS/DNS-SD credential exfiltration on LAN | Medium | v2026.2.14 |
| CVE-2026-26329 | Browser upload path traversal | High | v2026.2.14 |
| CVE-2026-21636 | Node.js permission model bypass via UDS | Medium | Node 22.12+ |

## Detection Strategy

| Layer | What We Monitor | How |
|-------|----------------|-----|
| Static | Skill content analysis | grep patterns in SKILL.md and scripts |
| IOC | Known bad indicators | IP, domain, hash, publisher databases |
| Behavioral | Process ancestry | witr traces for unexpected parents |
| Network | Active connections | lsof + C2 IP matching |
| Integrity | File changes | SHA-256 hash baselines |
| Config | Gateway security | Auth mode, bind address, version |
| Memory | Persistence files | SOUL.md/MEMORY.md injection analysis |
| Logs | Log poisoning detection | Header sanitization, injection patterns |
| CVE | Version compliance | Minimum v2026.2.14 enforcement |

## Hardening Recommendations

1. **Update OpenClaw to v2026.2.14+** (minimum safe version; v2026.2.17 latest)
2. Set `gateway.auth.mode` to `token` (never `none`)
3. Bind gateway to `loopback` not `lan`
4. Set file permissions to 600 on configs
5. Configure `tools.deny` for dangerous commands
6. Run the security scan before installing new skills
7. Use `update-ioc.sh` to keep threat intelligence current
8. Monitor SOUL.md/MEMORY.md for unauthorized changes
9. **Set Telegram webhookSecret** to prevent webhook spoofing (CVE-2026-25474)
10. **Disable mDNS broadcasting** or restrict to "off" mode (CVE-2026-26327)
11. **Use Node.js 22.12+** to prevent UDS sandbox escape (CVE-2026-21636)
12. **Audit exec-approvals config** for safeBins bypass (GHSA-xvhf)
13. **Review channel DM policies** — avoid dmPolicy=open on any channel (GHSA-v773)
14. **Monitor for Vidar infostealer** targeting ~/.openclaw/ directories

## Sources

- [ClawHavoc: 341+ Malicious Skills](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) (Koi Security)
- [Snyk ToxicSkills: 36% Flawed](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) (Feb 5)
- [CVE-2026-25253: 1-Click RCE](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)
- [Hudson Rock: Vidar Targets Agent Identity](https://www.infostealers.com/article/hudson-rock-identifies-real-world-infostealer-infection-targeting-openclaw-configurations/) (Feb 13)
- [Eye Security: Log Poisoning](https://research.eye.security/log-poisoning-in-openclaw/) (Feb 2026)
- [CrowdStrike Advisory](https://www.crowdstrike.com/en-us/blog/what-security-teams-need-to-know-about-openclaw-ai-super-agent/)
- [Bitdefender Technical Advisory](https://businessinsights.bitdefender.com/technical-advisory-openclaw-exploitation-enterprise-networks)
- [SecurityScorecard STRIKE: 135K Instances](https://securityscorecard.com) (Feb 9)
- [Antiy CERT: 1,184 Packages](https://gbhackers.com/clawhavoc-infects-openclaws-clawhub/)
- [OpenClaw v2026.2.12 Emergency Patch](https://gbhackers.com/openclaw-2026-2-12-released/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Snyk: SKILL.md to Shell Access](https://snyk.io/articles/skill-md-shell-access/)
- [Adversa AI: SecureClaw](https://adversa.ai/blog/secureclaw-open-source-ai-agent-security-for-openclaw-aligned-with-owasp-mitre-frameworks/)
