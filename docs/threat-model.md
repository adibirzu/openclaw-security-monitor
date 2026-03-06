# OpenClaw Threat Model

**Last Updated**: 2026-03-06
**Version**: 3.5

## Attack Surface

OpenClaw AI agents have three critical properties that create what security researchers call the "lethal trifecta":

1. **Access to private data** — file system, credentials, configs, environment variables
2. **Exposure to untrusted content** — skills from ClawHub, external data, prompt injection
3. **Ability to communicate externally** — network access, shell execution, API calls

Combined with persistent memory (SOUL.md, MEMORY.md), these create compounding risk.

## Threat Landscape (Mar 2026)

- **135,000+ exposed instances** across 82 countries (SecurityScorecard STRIKE, Feb 9)
- **12,812 exploitable via RCE** from CVE-2026-25253
- **1,800 instances** leaking API keys and credentials
- **824+ confirmed malicious skills** in ClawHavoc (up from 341)
- **1,184 malicious packages** across 12 publisher accounts (Antiy CERT)
- **36% of all ClawHub skills** contain security flaws (Snyk ToxicSkills, 3,984 scanned)
- **ClawJacked** WebSocket brute-force attack discovered (Oasis Security, Feb 26)
- **CVE-2026-28363** critical safeBins bypass (CVSS 9.9) disclosed
- **CVE-2026-28446** voice-call RCE (CVSS 9.8) — 42,000 instances remotely exploitable
- **CVE-2026-28484** git pre-commit hook command injection (CVSS 9.3)
- **8+ new CVEs** disclosed in Mar 2026: browser relay CDP bypass, path traversal, shell expansion bypass, approval injection, webhook DoS, TAR traversal, fetchWithGuard DoS
- **10+ new GHSAs** in Mar 2026: SSRF guard bypass, avatar symlink traversal, cross-account pairing, Slack callback bypass, sandbox --no-sandbox, webhook replay, exec approval replay
- **Fake OpenClaw installers** promoted via Bing AI search poisoning — GhostSocks + Vidar via Stealth Packer (Huntress, Mar 4)
- **6 new vulnerabilities** disclosed by Endor Labs (SSRF, webhook bypass, auth bypass)
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

### 14. macOS Deep Link Truncation (CVE-2026-26320)
- **Technique**: Attackers conceal malicious payloads past 240-character preview in confirmation dialog
- **Impact**: Users approve actions without seeing full payload
- **Patched in**: v2026.2.14

### 15. ClawJacked - WebSocket Brute-Force Hijacking (NEW - Feb 26 2026, Oasis Security)
- **Technique**: Malicious website opens WebSocket to localhost, brute-forces gateway password (no rate limiting), auto-registers as trusted device
- **Vector**: Social engineering → victim visits attacker page → JS brute-forces localhost WebSocket → full agent takeover
- **Impact**: Read private Slack messages, steal API keys, exfiltrate files, command AI agent
- **Why it works**: Browser cross-origin policies do not block WebSocket connections to localhost
- **Patched in**: v2026.2.25 (full fix v2026.2.26)
- **Source**: [Oasis Security](https://www.oasis.security/blog/openclaw-vulnerability)

### 16. Server-Side Request Forgery (NEW - CVE-2026-26322, CVE-2026-27488)
- **CVE-2026-26322** (CVSS 7.6): Gateway tool accepts tool-supplied gatewayUrl without restrictions, enabling network reconnaissance, cloud metadata access, and internal service probing
- **CVE-2026-27488** (CVSS 6.9): Cron webhook delivery uses `fetch()` directly without SSRF policy checks, allowing webhook targets to reach private/metadata/internal endpoints
- **GHSA-56f2-hvwg-5743** (CVSS 7.6): Image tool SSRF
- **GHSA-pg2v-8xwh-qhcc** (CVSS 6.5): Urbit authentication SSRF
- **Patched in**: v2026.2.14 (gateway), v2026.2.19 (cron)

### 17. Exec safeBins Validation Bypass (NEW - CVE-2026-28363, CVSS 9.9)
- **Technique**: GNU long-option abbreviations (e.g., `--compress-prog` for `sort`) bypass the safeBins allowlist, enabling approval-free execution of unintended binaries
- **Impact**: Complete sandbox escape — attacker achieves arbitrary code execution via allowlisted tool
- **CWE**: CWE-184 (Incomplete List of Disallowed Inputs)
- **Patched in**: v2026.2.23

### 18. ACP Permission Auto-Approval Bypass (NEW - GHSA-7jx5-9fjg-hp4m, CVSS 8.2)
- **Technique**: ACP client auto-approves tool calls based on untrusted metadata and permissive name heuristics
- **Impact**: Malicious tool invocations bypass interactive approval prompts for read-class operations
- **CWE**: CWE-639 (Authorization Bypass), CWE-863 (Incorrect Authorization)
- **Patched in**: v2026.2.23

### 19. Command Hijacking via PATH (NEW - GHSA-jqpq-mgvm-f9r6)
- **Technique**: Unsafe PATH handling in bootstrapping and node-host PATH overrides allows resolving and executing unintended binaries
- **Scenarios**: (A) Node host PATH override with malicious executables, (B) project-local `node_modules/.bin/openclaw` bootstrapping
- **CWE**: CWE-78, CWE-427, CWE-807
- **Patched in**: v2026.2.14

### 20. Skill Env Override Host Injection (NEW - GHSA-82g8-464f-2mv7)
- **Technique**: `applySkillConfigEnvOverrides` copies skill env values into host `process.env` without safety policy
- **Impact**: Low severity (CVSS 2.7), requires high privileges, but enables external control of system configuration
- **CWE**: CWE-15, CWE-94
- **Patched in**: v2026.2.21

### 21. Browser Relay CDP Unauthenticated Access (NEW - CVE-2026-28458, CVSS 7.5)
- **Technique**: Browser Relay /cdp WebSocket endpoint accepts connections without auth tokens
- **Impact**: Websites connect via ws://127.0.0.1:18792/cdp to steal session cookies and execute JS in other tabs
- **Requires**: Browser Relay extension installed and enabled
- **Patched in**: v2026.2.1

### 22. Voice-Call Extension RCE (NEW - CVE-2026-28446, CVSS 9.8)
- **Technique**: Pre-auth RCE via crafted audio payload to voice-call transcription pipeline
- **Impact**: Remote unauthenticated shell access, 42,000 instances remotely exploitable
- **Patched in**: v2026.2.1

### 23. Browser Control API Path Traversal (NEW - CVE-2026-28462, CVSS 7.5)
- **Technique**: /trace/stop, /wait/download, /download accept user-supplied output paths without constraining to temp dirs
- **Impact**: Arbitrary file writes outside intended roots, config tampering, malware placement
- **Patched in**: v2026.2.13

### 24. Exec-Approvals Shell Expansion Bypass (NEW - CVE-2026-28463)
- **Technique**: Allowlist validates pre-expansion argv but execution uses real shell expansion (glob, env vars)
- **Impact**: head/tail/grep in safeBins can read arbitrary local files via prompt injection
- **Patched in**: v2026.2.14

### 25. Approval Field Injection (NEW - CVE-2026-28466)
- **Technique**: Gateway fails to sanitize internal approval fields in node.invoke params
- **Impact**: Authenticated clients bypass exec approval gating for system.run commands
- **Patched in**: v2026.2.14

### 26. Webhook Body DoS (NEW - CVE-2026-28478)
- **Technique**: Webhook handlers buffer bodies without byte/time limits
- **Impact**: Remote unauthenticated memory pressure via oversized JSON / slow uploads
- **Patched in**: v2026.2.13

### 27. TAR Archive Path Traversal (NEW - CVE-2026-28453)
- **Technique**: TAR extraction does not validate entry paths, ../../ traversal escapes boundaries
- **Impact**: Config tampering, code execution via arbitrary file writes
- **Patched in**: v2026.2.14

### 28. fetchWithGuard Memory DoS (NEW - CVE-2026-29609, CVSS 7.5)
- **Technique**: Allocates entire response payloads in memory before enforcing maxBytes limits
- **Impact**: Memory exhaustion via oversized responses without Content-Length
- **Patched in**: v2026.2.14

### 29. Fake Installer Campaign — Bing AI Search Poisoning (NEW - Mar 2026, Huntress)
- **Technique**: Fake OpenClaw installer repos on GitHub promoted by Bing AI search results
- **Impact**: GhostSocks proxy malware + Vidar stealer via novel Stealth Packer loader
- **Scope**: Active Feb 2–10 2026, repos removed but technique reproducible
- **Source**: [Huntress](https://www.huntress.com/blog/openclaw-github-ghostsocks-infostealer)

### 30. Git Pre-Commit Hook Command Injection (NEW - CVE-2026-28484, CVSS 9.3)
- **Technique**: git-hooks/pre-commit fails to sanitize filenames when processing staged files
- **Impact**: Pre-auth RCE via crafted filenames in cloned repositories
- **Patched in**: v2026.2.15

## CVE Summary (as of 2026-03-06)

| CVE | Description | Severity | Patched |
|-----|-------------|----------|---------|
| CVE-2026-28363 | Exec safeBins bypass via sort --compress-prog | **Critical (9.9)** | v2026.2.23 |
| CVE-2026-28446 | Voice-call extension pre-auth RCE | **Critical (9.8)** | v2026.2.1 |
| CVE-2026-28484 | Git pre-commit hook command injection | **Critical (9.3)** | v2026.2.15 |
| CVE-2026-25253 | WebSocket hijacking 1-click RCE | Critical (8.8) | v2026.1.29 |
| CVE-2026-28458 | Browser Relay CDP unauthenticated access | High (7.5) | v2026.2.1 |
| CVE-2026-28462 | Browser control API path traversal | High (7.5) | v2026.2.13 |
| CVE-2026-29609 | fetchWithGuard memory exhaustion DoS | High (7.5) | v2026.2.14 |
| CVE-2026-26322 | Gateway SSRF via tool-supplied gatewayUrl | High (7.6) | v2026.2.14 |
| CVE-2026-28463 | Exec-approvals shell expansion bypass | High | v2026.2.14 |
| CVE-2026-28466 | Approval field injection / exec gating bypass | High | v2026.2.14 |
| CVE-2026-28468 | Sandbox browser bridge auth bypass | High | v2026.2.14 |
| CVE-2026-28453 | TAR archive path traversal | High | v2026.2.14 |
| CVE-2026-29610 | Command hijacking via PATH manipulation | High | v2026.2.14 |
| CVE-2026-28485 | /agent/act browser-control auth missing | High | v2026.2.12 |
| CVE-2026-28478 | Webhook DoS via oversized payloads | High | v2026.2.13 |
| CVE-2026-26329 | Browser upload path traversal | High | v2026.2.14 |
| CVE-2026-26325 | Node host system.run exec bypass | High | v2026.2.14 |
| CVE-2026-26327 | mDNS/DNS-SD credential exfiltration on LAN | High (7.1) | v2026.2.14 |
| CVE-2026-27488 | Cron webhook SSRF | Moderate (6.9) | v2026.2.19 |
| CVE-2026-28465 | Voice-call webhook auth bypass via forwarded headers | Medium | v2026.2.3 |
| CVE-2026-25475 | Local File Inclusion via MEDIA: path | 6.5 | v2026.1.30 |
| CVE-2026-25474 | Telegram webhook request forgery | Medium | v2026.2.1 |
| CVE-2026-26319 | Telnyx voice-call webhook missing auth | Medium | v2026.2.14 |
| CVE-2026-26320 | macOS deep link confirmation truncation | Medium | v2026.2.14 |
| CVE-2026-26321 | Feishu/Lark local file disclosure | 3.1 | v2026.2.14 |
| CVE-2026-26326 | skills.status leaks secrets to operators | 3.1 | v2026.2.14 |
| CVE-2026-21636 | Node.js permission model bypass via UDS | Medium | Node 22.12+ |

## GHSA Summary (as of 2026-03-06)

| GHSA | Description | Severity | Patched |
|------|-------------|----------|---------|
| GHSA-7jx5-9fjg-hp4m | ACP auto-approval bypass via untrusted metadata | High (8.2) | v2026.2.23 |
| GHSA-7977-c43c-xpwj | safeBins sort --compress-prog bypass (CVE-2026-28363) | Critical (9.9) | v2026.2.23 |
| GHSA-56f2-hvwg-5743 | Image tool SSRF | High (7.6) | v2026.2.14 |
| GHSA-jqpq-mgvm-f9r6 | Command hijacking via unsafe PATH | High | v2026.2.14 |
| GHSA-pv58-549p-qh99 | Discovery TXT records steering (CVE-2026-26327) | High (7.1) | v2026.2.14 |
| GHSA-g8p2-7wf7-98mq | 1-Click RCE via gatewayUrl (CVE-2026-25253) | Critical | v2026.1.29 |
| GHSA-w45g-5746-x9fp | Cron webhook SSRF (CVE-2026-27488) | Moderate (6.9) | v2026.2.19 |
| GHSA-pg2v-8xwh-qhcc | Urbit auth SSRF | Moderate (6.5) | v2026.2.14 |
| GHSA-c37p-4qqg-3p76 | Twilio webhook auth bypass | Moderate (6.5) | v2026.2.14 |
| GHSA-82g8-464f-2mv7 | Skill env override host injection | Low (2.7) | v2026.2.21 |
| GHSA-3hcm-* | Exec allowlist bypass (command substitution) | High | v2026.2.2 |
| GHSA-qj77-* | Windows cmd.exe exec bypass | High | v2026.2.2 |
| GHSA-xc7w-* | Webhook auth bypass behind reverse proxy | Medium | v2026.2.14 |
| GHSA-v773-* | Slack dmPolicy=open privilege escalation | Medium | v2026.2.14 |
| GHSA-rmxw-* | Matrix allowlist bypass | Medium | v2026.2.14 |
| GHSA-4rj2-* | Voice-call allowlist bypass | Medium | v2026.2.14 |
| GHSA-4rqq-w8v4-7p47 | Incomplete IPv4 SSRF blocking in web fetch guard | High | v2026.3.2+ |
| GHSA-9mph-4f7v-fmvh | Avatar symlink traversal in gateway session metadata | High | v2026.3.2+ |
| GHSA-vjp8-wprm-2jw9 | Cross-account DM pairing authorization bypass | High | v2026.2.26 |
| GHSA-x2ff-j5c2-ggpr | Slack interactive callback sender check bypass | Medium | v2026.3.2+ |
| GHSA-43x4-g22p-3hrq | Chrome --no-sandbox disabled OS sandbox in container | Medium | v2026.3.2+ |
| GHSA-6x2m-hqfw-hvpj | Exec approval replay across nodes | Medium | v2026.3.2+ |
| GHSA-f6h3-846h-2r8w | Elevated allowFrom accepts broader identity signals | Medium | v2026.3.2+ |
| GHSA-x4vp-4235-65hg | Pre-auth webhook body parsing enables DoS | Medium | v2026.3.2+ |
| GHSA-3pxq-f3cp-jmxp | Path-confinement bypass in browser output handling | High | v2026.3.2+ |
| GHSA-gcj7-r3hg-m7w6 | Webhook replay via unsigned idempotency headers | Medium | v2026.3.2+ |

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
| SSRF | Webhook/cron targets | Internal/metadata endpoint detection |
| Auth | Brute-force resistance | Rate limiting, password strength audit |
| CVE | Version compliance | Minimum v2026.3.2 enforcement |
| Browser | CDP/Bridge auth | Port listening, auth mode, version checks |
| Archives | TAR extraction | Path validation, traversal detection |

## Hardening Recommendations

1. **Update OpenClaw to v2026.3.2+** (minimum safe version; addresses all known CVEs through Mar 2026)
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
15. **Set strong gateway password** and ensure rate limiting is enabled (ClawJacked mitigation)
16. **Audit cron webhook targets** for internal/metadata endpoint SSRF (CVE-2026-27488)
17. **Remove `sort` from safeBins** or ensure v2026.2.23+ (CVE-2026-28363, CVSS 9.9)
18. **Disable ACP auto-approve** or ensure v2026.2.23+ (GHSA-7jx5)
19. **Audit PATH for hijacking** — remove skill directories and writable non-standard directories from PATH (GHSA-jqpq)
20. **Review skill env declarations** — reject skills that override HOST/PORT/OPENCLAW_* variables (GHSA-82g8)
21. **Update to v2026.2.14+** to fix macOS deep link truncation (CVE-2026-26320)
22. **Enable logging.redactHeaders** and monitor logs for ANSI escape sequences / control characters (log poisoning)
23. **Disable Browser Relay** if not needed, or ensure v2026.2.1+ for CDP auth (CVE-2026-28458)
24. **Disable voice-call extension** if not needed, or ensure v2026.2.1+ (CVE-2026-28446, CVSS 9.8)
25. **Update to v2026.2.13+** for browser control path traversal and webhook DoS fixes (CVE-2026-28462, CVE-2026-28478)
26. **Update to v2026.2.14+** for exec shell expansion, approval injection, TAR traversal, fetchWithGuard fixes
27. **Update to v2026.2.15+** for git pre-commit hook command injection fix (CVE-2026-28484, CVSS 9.3)
28. **Update to v2026.3.2+** for SSRF guard bypass, avatar symlink traversal, Slack callback bypass, exec approval replay fixes
29. **Verify downloads** — never trust Bing/Google AI search results for OpenClaw installers; only use official GitHub (Huntress advisory)
30. **Audit head/tail/grep in safeBins** — these can read arbitrary files via glob patterns on unpatched versions (CVE-2026-28463)

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
- [Oasis Security: ClawJacked](https://www.oasis.security/blog/openclaw-vulnerability) (Feb 26)
- [Endor Labs: Six New Vulnerabilities](https://www.infosecurity-magazine.com/news/researchers-six-new-openclaw/)
- [VirusTotal: From Automation to Infection](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html)
- [Flare: Widespread Exploitation by Multiple Groups](https://flare.io/learn/resources/blog/widespread-openclaw-exploitation) (Feb 25)
- [CVE-2026-28363: safeBins Bypass](https://advisories.gitlab.com/pkg/npm/openclaw/CVE-2026-28363/) (CVSS 9.9)
- [GHSA-7jx5: ACP Auto-Approval Bypass](https://advisories.gitlab.com/pkg/npm/openclaw/GHSA-7jx5-9fjg-hp4m/) (CVSS 8.2)
- [CVE-2026-28446: Voice-Call RCE (CVSS 9.8)](https://dev.to/tiamatenity/cve-2026-28446-cvss-98-openclaw-voice-extension-rce-what-you-need-to-know-n2i)
- [CVE-2026-28458: Browser Relay CDP Auth Bypass](https://www.redpacketsecurity.com/cve-alert-cve-2026-28458-openclaw-openclaw/) (CVSS 7.5)
- [CVE-2026-28462: Browser Control Path Traversal](https://www.redpacketsecurity.com/cve-alert-cve-2026-28462-openclaw-openclaw/) (CVSS 7.5)
- [CVE-2026-28463: Exec Shell Expansion Bypass](https://www.redpacketsecurity.com/cve-alert-cve-2026-28463-openclaw-openclaw/)
- [CVE-2026-28466: Approval Field Injection](https://www.redpacketsecurity.com/cve-alert-cve-2026-28466-openclaw-openclaw/)
- [CVE-2026-28478: Webhook DoS](https://www.redpacketsecurity.com/cve-alert-cve-2026-28478-openclaw-openclaw/)
- [CVE-2026-28453: TAR Path Traversal](https://www.redpacketsecurity.com/cve-alert-cve-2026-28453-openclaw-openclaw/)
- [CVE-2026-29609: fetchWithGuard Memory DoS](https://www.redpacketsecurity.com/cve-alert-cve-2026-29609-openclaw-openclaw/) (CVSS 7.5)
- [CVE-2026-28484: Git Pre-Commit Hook RCE](https://www.sentinelone.com/vulnerability-database/cve-2026-28484/) (CVSS 9.3)
- [CVE-2026-28485: /agent/act Auth Missing](https://www.redpacketsecurity.com/cve-alert-cve-2026-28485-openclaw-openclaw/)
- [Huntress: Fake OpenClaw Installers — GhostSocks + Vidar](https://www.huntress.com/blog/openclaw-github-ghostsocks-infostealer) (Mar 4)
- [BleepingComputer: Bing AI Promoted Fake Installers](https://www.bleepingcomputer.com/news/security/bing-ai-promoted-fake-openclaw-github-repo-pushing-info-stealing-malware/)
- [Malwarebytes: Beware Fake OpenClaw Installers](https://www.malwarebytes.com/blog/news/2026/03/beware-of-fake-openclaw-installers-even-if-bing-points-you-to-github)
- [MintMCP: Every OpenClaw CVE Explained](https://www.mintmcp.com/blog/openclaw-cve-explained)
- [GHSA-4rqq: Incomplete SSRF Blocking](https://advisories.gitlab.com/pkg/npm/openclaw/GHSA-4rqq-w8v4-7p47/)
- [GHSA-9mph: Avatar Symlink Traversal](https://advisories.gitlab.com/pkg/npm/openclaw/GHSA-9mph-4f7v-fmvh/)
- [GHSA-vjp8: Cross-Account DM Pairing Bypass](https://advisories.gitlab.com/pkg/npm/openclaw/GHSA-vjp8-wprm-2jw9/)
- [GHSA-3pxq: Browser Output Path Bypass](https://advisories.gitlab.com/pkg/npm/openclaw/GHSA-3pxq-f3cp-jmxp/)
- [Check Point: Claude Code Flaws](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [IBM X-Force 2026 Threat Index](https://newsroom.ibm.com/2026-02-25-ibm-2026-x-force-threat-index-ai-driven-attacks-are-escalating-as-basic-security-gaps-leave-enterprises-exposed)
- [ReversingLabs: AI Agents and SSC Security](https://www.reversinglabs.com/blog/how-ai-agents-upend-sscs)
- [jgamblin/OpenClawCVEs: CVE Tracker](https://github.com/jgamblin/OpenClawCVEs/)
