# OpenClaw Threat Model

## Attack Surface

OpenClaw AI agents have three critical properties that create what security researchers call the "lethal trifecta":

1. **Access to private data** — file system, credentials, configs, environment variables
2. **Exposure to untrusted content** — skills from ClawHub, external data, prompt injection
3. **Ability to communicate externally** — network access, shell execution, API calls

Combined with persistent memory (SOUL.md, MEMORY.md), these create compounding risk.

## Attack Vectors

### 1. Supply Chain (ClawHub Skills)
- **ClawHavoc campaign**: 341 malicious skills (12% of registry)
- **Technique**: Social engineering via professional-looking SKILL.md
- **Payload**: AMOS stealer via Prerequisites section
- **Target**: macOS (osascript/glot.io) and Windows (openclaw-agent.exe)

### 2. WebSocket Hijacking (CVE-2026-25253)
- **Technique**: Cross-Site WebSocket Hijacking (CSWSH)
- **Vector**: Malicious link → gatewayUrl parameter → token exfiltration
- **Impact**: Full RCE even on localhost-bound instances
- **Kill chain**: Token steal → sandbox escape → arbitrary code execution

### 3. Memory Poisoning
- **Technique**: Skill modifies SOUL.md/MEMORY.md to alter future behavior
- **Impact**: Persistent backdoor across all future sessions
- **Detection**: Hash monitoring, content analysis for injection patterns

### 4. SKILL.md Shell Injection
- **Technique**: Embed shell commands in markdown that agents execute
- **Example**: Prerequisites section with `curl | bash` instructions
- **Impact**: Arbitrary code execution with agent's permissions

### 5. Credential Harvesting
- **Technique**: Skills read .env, .ssh, .aws, keychain files
- **Exfiltration**: webhook.site, pipedream, ngrok tunnels
- **Target**: API keys, SSH keys, browser passwords, crypto wallets

### 6. Typosquatting
- **Technique**: Register skill names similar to popular tools
- **Examples**: clawhub → clawhubb, cllawhub, clawhubcli
- **Scale**: 28 typosquat variants in ClawHavoc alone

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

## Hardening Recommendations

1. Update OpenClaw to v2026.1.29+ (CVE-2026-25253 fix)
2. Set `gateway.auth.mode` to `token` (never `none`)
3. Bind gateway to `loopback` not `lan`
4. Set file permissions to 600 on configs
5. Configure `tools.deny` for dangerous commands
6. Run security-monitor scan before installing new skills
7. Use `update-ioc.sh` to keep threat intelligence current
8. Monitor SOUL.md/MEMORY.md for unauthorized changes
