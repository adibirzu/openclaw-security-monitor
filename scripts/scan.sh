#!/bin/bash
# OpenClaw Security Monitor - Enhanced Threat Scanner v5.0.0
# https://github.com/adibirzu/openclaw-security-monitor
#
# 41-point security scanner (consolidated from 62). Detects: ClawHavoc AMOS
# stealer (824+ skills), C2 infrastructure, reverse shells, credential
# exfiltration, memory poisoning, SKILL.md injection, WebSocket hijacking
# (CVE-2026-25253), ClawJacked brute-force (v2026.2.25), CSWSH
# (CVE-2026-32302), device identity skip (CVE-2026-28472), SSRF
# (CVE-2026-26322, CVE-2026-27488), safeBins bypass (CVE-2026-28363),
# ACP auto-approval bypass (GHSA-7jx5), PATH hijacking (GHSA-jqpq,
# CVE-2026-29610), env override injection (GHSA-82g8), deep link truncation
# (CVE-2026-26320), log poisoning, Browser Relay CDP auth bypass
# (CVE-2026-28458), browser control path traversal (CVE-2026-28462), exec
# shell expansion bypass (CVE-2026-28463), approval field injection
# (CVE-2026-28466), /agent/act no-auth (CVE-2026-28485), sandbox bridge
# auth bypass (CVE-2026-28468), SHA-1 cache poisoning (CVE-2026-28479),
# webhook DoS (CVE-2026-28478), TAR traversal (CVE-2026-28453),
# fetchWithGuard memory DoS (CVE-2026-29609), Google Chat webhook bypass
# (CVE-2026-28469), MCP tool poisoning (OWASP MCP03/MCP06), SANDWORM_MODE
# MCP worm detection, rules file backdoor / Unicode injection, symlink
# traversal (CVE-2026-32013, CVE-2026-32055), sandbox escape
# (CVE-2026-32048, CVE-2026-32051), shell env RCE (CVE-2026-32056,
# CVE-2026-27566), VNC observer auth bypass (CVE-2026-32064), device
# identity spoofing (CVE-2026-32014, CVE-2026-32042, CVE-2026-32025),
# privilege escalation, scope abuse, DM/tool/sandbox policy violations,
# persistence mechanisms, plugin threats, and more.
#
# IOC database updated: 2026-03-22
# Threat coverage: 60+ CVEs, 60+ GHSAs, 1,200+ malicious packages
#
# Exit codes: 0=SECURE, 1=WARNINGS, 2=COMPROMISED
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IOC_DIR="$PROJECT_DIR/ioc"
SELF_DIR_NAME="$(basename "$PROJECT_DIR")"

OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
SKILLS_DIR="$OPENCLAW_DIR/workspace/skills"
WORKSPACE_DIR="$OPENCLAW_DIR/workspace"
LOG_DIR="$OPENCLAW_DIR/logs"
LOG_FILE="$LOG_DIR/security-scan.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export PATH="$HOME/.local/bin:/opt/homebrew/opt/node@22/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

CRITICAL=0
WARNINGS=0
CLEAN=0
TOTAL_CHECKS=0

mkdir -p "$LOG_DIR"

log() { echo "$1" | tee -a "$LOG_FILE"; }
header() { log ""; log "[$1/$TOTAL_CHECKS] $2"; }
result_clean() { log "CLEAN: $1"; CLEAN=$((CLEAN + 1)); }
result_warn() { log "WARNING: $1"; WARNINGS=$((WARNINGS + 1)); }
result_critical() { log "CRITICAL: $1"; CRITICAL=$((CRITICAL + 1)); }

extract_version() {
    echo "$1" | grep -oE '[0-9]{4}\.[0-9]+\.[0-9]+' | head -1
}

version_lt() {
    local left right
    left=$(extract_version "$1")
    right=$(extract_version "$2")
    [ -z "$left" ] || [ -z "$right" ] && return 1

    local lmaj lmin lpat rmaj rmin rpat
    lmaj=$(echo "$left" | cut -d'.' -f1)
    lmin=$(echo "$left" | cut -d'.' -f2)
    lpat=$(echo "$left" | cut -d'.' -f3)
    rmaj=$(echo "$right" | cut -d'.' -f1)
    rmin=$(echo "$right" | cut -d'.' -f2)
    rpat=$(echo "$right" | cut -d'.' -f3)

    if [ "$lmaj" -lt "$rmaj" ] 2>/dev/null; then
        return 0
    elif [ "$lmaj" -gt "$rmaj" ] 2>/dev/null; then
        return 1
    fi

    if [ "$lmin" -lt "$rmin" ] 2>/dev/null; then
        return 0
    elif [ "$lmin" -gt "$rmin" ] 2>/dev/null; then
        return 1
    fi

    [ "$lpat" -lt "$rpat" ] 2>/dev/null
}

# Emit a version advisory finding. Usage:
#   version_advisory <min_version> <message> [warn|critical]
# Returns 0 if vulnerable (finding emitted), 1 if safe/unknown.
version_advisory() {
    local min_ver="$1"
    local msg="$2"
    local severity="${3:-critical}"
    if [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
        if version_lt "$OC_VERSION" "$min_ver"; then
            if [ "$severity" = "warn" ]; then
                result_warn "OpenClaw v$OC_VERSION: $msg. Update to v${min_ver}+"
            else
                result_critical "OpenClaw v$OC_VERSION: $msg. Update to v${min_ver}+"
            fi
            return 0
        fi
    fi
    return 1
}

# Use timeout if available (macOS may only have gtimeout via coreutils)
TIMEOUT_BIN=""
if command -v timeout &>/dev/null; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout &>/dev/null; then
    TIMEOUT_BIN="gtimeout"
fi

run_with_timeout() {
    local secs="$1"
    shift
    if [ -n "$TIMEOUT_BIN" ]; then
        "$TIMEOUT_BIN" "$secs" "$@"
    elif command -v python3 &>/dev/null; then
        python3 - "$secs" "$@" <<'PY'
import os
import signal
import subprocess
import sys

def main():
    try:
        secs = float(sys.argv[1])
    except Exception:
        secs = 0
    cmd = sys.argv[2:]
    if not cmd:
        sys.exit(1)

    try:
        proc = subprocess.Popen(cmd)
        try:
            proc.wait(timeout=secs if secs > 0 else None)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            sys.exit(124)
        sys.exit(proc.returncode if proc.returncode is not None else 0)
    except FileNotFoundError:
        sys.exit(127)

if __name__ == "__main__":
    main()
PY
    else
        "$@"
    fi
}

# Count total checks
TOTAL_CHECKS=41

log "========================================"
log "OPENCLAW SECURITY SCAN - $TIMESTAMP"
log "Scanner: v5.0.0 (openclaw-security-monitor)"
log "========================================"

# Load IOC data
load_ips() {
    if [ -f "$IOC_DIR/c2-ips.txt" ]; then
        grep -v '^#' "$IOC_DIR/c2-ips.txt" | grep -v '^$' | cut -d'|' -f1
    else
        echo "91.92.242"
    fi
}

load_domains() {
    if [ -f "$IOC_DIR/malicious-domains.txt" ]; then
        grep -v '^#' "$IOC_DIR/malicious-domains.txt" | grep -v '^$' | cut -d'|' -f1
    else
        echo "webhook.site"
    fi
}

# ============================================================
# CHECK 1: Known C2 Infrastructure
# ============================================================
header 1 "Scanning for known C2 infrastructure..."

C2_PATTERN=$(load_ips | tr '\n' '|' | sed 's/|$//' | sed 's/\./\\./g')
if [ -n "$C2_PATTERN" ]; then
    C2_HITS=$(grep -rlE --exclude-dir="$SELF_DIR_NAME" "$C2_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
    if [ -n "$C2_HITS" ]; then
        result_critical "Known C2 IP found in:"
        log "$C2_HITS"
    else
        result_clean "No C2 IPs detected"
    fi
else
    result_clean "No C2 IPs detected"
fi

# ============================================================
# CHECK 2: Malware Signatures & Obfuscation
# (Merges old checks 2, 11, 12)
# ============================================================
header 2 "Scanning for malware signatures & obfuscation..."

MAL2_FOUND=0

# AMOS stealer / AuthTool markers
AMOS_PATTERN="authtool|atomic.stealer|AMOS|NovaStealer|nova.stealer|osascript.*password|osascript.*dialog|osascript.*keychain|Security\.framework.*Auth|openclaw-agent\.exe|openclaw-agent\.zip|openclawcli\.zip|AuthTool|Installer-Package"
AMOS_HITS=$(grep -rliE --exclude-dir="$SELF_DIR_NAME" "$AMOS_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$AMOS_HITS" ]; then
    result_critical "AMOS/stealer markers found in:"
    log "$AMOS_HITS"
    MAL2_FOUND=$((MAL2_FOUND + 1))
fi

# Base64-obfuscated payloads (ClawHavoc glot.io delivery)
B64_PATTERN="base64 -[dD]|base64 --decode|atob\(|Buffer\.from\(.*base64|echo.*\|.*base64.*\|.*bash|echo.*\|.*base64.*\|.*sh|python.*b64decode|import base64"
B64_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "$B64_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$B64_HITS" ]; then
    result_warn "Base64 decode patterns found in:"
    log "$B64_HITS"
    MAL2_FOUND=$((MAL2_FOUND + 1))
fi

# External binary downloads (openclaw-agent.exe, password-protected archives)
BIN_PATTERN="\.exe|\.dmg|\.pkg|\.msi|\.app\.zip|releases/download|github\.com/.*/releases|\.zip.*password|password.*\.zip|openclawcli\.zip|openclaw-agent|AuthTool.*download|download.*AuthTool"
BIN_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "$BIN_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$BIN_HITS" ]; then
    result_warn "External binary download references found in:"
    log "$BIN_HITS"
    MAL2_FOUND=$((MAL2_FOUND + 1))
fi

if [ "$MAL2_FOUND" -eq 0 ]; then
    result_clean "No malware signatures or obfuscation detected"
fi

# ============================================================
# CHECK 3: Reverse Shells & Backdoors
# ============================================================
header 3 "Scanning for reverse shells & backdoors..."

SHELL_PATTERN="nc -e|/dev/tcp/|mkfifo.*nc|bash -i >|socat.*exec|python.*socket.*connect|nohup.*bash.*tcp|perl.*socket.*INET|ruby.*TCPSocket|php.*fsockopen|lua.*socket\.tcp|xattr -[cr]|com\.apple\.quarantine"
SHELL_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "$SHELL_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$SHELL_HITS" ]; then
    result_critical "Reverse shell patterns found in:"
    log "$SHELL_HITS"
else
    result_clean "No reverse shells"
fi

# ============================================================
# CHECK 4: Credential Exfiltration Endpoints
# ============================================================
header 4 "Scanning for credential exfiltration endpoints..."

DOMAIN_PATTERN=$(load_domains | tr '\n' '|' | sed 's/|$//' | sed 's/\./\\./g')
EXFIL_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "$DOMAIN_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$EXFIL_HITS" ]; then
    result_critical "Exfiltration endpoints found in:"
    log "$EXFIL_HITS"
else
    result_clean "No exfiltration endpoints"
fi

# ============================================================
# CHECK 5: Crypto Wallet Targeting
# ============================================================
header 5 "Scanning for crypto wallet targeting..."

CRYPTO_PATTERN="wallet.*private.*key|seed.phrase|mnemonic|keystore.*decrypt|phantom.*wallet|metamask.*vault|exchange.*api.*key|solana.*keypair|ethereum.*keyfile"
CRYPTO_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "$CRYPTO_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$CRYPTO_HITS" ]; then
    result_warn "Crypto wallet patterns found in:"
    log "$CRYPTO_HITS"
else
    result_clean "No crypto targeting"
fi

# ============================================================
# CHECK 6: Curl-Pipe / Download Attacks
# ============================================================
header 6 "Scanning for curl-pipe and download attacks..."

CURL_PATTERN="curl.*\|.*sh|curl.*\|.*bash|wget.*\|.*sh|curl -fsSL.*\||wget -q.*\||curl.*-o.*/tmp/"
CURL_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "$CURL_PATTERN" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$CURL_HITS" ]; then
    result_warn "Curl-pipe patterns found in:"
    log "$CURL_HITS"
else
    result_clean "No curl-pipe attacks"
fi

# ============================================================
# CHECK 7: File & Credential Permission Audit
# (Merges old checks 7, 21)
# ============================================================
header 7 "Auditing file and credential permissions..."

PERM7_ISSUES=0

# Sensitive config file permissions (was check 7)
for f in "$OPENCLAW_DIR/openclaw.json" \
         "$OPENCLAW_DIR/agents/main/agent/auth-profiles.json" \
         "$OPENCLAW_DIR/exec-approvals.json"; do
    if [ -f "$f" ]; then
        PERMS=$(stat -f "%Lp" "$f" 2>/dev/null || stat -c "%a" "$f" 2>/dev/null)
        if [ "$PERMS" != "600" ]; then
            result_warn "$f has permissions $PERMS (should be 600)"
            PERM7_ISSUES=$((PERM7_ISSUES + 1))
        fi
    fi
done

# Credentials directory (was check 21)
CRED_DIR="$OPENCLAW_DIR/credentials"
if [ -d "$CRED_DIR" ]; then
    DIR_PERMS=$(stat -f "%Lp" "$CRED_DIR" 2>/dev/null || stat -c "%a" "$CRED_DIR" 2>/dev/null)
    if [ "$DIR_PERMS" != "700" ]; then
        result_warn "Credentials dir has permissions $DIR_PERMS (should be 700)"
        PERM7_ISSUES=$((PERM7_ISSUES + 1))
    fi
    while IFS= read -r cred_file; do
        FPERMS=$(stat -f "%Lp" "$cred_file" 2>/dev/null || stat -c "%a" "$cred_file" 2>/dev/null)
        if [ "$FPERMS" != "600" ]; then
            result_warn "$(basename "$cred_file") has permissions $FPERMS (should be 600)"
            PERM7_ISSUES=$((PERM7_ISSUES + 1))
        fi
    done < <(find "$CRED_DIR" -type f -name "*.json" 2>/dev/null)
fi

# Session file permissions
for agent_dir in "$OPENCLAW_DIR"/agents/*/; do
    SESSION_DIR="$agent_dir/sessions"
    if [ -d "$SESSION_DIR" ]; then
        SDIR_PERMS=$(stat -f "%Lp" "$SESSION_DIR" 2>/dev/null || stat -c "%a" "$SESSION_DIR" 2>/dev/null)
        if [ -n "$SDIR_PERMS" ] && [ "$SDIR_PERMS" != "700" ]; then
            result_warn "Session dir $(basename "$agent_dir")/sessions has permissions $SDIR_PERMS (should be 700)"
            PERM7_ISSUES=$((PERM7_ISSUES + 1))
        fi
    fi
done

# OpenClaw home directory
if [ -d "$OPENCLAW_DIR" ]; then
    HOME_PERMS=$(stat -f "%Lp" "$OPENCLAW_DIR" 2>/dev/null || stat -c "%a" "$OPENCLAW_DIR" 2>/dev/null)
    if [ "$HOME_PERMS" != "700" ]; then
        result_warn "OpenClaw home dir has permissions $HOME_PERMS (should be 700)"
        PERM7_ISSUES=$((PERM7_ISSUES + 1))
    fi
fi

if [ "$PERM7_ISSUES" -eq 0 ]; then
    result_clean "All file and credential permissions correct"
fi

# ============================================================
# CHECK 8: Skill Integrity Hashes
# ============================================================
header 8 "Computing skill integrity hashes..."

HASH_FILE="$LOG_DIR/skill-hashes.sha256"
HASH_FILE_PREV="$LOG_DIR/skill-hashes.sha256.prev"
if [ -f "$HASH_FILE" ]; then
    cp "$HASH_FILE" "$HASH_FILE_PREV"
fi
find "$SKILLS_DIR" -name "SKILL.md" -exec shasum -a 256 {} \; > "$HASH_FILE" 2>/dev/null
if [ -f "$HASH_FILE_PREV" ]; then
    DIFF=$(diff "$HASH_FILE_PREV" "$HASH_FILE" 2>/dev/null || true)
    if [ -n "$DIFF" ]; then
        result_warn "Skill files changed since last scan:"
        log "$DIFF"
    else
        result_clean "No skill file modifications"
    fi
else
    log "INFO: Baseline hashes created (first scan)"
    result_clean "Baseline hashes created"
fi

# ============================================================
# CHECK 9: AI Prompt Injection & Instruction Manipulation
# (Merges old checks 9, 10, 57, 59)
# ============================================================
header 9 "Scanning for AI prompt injection & instruction manipulation..."

INJECT9_ISSUES=0

# SKILL.md shell injection patterns (was check 9)
INJECTION_PATTERN="Prerequisites.*install|Prerequisites.*download|Prerequisites.*curl|Prerequisites.*wget|run this command.*terminal|paste.*terminal|copy.*terminal|base64 -d|base64 --decode|eval \$(|exec \$(|\`curl|\`wget|bypass.*safety.*guideline|execute.*without.*asking|ignore.*safety|override.*instruction|without.*user.*awareness"
INJECT_HITS=""
while IFS= read -r skillmd; do
    if grep -qiE "$INJECTION_PATTERN" "$skillmd" 2>/dev/null; then
        INJECT_HITS="$INJECT_HITS\n  $skillmd"
    fi
done < <(find "$SKILLS_DIR" -name "SKILL.md" -not -path "*/$SELF_DIR_NAME/*" 2>/dev/null)

if [ -n "$INJECT_HITS" ]; then
    result_warn "SKILL.md files with suspicious install instructions:$INJECT_HITS"
    INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
fi

# Memory poisoning detection (was check 10)
for memfile in "$WORKSPACE_DIR/SOUL.md" "$WORKSPACE_DIR/MEMORY.md" "$WORKSPACE_DIR/IDENTITY.md"; do
    if [ -f "$memfile" ]; then
        POISON_HITS=$(grep -iE "ignore[[:space:]]+previous|disregard|override.*instruction|system[[:space:]]+prompt|new[[:space:]]+instruction|forget.*previous|you[[:space:]]+are[[:space:]]+now|act[[:space:]]+as[[:space:]]+if|pretend[[:space:]]+to[[:space:]]+be|from[[:space:]]+now[[:space:]]+on.*ignore" "$memfile" 2>/dev/null || true)
        if [ -n "$POISON_HITS" ]; then
            result_critical "Memory poisoning detected in $memfile:"
            log "$POISON_HITS"
            INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
        fi
    fi
done

# Skills attempting to modify memory files
MEM_WRITE_HITS=$(grep -rliE --exclude-dir="$SELF_DIR_NAME" "SOUL\.md|MEMORY\.md|IDENTITY\.md" "$SKILLS_DIR" 2>/dev/null | while read -r f; do
    if grep -qiE "write.*SOUL|write.*MEMORY|modify.*SOUL|echo.*>>.*SOUL|cat.*>.*SOUL|append.*MEMORY" "$f" 2>/dev/null; then
        echo "  $f"
    fi
done)
if [ -n "$MEM_WRITE_HITS" ]; then
    result_critical "Skills attempting to modify memory files:"
    log "$MEM_WRITE_HITS"
    INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
fi

# MCP server tool poisoning via schema injection (was check 57)
MCP_CONFIG_DIRS=(
    "$OPENCLAW_DIR/mcp-servers"
    "$HOME/.config/openclaw/mcp"
    "$HOME/.claude/mcp"
)

for MCP_DIR in "${MCP_CONFIG_DIRS[@]}"; do
    if [ -d "$MCP_DIR" ]; then
        while IFS= read -r mcpfile; do
            [ -z "$mcpfile" ] && continue
            if grep -Pq '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{00AD}]' "$mcpfile" 2>/dev/null; then
                result_critical "Hidden Unicode in MCP config: $mcpfile (tool poisoning/prompt injection)"
                INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
            fi
            if grep -iE '(bcc|forward_to|redirect|exfiltrate|steal|siphon)' "$mcpfile" 2>/dev/null | grep -vq '^#'; then
                result_warn "Suspicious BCC/forwarding pattern in MCP config: $mcpfile"
                INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
            fi
            if grep -iE '(ignore previous|disregard|you are now|act as|system prompt|<\|im_sep\|>|<\|endoftext\|>)' "$mcpfile" 2>/dev/null | grep -vq '^#'; then
                result_critical "Prompt injection detected in MCP config: $mcpfile"
                INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
            fi
        done < <(find "$MCP_DIR" -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" \) 2>/dev/null)
    fi
done

# Rules file backdoor / hidden Unicode injection (was check 59)
RULES_FILES=(
    ".cursorrules"
    ".cursor/rules"
    ".github/copilot-instructions.md"
    "CLAUDE.md"
    ".claude/settings.json"
    ".clawrules"
    ".openclaw/rules.md"
    "SOUL.md"
)

SCAN_ROOTS=("$(pwd)" "$HOME")
for SROOT in "${SCAN_ROOTS[@]}"; do
    for RFILE in "${RULES_FILES[@]}"; do
        TARGET="$SROOT/$RFILE"
        if [ -f "$TARGET" ]; then
            if grep -Pq '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{00AD}\x{2028}\x{2029}\x{202A}-\x{202E}\x{2066}-\x{2069}]' "$TARGET" 2>/dev/null; then
                result_critical "Hidden Unicode injection in rules file: $TARGET (Pillar Security attack)"
                INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
            fi
            if grep -qE '[A-Za-z0-9+/]{40,}={0,2}' "$TARGET" 2>/dev/null; then
                B64_LINES=$(grep -cE '[A-Za-z0-9+/]{100,}={0,2}' "$TARGET" 2>/dev/null || echo "0")
                if [ "$B64_LINES" -gt 2 ]; then
                    result_warn "Large base64 blocks in rules file: $TARGET (potential obfuscated injection)"
                    INJECT9_ISSUES=$((INJECT9_ISSUES + 1))
                fi
            fi
        fi
    done
done

if [ "$INJECT9_ISSUES" -eq 0 ]; then
    result_clean "No prompt injection or instruction manipulation detected"
fi

# ============================================================
# CHECK 10: Gateway Security Configuration
# (was old check 13)
# ============================================================
header 10 "Auditing gateway security configuration..."

GW_ISSUES=0

if command -v openclaw &>/dev/null; then
    BIND=$(run_with_timeout 10 openclaw config get gateway.bind 2>/dev/null || echo "unknown")
    if [ "$BIND" = "lan" ] || [ "$BIND" = "0.0.0.0" ]; then
        result_warn "Gateway bound to LAN ($BIND) - accessible from network"
        GW_ISSUES=$((GW_ISSUES + 1))
    fi

    AUTH_MODE=$(run_with_timeout 10 openclaw config get gateway.auth.mode 2>/dev/null || echo "unknown")
    if [ "$AUTH_MODE" = "none" ] || [ "$AUTH_MODE" = "off" ]; then
        result_critical "Gateway authentication is DISABLED"
        GW_ISSUES=$((GW_ISSUES + 1))
    fi

    OC_VERSION=$(run_with_timeout 5 openclaw --version 2>/dev/null || echo "unknown")
    log "  OpenClaw version: $OC_VERSION"
    if version_lt "$OC_VERSION" "2026.3.21"; then
        result_critical "OpenClaw version $OC_VERSION is below the current safe baseline (v2026.3.21+) and misses March 2026 security fixes"
        GW_ISSUES=$((GW_ISSUES + 1))
    fi
fi

if [ "$GW_ISSUES" -eq 0 ]; then
    result_clean "Gateway configuration acceptable"
fi

# ============================================================
# CHECK 11: WebSocket Security
# (Merges old checks 14, 33, 53, 54)
# ============================================================
header 11 "Checking WebSocket security..."

WS11_ISSUES=0

# Gateway port detection
GW_PORT=$(run_with_timeout 5 openclaw config get gateway.port 2>/dev/null || echo "18789")
GW_PORT=$(echo "$GW_PORT" | grep -o '[0-9]*' | head -1)
GW_PORT=${GW_PORT:-18789}

# WebSocket origin validation (was check 14, CVE-2026-25253)
WS_RAW=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Origin: http://evil.attacker.com" \
    --connect-timeout 3 --max-time 5 \
    "http://127.0.0.1:$GW_PORT/" 2>/dev/null || echo "000")
WS_TEST=$(echo "$WS_RAW" | head -c 3)

if [ "$WS_TEST" = "101" ]; then
    PATCHED_WS=false
    if [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
        if ! version_lt "$OC_VERSION" "2026.1.29"; then
            PATCHED_WS=true
        fi
    fi
    HAS_GW_AUTH=$(run_with_timeout 5 openclaw config get gateway.auth.mode 2>/dev/null || echo "")
    if [ "$PATCHED_WS" = true ] && [ -n "$HAS_GW_AUTH" ] && [ "$HAS_GW_AUTH" != "none" ]; then
        result_clean "WebSocket: patched + gateway auth ($HAS_GW_AUTH) - CVE-2026-25253 mitigated"
    elif [ "$PATCHED_WS" = true ]; then
        result_warn "WebSocket: patched but no gateway auth token (recommend setting gateway.auth)"
        WS11_ISSUES=$((WS11_ISSUES + 1))
    else
        result_critical "Gateway accepts WebSocket from arbitrary origins (CVE-2026-25253 may be unpatched)"
        WS11_ISSUES=$((WS11_ISSUES + 1))
    fi
elif [ "$WS_TEST" = "000" ]; then
    log "  Gateway not reachable on port $GW_PORT (may be normal)"
elif [ "$WS_TEST" = "403" ] || [ "$WS_TEST" = "401" ]; then
    log "  WebSocket origin validation active (HTTP $WS_TEST - rejected)"
else
    log "  WebSocket responded HTTP $WS_TEST"
fi

if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    # ClawJacked WebSocket brute-force (was check 33, fixed v2026.2.26)
    if version_advisory "2026.2.26" "ClawJacked WebSocket brute-force vulnerability"; then
        WS11_ISSUES=$((WS11_ISSUES + 1))
    fi

    # Gateway auth token check
    GW_AUTH_TOKEN=$(run_with_timeout 5 openclaw config get "gateway.auth.token" 2>/dev/null || echo "")
    if [ -z "$GW_AUTH_TOKEN" ] || [ "$GW_AUTH_TOKEN" = "null" ]; then
        result_warn "No gateway auth token set (ClawJacked can brute-force default credentials)"
        WS11_ISSUES=$((WS11_ISSUES + 1))
    fi

    # Rate limiting check
    RATE_LIMIT=$(run_with_timeout 5 openclaw config get "gateway.auth.rateLimit" 2>/dev/null || echo "")
    if [ "$RATE_LIMIT" = "off" ] || [ "$RATE_LIMIT" = "false" ]; then
        result_warn "Gateway auth rate limiting is disabled (enables brute-force attacks)"
        WS11_ISSUES=$((WS11_ISSUES + 1))
    fi

    # Gateway WebSocket device identity skip (was check 53, CVE-2026-28472, fixed v2026.3.11)
    if version_advisory "2026.3.11" "gateway WebSocket skips device identity check (CVE-2026-28472)"; then
        WS11_ISSUES=$((WS11_ISSUES + 1))
    fi

    # Cross-Site WebSocket Hijacking in trusted-proxy (was check 54, CVE-2026-32302, fixed v2026.3.11)
    if version_advisory "2026.3.11" "Cross-Site WebSocket Hijacking via Origin bypass (CVE-2026-32302)"; then
        WS11_ISSUES=$((WS11_ISSUES + 1))
    fi

    # Extra risk if trusted-proxy mode is active
    TRUSTED_PROXY_MODE=$(run_with_timeout 5 openclaw config get "gateway.trustedProxy" 2>/dev/null || echo "")
    if [ "$TRUSTED_PROXY_MODE" = "true" ] && [ "$WS11_ISSUES" -gt 0 ]; then
        log "  Trusted-proxy mode is ACTIVE — CSWSH exploitation risk elevated"
    fi
fi

if [ "$WS11_ISSUES" -eq 0 ]; then
    result_clean "WebSocket security acceptable"
fi

# ============================================================
# CHECK 12: Known Malicious Publisher Detection
# (was old check 15)
# ============================================================
header 12 "Checking installed skills against known malicious publishers..."

if [ -f "$IOC_DIR/malicious-publishers.txt" ]; then
    PUBLISHERS=$(grep -v '^#' "$IOC_DIR/malicious-publishers.txt" | grep -v '^$' | cut -d'|' -f1)
    PUB_HITS=""
    for pub in $PUBLISHERS; do
        FOUND=$(grep -rl --exclude-dir="$SELF_DIR_NAME" "$pub" "$SKILLS_DIR" 2>/dev/null || true)
        if [ -n "$FOUND" ]; then
            PUB_HITS="$PUB_HITS\n  Publisher '$pub' referenced in: $FOUND"
        fi
    done
    if [ -n "$PUB_HITS" ]; then
        result_critical "Known malicious publisher references found:$PUB_HITS"
    else
        result_clean "No known malicious publishers"
    fi
else
    result_clean "Publisher database not available (skipped)"
fi

# ============================================================
# CHECK 13: Credential Leakage & Plaintext Secrets
# (Merges old checks 16, 29)
# ============================================================
header 13 "Scanning for credential leakage & plaintext secrets..."

CRED13_ISSUES=0

# Sensitive environment/credential file access (was check 16)
ENV_PATTERN="\.env|\.bashrc|\.zshrc|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.kube/config|\.docker/config|keychain|login\.keychain|Cookies\.binarycookies|\.clawdbot/\.env|\.openclaw/openclaw\.json|auth-profiles\.json|\.git-credentials|\.netrc|moltbook.*token|moltbook.*api|MOLTBOOK_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|sk-[a-zA-Z0-9]"
ENV_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "cat.*(${ENV_PATTERN})|read.*(${ENV_PATTERN})|open.*(${ENV_PATTERN})|fs\.read.*(${ENV_PATTERN})|source.*(${ENV_PATTERN})" "$SKILLS_DIR" 2>/dev/null || true)

API_KEY_HITS=$(grep -rlinE --exclude-dir="$SELF_DIR_NAME" "sk-[a-zA-Z0-9]{20,}|OPENAI_API_KEY\s*=\s*['\"][^$]|ANTHROPIC_API_KEY\s*=\s*['\"][^$]|moltbook.*token\s*=\s*['\"]" "$SKILLS_DIR" 2>/dev/null || true)
if [ -n "$API_KEY_HITS" ]; then
    result_critical "Hardcoded API keys or Moltbook tokens found in:"
    log "$API_KEY_HITS"
    CRED13_ISSUES=$((CRED13_ISSUES + 1))
fi
if [ -n "$ENV_HITS" ]; then
    result_warn "Skills accessing sensitive env/credential files:"
    log "$ENV_HITS"
    CRED13_ISSUES=$((CRED13_ISSUES + 1))
fi

# Plaintext credentials in config files (was check 29)
CRED_PATTERNS="sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|xoxb-[0-9]{10,}|xoxp-[0-9]{10,}|glpat-[a-zA-Z0-9_-]{20}"
for cfile in "$OPENCLAW_DIR/openclaw.json" \
             "$OPENCLAW_DIR/agents/main/agent/auth-profiles.json"; do
    if [ -f "$cfile" ]; then
        CRED_FOUND=$(grep -oE "$CRED_PATTERNS" "$cfile" 2>/dev/null | head -5 || true)
        if [ -n "$CRED_FOUND" ]; then
            result_warn "Plaintext credentials found in $(basename "$cfile") (consider using a secrets manager)"
            CRED13_ISSUES=$((CRED13_ISSUES + 1))
        fi
    fi
done
if [ -d "$OPENCLAW_DIR/credentials" ]; then
    CRED_FILES=$(find "$OPENCLAW_DIR/credentials" -name "*.json" -exec grep -lE "$CRED_PATTERNS" {} \; 2>/dev/null || true)
    if [ -n "$CRED_FILES" ]; then
        result_warn "Plaintext API keys in credentials directory"
        CRED13_ISSUES=$((CRED13_ISSUES + 1))
    fi
fi

if [ "$CRED13_ISSUES" -eq 0 ]; then
    result_clean "No credential leakage or plaintext secrets detected"
fi

# ============================================================
# CHECK 14: DM, Tool & Sandbox Policies
# (Merges old checks 17, 18, 19)
# ============================================================
header 14 "Auditing DM, tool, and sandbox policies..."

POL14_ISSUES=0
if command -v openclaw &>/dev/null; then
    # DM policy audit (was check 17)
    for channel in whatsapp telegram discord slack signal; do
        DM_POLICY=$(run_with_timeout 10 openclaw config get "channels.${channel}.dmPolicy" 2>/dev/null || echo "")
        if [ "$DM_POLICY" = "open" ]; then
            result_warn "Channel '$channel' has dmPolicy='open' (anyone can message)"
            POL14_ISSUES=$((POL14_ISSUES + 1))
        fi
        ALLOW_FROM=$(run_with_timeout 10 openclaw config get "channels.${channel}.allowFrom" 2>/dev/null || echo "")
        if echo "$ALLOW_FROM" | grep -q '"*"' 2>/dev/null; then
            result_warn "Channel '$channel' has wildcard '*' in allowFrom"
            POL14_ISSUES=$((POL14_ISSUES + 1))
        fi
    done

    # Tool policy / elevated tools audit (was check 18)
    ELEVATED=$(run_with_timeout 10 openclaw config get "tools.elevated.enabled" 2>/dev/null || echo "")
    if [ "$ELEVATED" = "true" ]; then
        ELEVATED_ALLOW=$(run_with_timeout 10 openclaw config get "tools.elevated.allowFrom" 2>/dev/null || echo "")
        if echo "$ELEVATED_ALLOW" | grep -q '"*"' 2>/dev/null; then
            result_critical "Elevated tools enabled with wildcard allowFrom"
            POL14_ISSUES=$((POL14_ISSUES + 1))
        else
            log "  INFO: Elevated tools enabled (restricted allowFrom)"
        fi
    fi

    DENY_LIST=$(run_with_timeout 10 openclaw config get "tools.deny" 2>/dev/null || echo "")
    if [ -z "$DENY_LIST" ] || [ "$DENY_LIST" = "[]" ] || [ "$DENY_LIST" = "null" ]; then
        result_warn "No tools in deny list (consider blocking: exec, process, browser)"
        POL14_ISSUES=$((POL14_ISSUES + 1))
    fi

    # Sandbox configuration (was check 19)
    SANDBOX_MODE=$(run_with_timeout 10 openclaw config get "sandbox.mode" 2>/dev/null || echo "")
    if [ "$SANDBOX_MODE" = "off" ] || [ "$SANDBOX_MODE" = "none" ]; then
        result_warn "Sandbox mode is disabled (consider: mode='all')"
        POL14_ISSUES=$((POL14_ISSUES + 1))
    elif [ -n "$SANDBOX_MODE" ]; then
        log "  Sandbox mode: $SANDBOX_MODE"
    fi
fi

if [ "$POL14_ISSUES" -eq 0 ]; then
    result_clean "DM, tool, and sandbox policies acceptable"
fi

# ============================================================
# CHECK 15: mDNS/Bonjour Exposure
# (was old check 20)
# ============================================================
header 15 "Checking mDNS/Bonjour discovery settings..."

MDNS_ISSUES=0
if command -v openclaw &>/dev/null; then
    MDNS_MODE=$(run_with_timeout 10 openclaw config get "discovery.mdns.mode" 2>/dev/null || echo "")
    if [ "$MDNS_MODE" = "full" ]; then
        result_warn "mDNS broadcasting in 'full' mode (exposes paths, SSH port)"
        MDNS_ISSUES=$((MDNS_ISSUES + 1))
    elif [ -n "$MDNS_MODE" ]; then
        log "  mDNS mode: $MDNS_MODE"
    fi
fi
if [ "$MDNS_ISSUES" -eq 0 ]; then
    result_clean "mDNS configuration acceptable"
fi

# ============================================================
# CHECK 16: Persistence Mechanism Scan
# (was old check 22)
# ============================================================
header 16 "Scanning for unauthorized persistence mechanisms..."

PERSIST_ISSUES=0
if [ -d "$HOME/Library/LaunchAgents" ]; then
    SUSPICIOUS_AGENTS=$(find "$HOME/Library/LaunchAgents" -name "*.plist" -exec grep -li "openclaw\|clawdbot\|moltbot" {} \; 2>/dev/null || true)
    if [ -n "$SUSPICIOUS_AGENTS" ]; then
        log "  LaunchAgents referencing openclaw:"
        log "  $SUSPICIOUS_AGENTS"
        for agent in $SUSPICIOUS_AGENTS; do
            if ! grep -q "com.openclaw.security-dashboard" "$agent" 2>/dev/null; then
                AGENT_LABEL=$(grep -A1 "<key>Label</key>" "$agent" 2>/dev/null | tail -1 | sed 's/.*<string>\(.*\)<\/string>.*/\1/')
                result_warn "Unknown LaunchAgent: $AGENT_LABEL ($(basename "$agent"))"
                PERSIST_ISSUES=$((PERSIST_ISSUES + 1))
            fi
        done
    fi
fi

CRON_ENTRIES=$(crontab -l 2>/dev/null | grep -ivE "${SELF_DIR_NAME}|#" | grep -iE "openclaw|clawdbot|moltbot|curl.*\|.*sh|wget.*\|.*bash" || true)
if [ -n "$CRON_ENTRIES" ]; then
    result_warn "Suspicious cron entries found:"
    log "  $CRON_ENTRIES"
    PERSIST_ISSUES=$((PERSIST_ISSUES + 1))
fi

if command -v systemctl &>/dev/null; then
    SYS_SERVICES=$(systemctl --user list-units --type=service --all 2>/dev/null | grep -iE "openclaw|clawdbot|moltbot" | grep -v "$SELF_DIR_NAME" || true)
    if [ -n "$SYS_SERVICES" ]; then
        log "  Systemd services:"
        log "  $SYS_SERVICES"
    fi
fi

if [ "$PERSIST_ISSUES" -eq 0 ]; then
    result_clean "No unauthorized persistence mechanisms"
fi

# ============================================================
# CHECK 17: Log Security & Poisoning
# (Merges old checks 24, 40)
# ============================================================
header 17 "Checking log security and poisoning indicators..."

LOG17_ISSUES=0

# Log redaction settings (was check 24)
if command -v openclaw &>/dev/null; then
    REDACT=$(run_with_timeout 10 openclaw config get "logging.redactSensitive" 2>/dev/null || echo "")
    if [ "$REDACT" = "off" ] || [ "$REDACT" = "false" ] || [ "$REDACT" = "none" ]; then
        result_warn "Log redaction is disabled (sensitive data may leak to logs)"
        LOG17_ISSUES=$((LOG17_ISSUES + 1))
    elif [ -n "$REDACT" ]; then
        log "  Log redaction: $REDACT"
    fi

    GW_LOG="/tmp/openclaw"
    if [ -d "$GW_LOG" ]; then
        GW_LOG_PERMS=$(stat -f "%Lp" "$GW_LOG" 2>/dev/null || stat -c "%a" "$GW_LOG" 2>/dev/null)
        if [ "$GW_LOG_PERMS" != "700" ] && [ "$GW_LOG_PERMS" != "750" ]; then
            result_warn "Gateway log dir /tmp/openclaw has permissions $GW_LOG_PERMS (should be 700)"
            LOG17_ISSUES=$((LOG17_ISSUES + 1))
        fi
    fi

    # WebSocket header redaction (was check 40)
    LOG_REDACT=$(run_with_timeout 5 openclaw config get "logging.redactHeaders" 2>/dev/null || echo "")
    if [ -z "$LOG_REDACT" ] || [ "$LOG_REDACT" = "false" ] || [ "$LOG_REDACT" = "null" ]; then
        result_warn "WebSocket header redaction not enabled (logging.redactHeaders)"
        LOG17_ISSUES=$((LOG17_ISSUES + 1))
    fi
fi

# Log poisoning indicators (was check 40)
if [ -d "$LOG_DIR" ]; then
    ANSI_HITS=$(grep -rlP '\x1b\[' "$LOG_DIR" 2>/dev/null | head -5)
    if [ -n "$ANSI_HITS" ]; then
        ANSI_COUNT=$(echo "$ANSI_HITS" | wc -l | tr -d ' ')
        result_warn "ANSI escape sequences found in $ANSI_COUNT log file(s) — possible log poisoning"
        LOG17_ISSUES=$((LOG17_ISSUES + 1))
    fi

    FAKE_ENTRIES=$(grep -rlE '\]\s*(INFO|WARN|ERROR|CRITICAL)\s*:.*\[20[0-9]{2}-' "$LOG_DIR" 2>/dev/null | head -3)
    if [ -n "$FAKE_ENTRIES" ]; then
        while IFS= read -r FFILE; do
            NESTED=$(grep -cE '^\[.*\]\s*(INFO|ERROR).*\[20[0-9]{2}-[0-9]{2}' "$FFILE" 2>/dev/null || echo "0")
            if [ "$NESTED" -gt 0 ]; then
                result_warn "Possible injected log entries in $(basename "$FFILE") — log poisoning indicator"
                LOG17_ISSUES=$((LOG17_ISSUES + 1))
                break
            fi
        done <<< "$FAKE_ENTRIES"
    fi

    CTRL_HITS=$(grep -rlP '[\x00-\x08\x0e-\x1f]' "$LOG_DIR" 2>/dev/null | grep -v '.log.gz' | head -3)
    if [ -n "$CTRL_HITS" ]; then
        result_warn "Control characters found in logs — possible WebSocket header injection"
        LOG17_ISSUES=$((LOG17_ISSUES + 1))
    fi
fi

if [ "$LOG17_ISSUES" -eq 0 ]; then
    result_clean "Log security and poisoning checks passed"
fi

# ============================================================
# CHECK 18: Plugin/Extension Security
# (was old check 23)
# ============================================================
header 18 "Auditing installed plugins and extensions..."

EXT_DIR="$OPENCLAW_DIR/extensions"
EXT_ISSUES=0
if [ -d "$EXT_DIR" ]; then
    EXT_COUNT=$(find "$EXT_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d " ")
    log "  Installed extensions: $EXT_COUNT"
    if [ "$EXT_COUNT" -gt 0 ]; then
        while IFS= read -r ext; do
            EXT_NAME=$(basename "$ext")
            EXT_SUS=$(grep -rlE "eval\(|exec\(|child_process|\.exec\(|net\.connect|http\.request|fetch\(" "$ext" 2>/dev/null | head -3 || true)
            if [ -n "$EXT_SUS" ]; then
                result_warn "Extension '$EXT_NAME' has code execution patterns"
                EXT_ISSUES=$((EXT_ISSUES + 1))
            fi
            EXT_MAL=$(grep -rlE "$DOMAIN_PATTERN" "$ext" 2>/dev/null || true)
            if [ -n "$EXT_MAL" ]; then
                result_critical "Extension '$EXT_NAME' references known malicious domains"
                EXT_ISSUES=$((EXT_ISSUES + 1))
            fi
        done < <(find "$EXT_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    fi
fi
if [ "$EXT_ISSUES" -eq 0 ]; then
    result_clean "No suspicious plugins/extensions"
fi

# ============================================================
# CHECK 19: Docker Container Security
# (was old check 27)
# ============================================================
header 19 "Auditing Docker container security..."

DOCKER_ISSUES=0
if command -v docker &>/dev/null; then
    OC_CONTAINERS=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -iE "openclaw|clawdbot|moltbot" || true)
    if [ -n "$OC_CONTAINERS" ]; then
        while IFS= read -r container_line; do
            CNAME=$(echo "$container_line" | awk '{print $1}')
            CUSER=$(docker inspect --format '{{.Config.User}}' "$CNAME" 2>/dev/null || echo "")
            if [ -z "$CUSER" ] || [ "$CUSER" = "root" ] || [ "$CUSER" = "0" ]; then
                result_warn "Container '$CNAME' running as root (use non-root user)"
                DOCKER_ISSUES=$((DOCKER_ISSUES + 1))
            fi
            DSOCK=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$CNAME" 2>/dev/null | grep "docker.sock" || true)
            if [ -n "$DSOCK" ]; then
                result_critical "Container '$CNAME' has Docker socket mounted (container escape risk)"
                DOCKER_ISSUES=$((DOCKER_ISSUES + 1))
            fi
            PRIV=$(docker inspect --format '{{.HostConfig.Privileged}}' "$CNAME" 2>/dev/null || echo "")
            if [ "$PRIV" = "true" ]; then
                result_critical "Container '$CNAME' is running in privileged mode"
                DOCKER_ISSUES=$((DOCKER_ISSUES + 1))
            fi
        done <<< "$OC_CONTAINERS"
    else
        log "  No OpenClaw Docker containers detected"
    fi
fi
if [ "$DOCKER_ISSUES" -eq 0 ]; then
    result_clean "Docker security acceptable"
fi

# ============================================================
# CHECK 20: Authentication & Route Security
# (Merges old checks 25, 41, 45, 49)
# ============================================================
header 20 "Checking authentication and route security..."

AUTH20_ISSUES=0
if command -v openclaw &>/dev/null; then
    # Reverse proxy localhost trust bypass (was check 25)
    BIND_ADDR=$(run_with_timeout 10 openclaw config get "gateway.bind" 2>/dev/null || echo "")
    TRUSTED_PROXIES=$(run_with_timeout 10 openclaw config get "gateway.trustedProxies" 2>/dev/null || echo "")
    DISABLE_DEVICE_AUTH=$(run_with_timeout 10 openclaw config get "gateway.dangerouslyDisableDeviceAuth" 2>/dev/null || echo "")

    if [ "$DISABLE_DEVICE_AUTH" = "true" ]; then
        result_critical "Device authentication is disabled (dangerouslyDisableDeviceAuth=true)"
        AUTH20_ISSUES=$((AUTH20_ISSUES + 1))
    fi

    if [ "$BIND_ADDR" = "lan" ] || [ "$BIND_ADDR" = "0.0.0.0" ]; then
        if [ -z "$TRUSTED_PROXIES" ] || [ "$TRUSTED_PROXIES" = "null" ] || [ "$TRUSTED_PROXIES" = "[]" ]; then
            result_warn "Gateway on LAN without trustedProxies - localhost trust bypass risk"
            AUTH20_ISSUES=$((AUTH20_ISSUES + 1))
        fi
    fi

    if [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
        # Browser Relay CDP unauthenticated access (was check 41, CVE-2026-28458, fixed v2026.2.1)
        if command -v lsof &>/dev/null; then
            CDP_LISTEN=$(lsof -iTCP:18792 -sTCP:LISTEN -nP 2>/dev/null | grep -v COMMAND)
            if [ -n "$CDP_LISTEN" ]; then
                log "  Browser Relay is listening on port 18792"
                if version_advisory "2026.2.1" "Browser Relay /cdp endpoint unauthenticated (CVE-2026-28458, CVSS 7.5)"; then
                    AUTH20_ISSUES=$((AUTH20_ISSUES + 1))
                fi
            fi
        fi

        # Sandbox browser bridge auth bypass (was check 45, CVE-2026-28468, fixed v2026.2.14)
        if version_advisory "2026.2.14" "sandbox browser bridge unauthenticated (CVE-2026-28468)" "warn"; then
            AUTH20_ISSUES=$((AUTH20_ISSUES + 1))
        fi

        # /agent/act no authentication (was check 49, CVE-2026-28485, fixed v2026.2.12)
        if version_advisory "2026.2.12" "/agent/act HTTP route unauthenticated (CVE-2026-28485)"; then
            AUTH20_ISSUES=$((AUTH20_ISSUES + 1))
        fi

        # Check if browser extension is enabled (required for the endpoints above)
        BROWSER_EXT=$(run_with_timeout 5 openclaw config get "browser.extension.enabled" 2>/dev/null || echo "")
        if [ "$BROWSER_EXT" = "true" ] && [ "$AUTH20_ISSUES" -gt 0 ]; then
            log "  Browser extension is enabled — auth bypass attack surface is active"
        fi
    fi
fi

if [ "$AUTH20_ISSUES" -eq 0 ]; then
    result_clean "Authentication and route security acceptable"
fi

# ============================================================
# CHECK 21: Exec Guardrails & Approval Security
# (Merges old checks 26, 35, 43, 44, 62)
# ============================================================
header 21 "Checking exec guardrails and approval security..."

EXEC21_ISSUES=0

# Exec-approvals configuration (was check 26)
EXEC_FILE="$OPENCLAW_DIR/exec-approvals.json"
if [ -f "$EXEC_FILE" ]; then
    UNSAFE_EXEC=$(grep -iE '"security"\s*:\s*"allow"|"ask"\s*:\s*"off"|"allowlist"\s*:\s*\[\s*\]' "$EXEC_FILE" 2>/dev/null || true)
    if [ -n "$UNSAFE_EXEC" ]; then
        result_critical "Exec-approvals has unsafe configuration (allows remote exec):"
        log "  $UNSAFE_EXEC"
        EXEC21_ISSUES=$((EXEC21_ISSUES + 1))
    fi
    EXEC_PERMS=$(stat -f "%Lp" "$EXEC_FILE" 2>/dev/null || stat -c "%a" "$EXEC_FILE" 2>/dev/null)
    if [ "$EXEC_PERMS" != "600" ]; then
        result_warn "exec-approvals.json has permissions $EXEC_PERMS (should be 600)"
        EXEC21_ISSUES=$((EXEC21_ISSUES + 1))
    fi
fi

if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    # safeBins bypass (was check 35, CVE-2026-28363, CVSS 9.9, fixed v2026.2.23)
    if version_advisory "2026.2.23" "CVE-2026-28363 (CVSS 9.9) safeBins bypass via sort --compress-prog"; then
        EXEC21_ISSUES=$((EXEC21_ISSUES + 1))
    fi

    # Audit safeBins list
    SAFE_BINS=$(run_with_timeout 5 openclaw config get "tools.exec.safeBins" 2>/dev/null || echo "")
    if echo "$SAFE_BINS" | grep -q '"sort"' 2>/dev/null; then
        log "  INFO: 'sort' is in safeBins list (ensure v2026.2.23+ for CVE-2026-28363 fix)"
    fi

    # Shell expansion bypass (was check 43, CVE-2026-28463, fixed v2026.2.14)
    if version_advisory "2026.2.14" "exec-approvals shell expansion bypass (CVE-2026-28463)"; then
        EXEC21_ISSUES=$((EXEC21_ISSUES + 1))
    fi

    for RBIN in head tail grep cat; do
        if echo "$SAFE_BINS" | grep -q "\"$RBIN\"" 2>/dev/null; then
            log "  INFO: '$RBIN' in safeBins — ensure v2026.2.14+ for CVE-2026-28463 fix"
        fi
    done

    # Approval field injection (was check 44, CVE-2026-28466, fixed v2026.2.14)
    if version_advisory "2026.2.14" "approval field injection bypass (CVE-2026-28466)"; then
        EXEC21_ISSUES=$((EXEC21_ISSUES + 1))
    fi

    # Exec approval integrity replay (was check 62)
    EXEC_SECURITY=$(run_with_timeout 10 openclaw config get "tools.exec.security" 2>/dev/null || echo "")
    APPROVALS=$(run_with_timeout 10 openclaw config get "tools.exec.approvals" 2>/dev/null || echo "")

    if version_lt "${OC_VERSION:-unknown}" "2026.3.13"; then
        if [ "$EXEC_SECURITY" = "allowlist" ] || { [ -n "$SAFE_BINS" ] && [ "$SAFE_BINS" != "[]" ] && [ "$SAFE_BINS" != "null" ]; }; then
            result_warn "Exec guardrails rely on pre-v2026.3.13 approval integrity (GHSA-qc36, GHSA-xf99, GHSA-rw39, GHSA-f8r2)"
            EXEC21_ISSUES=$((EXEC21_ISSUES + 1))
        fi
        if [ -n "$APPROVALS" ] && [ "$APPROVALS" != "[]" ] && [ "$APPROVALS" != "null" ]; then
            log "  Existing exec approval config present: review previously approved script-runner commands after upgrading"
        fi
    fi
fi

if [ "$EXEC21_ISSUES" -eq 0 ]; then
    result_clean "Exec guardrails and approval security acceptable"
fi

# ============================================================
# CHECK 22: Node.js Version / CVE-2026-21636
# (was old check 28)
# ============================================================
header 22 "Checking Node.js version for known CVEs..."

NODE_ISSUES=0
if command -v node &>/dev/null; then
    NODE_VER=$(node --version 2>/dev/null | sed 's/v//')
    NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
    NODE_MINOR=$(echo "$NODE_VER" | cut -d. -f2)
    log "  Node.js version: v$NODE_VER"

    if [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -lt 12 ]; then
        result_warn "Node.js v$NODE_VER is vulnerable to CVE-2026-21636 (permission model bypass). Upgrade to 22.12.0+"
        NODE_ISSUES=$((NODE_ISSUES + 1))
    elif [ "$NODE_MAJOR" -lt 22 ]; then
        result_warn "Node.js v$NODE_VER is below recommended v22 LTS"
        NODE_ISSUES=$((NODE_ISSUES + 1))
    fi
else
    log "  Node.js not found"
fi
if [ "$NODE_ISSUES" -eq 0 ]; then
    result_clean "Node.js version acceptable"
fi

# ============================================================
# CHECK 23: VS Code Extension Trojan Detection
# (was old check 30)
# ============================================================
header 23 "Checking for fake ClawdBot/OpenClaw VS Code extensions..."

VSCODE_ISSUES=0
VSCODE_EXT_DIR="$HOME/.vscode/extensions"
if [ -d "$VSCODE_EXT_DIR" ]; then
    FAKE_EXT=$(find "$VSCODE_EXT_DIR" -maxdepth 1 -type d -iname "*clawdbot*" -o -iname "*moltbot*" -o -iname "*openclaw*" 2>/dev/null || true)
    if [ -n "$FAKE_EXT" ]; then
        result_critical "Suspicious VS Code extension found (OpenClaw has NO official VS Code extension):"
        log "  $FAKE_EXT"
        VSCODE_ISSUES=$((VSCODE_ISSUES + 1))
    fi
fi
VSCODE_INS_DIR="$HOME/.vscode-insiders/extensions"
if [ -d "$VSCODE_INS_DIR" ]; then
    FAKE_INS=$(find "$VSCODE_INS_DIR" -maxdepth 1 -type d -iname "*clawdbot*" -o -iname "*moltbot*" -o -iname "*openclaw*" 2>/dev/null || true)
    if [ -n "$FAKE_INS" ]; then
        result_critical "Suspicious VS Code Insiders extension found:"
        log "  $FAKE_INS"
        VSCODE_ISSUES=$((VSCODE_ISSUES + 1))
    fi
fi
if [ "$VSCODE_ISSUES" -eq 0 ]; then
    result_clean "No fake VS Code extensions"
fi

# ============================================================
# CHECK 24: Internet Exposure Detection
# (was old check 31)
# ============================================================
header 24 "Checking for internet exposure of gateway..."

EXPOSURE_ISSUES=0
GW_LISTEN=$(lsof -i ":${GW_PORT}" -nP 2>/dev/null | grep LISTEN | awk '{print $9}' | head -5 || true)
if [ -n "$GW_LISTEN" ]; then
    NON_LOCAL=$(echo "$GW_LISTEN" | grep -vE "127\.0\.0\.1|localhost|\[::1\]|\*:" || true)
    if [ -n "$NON_LOCAL" ]; then
        result_warn "Gateway listening on non-loopback interface:"
        log "  $GW_LISTEN"
        EXPOSURE_ISSUES=$((EXPOSURE_ISSUES + 1))
    fi
    WILDCARD=$(echo "$GW_LISTEN" | grep "\*:" || true)
    if [ -n "$WILDCARD" ]; then
        result_warn "Gateway bound to all interfaces (*:$GW_PORT) - potentially internet-exposed"
        EXPOSURE_ISSUES=$((EXPOSURE_ISSUES + 1))
    fi
fi
if [ "$EXPOSURE_ISSUES" -eq 0 ]; then
    result_clean "Gateway not exposed to external network"
fi

# ============================================================
# CHECK 25: MCP Server Security
# (was old check 32)
# ============================================================
header 25 "Auditing MCP server configuration..."

MCP_ISSUES=0
if command -v openclaw &>/dev/null; then
    MCP_ALL=$(run_with_timeout 10 openclaw config get "mcp.enableAllProjectMcpServers" 2>/dev/null || echo "")
    if [ "$MCP_ALL" = "true" ]; then
        result_warn "All project MCP servers enabled (use explicit allowlist instead)"
        MCP_ISSUES=$((MCP_ISSUES + 1))
    fi
fi
MCP_CONFIG="$OPENCLAW_DIR/mcp.json"
if [ -f "$MCP_CONFIG" ]; then
    MCP_INJECT=$(grep -iE "ignore[[:space:]]+previous|system[[:space:]]+prompt|override[[:space:]]+instruction|execute[[:space:]]+command|run[[:space:]]+this" "$MCP_CONFIG" 2>/dev/null || true)
    if [ -n "$MCP_INJECT" ]; then
        result_critical "Prompt injection patterns in MCP server config:"
        log "  $MCP_INJECT"
        MCP_ISSUES=$((MCP_ISSUES + 1))
    fi
fi
if [ "$MCP_ISSUES" -eq 0 ]; then
    result_clean "MCP server configuration acceptable"
fi

# ============================================================
# CHECK 26: PATH Hijacking & Command Resolution
# (Merges old checks 37, 50)
# ============================================================
header 26 "Checking PATH hijacking and command resolution..."

PATH26_ISSUES=0

# Check for writable directories early in PATH with command shadowing (was check 37)
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for PDIR in "${PATH_DIRS[@]}"; do
    if [ -d "$PDIR" ] && [ -w "$PDIR" ]; then
        case "$PDIR" in
            "$HOME/bin"|"$HOME/.local/bin"|"$HOME/.cargo/bin"|"$HOME/go/bin") continue ;;
        esac
        for CMD in node python3 bash curl git ssh openclaw; do
            if [ -f "$PDIR/$CMD" ] && [ -x "$PDIR/$CMD" ]; then
                SYS_BIN=$(which -a "$CMD" 2>/dev/null | tail -1)
                if [ -n "$SYS_BIN" ] && [ "$PDIR/$CMD" != "$SYS_BIN" ]; then
                    result_critical "PATH hijack: $PDIR/$CMD shadows system $SYS_BIN (GHSA-jqpq)"
                    PATH26_ISSUES=$((PATH26_ISSUES + 1))
                fi
            fi
        done
    fi
done

# Check for planted binaries in workspace
if [ -d "$WORKSPACE_DIR" ]; then
    PLANTED=$(find "$WORKSPACE_DIR" -maxdepth 3 -type f -name "node" -o -name "python3" -o -name "bash" -o -name "curl" -o -name "git" 2>/dev/null | head -5)
    if [ -n "$PLANTED" ]; then
        while IFS= read -r PBIN; do
            if [ -x "$PBIN" ]; then
                result_critical "Planted binary in workspace: $PBIN (PATH hijack vector)"
                PATH26_ISSUES=$((PATH26_ISSUES + 1))
            fi
        done <<< "$PLANTED"
    fi
fi

# CVE-2026-29610 version check (was check 50, fixed v2026.2.14)
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.2.14" "PATH command hijacking via unsafe resolution (CVE-2026-29610)" "warn"; then
        PATH26_ISSUES=$((PATH26_ISSUES + 1))
    fi
fi

# Detect writable PATH directories preceding system dirs
SYSTEM_DIRS="/usr/bin /bin /usr/sbin /sbin"
IFS=':' read -ra P610_DIRS <<< "$PATH"
FOUND_SYSTEM=false
for PDIR610 in "${P610_DIRS[@]}"; do
    for SDIR in $SYSTEM_DIRS; do
        if [ "$PDIR610" = "$SDIR" ]; then
            FOUND_SYSTEM=true
            break
        fi
    done
    if [ "$FOUND_SYSTEM" = false ] && [ -d "$PDIR610" ]; then
        DIR_PERMS=$(stat -f "%Lp" "$PDIR610" 2>/dev/null || stat -c "%a" "$PDIR610" 2>/dev/null || echo "")
        if [ -n "$DIR_PERMS" ]; then
            case "$DIR_PERMS" in
                *7|*6|*3|*2)
                    result_warn "Writable dir '$PDIR610' precedes system dirs in PATH (CVE-2026-29610 hijack vector)"
                    PATH26_ISSUES=$((PATH26_ISSUES + 1))
                    ;;
            esac
        fi
    fi
done

if [ "$PATH26_ISSUES" -eq 0 ]; then
    result_clean "No PATH hijacking indicators found"
fi

# ============================================================
# CHECK 27: SSRF Protection
# (was old check 34)
# ============================================================
header 27 "Checking SSRF protections (CVE-2026-26322, CVE-2026-27488)..."

SSRF_ISSUES=0
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    # CVE-2026-26322: Gateway SSRF (fixed v2026.2.14)
    # CVE-2026-27488: Cron webhook SSRF (fixed v2026.2.19)
    if version_advisory "2026.2.19" "cron webhook SSRF (CVE-2026-27488)" "warn"; then
        SSRF_ISSUES=$((SSRF_ISSUES + 1))
    fi
    if version_lt "$OC_VERSION" "2026.2.14"; then
        result_critical "OpenClaw v$OC_VERSION also vulnerable to gateway SSRF (CVE-2026-26322)"
        SSRF_ISSUES=$((SSRF_ISSUES + 1))
    fi

    # Check if cron webhook URLs point to internal/metadata endpoints
    CRON_CONFIG=$(run_with_timeout 5 openclaw config get "cron" 2>/dev/null || echo "")
    if echo "$CRON_CONFIG" | grep -qiE "169\.254\.|127\.0\.0\.|10\.\|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|metadata\.google|metadata\.aws" 2>/dev/null; then
        result_warn "Cron webhook targets internal/metadata endpoints (SSRF risk)"
        SSRF_ISSUES=$((SSRF_ISSUES + 1))
    fi
fi
if [ "$SSRF_ISSUES" -eq 0 ]; then
    result_clean "SSRF protections acceptable"
fi

# ============================================================
# CHECK 28: Path Traversal & File Handling
# (Merges old checks 39, 42, 47)
# ============================================================
header 28 "Checking path traversal and file handling..."

PTRAV28_ISSUES=0

if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    # macOS deep link truncation (was check 39, CVE-2026-26320, fixed v2026.2.14)
    if [ "$(uname -s)" = "Darwin" ]; then
        if version_advisory "2026.2.14" "deep link truncation (CVE-2026-26320)" "warn"; then
            PTRAV28_ISSUES=$((PTRAV28_ISSUES + 1))
        fi
    fi

    # Browser control API path traversal (was check 42, CVE-2026-28462, fixed v2026.2.13)
    if version_advisory "2026.2.13" "browser control API path traversal (CVE-2026-28462, CVSS 7.5)"; then
        PTRAV28_ISSUES=$((PTRAV28_ISSUES + 1))
    fi

    # TAR archive path traversal (was check 47, CVE-2026-28453, fixed v2026.2.14)
    if version_advisory "2026.2.14" "TAR archive path traversal (CVE-2026-28453)"; then
        PTRAV28_ISSUES=$((PTRAV28_ISSUES + 1))
    fi
fi

# Check recent deep link invocations for suspiciously long payloads
if [ "$(uname -s)" = "Darwin" ] && [ -d "$LOG_DIR" ]; then
    LONG_LINKS=$(grep -rl 'openclaw://' "$LOG_DIR" 2>/dev/null | head -3)
    if [ -n "$LONG_LINKS" ]; then
        while IFS= read -r LFILE; do
            if grep -E 'openclaw://[^ ]{240,}' "$LFILE" &>/dev/null; then
                result_warn "Long deep link (>240 chars) found in logs — potential CVE-2026-26320 exploit attempt"
                PTRAV28_ISSUES=$((PTRAV28_ISSUES + 1))
                break
            fi
        done <<< "$LONG_LINKS"
    fi
fi

if [ "$PTRAV28_ISSUES" -eq 0 ]; then
    result_clean "Path traversal and file handling acceptable"
fi

# ============================================================
# CHECK 29: DoS Protection
# (Merges old checks 46, 48)
# ============================================================
header 29 "Checking denial-of-service protections..."

DOS29_ISSUES=0
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    # Webhook DoS (was check 46, CVE-2026-28478, fixed v2026.2.13)
    if version_advisory "2026.2.13" "webhook handlers lack body size/time limits (CVE-2026-28478)" "warn"; then
        DOS29_ISSUES=$((DOS29_ISSUES + 1))
    fi

    # fetchWithGuard memory exhaustion (was check 48, CVE-2026-29609, fixed v2026.2.14)
    if version_advisory "2026.2.14" "fetchWithGuard memory exhaustion DoS (CVE-2026-29609, CVSS 7.5)" "warn"; then
        DOS29_ISSUES=$((DOS29_ISSUES + 1))
    fi
fi

if [ "$DOS29_ISSUES" -eq 0 ]; then
    result_clean "DoS protections acceptable"
fi

# ============================================================
# CHECK 30: ACP Permission Auto-Approval
# (was old check 36)
# ============================================================
header 30 "Checking ACP auto-approval bypass (GHSA-7jx5)..."

ACP_ISSUES=0
if command -v openclaw &>/dev/null; then
    if [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
        if version_advisory "2026.2.23" "GHSA-7jx5 ACP auto-approval bypass" "warn"; then
            ACP_ISSUES=$((ACP_ISSUES + 1))
        fi
    fi

    ACP_AUTO=$(run_with_timeout 5 openclaw config get "acp.autoApprove" 2>/dev/null || echo "")
    if [ "$ACP_AUTO" = "true" ] || [ "$ACP_AUTO" = "all" ]; then
        result_warn "ACP auto-approve is enabled (tool calls bypass interactive approval)"
        ACP_ISSUES=$((ACP_ISSUES + 1))
    fi
fi
if [ "$ACP_ISSUES" -eq 0 ]; then
    result_clean "ACP permission controls acceptable"
fi

# ============================================================
# CHECK 31: Skill Env Override Host Injection
# (was old check 38)
# ============================================================
header 31 "Checking skill env override host injection (GHSA-82g8)..."

ENV_OVERRIDE_ISSUES=0
if [ -d "$SKILLS_DIR" ]; then
    while IFS= read -r SKILL_DIR; do
        SKILL_NAME=$(basename "$SKILL_DIR")
        if [ "$SKILL_NAME" = "$SELF_DIR_NAME" ]; then continue; fi

        SKILL_MD="$SKILL_DIR/SKILL.md"
        if [ -f "$SKILL_MD" ]; then
            if grep -qiE '^\s*"?(HOST|PORT|OPENCLAW_|API_URL|BASE_URL|GATEWAY_URL|SERVER_URL)"?\s*:' "$SKILL_MD" 2>/dev/null; then
                result_warn "Skill '$SKILL_NAME' declares HOST/PORT/URL env override (GHSA-82g8)"
                ENV_OVERRIDE_ISSUES=$((ENV_OVERRIDE_ISSUES + 1))
            fi
        fi

        for CFG in "$SKILL_DIR/package.json" "$SKILL_DIR/config.json" "$SKILL_DIR/.env"; do
            if [ -f "$CFG" ]; then
                if grep -qiE '(OPENCLAW_HOME|OPENCLAW_DIR|GATEWAY_URL|API_BASE)' "$CFG" 2>/dev/null; then
                    result_warn "Skill '$SKILL_NAME' overrides OpenClaw env in $(basename "$CFG") (GHSA-82g8)"
                    ENV_OVERRIDE_ISSUES=$((ENV_OVERRIDE_ISSUES + 1))
                fi
            fi
        done
    done < <(find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
fi

if [ "$ENV_OVERRIDE_ISSUES" -eq 0 ]; then
    result_clean "No suspicious skill env overrides found"
fi

# ============================================================
# CHECK 32: Privilege Escalation & Scope Abuse
# (Merges old checks 55, 56, 61)
# ============================================================
header 32 "Checking privilege escalation and scope abuse..."

PRIV32_ISSUES=0
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    # Device pairing credential exposure (was check 55, GHSA-7h7g, fixed v2026.3.12)
    if version_advisory "2026.3.12" "device pairing exposes long-lived credentials (GHSA-7h7g)" "warn"; then
        PRIV32_ISSUES=$((PRIV32_ISSUES + 1))
    fi

    DEVICE_JSON="$OPENCLAW_DIR/device.json"
    if [ -f "$DEVICE_JSON" ] && [ "$PRIV32_ISSUES" -gt 0 ]; then
        log "  device.json exists — rotate credentials after upgrading"
    fi

    # Operator privilege escalation (was check 56, GHSA-vmhq, fixed v2026.3.12)
    if version_advisory "2026.3.12" "operator accounts can escalate to admin (GHSA-vmhq)" "warn"; then
        PRIV32_ISSUES=$((PRIV32_ISSUES + 1))
    fi

    # Shared-auth scope escalation (was check 61)
    GATEWAY_AUTH_MODE=$(run_with_timeout 10 openclaw config get "gateway.auth.mode" 2>/dev/null || echo "")
    PAIRING_MODE=$(run_with_timeout 10 openclaw config get "pairing.enabled" 2>/dev/null || echo "")

    if version_lt "${OC_VERSION:-unknown}" "2026.3.13"; then
        if [ "$GATEWAY_AUTH_MODE" = "password" ] || [ "$GATEWAY_AUTH_MODE" = "token" ]; then
            result_critical "OpenClaw $OC_VERSION may allow shared-auth clients to self-assert elevated scopes (GHSA-rqpp-rjj8-7wv8)"
            PRIV32_ISSUES=$((PRIV32_ISSUES + 1))
        fi
        if [ -n "$PAIRING_MODE" ] && [ "$PAIRING_MODE" != "false" ] && [ "$PAIRING_MODE" != "off" ]; then
            result_critical "OpenClaw $OC_VERSION may allow pairing-scoped credentials to escalate privileges (GHSA-4jpw, GHSA-63f5)"
            PRIV32_ISSUES=$((PRIV32_ISSUES + 1))
        fi
    fi
fi

if [ "$PRIV32_ISSUES" -eq 0 ]; then
    result_clean "Privilege escalation and scope abuse checks passed"
fi

# ============================================================
# CHECK 33: SHA-1 Cache Poisoning
# (was old check 51)
# ============================================================
header 33 "Checking SHA-1 sandbox cache poisoning (CVE-2026-28479)..."

SHA1_ISSUES=0
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.2.15" "SHA-1 used for sandbox cache keys (CVE-2026-28479, CVSS 8.7)"; then
        SHA1_ISSUES=$((SHA1_ISSUES + 1))
    fi

    SANDBOX_CACHE=$(run_with_timeout 5 openclaw config get "sandbox.cache.enabled" 2>/dev/null || echo "")
    if [ "$SANDBOX_CACHE" = "true" ] && [ "$SHA1_ISSUES" -gt 0 ]; then
        log "  Sandbox caching is enabled — SHA-1 collision attack surface is active"
    elif [ "$SANDBOX_CACHE" = "true" ]; then
        log "  INFO: Sandbox caching enabled; verify v2026.2.15+ for CVE-2026-28479 fix"
    fi
fi

if [ "$SHA1_ISSUES" -eq 0 ]; then
    result_clean "Sandbox cache key algorithm acceptable"
fi

# ============================================================
# CHECK 34: Google Chat Webhook Cross-Account Bypass
# (was old check 52)
# ============================================================
header 34 "Checking Google Chat webhook authorization (CVE-2026-28469)..."

GCW_ISSUES=0
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.2.14" "Google Chat webhook cross-account bypass (CVE-2026-28469, CVSS 9.8)"; then
        GCW_ISSUES=$((GCW_ISSUES + 1))
    fi

    GCHAT_ENABLED=$(run_with_timeout 5 openclaw config get "integrations.googlechat.enabled" 2>/dev/null || echo "")
    if [ "$GCHAT_ENABLED" = "true" ] && [ "$GCW_ISSUES" -gt 0 ]; then
        log "  Google Chat integration is active — CVE-2026-28469 attack surface is live"
    fi
fi

if [ "$GCW_ISSUES" -eq 0 ]; then
    result_clean "Google Chat webhook authorization acceptable"
fi

# ============================================================
# CHECK 35: SANDWORM Worm Detection
# (was old check 58)
# ============================================================
header 35 "Checking for SANDWORM_MODE MCP worm artifacts..."

SANDWORM_ISSUES=0
SANDWORM_PKGS="@anthropic/sdk-extra|@anthropic/cli-tools|claude-code-utils|claude-mcp-helper|claudecode-ext|claude-dev-tools|cursor-mcp-bridge|cursor-tools-ext|mcp-server-utils|mcp-tool-runner|mcp-proxy-server|windsurf-mcp-bridge|continue-mcp-ext|vscode-ai-helper|ai-code-review|copilot-mcp-bridge|openai-mcp-tools|llm-gateway-utils|agent-tool-sdk"

WORM_CONFIG_FILES=(
    "$HOME/.claude.json"
    "$HOME/.claude/config.json"
    "$HOME/.cursor/mcp.json"
    "$HOME/.continue/config.json"
    "$HOME/.windsurf/mcp.json"
    "$HOME/.vscode/mcp.json"
)

for WCONF in "${WORM_CONFIG_FILES[@]}"; do
    if [ -f "$WCONF" ]; then
        for SPKG in $(echo "$SANDWORM_PKGS" | tr '|' ' '); do
            if grep -q "$SPKG" "$WCONF" 2>/dev/null; then
                result_critical "SANDWORM_MODE worm artifact: '$SPKG' found in $WCONF"
                SANDWORM_ISSUES=$((SANDWORM_ISSUES + 1))
            fi
        done
        if grep -iE '(ssh_key|aws_secret|npm_token|anthropic_api_key|openai_api_key|GROQ_API_KEY)' "$WCONF" 2>/dev/null | grep -vq '^#'; then
            result_critical "Credential harvesting pattern in MCP config: $WCONF"
            SANDWORM_ISSUES=$((SANDWORM_ISSUES + 1))
        fi
    fi
done

if command -v npm &>/dev/null; then
    NPM_LIST=$(npm list -g --depth=0 2>/dev/null || true)
    for SPKG in $(echo "$SANDWORM_PKGS" | tr '|' ' '); do
        if echo "$NPM_LIST" | grep -q "$SPKG" 2>/dev/null; then
            result_critical "SANDWORM_MODE malicious npm package installed: $SPKG"
            SANDWORM_ISSUES=$((SANDWORM_ISSUES + 1))
        fi
    done
fi

if [ "$SANDWORM_ISSUES" -eq 0 ]; then
    result_clean "No SANDWORM_MODE worm artifacts detected"
fi

# ============================================================
# CHECK 36: Workspace Plugin Auto-Discovery
# (was old check 60)
# ============================================================
header 36 "Checking for workspace plugin auto-discovery risks..."

WPA_ISSUES=0
WORKSPACE_PLUGIN_ROOTS=(
    "$WORKSPACE_DIR"
    "$(pwd)"
)

WPA_SEEN=""
for WROOT in "${WORKSPACE_PLUGIN_ROOTS[@]}"; do
    [ -d "$WROOT" ] || continue
    while IFS= read -r extdir; do
        [ -z "$extdir" ] && continue
        case "$WPA_SEEN" in
            *"|$extdir|"*) continue ;;
        esac
        WPA_SEEN="${WPA_SEEN}|$extdir|"
        if [[ "$extdir" == *"/$SELF_DIR_NAME/"* ]]; then
            continue
        fi
        result_critical "Workspace plugin auto-discovery candidate found: $extdir"
        WPA_ISSUES=$((WPA_ISSUES + 1))
    done < <(find "$WROOT" -maxdepth 5 -type d -path "*/.openclaw/extensions" 2>/dev/null)
done

if command -v openclaw &>/dev/null; then
    PLUGIN_DISCOVERY=$(run_with_timeout 10 openclaw config get "plugins.workspaceDiscovery" 2>/dev/null || echo "")
    if [ "$PLUGIN_DISCOVERY" = "true" ] || [ "$PLUGIN_DISCOVERY" = "on" ] || [ "$PLUGIN_DISCOVERY" = "auto" ]; then
        result_warn "Workspace plugin discovery is enabled ($PLUGIN_DISCOVERY)"
        WPA_ISSUES=$((WPA_ISSUES + 1))
    fi
fi

if version_lt "${OC_VERSION:-unknown}" "2026.3.13" && [ "$WPA_ISSUES" -gt 0 ]; then
    log "  Advisory coverage: GHSA-99qw-6mr3-36qr (workspace plugin auto-discovery)"
fi

if [ "$WPA_ISSUES" -eq 0 ]; then
    result_clean "No workspace plugin auto-discovery risks detected"
fi

# ============================================================
# CHECK 37: Symlink Traversal
# (NEW - CVE-2026-32013, CVE-2026-32055)
# ============================================================
header 37 "Checking symlink traversal protections (CVE-2026-32013, CVE-2026-32055)..."

SYMLINK37_ISSUES=0

# CVE-2026-32013: agents.files.get/set follows symlinks to read/write outside workspace root
# CVE-2026-32055: In-workspace symlinks created by agents escape sandbox boundaries
# Both fixed in v2026.3.21
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.3.21" "agents.files.get/set symlink escape (CVE-2026-32013) and in-workspace symlink traversal (CVE-2026-32055)"; then
        SYMLINK37_ISSUES=$((SYMLINK37_ISSUES + 1))
    fi
fi

# Scan workspace for suspicious symlinks pointing outside workspace root
if [ -d "$WORKSPACE_DIR" ]; then
    SUSPICIOUS_SYMLINKS=""
    while IFS= read -r symlink; do
        [ -z "$symlink" ] && continue
        LINK_TARGET=$(readlink -f "$symlink" 2>/dev/null || readlink "$symlink" 2>/dev/null || echo "")
        if [ -n "$LINK_TARGET" ]; then
            case "$LINK_TARGET" in
                "$WORKSPACE_DIR"*) ;; # within workspace, OK
                *)
                    SUSPICIOUS_SYMLINKS="$SUSPICIOUS_SYMLINKS\n  $symlink -> $LINK_TARGET"
                    ;;
            esac
        fi
    done < <(find "$WORKSPACE_DIR" -type l -maxdepth 5 2>/dev/null | head -20)

    if [ -n "$SUSPICIOUS_SYMLINKS" ]; then
        result_warn "Symlinks pointing outside workspace root:$SUSPICIOUS_SYMLINKS"
        SYMLINK37_ISSUES=$((SYMLINK37_ISSUES + 1))
    fi
fi

if [ "$SYMLINK37_ISSUES" -eq 0 ]; then
    result_clean "Symlink traversal protections acceptable"
fi

# ============================================================
# CHECK 38: Sandbox Escape & Session Inheritance
# (NEW - CVE-2026-32048, CVE-2026-32051)
# ============================================================
header 38 "Checking sandbox escape and session inheritance (CVE-2026-32048, CVE-2026-32051)..."

ESCAPE38_ISSUES=0

# CVE-2026-32048: sessions_spawn bypass allows sandbox escape via session inheritance
# CVE-2026-32051: operator.write auth scope mismatch allows cross-session writes
# Both fixed in v2026.3.21
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.3.21" "sessions_spawn sandbox escape (CVE-2026-32048) and operator.write auth mismatch (CVE-2026-32051)"; then
        ESCAPE38_ISSUES=$((ESCAPE38_ISSUES + 1))
    fi

    # Check if session spawning is enabled
    SESSION_SPAWN=$(run_with_timeout 5 openclaw config get "sessions.spawn.enabled" 2>/dev/null || echo "")
    if [ "$SESSION_SPAWN" = "true" ] && [ "$ESCAPE38_ISSUES" -gt 0 ]; then
        log "  Session spawning is enabled — sandbox escape attack surface is active"
    fi

    # Check operator.write scope
    OP_WRITE=$(run_with_timeout 5 openclaw config get "permissions.operator.write" 2>/dev/null || echo "")
    if [ -n "$OP_WRITE" ] && [ "$OP_WRITE" != "false" ] && [ "$ESCAPE38_ISSUES" -gt 0 ]; then
        log "  operator.write scope is configured — cross-session write risk elevated"
    fi
fi

if [ "$ESCAPE38_ISSUES" -eq 0 ]; then
    result_clean "Sandbox escape and session inheritance checks passed"
fi

# ============================================================
# CHECK 39: Shell Environment RCE
# (NEW - CVE-2026-32056, CVE-2026-27566)
# ============================================================
header 39 "Checking shell environment RCE vectors (CVE-2026-32056, CVE-2026-27566)..."

SHELLRCE39_ISSUES=0

# CVE-2026-32056: HOME/ZDOTDIR injection in system.run allows .zshrc/.bashrc execution in agent context
# CVE-2026-27566: env/wrapper binary unwrapping in PATH allows arbitrary code execution before sandboxing
# Both fixed in v2026.3.21
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.3.21" "HOME/ZDOTDIR injection in system.run (CVE-2026-32056) and env/wrapper binary unwrapping (CVE-2026-27566)"; then
        SHELLRCE39_ISSUES=$((SHELLRCE39_ISSUES + 1))
    fi
fi

# Check for suspicious ZDOTDIR overrides
if [ -n "${ZDOTDIR:-}" ] && [ "$ZDOTDIR" != "$HOME" ]; then
    result_warn "ZDOTDIR is set to '$ZDOTDIR' (non-default — potential CVE-2026-32056 vector)"
    SHELLRCE39_ISSUES=$((SHELLRCE39_ISSUES + 1))
fi

# Check for wrapper/shim binaries that could be unwrapped unsafely
for WBIN in env bash zsh; do
    WBIN_PATH=$(command -v "$WBIN" 2>/dev/null || true)
    if [ -n "$WBIN_PATH" ] && [ -L "$WBIN_PATH" ]; then
        REAL_BIN=$(readlink -f "$WBIN_PATH" 2>/dev/null || readlink "$WBIN_PATH" 2>/dev/null || echo "")
        if [ -n "$REAL_BIN" ] && [[ "$REAL_BIN" != /usr/* ]] && [[ "$REAL_BIN" != /bin/* ]] && [[ "$REAL_BIN" != /opt/homebrew/* ]]; then
            result_warn "'$WBIN' resolves to non-system path: $REAL_BIN (CVE-2026-27566 vector)"
            SHELLRCE39_ISSUES=$((SHELLRCE39_ISSUES + 1))
        fi
    fi
done

if [ "$SHELLRCE39_ISSUES" -eq 0 ]; then
    result_clean "Shell environment RCE vectors acceptable"
fi

# ============================================================
# CHECK 40: VNC & Observer Authentication
# (NEW - CVE-2026-32064)
# ============================================================
header 40 "Checking VNC and observer authentication (CVE-2026-32064)..."

VNC40_ISSUES=0

# CVE-2026-32064: Missing authentication on noVNC sandbox observer sessions allows
# unauthenticated screen viewing and interaction with sandboxed agent sessions
# Fixed in v2026.3.21
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.3.21" "missing VNC auth for noVNC sandbox observer sessions (CVE-2026-32064)"; then
        VNC40_ISSUES=$((VNC40_ISSUES + 1))
    fi
fi

# Check if noVNC/VNC ports are listening
for VNC_PORT in 5900 5901 6080 6081; do
    if command -v lsof &>/dev/null; then
        VNC_LISTEN=$(lsof -iTCP:$VNC_PORT -sTCP:LISTEN -nP 2>/dev/null | grep -v COMMAND)
        if [ -n "$VNC_LISTEN" ]; then
            log "  VNC/noVNC service listening on port $VNC_PORT"
            if [ "$VNC40_ISSUES" -gt 0 ]; then
                log "  Active VNC listener with unauthenticated observer vulnerability"
            fi
        fi
    fi
done

# Check observer config
if command -v openclaw &>/dev/null; then
    OBSERVER_MODE=$(run_with_timeout 5 openclaw config get "sandbox.observer.enabled" 2>/dev/null || echo "")
    if [ "$OBSERVER_MODE" = "true" ] && [ "$VNC40_ISSUES" -gt 0 ]; then
        log "  Sandbox observer mode is enabled — CVE-2026-32064 attack surface is active"
    fi
fi

if [ "$VNC40_ISSUES" -eq 0 ]; then
    result_clean "VNC and observer authentication acceptable"
fi

# ============================================================
# CHECK 41: Device Identity & Metadata Spoofing
# (NEW - CVE-2026-32014, CVE-2026-32042, CVE-2026-32025)
# ============================================================
header 41 "Checking device identity and metadata spoofing (CVE-2026-32014, CVE-2026-32042, CVE-2026-32025)..."

DEVID41_ISSUES=0

# CVE-2026-32014: Reconnect field spoofing allows session hijacking via forged device metadata
# CVE-2026-32042: Unpaired devices can self-assign admin role during initial connection
# CVE-2026-32025: Origin bypass combined with brute-force enables unauthorized device registration
# All fixed in v2026.3.21
if command -v openclaw &>/dev/null && [ -n "${OC_VERSION:-}" ] && [ "${OC_VERSION:-}" != "unknown" ]; then
    if version_advisory "2026.3.21" "reconnect field spoofing (CVE-2026-32014), unpaired device admin self-assign (CVE-2026-32042), origin bypass brute-force (CVE-2026-32025)"; then
        DEVID41_ISSUES=$((DEVID41_ISSUES + 1))
    fi
fi

# Check for stale/unexpected device registrations
DEVICE_DIR="$OPENCLAW_DIR/devices"
if [ -d "$DEVICE_DIR" ]; then
    DEVICE_COUNT=$(find "$DEVICE_DIR" -type f -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$DEVICE_COUNT" -gt 10 ]; then
        result_warn "Unusually high number of registered devices ($DEVICE_COUNT) — review for unauthorized registrations"
        DEVID41_ISSUES=$((DEVID41_ISSUES + 1))
    elif [ "$DEVICE_COUNT" -gt 0 ]; then
        log "  Registered devices: $DEVICE_COUNT"
    fi
fi

# Check if auto-pairing is enabled (increases exposure to CVE-2026-32042)
if command -v openclaw &>/dev/null; then
    AUTO_PAIR=$(run_with_timeout 5 openclaw config get "pairing.autoAccept" 2>/dev/null || echo "")
    if [ "$AUTO_PAIR" = "true" ]; then
        result_warn "Auto-pairing is enabled (pairing.autoAccept=true) — increases CVE-2026-32042 exposure"
        DEVID41_ISSUES=$((DEVID41_ISSUES + 1))
    fi
fi

if [ "$DEVID41_ISSUES" -eq 0 ]; then
    result_clean "Device identity and metadata spoofing checks passed"
fi

# ============================================================
# SUMMARY
# ============================================================
log ""
log "========================================"
log "SCAN COMPLETE: $CRITICAL critical, $WARNINGS warnings, $CLEAN clean"
log "========================================"

if [ "$CRITICAL" -gt 0 ]; then
    log "STATUS: COMPROMISED - Immediate action required"
    exit 2
elif [ "$WARNINGS" -gt 0 ]; then
    log "STATUS: ATTENTION - Review warnings"
    exit 1
else
    log "STATUS: SECURE"
    exit 0
fi
