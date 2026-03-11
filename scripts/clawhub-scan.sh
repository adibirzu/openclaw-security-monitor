#!/bin/bash
# OpenClaw Security Monitor - ClawHub Skill Scanner v1.0
# https://github.com/adibirzu/openclaw-security-monitor
#
# Scans locally installed ClawHub skills for security issues:
#   - Malicious publishers (ioc/malicious-publishers.txt)
#   - Malicious skill name patterns (ioc/malicious-skill-patterns.txt)
#   - Suspicious script patterns (curl|bash, base64, reverse shells, etc.)
#   - C2 IP / malicious domain references (ioc/c2-ips.txt, ioc/malicious-domains.txt)
#   - SKILL.md integrity (shell injection in Prerequisites)
#   - Known malicious file hashes (ioc/file-hashes.txt)
#
# Exit codes: 0=all clean, 1=warnings found, 2=critical findings
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IOC_DIR="$PROJECT_DIR/ioc"
SELF_DIR_NAME="$(basename "$PROJECT_DIR")"

OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
SKILLS_DIR="$OPENCLAW_DIR/workspace/skills"
LOG_DIR="$OPENCLAW_DIR/logs"
LOG_FILE="$LOG_DIR/clawhub-scan.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

CRITICAL=0
WARNINGS=0
CLEAN=0
TOTAL_CHECKS=0

mkdir -p "$LOG_DIR"

log()            { echo "$1" | tee -a "$LOG_FILE"; }
result_clean()   { log "CLEAN: $1";    CLEAN=$((CLEAN + 1)); }
result_warn()    { log "WARNING: $1";  WARNINGS=$((WARNINGS + 1)); }
result_critical(){ log "CRITICAL: $1"; CRITICAL=$((CRITICAL + 1)); }

# ============================================================
# IOC loaders — same helpers as scan.sh
# ============================================================
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

load_publishers() {
    if [ -f "$IOC_DIR/malicious-publishers.txt" ]; then
        grep -v '^#' "$IOC_DIR/malicious-publishers.txt" | grep -v '^$' | cut -d'|' -f1
    fi
}

load_skill_patterns() {
    if [ -f "$IOC_DIR/malicious-skill-patterns.txt" ]; then
        grep -v '^#' "$IOC_DIR/malicious-skill-patterns.txt" | grep -v '^$' | cut -d'|' -f1
    fi
}

load_hashes() {
    if [ -f "$IOC_DIR/file-hashes.txt" ]; then
        grep -v '^#' "$IOC_DIR/file-hashes.txt" | grep -v '^$' | cut -d'|' -f1
    fi
}

# ============================================================
# Parse SKILL.md frontmatter: returns value for a given key
# ============================================================
parse_frontmatter() {
    local skillmd="$1"
    local key="$2"
    # Frontmatter is between the first and second --- lines
    awk '/^---/{if(++n==2)exit} n==1 && /^'"$key"':/{sub(/^'"$key"':[[:space:]]*/,""); print}' "$skillmd"
}

# ============================================================
# Header / summary helpers
# ============================================================
skill_header() {
    log ""
    log "  -- Skill: $1 --"
}

# ============================================================
# Pre-flight
# ============================================================
log "========================================"
log "CLAWHUB SKILL SCAN - $TIMESTAMP"
log "Scanner: v1.0 (openclaw-security-monitor)"
log "========================================"
log ""

if [ ! -d "$SKILLS_DIR" ]; then
    log "INFO: Skills directory not found: $SKILLS_DIR"
    log "INFO: No skills to scan."
    log ""
    log "=== Summary ==="
    log "  Skills scanned: 0"
    log "  Critical: 0 | Warnings: 0 | Clean: 0"
    exit 0
fi

# ============================================================
# Collect skill list (skip self)
# ============================================================
SKILL_DIRS=()
for skilldir in "$SKILLS_DIR"/*/; do
    sname="$(basename "$skilldir")"
    [ "$sname" = "$SELF_DIR_NAME" ] && continue
    [ -d "$skilldir" ] || continue
    SKILL_DIRS+=("$skilldir")
done

SKILL_COUNT="${#SKILL_DIRS[@]}"
log "Skills found: $SKILL_COUNT"
log ""

if [ "$SKILL_COUNT" -eq 0 ]; then
    log "INFO: No third-party skills installed."
    log ""
    log "=== Summary ==="
    log "  Skills scanned: 0"
    log "  Critical: 0 | Warnings: 0 | Clean: 0"
    exit 0
fi

# Pre-build IOC lookup arrays
C2_IPS=$(load_ips)
C2_PATTERN=$(echo "$C2_IPS" | tr '\n' '|' | sed 's/|$//' | sed 's/\./\\./g')
DOMAIN_PATTERN=$(load_domains | tr '\n' '|' | sed 's/|$//' | sed 's/\./\\./g')
PUBLISHERS=$(load_publishers)
SKILL_PATTERNS=$(load_skill_patterns)
FILE_HASHES=$(load_hashes)

# ============================================================
# Per-skill scan loop
# ============================================================
for skilldir in "${SKILL_DIRS[@]}"; do
    sname="$(basename "$skilldir")"
    skillmd="$skilldir/SKILL.md"
    skill_header "$sname"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 7))  # 7 check categories per skill

    # ----------------------------------------------------------
    # CHECK A: Read SKILL.md frontmatter
    # ----------------------------------------------------------
    SKILL_NAME_META=""
    SKILL_VERSION=""
    SKILL_AUTHOR=""

    if [ -f "$skillmd" ]; then
        SKILL_NAME_META="$(parse_frontmatter "$skillmd" "name")"
        SKILL_VERSION="$(parse_frontmatter "$skillmd" "version")"
        SKILL_AUTHOR="$(parse_frontmatter "$skillmd" "author")"
        log "  Meta: name=${SKILL_NAME_META:-<none>} version=${SKILL_VERSION:-<none>} author=${SKILL_AUTHOR:-<none>}"
    else
        result_warn "[$sname] No SKILL.md found — unregistered skill"
        SKILL_NAME_META="$sname"
    fi

    # ----------------------------------------------------------
    # CHECK B: Author against malicious publishers list
    # ----------------------------------------------------------
    AUTHOR_HIT=false
    if [ -n "$SKILL_AUTHOR" ] && [ -n "$PUBLISHERS" ]; then
        while IFS= read -r pub; do
            [ -z "$pub" ] && continue
            if echo "$SKILL_AUTHOR" | grep -qiF "$pub" 2>/dev/null; then
                result_critical "[$sname] Author '$SKILL_AUTHOR' matches malicious publisher: $pub"
                AUTHOR_HIT=true
                break
            fi
        done <<< "$PUBLISHERS"
    fi
    if [ "$AUTHOR_HIT" = false ]; then
        result_clean "[$sname] Author not in malicious publishers list"
    fi

    # ----------------------------------------------------------
    # CHECK C: Skill name against malicious patterns
    # ----------------------------------------------------------
    NAME_HIT=false
    DISPLAY_NAME="${SKILL_NAME_META:-$sname}"
    if [ -n "$SKILL_PATTERNS" ]; then
        while IFS= read -r pattern; do
            [ -z "$pattern" ] && continue
            # Convert glob-style wildcards to ERE: * -> .*
            ere_pattern="$(echo "$pattern" | sed 's/\*/\.\*/g')"
            if echo "$DISPLAY_NAME" | grep -qiE "$ere_pattern" 2>/dev/null; then
                result_warn "[$sname] Skill name '$DISPLAY_NAME' matches malicious pattern: $pattern"
                NAME_HIT=true
                break
            fi
        done <<< "$SKILL_PATTERNS"
    fi
    if [ "$NAME_HIT" = false ]; then
        result_clean "[$sname] Skill name does not match malicious patterns"
    fi

    # ----------------------------------------------------------
    # CHECK D: Suspicious script patterns
    # ----------------------------------------------------------
    SCRIPT_ISSUES=0

    # D1: curl/wget piped to shell
    CURL_PIPE_PATTERN="curl[[:space:]].*\|[[:space:]]*(ba)?sh|wget[[:space:]].*\|[[:space:]]*(ba)?sh|curl -fsSL.*\||wget -q.*\||curl.*-o[[:space:]]*/tmp/"
    CURL_HITS=$(grep -rlinE --include="*.sh" --include="*.bash" --include="*.zsh" \
        --include="*.py" --include="*.js" --include="*.ts" \
        "$CURL_PIPE_PATTERN" "$skilldir" 2>/dev/null || true)
    if [ -n "$CURL_HITS" ]; then
        result_warn "[$sname] curl/wget pipe-to-shell pattern detected:"
        log "    $CURL_HITS"
        SCRIPT_ISSUES=$((SCRIPT_ISSUES + 1))
    fi

    # D2: Base64 encoded payloads
    BASE64_PATTERN="base64[[:space:]]+-d|base64[[:space:]]+--decode|echo[[:space:]]+['\"][A-Za-z0-9+/=]{40,}['\"][[:space:]]*\|[[:space:]]*(base64|ba?sh)|eval[[:space:]]+\\\$\\(.*base64"
    BASE64_HITS=$(grep -rlinE --include="*.sh" --include="*.bash" --include="*.zsh" \
        --include="*.py" --include="*.js" --include="*.ts" \
        "$BASE64_PATTERN" "$skilldir" 2>/dev/null || true)
    if [ -n "$BASE64_HITS" ]; then
        result_warn "[$sname] Base64 decode/eval pattern detected:"
        log "    $BASE64_HITS"
        SCRIPT_ISSUES=$((SCRIPT_ISSUES + 1))
    fi

    # D3: C2 IP references
    if [ -n "$C2_PATTERN" ]; then
        C2_HITS=$(grep -rlinE "$C2_PATTERN" "$skilldir" 2>/dev/null || true)
        if [ -n "$C2_HITS" ]; then
            result_critical "[$sname] Known C2 IP reference found:"
            log "    $C2_HITS"
            SCRIPT_ISSUES=$((SCRIPT_ISSUES + 1))
        fi
    fi

    # D4: Malicious domain references
    if [ -n "$DOMAIN_PATTERN" ]; then
        DOMAIN_HITS=$(grep -rlinE "$DOMAIN_PATTERN" "$skilldir" 2>/dev/null || true)
        if [ -n "$DOMAIN_HITS" ]; then
            result_critical "[$sname] Malicious domain reference found:"
            log "    $DOMAIN_HITS"
            SCRIPT_ISSUES=$((SCRIPT_ISSUES + 1))
        fi
    fi

    # D5: Reverse shell patterns
    REVSHELL_PATTERN="nc[[:space:]]+-e|/dev/tcp/|mkfifo.*nc|bash[[:space:]]+-i[[:space:]]+>|socat.*exec|python.*socket.*connect|nohup.*bash.*tcp|perl.*socket.*INET|ruby.*TCPSocket|php.*fsockopen|lua.*socket\.tcp"
    REVSHELL_HITS=$(grep -rlinE --include="*.sh" --include="*.bash" --include="*.zsh" \
        --include="*.py" --include="*.js" --include="*.ts" \
        "$REVSHELL_PATTERN" "$skilldir" 2>/dev/null || true)
    if [ -n "$REVSHELL_HITS" ]; then
        result_critical "[$sname] Reverse shell pattern detected:"
        log "    $REVSHELL_HITS"
        SCRIPT_ISSUES=$((SCRIPT_ISSUES + 1))
    fi

    # D6: Credential file access patterns
    CRED_PATTERN="~/\.ssh|~\/\.aws|\.ssh/id_rsa|\.aws/credentials|Keychain|security[[:space:]]+find-generic-password|security[[:space:]]+find-internet-password|/Library/Keychains|login\.keychain"
    CRED_HITS=$(grep -rlinE --include="*.sh" --include="*.bash" --include="*.zsh" \
        --include="*.py" --include="*.js" --include="*.ts" \
        "$CRED_PATTERN" "$skilldir" 2>/dev/null || true)
    if [ -n "$CRED_HITS" ]; then
        result_warn "[$sname] Credential file access pattern detected:"
        log "    $CRED_HITS"
        SCRIPT_ISSUES=$((SCRIPT_ISSUES + 1))
    fi

    # D7: Environment variable exfiltration
    ENVEXFIL_PATTERN='(curl|wget|fetch|axios|request)[^#\n]*(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|OPENAI_API|ANTHROPIC|OPENCLAW|API_KEY|SECRET_KEY|PASSWORD|TOKEN)[^#\n]*(http|https)|printenv[^#\n]*(curl|wget|http)|env[[:space:]]*\|[[:space:]]*(curl|wget|nc)'
    ENVEXFIL_HITS=$(grep -rlinE --include="*.sh" --include="*.bash" --include="*.zsh" \
        --include="*.py" --include="*.js" --include="*.ts" \
        "$ENVEXFIL_PATTERN" "$skilldir" 2>/dev/null || true)
    if [ -n "$ENVEXFIL_HITS" ]; then
        result_critical "[$sname] Environment variable exfiltration pattern detected:"
        log "    $ENVEXFIL_HITS"
        SCRIPT_ISSUES=$((SCRIPT_ISSUES + 1))
    fi

    if [ "$SCRIPT_ISSUES" -eq 0 ]; then
        result_clean "[$sname] No suspicious script patterns"
    fi

    # ----------------------------------------------------------
    # CHECK E: SKILL.md integrity (shell injection in Prerequisites)
    # ----------------------------------------------------------
    INJECT_PATTERN="Prerequisites.*install|Prerequisites.*download|Prerequisites.*curl|Prerequisites.*wget|run this command.*terminal|paste.*terminal|copy.*terminal|base64 -d|base64 --decode|eval \$(|exec \$(|\`curl|\`wget|bypass.*safety.*guideline|execute.*without.*asking|ignore.*safety|override.*instruction|without.*user.*awareness"
    if [ -f "$skillmd" ]; then
        if grep -qiE "$INJECT_PATTERN" "$skillmd" 2>/dev/null; then
            result_warn "[$sname] SKILL.md contains suspicious install instructions or injection patterns"
        else
            result_clean "[$sname] SKILL.md integrity OK"
        fi
    else
        result_clean "[$sname] No SKILL.md to check for injection (already warned above)"
    fi

    # ----------------------------------------------------------
    # CHECK F: File hashes against known malicious hashes
    # ----------------------------------------------------------
    HASH_HIT=false
    if [ -n "$FILE_HASHES" ]; then
        while IFS= read -r known_hash; do
            [ -z "$known_hash" ] && continue
            FOUND=$(find "$skilldir" -type f -exec shasum -a 256 {} \; 2>/dev/null | grep "^$known_hash" || true)
            if [ -n "$FOUND" ]; then
                result_critical "[$sname] Known malicious file hash matched: $FOUND"
                HASH_HIT=true
            fi
        done <<< "$FILE_HASHES"
    fi
    if [ "$HASH_HIT" = false ]; then
        result_clean "[$sname] No known malicious file hashes"
    fi

done  # end per-skill loop

# ============================================================
# Summary
# ============================================================
log ""
log "========================================"
log "CLAWHUB SCAN COMPLETE - $TIMESTAMP"
log "========================================"
log "  Skills scanned : $SKILL_COUNT"
log "  Total checks   : $TOTAL_CHECKS"
log "  Critical       : $CRITICAL"
log "  Warnings       : $WARNINGS"
log "  Clean          : $CLEAN"
log ""

if [ "$CRITICAL" -gt 0 ]; then
    log "STATUS: CRITICAL — $CRITICAL critical finding(s) detected. Immediate action required."
    exit 2
elif [ "$WARNINGS" -gt 0 ]; then
    log "STATUS: WARNING — $WARNINGS warning(s) detected. Review recommended."
    exit 1
else
    log "STATUS: CLEAN — All $SKILL_COUNT skills passed ClawHub security checks."
    exit 0
fi
