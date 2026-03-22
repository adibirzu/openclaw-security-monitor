#!/bin/bash
# OpenClaw Security Monitor - Shared Remediation Helpers
# Sourced by each per-check remediation script
# https://github.com/adibirzu/openclaw-security-monitor

OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
SKILLS_DIR="$OPENCLAW_DIR/workspace/skills"
COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "$COMMON_DIR/.." && pwd)"
SELF_DIR_NAME="$(basename "$SKILL_ROOT")"
export PATH="$HOME/.local/bin:/opt/homebrew/opt/node@22/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
LOG_DIR="$OPENCLAW_DIR/logs"
LOG_FILE="$LOG_DIR/remediation.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

FIXED=0
FAILED=0
AUTO=false
DRY_RUN=false
ALLOW_UNATTENDED="${OPENCLAW_ALLOW_UNATTENDED_REMEDIATE:-0}"

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --yes|-y)
            if [ "$ALLOW_UNATTENDED" = "1" ]; then
                AUTO=true
            else
                echo "INFO: --yes ignored. Set OPENCLAW_ALLOW_UNATTENDED_REMEDIATE=1 to enable unattended remediation." >&2
            fi
            ;;
        --dry-run) DRY_RUN=true ;;
    esac
done

mkdir -p "$LOG_DIR" 2>/dev/null

log() {
    local msg="[$TIMESTAMP] $1"
    echo "$msg"
    if ! $DRY_RUN; then
        echo "$msg" >> "$LOG_FILE" 2>/dev/null
    fi
}

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

confirm() {
    local prompt="$1"
    if $AUTO; then return 0; fi
    printf "%s [y/N] " "$prompt"
    read -r answer
    [[ "$answer" =~ ^[Yy] ]]
}

is_self_skill() {
    local path="$1"
    if [[ "$path" == *"/$SELF_DIR_NAME/"* ]] || [[ "$(basename "$path")" == "$SELF_DIR_NAME" ]]; then
        return 0
    fi
    return 1
}

fix_perms() {
    local target="$1"
    local mode="$2"
    local label="$3"
    if [ ! -e "$target" ]; then
        return 1
    fi
    local current
    current=$(stat -f "%Lp" "$target" 2>/dev/null || stat -c "%a" "$target" 2>/dev/null)
    if [ "$current" = "$mode" ]; then
        return 1  # already correct
    fi
    if $DRY_RUN; then
        log "  [DRY-RUN] Would chmod $mode $target ($label, currently $current)"
        FIXED=$((FIXED + 1))
        return 0
    fi
    if chmod "$mode" "$target" 2>/dev/null; then
        log "  FIXED: chmod $mode $target ($label, was $current)"
        FIXED=$((FIXED + 1))
    else
        log "  FAILED: chmod $mode $target ($label)"
        FAILED=$((FAILED + 1))
    fi
}

# Print guidance instructions (for guidance-only scripts)
# Accepts multiple arguments or reads from stdin (heredoc)
guidance() {
    echo ""
    echo "  MANUAL ACTION REQUIRED:"
    if [ $# -gt 0 ]; then
        for line in "$@"; do
            echo "  $line"
        done
    else
        while IFS= read -r line; do
            echo "  $line"
        done
    fi
    echo ""
}

# Exit with appropriate code
# 0 = fixed something, 1 = failed, 2 = nothing to fix / not applicable
finish() {
    if [ "$FIXED" -gt 0 ] && [ "$FAILED" -eq 0 ]; then
        exit 0
    elif [ "$FAILED" -gt 0 ]; then
        exit 1
    else
        exit 2
    fi
}
