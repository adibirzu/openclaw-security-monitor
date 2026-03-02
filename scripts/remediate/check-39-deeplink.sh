#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 39: macOS deep link truncation (CVE-2026-26320)"

if [ "$(uname -s)" != "Darwin" ]; then
    log "  Not macOS, skipping"
    exit 2
fi

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  OpenClaw version: $OC_VERSION"

NEEDS_UPDATE=false
if [ "$OC_VERSION" != "unknown" ]; then
    DL_MAJOR=$(echo "$OC_VERSION" | cut -d'.' -f1)
    DL_MINOR=$(echo "$OC_VERSION" | cut -d'.' -f2)
    DL_PATCH=$(echo "$OC_VERSION" | cut -d'.' -f3 | cut -d'-' -f1)
    if [ "$DL_MAJOR" -eq 2026 ] 2>/dev/null; then
        if [ "$DL_MINOR" -lt 2 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        elif [ "$DL_MINOR" -eq 2 ] && [ "$DL_PATCH" -lt 14 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "VULNERABLE: CVE-2026-26320 - Deep link truncation"
    log "=========================================="
    log ""
    log "macOS deep link handler truncates at ~240 characters. Attackers"
    log "pad benign-looking text followed by hidden malicious instructions"
    log "that bypass the notification preview."
    log ""
    log "RECOMMENDED ACTIONS:"
    log "1. Update OpenClaw:"
    log "   openclaw update"
    log ""

    guidance "Update OpenClaw to v2026.2.14+ to fix CVE-2026-26320 deep link truncation"
fi

# Check logs for suspiciously long deep links
OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
LOG_DIR="$OPENCLAW_DIR/logs"

if [ -d "$LOG_DIR" ]; then
    LONG_LINKS=$(grep -rl 'openclaw://' "$LOG_DIR" 2>/dev/null | head -5)
    if [ -n "$LONG_LINKS" ]; then
        while IFS= read -r LFILE; do
            LONG_COUNT=$(grep -cE 'openclaw://[^ ]{240,}' "$LFILE" 2>/dev/null || echo "0")
            if [ "$LONG_COUNT" -gt 0 ]; then
                log "  WARNING: $LONG_COUNT long deep links (>240 chars) in $(basename "$LFILE")"
                log "  These may be CVE-2026-26320 exploit attempts"
                guidance "Investigate long deep links in $LFILE for hidden payloads"
            fi
        done <<< "$LONG_LINKS"
    fi
fi

finish
