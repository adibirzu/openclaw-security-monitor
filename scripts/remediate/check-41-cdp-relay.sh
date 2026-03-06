#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 41: Browser Relay CDP unauthenticated access (CVE-2026-28458, CVSS 7.5)"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  OpenClaw version: $OC_VERSION"

NEEDS_UPDATE=false
if [ "$OC_VERSION" != "unknown" ]; then
    MAJOR=$(echo "$OC_VERSION" | cut -d'.' -f1)
    MINOR=$(echo "$OC_VERSION" | cut -d'.' -f2)
    PATCH=$(echo "$OC_VERSION" | cut -d'.' -f3 | cut -d'-' -f1)
    if [ "$MAJOR" -eq 2026 ] 2>/dev/null; then
        if [ "$MINOR" -lt 2 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        elif [ "$MINOR" -eq 2 ] && [ "$PATCH" -lt 1 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28458 - Browser Relay /cdp unauthenticated"
    log "=========================================="
    log ""
    log "The Browser Relay /cdp WebSocket endpoint does not require auth"
    log "tokens. Websites can connect via ws://127.0.0.1:18792/cdp to"
    log "steal session cookies and execute JavaScript in other browser tabs."
    log ""
    log "RECOMMENDED ACTIONS:"
    log "1. Update OpenClaw immediately:"
    log "   openclaw update"
    log ""
    log "2. Disable Browser Relay until patched:"
    log "   openclaw config set browser.relay.enabled false"
    log ""

    if confirm "Disable Browser Relay until update?"; then
        if $DRY_RUN; then
            log "  [DRY-RUN] Would set browser.relay.enabled=false"
            FIXED=$((FIXED + 1))
        else
            if openclaw config set browser.relay.enabled false 2>/dev/null; then
                log "  FIXED: Disabled Browser Relay"
                FIXED=$((FIXED + 1))
            else
                log "  FAILED: Could not disable Browser Relay"
                FAILED=$((FAILED + 1))
            fi
        fi
    fi

    guidance "Update OpenClaw to v2026.2.1+ to fix CVE-2026-28458"
fi

finish
