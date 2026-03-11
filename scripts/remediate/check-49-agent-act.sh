#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 49: /agent/act unauthenticated access (CVE-2026-28485)"

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
        elif [ "$MINOR" -eq 2 ] && [ "$PATCH" -lt 12 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28485 - /agent/act missing auth"
    log "=========================================="
    log ""
    log "The /agent/act browser-control route may accept requests"
    log "without authentication in vulnerable versions."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.12+"
    log "   openclaw update"
    log ""
    log "INTERIM: Disable browser extension if not needed:"
    log "   openclaw config set browser.extension.enabled false"
    log ""

    guidance \
        "Update OpenClaw to v2026.2.12+ to fix CVE-2026-28485" \
        "Disable browser extension as interim mitigation if upgrade is delayed"
fi

finish
