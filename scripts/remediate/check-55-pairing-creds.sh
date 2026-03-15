#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 55: Device pairing credential exposure (GHSA-7h7g-x2px-94hj)"

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
        if [ "$MINOR" -lt 3 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        elif [ "$MINOR" -eq 3 ] && [ "$PATCH" -lt 12 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "WARNING: GHSA-7h7g - Device pairing credential exposure"
    log "=========================================="
    log ""
    log "Setup codes expose long-lived gateway credentials instead of"
    log "short-lived bootstrap tokens. Compromised codes grant persistent access."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.3.12+"
    log "   openclaw update"
    log ""
    log "POST-UPDATE: Rotate device credentials:"
    log "   openclaw device rotate-credentials"
    log ""

    guidance \
        "Update OpenClaw to v2026.3.12+ to fix GHSA-7h7g" \
        "Rotate device credentials after upgrading"
fi

finish
