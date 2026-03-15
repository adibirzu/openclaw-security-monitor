#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 53: Gateway WebSocket device identity skip (CVE-2026-28472)"

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
        elif [ "$MINOR" -eq 3 ] && [ "$PATCH" -lt 11 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28472 - Gateway WebSocket device identity skip"
    log "=========================================="
    log ""
    log "WebSocket connect handshake skips device identity checks, granting"
    log "operator access without device verification."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.3.11+"
    log "   openclaw update"
    log ""

    guidance \
        "Update OpenClaw to v2026.3.11+ to fix CVE-2026-28472" \
        "Restrict gateway binding to localhost until upgraded"
fi

finish
