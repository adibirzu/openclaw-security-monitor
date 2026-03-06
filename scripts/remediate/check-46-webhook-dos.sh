#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 46: Webhook DoS — oversized payloads (CVE-2026-28478)"

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
        elif [ "$MINOR" -eq 2 ] && [ "$PATCH" -lt 13 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "WARNING: CVE-2026-28478 - Webhook body size/time DoS"
    log "=========================================="
    log ""
    log "Webhook handlers buffer request bodies without strict byte or"
    log "time limits. Remote unauthenticated attackers can send oversized"
    log "JSON payloads or slow uploads to cause memory pressure."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.13+"
    log "   openclaw update"
    log ""
    log "INTERIM MITIGATION: Use a reverse proxy with body size limits"
    log "   (e.g., nginx: client_max_body_size 1m;)"
    log ""

    guidance "Update OpenClaw to v2026.2.13+ or add reverse proxy body limits"
fi

finish
