#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 54: Cross-Site WebSocket Hijacking in trusted-proxy (CVE-2026-32302)"

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
    log "CRITICAL: CVE-2026-32302 - Cross-Site WebSocket Hijacking"
    log "=========================================="
    log ""
    log "Origin validation bypass in trusted-proxy mode allows attacker-origin"
    log "pages to establish privileged operator sessions via WebSocket."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.3.11+"
    log "   openclaw update"
    log ""
    log "INTERIM: Disable trusted-proxy mode if not required:"
    log "   openclaw config set gateway.trustedProxy false"
    log ""

    guidance \
        "Update OpenClaw to v2026.3.11+ to fix CVE-2026-32302" \
        "Disable trusted-proxy mode as interim mitigation"
fi

finish
