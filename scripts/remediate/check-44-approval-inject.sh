#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 44: Approval field injection / exec gating bypass (CVE-2026-28466)"

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
        elif [ "$MINOR" -eq 2 ] && [ "$PATCH" -lt 14 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28466 - Approval field injection"
    log "=========================================="
    log ""
    log "The gateway fails to sanitize internal approval fields in"
    log "node.invoke parameters. Authenticated clients can bypass exec"
    log "approval gating for system.run commands by injecting approval"
    log "fields into the request."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.14+"
    log "   openclaw update"
    log ""

    guidance "Update OpenClaw to v2026.2.14+ to fix CVE-2026-28466"
fi

finish
