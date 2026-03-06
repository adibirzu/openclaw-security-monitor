#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 48: fetchWithGuard memory exhaustion DoS (CVE-2026-29609, CVSS 7.5)"

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
    log "WARNING: CVE-2026-29609 - fetchWithGuard memory DoS"
    log "=========================================="
    log ""
    log "fetchWithGuard allocates entire response payloads in memory"
    log "before enforcing maxBytes limits. Oversized responses without"
    log "Content-Length headers cause memory exhaustion and service"
    log "disruption."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.14+"
    log "   openclaw update"
    log ""
    log "INTERIM: Configure Node.js --max-old-space-size to limit"
    log "process memory if running internet-facing."
    log ""

    guidance "Update OpenClaw to v2026.2.14+ to fix CVE-2026-29609"
fi

finish
