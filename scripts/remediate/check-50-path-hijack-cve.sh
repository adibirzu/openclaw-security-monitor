#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 50: PATH command hijacking (CVE-2026-29610)"

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
    log "WARNING: CVE-2026-29610 - PATH command hijacking"
    log "=========================================="
    log ""
    log "OpenClaw may resolve command names against user PATH before"
    log "system binaries, allowing hijack from writable directories."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.14+"
    log "   openclaw update"
    log ""
    log "INTERIM HARDENING:"
    log "  1) Ensure system dirs are first in PATH:"
    log "     export PATH=/usr/bin:/bin:/usr/sbin:/sbin:\$PATH"
    log "  2) Remove writable directories from PATH when possible."
    log ""

    guidance \
        "Update OpenClaw to v2026.2.14+ to fix CVE-2026-29610" \
        "Prioritize system directories first in PATH as interim mitigation"
fi

finish
