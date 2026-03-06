#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 42: Browser control API path traversal (CVE-2026-28462, CVSS 7.5)"

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
    log "CRITICAL: CVE-2026-28462 - Browser control path traversal"
    log "=========================================="
    log ""
    log "Browser control API accepts user-supplied output paths for trace"
    log "and download files without constraining writes to temp directories."
    log "Attackers can exploit /trace/stop, /wait/download, /download to"
    log "write files outside intended roots."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.13+"
    log "   openclaw update"
    log ""

    guidance "Update OpenClaw to v2026.2.13+ to fix CVE-2026-28462 path traversal"
fi

finish
