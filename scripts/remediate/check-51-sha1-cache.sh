#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 51: SHA-1 sandbox cache poisoning (CVE-2026-28479)"

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
        elif [ "$MINOR" -eq 2 ] && [ "$PATCH" -lt 15 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28479 - SHA-1 cache key poisoning"
    log "=========================================="
    log ""
    log "Vulnerable versions may use SHA-1 cache key derivation for"
    log "sandbox state. Collision attacks can cross-contaminate caches."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.15+"
    log "   openclaw update"
    log ""
    log "INTERIM: Disable sandbox cache until upgraded:"
    log "   openclaw config set sandbox.cache.enabled false"
    log ""

    guidance \
        "Update OpenClaw to v2026.2.15+ to fix CVE-2026-28479" \
        "Disable sandbox cache as interim mitigation if upgrade is delayed"
fi

finish
