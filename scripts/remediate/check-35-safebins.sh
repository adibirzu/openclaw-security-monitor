#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 35: Exec safeBins bypass (CVE-2026-28363, CVSS 9.9)"

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
        elif [ "$MINOR" -eq 2 ] && [ "$PATCH" -lt 23 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28363 (CVSS 9.9) - safeBins bypass"
    log "=========================================="
    log ""
    log "GNU long-option abbreviations (e.g., sort --compress-prog) bypass"
    log "the safeBins allowlist validation, enabling approval-free execution"
    log "of arbitrary commands via allowlisted tools."
    log ""
    log "This is the highest-severity OpenClaw CVE to date (CVSS 9.9)."
    log ""
    log "RECOMMENDED ACTIONS:"
    log "1. Update OpenClaw immediately:"
    log "   openclaw update"
    log ""
    log "2. Audit safeBins configuration:"
    log "   openclaw config get tools.exec.safeBins"
    log ""
    log "3. Consider removing 'sort' from safeBins until patched:"
    log "   openclaw config set tools.exec.safeBins <updated-list>"
    log ""

    guidance "Update OpenClaw to v2026.2.23+ to fix CVE-2026-28363 (CVSS 9.9)"
fi

# Audit safeBins list
SAFE_BINS=$(openclaw config get tools.exec.safeBins 2>/dev/null || echo "")
if [ -n "$SAFE_BINS" ] && [ "$SAFE_BINS" != "null" ] && [ "$SAFE_BINS" != "[]" ]; then
    log "  Current safeBins: $SAFE_BINS"
    if echo "$SAFE_BINS" | grep -q '"sort"' 2>/dev/null; then
        if [ "$NEEDS_UPDATE" = true ]; then
            log "  WARNING: 'sort' is in safeBins and version is vulnerable to bypass"
            guidance "Remove 'sort' from safeBins or update to v2026.2.23+"
        else
            log "  INFO: 'sort' is in safeBins (patched version - OK)"
        fi
    fi
fi

finish
