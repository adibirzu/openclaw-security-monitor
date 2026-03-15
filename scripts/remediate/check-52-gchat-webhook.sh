#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 52: Google Chat webhook cross-account bypass (CVE-2026-28469)"

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
    log "CRITICAL: CVE-2026-28469 - Google Chat webhook cross-account bypass"
    log "=========================================="
    log ""
    log "Google Chat webhook handler uses first-match semantics. A cross-account"
    log "attacker can register a matching path to intercept/inject messages."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.14+"
    log "   openclaw update"
    log ""
    log "INTERIM: Disable Google Chat integration if not actively used:"
    log "   openclaw config set integrations.googlechat.enabled false"
    log ""

    guidance \
        "Update OpenClaw to v2026.2.14+ to fix CVE-2026-28469" \
        "Disable Google Chat integration as interim mitigation"
fi

finish
