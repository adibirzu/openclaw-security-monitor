#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 56: Operator privilege escalation (GHSA-vmhq-cqm9-6p7q)"

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
        elif [ "$MINOR" -eq 3 ] && [ "$PATCH" -lt 12 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "WARNING: GHSA-vmhq - Operator privilege escalation"
    log "=========================================="
    log ""
    log "Accounts with operator.write permissions can access admin-only"
    log "endpoints to create/delete browser profiles."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.3.12+"
    log "   openclaw update"
    log ""
    log "INTERIM: Audit operator accounts and remove unnecessary write access"
    log ""

    guidance \
        "Update OpenClaw to v2026.3.12+ to fix GHSA-vmhq" \
        "Audit operator accounts for unnecessary write permissions"
fi

finish
