#!/bin/bash
# Consolidated privilege-escalation guidance (merges old checks 55, 56, 61)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 32: Privilege escalation (pairing creds, operator privesc, shared-auth scope)"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  OpenClaw version: $OC_VERSION"

AUTH_MODE=$(openclaw config get gateway.auth.mode 2>/dev/null || echo "")
PAIRING_MODE=$(openclaw config get pairing.enabled 2>/dev/null || echo "")
FOUND=false

# ---------------------------------------------------------------------------
# 1. Device pairing credential exposure (from old check 55 -- GHSA-7h7g)
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
    log ""
    log "=========================================="
    log "WARNING: GHSA-7h7g - Device pairing credential exposure"
    log "=========================================="
    log ""
    log "Setup codes expose long-lived gateway credentials instead of"
    log "short-lived bootstrap tokens. Compromised codes grant persistent access."
    log ""
    guidance \
        "Upgrade OpenClaw to v2026.4.15+ to fix GHSA-7h7g-x2px-94hj and subsequent auth issues" \
        "Rotate device credentials after upgrading: openclaw device rotate-credentials"
    FOUND=true
fi

# ---------------------------------------------------------------------------
# 2. Operator privilege escalation (from old check 56 -- GHSA-vmhq)
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
    log ""
    log "=========================================="
    log "WARNING: GHSA-vmhq - Operator privilege escalation"
    log "=========================================="
    log ""
    log "Accounts with operator.write permissions can access admin-only"
    log "endpoints to create/delete browser profiles."
    log ""
    guidance \
        "Upgrade OpenClaw to v2026.4.15+ to fix GHSA-vmhq-cqm9-6p7q and subsequent auth issues" \
        "Audit operator accounts for unnecessary write permissions"
    FOUND=true
fi

# ---------------------------------------------------------------------------
# 3. Shared-auth scope escalation (from old check 61 -- GHSA-rqpp)
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
    if [ "$AUTH_MODE" = "password" ] || [ "$AUTH_MODE" = "token" ]; then
        log ""
        log "=========================================="
        log "WARNING: GHSA-rqpp - Shared-auth scope escalation"
        log "=========================================="
        log ""
        log "Shared gateway credentials allow scope escalation across sessions."
        log ""
        guidance \
            "Upgrade OpenClaw to v2026.4.15+ to fix GHSA-rqpp-rjj8-7wv8 and subsequent auth issues" \
            "Rotate shared gateway tokens/passwords after upgrading"
        FOUND=true
    fi
fi

# ---------------------------------------------------------------------------
# 4. Pairing-scope privilege escalation (from old check 61 -- GHSA-4jpw, GHSA-63f5)
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
    if [ -n "$PAIRING_MODE" ] && [ "$PAIRING_MODE" != "false" ] && [ "$PAIRING_MODE" != "off" ]; then
        log ""
        log "=========================================="
        log "WARNING: GHSA-4jpw / GHSA-63f5 - Pairing-scope privilege escalation"
        log "=========================================="
        log ""
        log "Pending pairing requests can be exploited to escalate privileges."
        log ""
        guidance \
            "Upgrade OpenClaw to v2026.4.15+ to fix GHSA-4jpw-hj22-2xmc, GHSA-63f5-hhc7-cx6p, and subsequent auth issues" \
            "Re-issue pending pairing requests after upgrading"
        FOUND=true
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [ "$FOUND" = true ]; then
    log ""
    log "  Advisories covered: GHSA-7h7g, GHSA-vmhq, GHSA-rqpp, GHSA-4jpw, GHSA-63f5"
    log "  Minimum safe version: v2026.4.15+"
    FIXED=1  # signal to orchestrator that guidance was emitted
else
    log "  No privilege-escalation findings for current version"
fi

finish
