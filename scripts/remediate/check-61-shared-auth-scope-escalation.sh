#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 61: Shared-auth and pairing scope escalation"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
AUTH_MODE=$(openclaw config get gateway.auth.mode 2>/dev/null || echo "")
PAIRING_MODE=$(openclaw config get pairing.enabled 2>/dev/null || echo "")
FOUND=false

if version_lt "$OC_VERSION" "2026.3.13"; then
    if [ "$AUTH_MODE" = "password" ] || [ "$AUTH_MODE" = "token" ]; then
        log "  CRITICAL: Shared-auth scope escalation may be reachable on v$OC_VERSION"
        guidance "Upgrade OpenClaw to v2026.3.13+ for GHSA-rqpp-rjj8-7wv8" \
                 "Rotate shared gateway tokens/passwords after upgrading"
        FOUND=true
    fi
    if [ -n "$PAIRING_MODE" ] && [ "$PAIRING_MODE" != "false" ] && [ "$PAIRING_MODE" != "off" ]; then
        log "  CRITICAL: Pairing-scope privilege escalation may be reachable on v$OC_VERSION"
        guidance "Upgrade OpenClaw to v2026.3.13+ for GHSA-4jpw-hj22-2xmc and GHSA-63f5-hhc7-cx6p" \
                 "Re-issue pending pairing requests after upgrading"
        FOUND=true
    fi
fi

if [ "$FOUND" = true ]; then
    FIXED=1  # signal to orchestrator that guidance was emitted
elif [ "$FAILED" -eq 0 ]; then
    log "  No shared-auth or pairing escalation findings"
fi

finish
