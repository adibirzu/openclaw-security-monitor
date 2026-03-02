#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 34: SSRF protection (CVE-2026-26322, CVE-2026-27488)"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  OpenClaw version: $OC_VERSION"

NEEDS_UPDATE=false
SSRF_CVE=""
if [ "$OC_VERSION" != "unknown" ]; then
    MAJOR=$(echo "$OC_VERSION" | cut -d'.' -f1)
    MINOR=$(echo "$OC_VERSION" | cut -d'.' -f2)
    PATCH=$(echo "$OC_VERSION" | cut -d'.' -f3 | cut -d'-' -f1)
    if [ "$MAJOR" -eq 2026 ] 2>/dev/null; then
        if [ "$MINOR" -lt 2 ] 2>/dev/null; then
            NEEDS_UPDATE=true
            SSRF_CVE="CVE-2026-26322 (gateway SSRF) + CVE-2026-27488 (cron SSRF)"
        elif [ "$MINOR" -eq 2 ] && [ "$PATCH" -lt 19 ] 2>/dev/null; then
            NEEDS_UPDATE=true
            if [ "$PATCH" -lt 14 ] 2>/dev/null; then
                SSRF_CVE="CVE-2026-26322 (gateway SSRF) + CVE-2026-27488 (cron SSRF)"
            else
                SSRF_CVE="CVE-2026-27488 (cron webhook SSRF)"
            fi
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "VULNERABLE: $SSRF_CVE"
    log "=========================================="
    log ""
    log "CVE-2026-26322 (CVSS 7.6): Gateway tool accepts tool-supplied"
    log "gatewayUrl without restrictions, enabling network reconnaissance"
    log "and cloud metadata access. Fixed in v2026.2.14."
    log ""
    log "CVE-2026-27488 (CVSS 6.9): Cron webhook delivery uses fetch()"
    log "directly without SSRF policy checks. Fixed in v2026.2.19."
    log ""
    log "RECOMMENDED ACTIONS:"
    log "1. Update OpenClaw:"
    log "   openclaw update"
    log ""
    log "2. Audit cron webhook targets for internal endpoints:"
    log "   openclaw config get cron"
    log ""

    guidance "Update OpenClaw to v2026.2.19+ to fix SSRF vulnerabilities"
fi

# Audit cron config for internal/metadata targets
CRON_CONFIG=$(openclaw config get cron 2>/dev/null || echo "")
if echo "$CRON_CONFIG" | grep -qiE "169\.254\.|127\.0\.0\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|metadata\.google|metadata\.aws" 2>/dev/null; then
    log "  WARNING: Cron webhook targets internal/metadata endpoints"
    log "  Current cron config:"
    echo "$CRON_CONFIG" | sed 's/^/    /'
    guidance "Review and update cron webhook targets to external-only URLs"
fi

finish
