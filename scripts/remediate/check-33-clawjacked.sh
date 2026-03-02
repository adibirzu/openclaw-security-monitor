#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 33: ClawJacked - WebSocket brute-force protection"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  OpenClaw version: $OC_VERSION"

# Check version >= 2026.2.26
NEEDS_UPDATE=false
if [ "$OC_VERSION" != "unknown" ]; then
    CJ_MAJOR=$(echo "$OC_VERSION" | cut -d'.' -f1)
    CJ_MINOR=$(echo "$OC_VERSION" | cut -d'.' -f2)
    CJ_PATCH=$(echo "$OC_VERSION" | cut -d'.' -f3 | cut -d'-' -f1)
    if [ "$CJ_MAJOR" -eq 2026 ] 2>/dev/null; then
        if [ "$CJ_MINOR" -lt 2 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        elif [ "$CJ_MINOR" -eq 2 ] && [ "$CJ_PATCH" -lt 26 ] 2>/dev/null; then
            NEEDS_UPDATE=true
        fi
    fi
fi

if [ "$NEEDS_UPDATE" = true ]; then
    log ""
    log "=========================================="
    log "CRITICAL: Vulnerable to ClawJacked (v$OC_VERSION < v2026.2.26)"
    log "=========================================="
    log ""
    log "ClawJacked allows malicious websites to brute-force your gateway"
    log "password via localhost WebSocket with no rate limiting, then"
    log "auto-register as a trusted device to steal data and execute commands."
    log ""
    log "RECOMMENDED ACTIONS:"
    log "1. Update OpenClaw immediately:"
    log "   openclaw update"
    log ""
    log "2. Set a strong gateway password (if not already set):"
    log "   openclaw config set gateway.auth.mode token"
    log "   openclaw config set gateway.auth.token <strong-random-token>"
    log ""
    log "3. Verify rate limiting is enabled after update:"
    log "   openclaw config get gateway.auth.rateLimit"
    log ""

    if confirm "Set gateway.auth.mode to 'token'?"; then
        if $DRY_RUN; then
            log "  [DRY-RUN] Would set gateway.auth.mode=token"
            FIXED=$((FIXED + 1))
        else
            if openclaw config set gateway.auth.mode token 2>/dev/null; then
                log "  FIXED: Set gateway.auth.mode=token"
                FIXED=$((FIXED + 1))
            else
                log "  FAILED: Could not set gateway.auth.mode"
                FAILED=$((FAILED + 1))
            fi
        fi
    fi

    guidance "Update OpenClaw to v2026.2.26+ to fix ClawJacked vulnerability"
fi

# Check gateway auth token
GW_AUTH=$(openclaw config get gateway.auth.token 2>/dev/null || echo "")
if [ -z "$GW_AUTH" ] || [ "$GW_AUTH" = "null" ]; then
    log "  WARNING: No gateway auth token set (enables brute-force)"
    guidance "Set a strong gateway auth token: openclaw config set gateway.auth.token <token>"
fi

# Check rate limiting
RATE_LIMIT=$(openclaw config get gateway.auth.rateLimit 2>/dev/null || echo "")
if [ "$RATE_LIMIT" = "off" ] || [ "$RATE_LIMIT" = "false" ]; then
    log "  WARNING: Rate limiting is disabled"
    if confirm "Enable gateway auth rate limiting?"; then
        if $DRY_RUN; then
            log "  [DRY-RUN] Would enable gateway.auth.rateLimit"
            FIXED=$((FIXED + 1))
        else
            if openclaw config set gateway.auth.rateLimit true 2>/dev/null; then
                log "  FIXED: Enabled gateway.auth.rateLimit"
                FIXED=$((FIXED + 1))
            else
                log "  FAILED: Could not enable rate limiting"
                FAILED=$((FAILED + 1))
            fi
        fi
    fi
fi

finish
