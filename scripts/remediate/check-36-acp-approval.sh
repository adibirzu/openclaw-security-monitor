#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 36: ACP auto-approval bypass (GHSA-7jx5-9fjg-hp4m, CVSS 8.2)"

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
    log "VULNERABLE: GHSA-7jx5 (CVSS 8.2) - ACP auto-approval bypass"
    log "=========================================="
    log ""
    log "The ACP client auto-approves tool calls based on untrusted metadata"
    log "and permissive name heuristics. Malicious or compromised tool"
    log "invocations can bypass interactive approval prompts for read-class"
    log "operations, leading to unauthorized data access."
    log ""
    log "RECOMMENDED ACTIONS:"
    log "1. Update OpenClaw:"
    log "   openclaw update"
    log ""
    log "2. Disable ACP auto-approve until patched:"
    log "   openclaw config set acp.autoApprove false"
    log ""

    guidance "Update OpenClaw to v2026.2.23+ to fix GHSA-7jx5 ACP bypass"
fi

# Check ACP auto-approve config
ACP_AUTO=$(openclaw config get acp.autoApprove 2>/dev/null || echo "")
if [ "$ACP_AUTO" = "true" ] || [ "$ACP_AUTO" = "all" ]; then
    log "  WARNING: ACP auto-approve is enabled ($ACP_AUTO)"
    if confirm "Disable ACP auto-approve?"; then
        if $DRY_RUN; then
            log "  [DRY-RUN] Would set acp.autoApprove=false"
            FIXED=$((FIXED + 1))
        else
            if openclaw config set acp.autoApprove false 2>/dev/null; then
                log "  FIXED: Disabled ACP auto-approve"
                FIXED=$((FIXED + 1))
            else
                log "  FAILED: Could not disable ACP auto-approve"
                FAILED=$((FAILED + 1))
            fi
        fi
    fi
fi

finish
