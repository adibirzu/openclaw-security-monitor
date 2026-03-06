#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 43: Exec-approvals shell expansion bypass (CVE-2026-28463)"

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
    log "CRITICAL: CVE-2026-28463 - Shell expansion bypass in exec-approvals"
    log "=========================================="
    log ""
    log "The exec-approvals allowlist validates pre-expansion argv tokens"
    log "but execution uses real shell expansion. Commands like head, tail,"
    log "grep in safeBins can read arbitrary files via glob patterns or"
    log "environment variable expansion."
    log ""
    log "RECOMMENDED: Update OpenClaw to v2026.2.14+"
    log "   openclaw update"
    log ""

    # Audit safeBins for vulnerable commands
    SAFE_BINS=$(openclaw config get "tools.exec.safeBins" 2>/dev/null || echo "")
    for CMD in head tail grep cat less more; do
        if echo "$SAFE_BINS" | grep -q "\"$CMD\"" 2>/dev/null; then
            log "  WARNING: '$CMD' in safeBins — vulnerable to glob-based file reads"
            if confirm "Remove '$CMD' from safeBins until patched?"; then
                if $DRY_RUN; then
                    log "  [DRY-RUN] Would remove '$CMD' from safeBins"
                    FIXED=$((FIXED + 1))
                else
                    guidance "Manually remove '$CMD' from safeBins: openclaw config edit"
                fi
            fi
        fi
    done

    guidance "Update OpenClaw to v2026.2.14+ to fix CVE-2026-28463"
fi

finish
