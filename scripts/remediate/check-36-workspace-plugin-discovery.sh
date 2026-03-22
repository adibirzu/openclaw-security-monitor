#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 36: Workspace plugin auto-discovery"

FOUND=false
SEARCH_ROOTS=(
    "$OPENCLAW_DIR/workspace"
    "$(pwd)"
)

for root in "${SEARCH_ROOTS[@]}"; do
    [ -d "$root" ] || continue
    while IFS= read -r extdir; do
        [ -z "$extdir" ] && continue
        if is_self_skill "$extdir"; then
            continue
        fi

        FOUND=true
        log "  CRITICAL: Workspace plugin directory found: $extdir"
        guidance "Review the repository containing $extdir and remove untrusted workspace plugins" \
                 "Upgrade OpenClaw to v2026.3.13+ for GHSA-99qw-6mr3-36qr"
    done < <(find "$root" -maxdepth 5 -type d -path "*/.openclaw/extensions" 2>/dev/null)
done

if [ "$FOUND" = true ]; then
    FIXED=1  # signal to orchestrator that guidance was emitted
else
    log "  No workspace plugin auto-discovery risks detected"
fi

finish
