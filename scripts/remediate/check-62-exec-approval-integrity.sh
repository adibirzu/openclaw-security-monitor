#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 62: Exec approval integrity replay"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
EXEC_SECURITY=$(openclaw config get tools.exec.security 2>/dev/null || echo "")
SAFE_BINS=$(openclaw config get tools.exec.safeBins 2>/dev/null || echo "")

if version_lt "$OC_VERSION" "2026.3.13" && { [ "$EXEC_SECURITY" = "allowlist" ] || { [ -n "$SAFE_BINS" ] && [ "$SAFE_BINS" != "[]" ] && [ "$SAFE_BINS" != "null" ]; }; }; then
    log "  WARNING: Exec approval integrity can be bypassed by rewritten scripts/wrappers on v$OC_VERSION"
    guidance "Upgrade OpenClaw to v2026.4.24+ for GHSA-qc36-x95h-7j53, GHSA-xf99-j42q-5w5p, GHSA-rw39-5899-8mxp, GHSA-f8r2-vg7x-gh8m, and the current safe baseline" \
             "Re-review stored approvals for tsx, jiti, node, bun, deno, python, bash, and similar script runners"
    FIXED=1  # signal to orchestrator that guidance was emitted
else
    log "  Exec approval integrity baseline acceptable"
fi

finish
