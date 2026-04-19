#!/bin/bash
# Consolidated exec-guardrails guidance (merges old checks 26, 35, 43, 44, 62)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 21: Exec guardrails (approvals config, safeBins bypass, shell expansion, approval injection, approval replay)"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  OpenClaw version: $OC_VERSION"

EXEC_SECURITY=$(openclaw config get tools.exec.security 2>/dev/null || echo "")
SAFE_BINS=$(openclaw config get tools.exec.safeBins 2>/dev/null || echo "")
EXEC_APPROVALS="$OPENCLAW_DIR/exec-approvals.json"
FOUND=false

# ---------------------------------------------------------------------------
# 1. safeBins bypass via GNU long-option abbreviations (from old check 35)
#    CVE-2026-28363  CVSS 9.9
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28363 (CVSS 9.9) - safeBins bypass"
    log "=========================================="
    log ""
    log "GNU long-option abbreviations (e.g., sort --compress-prog) bypass"
    log "the safeBins allowlist validation, enabling approval-free execution"
    log "of arbitrary commands via allowlisted tools."
    log ""
    guidance \
        "Upgrade OpenClaw to v2026.4.15+ to cover CVE-2026-28363 and the April 2026 advisory wave" \
        "Audit safeBins configuration: openclaw config get tools.exec.safeBins" \
        "Consider removing 'sort' from safeBins until patched"
    FOUND=true
fi

# ---------------------------------------------------------------------------
# 2. Shell expansion bypass in exec-approvals (from old check 43)
#    CVE-2026-28463
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
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
    guidance \
        "Upgrade OpenClaw to v2026.4.15+ to cover CVE-2026-28463 and later auth fixes" \
        "Audit safeBins for file-reading commands (head, tail, grep, cat, less, more)"
    FOUND=true
fi

# ---------------------------------------------------------------------------
# 3. Approval field injection / exec gating bypass (from old check 44)
#    CVE-2026-28466
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
    log ""
    log "=========================================="
    log "CRITICAL: CVE-2026-28466 - Approval field injection"
    log "=========================================="
    log ""
    log "The gateway fails to sanitize internal approval fields in"
    log "node.invoke parameters. Authenticated clients can bypass exec"
    log "approval gating for system.run commands by injecting approval"
    log "fields into the request."
    log ""
    guidance \
        "Upgrade OpenClaw to v2026.4.15+ to cover CVE-2026-28466 and later auth fixes"
    FOUND=true
fi

# ---------------------------------------------------------------------------
# 4. Exec approval integrity replay (from old check 62)
#    GHSA-qc36, GHSA-xf99, GHSA-rw39, GHSA-f8r2
# ---------------------------------------------------------------------------
if version_lt "$OC_VERSION" "2026.3.21"; then
    if [ "$EXEC_SECURITY" = "allowlist" ] || { [ -n "$SAFE_BINS" ] && [ "$SAFE_BINS" != "[]" ] && [ "$SAFE_BINS" != "null" ]; }; then
        log ""
        log "=========================================="
        log "WARNING: Exec approval integrity replay"
        log "=========================================="
        log ""
        log "Exec approval integrity can be bypassed by rewritten scripts/wrappers."
        log ""
        guidance \
            "Upgrade OpenClaw to v2026.4.15+ for GHSA-qc36-x95h-7j53, GHSA-xf99-j42q-5w5p, GHSA-rw39-5899-8mxp, GHSA-f8r2-vg7x-gh8m, and the April 2026 rollup" \
            "Re-review stored approvals for tsx, jiti, node, bun, deno, python, bash, and similar script runners"
        FOUND=true
    fi
fi

# ---------------------------------------------------------------------------
# 5. Exec-approvals.json configuration audit (from old check 26)
# ---------------------------------------------------------------------------
if [ -f "$EXEC_APPROVALS" ] && [ -r "$EXEC_APPROVALS" ]; then
    UNSAFE_PATTERNS=0
    if grep -q '"security.*allow"' "$EXEC_APPROVALS" 2>/dev/null; then
        log "  WARNING: Found security.*allow pattern (overly permissive)"
        ((UNSAFE_PATTERNS++))
    fi
    if grep -q '"ask.*off"' "$EXEC_APPROVALS" 2>/dev/null; then
        log "  WARNING: Found ask.*off pattern (disables safety prompts)"
        ((UNSAFE_PATTERNS++))
    fi
    if grep -qi '"autoApprove".*true' "$EXEC_APPROVALS" 2>/dev/null; then
        log "  WARNING: Found autoApprove enabled (bypasses user confirmation)"
        ((UNSAFE_PATTERNS++))
    fi
    if grep -q '"command".*"\*"' "$EXEC_APPROVALS" 2>/dev/null; then
        log "  WARNING: Found wildcard command approval (allows all commands)"
        ((UNSAFE_PATTERNS++))
    fi
    if [ "$UNSAFE_PATTERNS" -gt 0 ]; then
        guidance \
            "Found $UNSAFE_PATTERNS unsafe pattern(s) in exec-approvals.json:" \
            "1. Remove wildcard allow patterns (security.*allow, ask.*off)" \
            "2. Disable autoApprove for sensitive commands" \
            "3. Use specific command allowlists instead of wildcards" \
            "4. Review and approve each execution approval manually" \
            "5. Backup before editing: cp $EXEC_APPROVALS ${EXEC_APPROVALS}.bak"
        FOUND=true
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [ "$FOUND" = true ]; then
    log ""
    log "  CVEs covered: CVE-2026-28363, CVE-2026-28463, CVE-2026-28466"
    log "  GHSAs covered: GHSA-qc36, GHSA-xf99, GHSA-rw39, GHSA-f8r2"
    log "  Minimum safe version: v2026.4.15+"
    FIXED=1  # signal to orchestrator that guidance was emitted
else
    log "  Exec guardrails baseline acceptable"
fi

finish
