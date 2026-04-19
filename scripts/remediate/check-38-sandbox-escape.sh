#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 38: Sandbox escape via session spawning and operator.write auth mismatch"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  Current OpenClaw version: $OC_VERSION"
FOUND=false

if version_lt "$OC_VERSION" "2026.3.21"; then
    log "  CRITICAL: OpenClaw version $OC_VERSION is vulnerable to sandbox escape"
    log "    CVE-2026-32048 — sessions_spawn bypass allows breaking out of sandboxed sessions"
    log "    CVE-2026-32051 — operator.write auth mismatch grants unintended write access"
    guidance "Upgrade OpenClaw to v2026.4.15+ to patch CVE-2026-32048, CVE-2026-32051, and later April 2026 issues" \
             "Disable session spawning if not required for your workflow:" \
             "  openclaw config set sessions.spawn_enabled false" \
             "Review operator.write permissions and ensure they match intended access policies:" \
             "  openclaw config get operator.write"
    FOUND=true
fi

if [ "$FOUND" = true ]; then
    FIXED=1
else
    log "  No sandbox escape risks detected"
fi

finish
