#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 40: Missing VNC authentication for noVNC sandbox observer"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  Current OpenClaw version: $OC_VERSION"
FOUND=false

if version_lt "$OC_VERSION" "2026.3.21"; then
    log "  CRITICAL: OpenClaw version $OC_VERSION is vulnerable to unauthenticated VNC access"
    log "    CVE-2026-32064 — missing VNC auth for noVNC sandbox observer allows unauthorized screen viewing"
    guidance "Upgrade OpenClaw to v2026.4.15+ to patch CVE-2026-32064 and later April 2026 issues" \
             "Disable sandbox observer mode if not needed:" \
             "  openclaw config set sandbox.observer.enabled false" \
             "Ensure VNC ports (5900-5999) are not exposed to untrusted networks:" \
             "  Check firewall rules and ensure VNC is bound to localhost only" \
             "If observer mode is required, add network-level access controls (e.g., SSH tunnel)"
    FOUND=true
fi

if [ "$FOUND" = true ]; then
    FIXED=1
else
    log "  No VNC observer authentication risks detected"
fi

finish
