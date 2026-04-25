#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 41: Device identity spoofing and auto-pairing vulnerabilities"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  Current OpenClaw version: $OC_VERSION"
FOUND=false

if version_lt "$OC_VERSION" "2026.3.21"; then
    log "  CRITICAL: OpenClaw version $OC_VERSION is vulnerable to device identity spoofing"
    log "    CVE-2026-32014 — reconnect field spoofing allows impersonating trusted devices"
    log "    CVE-2026-32042 — unpaired devices can self-assign admin privileges"
    log "    CVE-2026-32025 — origin bypass enables brute-force of device pairing codes"
    guidance "Upgrade OpenClaw to v2026.4.24+ to patch CVE-2026-32014, CVE-2026-32042, CVE-2026-32025, and later April 2026 issues" \
             "Disable auto-pairing to prevent unauthorized device registration:" \
             "  openclaw config set devices.auto_pair false" \
             "Review all registered devices and remove any that are unrecognized:" \
             "  openclaw devices list" \
             "Rotate device credentials and pairing secrets:" \
             "  openclaw devices rotate-credentials"
    FOUND=true
fi

if [ "$FOUND" = true ]; then
    FIXED=1
else
    log "  No device identity spoofing risks detected"
fi

finish
