#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 39: Shell environment RCE via HOME/ZDOTDIR injection and binary unwrapping"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  Current OpenClaw version: $OC_VERSION"
FOUND=false

if version_lt "$OC_VERSION" "2026.3.21"; then
    log "  CRITICAL: OpenClaw version $OC_VERSION is vulnerable to shell environment RCE"
    log "    CVE-2026-32056 — HOME/ZDOTDIR injection in system.run enables arbitrary code execution"
    log "    CVE-2026-27566 — env/wrapper binary unwrapping allows substitution of trusted binaries"
    guidance "Upgrade OpenClaw to v2026.4.23+ to patch CVE-2026-32056, CVE-2026-27566, and later April 2026 issues" \
             "Ensure ZDOTDIR is not overridden in your environment or OpenClaw config:" \
             "  echo \$ZDOTDIR  # should be empty or point to a trusted path" \
             "Verify shell binaries resolve to system paths and have not been replaced:" \
             "  which -a bash zsh sh  # check for unexpected wrapper binaries" \
             "  ls -la /usr/local/bin/{bash,zsh,sh} 2>/dev/null  # look for suspicious overrides"
    FOUND=true
fi

# Check if ZDOTDIR is set to a non-standard location
if [ -n "$ZDOTDIR" ] && [ "$ZDOTDIR" != "$HOME" ]; then
    log "  WARNING: ZDOTDIR is set to a non-standard path: $ZDOTDIR"
    FOUND=true
fi

if [ "$FOUND" = true ]; then
    FIXED=1
else
    log "  No shell environment RCE risks detected"
fi

finish
