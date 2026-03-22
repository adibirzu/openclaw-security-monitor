#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 37: Symlink traversal escape (agents.files.get/set, in-workspace symlinks)"

if ! command -v openclaw &>/dev/null; then
    log "  openclaw not found, skipping"
    exit 2
fi

OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
log "  Current OpenClaw version: $OC_VERSION"
FOUND=false

if version_lt "$OC_VERSION" "2026.3.21"; then
    log "  CRITICAL: OpenClaw version $OC_VERSION is vulnerable to symlink traversal attacks"
    log "    CVE-2026-32013 — agents.files.get/set symlink escape allows reading/writing outside sandbox"
    log "    CVE-2026-32055 — in-workspace symlinks can traverse to out-of-root paths"
    guidance "Upgrade OpenClaw to v2026.3.21+ to patch CVE-2026-32013 and CVE-2026-32055" \
             "Audit workspace directories for symlinks pointing outside the workspace root:" \
             "  find \$OPENCLAW_HOME/workspace -type l -exec ls -la {} \\;" \
             "Remove or replace any suspicious symlinks that resolve outside the workspace"
    FOUND=true
fi

# Check for suspicious symlinks in workspace
WORKSPACE_DIR="$OPENCLAW_DIR/workspace"
if [ -d "$WORKSPACE_DIR" ]; then
    while IFS= read -r symlink; do
        [ -z "$symlink" ] && continue
        target=$(readlink -f "$symlink" 2>/dev/null || readlink "$symlink" 2>/dev/null)
        if [ -n "$target" ] && [[ "$target" != "$WORKSPACE_DIR"* ]]; then
            log "  WARNING: Symlink escapes workspace root: $symlink -> $target"
            FOUND=true
        fi
    done < <(find "$WORKSPACE_DIR" -maxdepth 5 -type l 2>/dev/null)
fi

if [ "$FOUND" = true ]; then
    FIXED=1
else
    log "  No symlink traversal risks detected"
fi

finish
