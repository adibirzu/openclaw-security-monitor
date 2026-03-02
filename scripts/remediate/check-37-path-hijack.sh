#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 37: PATH hijacking / command hijacking (GHSA-jqpq-mgvm-f9r6)"

OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
WORKSPACE_DIR="$OPENCLAW_DIR/workspace"
SKILLS_DIR="$WORKSPACE_DIR/skills"

# Check for planted binaries in workspace
if [ -d "$WORKSPACE_DIR" ]; then
    PLANTED=$(find "$WORKSPACE_DIR" -maxdepth 3 -type f \( -name "node" -o -name "python3" -o -name "bash" -o -name "curl" -o -name "git" -o -name "ssh" -o -name "openclaw" \) 2>/dev/null)
    if [ -n "$PLANTED" ]; then
        while IFS= read -r PBIN; do
            if [ -x "$PBIN" ]; then
                log "  FOUND: Planted executable $PBIN"
                if confirm "Remove planted binary $PBIN?"; then
                    if $DRY_RUN; then
                        log "  [DRY-RUN] Would remove $PBIN"
                        FIXED=$((FIXED + 1))
                    else
                        if rm -f "$PBIN" 2>/dev/null; then
                            log "  FIXED: Removed $PBIN"
                            FIXED=$((FIXED + 1))
                        else
                            log "  FAILED: Could not remove $PBIN"
                            FAILED=$((FAILED + 1))
                        fi
                    fi
                fi
            fi
        done <<< "$PLANTED"
    else
        log "  No planted binaries found in workspace"
    fi
else
    log "  Workspace directory not found, skipping"
fi

# Check for suspicious PATH entries pointing into skills
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for PDIR in "${PATH_DIRS[@]}"; do
    case "$PDIR" in
        */.openclaw/workspace/skills/*)
            log "  WARNING: PATH includes skill directory: $PDIR"
            guidance "Remove skill directories from PATH to prevent command hijacking"
            ;;
    esac
done

guidance "Ensure OpenClaw uses absolute paths for command execution (GHSA-jqpq)"

finish
