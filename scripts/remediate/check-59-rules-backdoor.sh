#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 59: Rules file backdoor / hidden Unicode injection"

RULES_FILES=(
    ".cursorrules"
    ".cursor/rules"
    ".github/copilot-instructions.md"
    "CLAUDE.md"
    ".claude/settings.json"
    ".clawrules"
    ".openclaw/rules.md"
    "SOUL.md"
)

FOUND_ISSUES=false
SCAN_ROOTS=("$(pwd)" "$HOME")

for SROOT in "${SCAN_ROOTS[@]}"; do
    for RFILE in "${RULES_FILES[@]}"; do
        TARGET="$SROOT/$RFILE"
        if [ -f "$TARGET" ]; then
            if grep -Pq '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{00AD}\x{2028}\x{2029}\x{202A}-\x{202E}\x{2066}-\x{2069}]' "$TARGET" 2>/dev/null; then
                FOUND_ISSUES=true
                log "  CRITICAL: Hidden Unicode in $TARGET"

                if confirm "Strip hidden Unicode characters from $TARGET?"; then
                    if $DRY_RUN; then
                        log "  [DRY-RUN] Would strip hidden Unicode from $TARGET"
                        FIXED=$((FIXED + 1))
                    else
                        # Strip zero-width and bidirectional override characters
                        if perl -pi -e 's/[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{00AD}\x{2028}\x{2029}\x{202A}-\x{202E}\x{2066}-\x{2069}]//g' "$TARGET" 2>/dev/null; then
                            log "  FIXED: Stripped hidden Unicode from $TARGET"
                            FIXED=$((FIXED + 1))
                        else
                            log "  FAILED: Could not strip Unicode from $TARGET"
                            FAILED=$((FAILED + 1))
                        fi
                    fi
                fi
            fi
        fi
    done
done

if [ "$FOUND_ISSUES" = false ]; then
    log "  No hidden Unicode injection detected in rules files"
fi

finish
