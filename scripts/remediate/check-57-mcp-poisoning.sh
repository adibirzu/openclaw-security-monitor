#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
log "CHECK 57: MCP server tool poisoning via schema injection"

FOUND_ISSUES=false
MCP_CONFIG_DIRS=(
    "$OPENCLAW_DIR/mcp-servers"
    "$HOME/.config/openclaw/mcp"
    "$HOME/.claude/mcp"
)

for MCP_DIR in "${MCP_CONFIG_DIRS[@]}"; do
    if [ -d "$MCP_DIR" ]; then
        while IFS= read -r mcpfile; do
            [ -z "$mcpfile" ] && continue
            HAS_ISSUE=false

            # Check for hidden Unicode
            if grep -Pq '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{00AD}]' "$mcpfile" 2>/dev/null; then
                HAS_ISSUE=true
                log "  CRITICAL: Hidden Unicode in $mcpfile"
            fi

            # Check for prompt injection
            if grep -iE '(ignore previous|disregard|you are now|act as|system prompt)' "$mcpfile" 2>/dev/null | grep -vq '^#'; then
                HAS_ISSUE=true
                log "  CRITICAL: Prompt injection in $mcpfile"
            fi

            if [ "$HAS_ISSUE" = true ]; then
                FOUND_ISSUES=true
                if confirm "Quarantine suspicious MCP config $mcpfile?"; then
                    if $DRY_RUN; then
                        log "  [DRY-RUN] Would move $mcpfile to ${mcpfile}.quarantined"
                        FIXED=$((FIXED + 1))
                    else
                        if mv "$mcpfile" "${mcpfile}.quarantined" 2>/dev/null; then
                            log "  FIXED: Quarantined $mcpfile"
                            FIXED=$((FIXED + 1))
                        else
                            log "  FAILED: Could not quarantine $mcpfile"
                            FAILED=$((FAILED + 1))
                        fi
                    fi
                fi
            fi
        done < <(find "$MCP_DIR" -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" \) 2>/dev/null)
    fi
done

if [ "$FOUND_ISSUES" = false ]; then
    log "  No MCP tool poisoning detected"
fi

finish
