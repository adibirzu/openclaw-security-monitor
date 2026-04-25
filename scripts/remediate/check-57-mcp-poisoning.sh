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

            # Check for high-risk startup/runtime env variables
            if grep -iE 'NODE_OPTIONS|BASH_ENV|ENV=|ZDOTDIR|PYTHONPATH|RUBYOPT|GIT_DIR|GIT_WORK_TREE|HGRCPATH|RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WRAPPER|MAKEFLAGS|OPENCLAW_' "$mcpfile" 2>/dev/null | grep -vq '^#'; then
                HAS_ISSUE=true
                log "  WARNING: High-risk startup/runtime env variables in $mcpfile"
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

if command -v openclaw &>/dev/null; then
    OC_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
    if version_lt "$OC_VERSION" "2026.4.24"; then
        FOUND_ISSUES=true
        guidance \
            "Upgrade OpenClaw to v2026.4.24+ for MCP stdio env filtering, loopback owner-context bearer derivation, bundled MCP/LSP tool-policy enforcement, and ACP child-session envelope fixes." \
            "Review all MCP server configs for workspace-provided env values and unexpected tool schemas."
        FIXED=$((FIXED + 1))
    fi
fi

if [ "$FOUND_ISSUES" = false ]; then
    log "  No MCP tool poisoning detected"
fi

finish
