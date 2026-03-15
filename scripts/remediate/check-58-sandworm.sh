#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 58: SANDWORM_MODE MCP worm detection"

SANDWORM_PKGS="@anthropic/sdk-extra @anthropic/cli-tools claude-code-utils claude-mcp-helper claudecode-ext claude-dev-tools cursor-mcp-bridge cursor-tools-ext mcp-server-utils mcp-tool-runner mcp-proxy-server windsurf-mcp-bridge continue-mcp-ext vscode-ai-helper ai-code-review copilot-mcp-bridge openai-mcp-tools llm-gateway-utils agent-tool-sdk"

WORM_CONFIG_FILES=(
    "$HOME/.claude.json"
    "$HOME/.claude/config.json"
    "$HOME/.cursor/mcp.json"
    "$HOME/.continue/config.json"
    "$HOME/.windsurf/mcp.json"
    "$HOME/.vscode/mcp.json"
)

FOUND_WORM=false

for WCONF in "${WORM_CONFIG_FILES[@]}"; do
    if [ -f "$WCONF" ]; then
        for SPKG in $SANDWORM_PKGS; do
            if grep -q "$SPKG" "$WCONF" 2>/dev/null; then
                FOUND_WORM=true
                log "  CRITICAL: SANDWORM_MODE artifact '$SPKG' in $WCONF"

                if confirm "Remove malicious MCP entry from $WCONF?"; then
                    if $DRY_RUN; then
                        log "  [DRY-RUN] Would remove '$SPKG' reference from $WCONF"
                        FIXED=$((FIXED + 1))
                    else
                        log ""
                        log "=========================================="
                        log "CRITICAL: SANDWORM_MODE worm detected"
                        log "=========================================="
                        log ""
                        log "Your system has been infected by the SANDWORM_MODE MCP worm."
                        log "Immediate actions required:"
                        log ""
                        log "1. Remove the malicious MCP entry from $WCONF"
                        log "2. Uninstall malicious npm packages: npm uninstall -g $SPKG"
                        log "3. Rotate ALL credentials: SSH keys, AWS keys, API tokens"
                        log "4. Check git repos for unauthorized commits"
                        log "5. Review ~/.ssh/authorized_keys for additions"
                        log ""
                        FIXED=$((FIXED + 1))

                        guidance \
                            "Remove rogue MCP entries from $WCONF" \
                            "Uninstall malicious npm packages" \
                            "Rotate ALL credentials (SSH, AWS, API keys, npm tokens)" \
                            "Audit git repos for unauthorized commits"
                    fi
                fi
            fi
        done
    fi
done

# Check for installed malicious npm packages
if command -v npm &>/dev/null; then
    NPM_LIST=$(npm list -g --depth=0 2>/dev/null || true)
    for SPKG in $SANDWORM_PKGS; do
        if echo "$NPM_LIST" | grep -q "$SPKG" 2>/dev/null; then
            FOUND_WORM=true
            log "  CRITICAL: Malicious npm package installed globally: $SPKG"
            if confirm "Uninstall malicious package $SPKG?"; then
                if $DRY_RUN; then
                    log "  [DRY-RUN] Would run: npm uninstall -g $SPKG"
                    FIXED=$((FIXED + 1))
                else
                    if npm uninstall -g "$SPKG" 2>/dev/null; then
                        log "  FIXED: Uninstalled $SPKG"
                        FIXED=$((FIXED + 1))
                    else
                        log "  FAILED: Could not uninstall $SPKG"
                        FAILED=$((FAILED + 1))
                    fi
                fi
            fi
        fi
    done
fi

if [ "$FOUND_WORM" = false ]; then
    log "  No SANDWORM_MODE artifacts detected"
fi

finish
