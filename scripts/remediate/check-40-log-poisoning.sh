#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 40: Log poisoning / WebSocket header injection"

OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
LOG_DIR="$OPENCLAW_DIR/logs"

# Enable header redaction if openclaw CLI available
if command -v openclaw &>/dev/null; then
    LOG_REDACT=$(openclaw config get "logging.redactHeaders" 2>/dev/null || echo "")
    if [ -z "$LOG_REDACT" ] || [ "$LOG_REDACT" = "false" ] || [ "$LOG_REDACT" = "null" ]; then
        log "  WARNING: WebSocket header redaction not enabled"
        if confirm "Enable logging.redactHeaders?"; then
            if $DRY_RUN; then
                log "  [DRY-RUN] Would set logging.redactHeaders=true"
                FIXED=$((FIXED + 1))
            else
                if openclaw config set logging.redactHeaders true 2>/dev/null; then
                    log "  FIXED: Enabled logging.redactHeaders"
                    FIXED=$((FIXED + 1))
                else
                    log "  FAILED: Could not set logging.redactHeaders"
                    FAILED=$((FAILED + 1))
                fi
            fi
        fi
    fi
fi

# Clean ANSI escape sequences from existing logs
if [ -d "$LOG_DIR" ]; then
    ANSI_FILES=$(grep -rlP '\x1b\[' "$LOG_DIR" 2>/dev/null | head -10)
    if [ -n "$ANSI_FILES" ]; then
        ANSI_COUNT=$(echo "$ANSI_FILES" | wc -l | tr -d ' ')
        log "  WARNING: ANSI escape sequences found in $ANSI_COUNT log file(s)"

        if confirm "Strip ANSI escape sequences from affected log files?"; then
            while IFS= read -r AFILE; do
                if $DRY_RUN; then
                    log "  [DRY-RUN] Would strip ANSI from $(basename "$AFILE")"
                    FIXED=$((FIXED + 1))
                else
                    if sed -i.bak 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$AFILE" 2>/dev/null; then
                        rm -f "${AFILE}.bak" 2>/dev/null
                        log "  FIXED: Stripped ANSI from $(basename "$AFILE")"
                        FIXED=$((FIXED + 1))
                    else
                        log "  FAILED: Could not clean $(basename "$AFILE")"
                        FAILED=$((FAILED + 1))
                    fi
                fi
            done <<< "$ANSI_FILES"
        fi
    fi

    # Check for control characters (null bytes, etc.)
    CTRL_FILES=$(grep -rlP '[\x00-\x08\x0e-\x1f]' "$LOG_DIR" 2>/dev/null | grep -v '.log.gz' | head -10)
    if [ -n "$CTRL_FILES" ]; then
        CTRL_COUNT=$(echo "$CTRL_FILES" | wc -l | tr -d ' ')
        log "  WARNING: Control characters found in $CTRL_COUNT log file(s)"

        if confirm "Strip control characters from affected log files?"; then
            while IFS= read -r CFILE; do
                if $DRY_RUN; then
                    log "  [DRY-RUN] Would strip control chars from $(basename "$CFILE")"
                    FIXED=$((FIXED + 1))
                else
                    if tr -d '\000-\010\016-\037' < "$CFILE" > "${CFILE}.clean" 2>/dev/null && mv "${CFILE}.clean" "$CFILE" 2>/dev/null; then
                        log "  FIXED: Stripped control chars from $(basename "$CFILE")"
                        FIXED=$((FIXED + 1))
                    else
                        rm -f "${CFILE}.clean" 2>/dev/null
                        log "  FAILED: Could not clean $(basename "$CFILE")"
                        FAILED=$((FAILED + 1))
                    fi
                fi
            done <<< "$CTRL_FILES"
        fi
    fi
fi

guidance "Enable logging.redactHeaders and monitor logs for injection artifacts"

finish
