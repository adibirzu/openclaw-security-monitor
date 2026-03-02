#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 38: Skill env override host injection (GHSA-82g8-464f-2mv7, CVSS 2.7)"

OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
SKILLS_DIR="$OPENCLAW_DIR/workspace/skills"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
SELF_DIR_NAME="$(basename "$PROJECT_DIR")"

if [ ! -d "$SKILLS_DIR" ]; then
    log "  Skills directory not found, skipping"
    exit 2
fi

FOUND_OVERRIDES=false
while IFS= read -r SKILL_DIR; do
    SKILL_NAME=$(basename "$SKILL_DIR")
    # Skip self
    if [ "$SKILL_NAME" = "$SELF_DIR_NAME" ]; then continue; fi

    SKILL_MD="$SKILL_DIR/SKILL.md"
    if [ -f "$SKILL_MD" ]; then
        if grep -qiE '^\s*"?(HOST|PORT|OPENCLAW_|API_URL|BASE_URL|GATEWAY_URL|SERVER_URL)"?\s*:' "$SKILL_MD" 2>/dev/null; then
            log "  WARNING: Skill '$SKILL_NAME' declares HOST/PORT/URL env overrides"
            FOUND_OVERRIDES=true

            log ""
            log "  Matching lines in $SKILL_NAME/SKILL.md:"
            grep -niE '^\s*"?(HOST|PORT|OPENCLAW_|API_URL|BASE_URL|GATEWAY_URL|SERVER_URL)"?\s*:' "$SKILL_MD" 2>/dev/null | while IFS= read -r LINE; do
                log "    $LINE"
            done
            log ""

            guidance "Review skill '$SKILL_NAME' env declarations — may redirect OpenClaw traffic"
        fi
    fi

    # Check .env files in skills
    if [ -f "$SKILL_DIR/.env" ]; then
        if grep -qiE '(OPENCLAW_HOME|OPENCLAW_DIR|GATEWAY_URL|API_BASE)' "$SKILL_DIR/.env" 2>/dev/null; then
            log "  WARNING: Skill '$SKILL_NAME' has .env overriding OpenClaw vars"
            FOUND_OVERRIDES=true

            if confirm "Remove suspicious .env from skill '$SKILL_NAME'?"; then
                if $DRY_RUN; then
                    log "  [DRY-RUN] Would remove $SKILL_DIR/.env"
                    FIXED=$((FIXED + 1))
                else
                    if rm -f "$SKILL_DIR/.env" 2>/dev/null; then
                        log "  FIXED: Removed $SKILL_DIR/.env"
                        FIXED=$((FIXED + 1))
                    else
                        log "  FAILED: Could not remove $SKILL_DIR/.env"
                        FAILED=$((FAILED + 1))
                    fi
                fi
            fi
        fi
    fi
done < <(find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)

if [ "$FOUND_OVERRIDES" = false ]; then
    log "  No suspicious env overrides found"
fi

finish
