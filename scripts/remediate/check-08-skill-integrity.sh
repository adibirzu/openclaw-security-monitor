#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

log "CHECK 8: Checking skill integrity (comparing hashes)..."

HASH_FILE="$LOG_DIR/skill-hashes.sha256"
PREV_HASH_FILE="$LOG_DIR/skill-hashes.sha256.prev"

# Check if we have both hash files
if [ ! -f "$HASH_FILE" ]; then
  log "No current hash file found at $HASH_FILE"
  exit 2
fi

if [ ! -f "$PREV_HASH_FILE" ]; then
  log "No previous hash file found at $PREV_HASH_FILE"
  log "This is the first run - creating baseline"
  exit 2
fi

# Compare hash files
log "Comparing current hashes with previous baseline..."

DIFF_OUTPUT=$(diff "$PREV_HASH_FILE" "$HASH_FILE" 2>&1)

if [ -z "$DIFF_OUTPUT" ]; then
  log "No changes detected in skill hashes"
  exit 2
fi

# Parse diff output to find changed skills
CHANGED_SKILLS=()
ADDED_SKILLS=()
REMOVED_SKILLS=()

while IFS= read -r line; do
  # Lines starting with < are in old file (removed)
  if [[ "$line" =~ ^\<[[:space:]]+([a-f0-9]+)[[:space:]]+(.+) ]]; then
    skill_file="${BASH_REMATCH[2]}"
    skill_name=$(echo "$skill_file" | sed 's|.*/skills/||' | cut -d'/' -f1)
    if [[ ! " ${REMOVED_SKILLS[@]} " =~ " ${skill_name} " ]]; then
      REMOVED_SKILLS+=("$skill_name")
    fi
  # Lines starting with > are in new file (added)
  elif [[ "$line" =~ ^\>[[:space:]]+([a-f0-9]+)[[:space:]]+(.+) ]]; then
    skill_file="${BASH_REMATCH[2]}"
    skill_name=$(echo "$skill_file" | sed 's|.*/skills/||' | cut -d'/' -f1)
    if [[ ! " ${ADDED_SKILLS[@]} " =~ " ${skill_name} " ]]; then
      ADDED_SKILLS+=("$skill_name")
    fi
  fi
done <<< "$DIFF_OUTPUT"

# Find skills that appear in both (changed, not added/removed)
for skill in "${ADDED_SKILLS[@]}"; do
  if [[ " ${REMOVED_SKILLS[@]} " =~ " ${skill} " ]]; then
    CHANGED_SKILLS+=("$skill")
  fi
done

# Remove changed skills from added/removed lists
for skill in "${CHANGED_SKILLS[@]}"; do
  ADDED_SKILLS=(${ADDED_SKILLS[@]/$skill})
  REMOVED_SKILLS=(${REMOVED_SKILLS[@]/$skill})
done

# Display findings
HAS_CHANGES=false

if [ ${#CHANGED_SKILLS[@]} -gt 0 ]; then
  HAS_CHANGES=true
  log "WARNING: ${#CHANGED_SKILLS[@]} skill(s) have been MODIFIED:"
  for skill in "${CHANGED_SKILLS[@]}"; do
    log "  - $skill (content changed)"
  done
fi

if [ ${#ADDED_SKILLS[@]} -gt 0 ]; then
  HAS_CHANGES=true
  log "INFO: ${#ADDED_SKILLS[@]} new skill(s) added:"
  for skill in "${ADDED_SKILLS[@]}"; do
    log "  - $skill (new)"
  done
fi

if [ ${#REMOVED_SKILLS[@]} -gt 0 ]; then
  HAS_CHANGES=true
  log "INFO: ${#REMOVED_SKILLS[@]} skill(s) removed:"
  for skill in "${REMOVED_SKILLS[@]}"; do
    log "  - $skill (deleted)"
  done
fi

if [ "$HAS_CHANGES" = false ]; then
  log "No significant changes detected"
  exit 2
fi

# Show diff output
log ""
log "Detailed changes:"
log "─────────────────────────────────────────"
echo "$DIFF_OUTPUT" | head -50 | tee -a "$LOG_FILE"
if [ $(echo "$DIFF_OUTPUT" | wc -l) -gt 50 ]; then
  log "... (output truncated, see $LOG_FILE for full diff)"
  echo "$DIFF_OUTPUT" >> "$LOG_FILE"
fi
log "─────────────────────────────────────────"

# Provide guidance
{
  echo "Skill integrity check detected changes!"
  echo ""
  echo "Modified skills may indicate:"
  echo "- Legitimate skill updates"
  echo "- Manual edits you made"
  echo "- Tampering or malware injection"
  echo ""
  echo "RECOMMENDED ACTIONS:"
  echo ""
  echo "1. For MODIFIED skills (unexpected changes):"
  echo "   Review what changed:"
  echo ""
  echo "   openclaw skill show <skill-name>"
  echo ""
  echo "   If suspicious, reinstall from ClawHub:"
  if [ ${#CHANGED_SKILLS[@]} -gt 0 ]; then
    for skill in "${CHANGED_SKILLS[@]}"; do
      echo "   openclaw skill rm $skill && openclaw skill add $skill"
    done
  fi
  echo ""
  echo "2. For NEW skills:"
  echo "   Verify you intentionally installed them:"
  echo ""
  echo "   openclaw skill list"
  echo ""
  echo "   If unrecognized, remove immediately:"
  if [ ${#ADDED_SKILLS[@]} -gt 0 ]; then
    for skill in "${ADDED_SKILLS[@]}"; do
      echo "   openclaw skill rm $skill"
    done
  fi
  echo ""
  echo "3. Update your baseline after verification:"
  echo ""
  echo "   cp $LOG_DIR/skill-hashes.sha256 $LOG_DIR/skill-hashes.sha256.prev"
  echo ""
  echo "4. For critical skills, verify against ClawHub:"
  echo "   - Check skill source repository"
  echo "   - Compare checksums with official versions"
  echo "   - Review recent commits for unauthorized changes"
  echo ""
  echo "5. If tampering is suspected:"
  echo "   - Run full security scan"
  echo "   - Check system logs for unauthorized access"
  echo "   - Review all skills for suspicious code"
  echo "   - Consider removing all skills and reinstalling"
} | guidance

exit 1
