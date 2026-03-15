#!/bin/bash
# OpenClaw Security Monitor - IOC Database Updater
# Fetches latest threat intelligence from community sources and updates
# the local IOC database. Run periodically or before scans.
#
# Sources:
#   - Koi Security ClawHavoc feed
#   - GitHub community IOC contributions
#   - Local scan findings
#   - ClawHub API (malicious publishers feed)
#
# Usage: update-ioc.sh [--check | --check-only] [--auto] [--github-repo URL]
#
#   --check / --check-only   Show what would update without writing files
#   --auto                   Unattended / cron mode: suppress prompts, exit non-zero on error
#   --github-repo URL        Override the upstream raw GitHub base URL
#                           (requires OPENCLAW_ALLOW_UNTRUSTED_IOC_SOURCE=1 unless trusted)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IOC_DIR="$PROJECT_DIR/ioc"
SELF_DIR_NAME="$(basename "$PROJECT_DIR")"
LOG_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}/logs"
UPDATE_LOG="$LOG_DIR/ioc-update.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
TIMESTAMP_FILE="$IOC_DIR/.last-update"
OUTDATED_DAYS=7

# Default upstream repo for IOC updates
DEFAULT_GITHUB_REPO="https://raw.githubusercontent.com/adibirzu/openclaw-security-monitor/main/ioc"
TRUSTED_GITHUB_PREFIX="https://raw.githubusercontent.com/adibirzu/openclaw-security-monitor/"
GITHUB_REPO="$DEFAULT_GITHUB_REPO"
CHECK_ONLY=false
AUTO_MODE=false
ALLOW_UNTRUSTED_SOURCE="${OPENCLAW_ALLOW_UNTRUSTED_IOC_SOURCE:-0}"

# ============================================================
# Argument parsing
# ============================================================
while [ $# -gt 0 ]; do
    case "$1" in
        --check|--check-only)
            CHECK_ONLY=true
            ;;
        --auto)
            AUTO_MODE=true
            ;;
        --github-repo)
            shift
            if [ -n "${1:-}" ]; then
                GITHUB_REPO="$1"
            fi
            ;;
    esac
    shift
done

mkdir -p "$LOG_DIR" "$IOC_DIR"

log() { echo "[$TIMESTAMP] $1" | tee -a "$UPDATE_LOG"; }
info() { echo "$1"; }

is_trusted_repo() {
    case "$1" in
        "$DEFAULT_GITHUB_REPO"|"$TRUSTED_GITHUB_PREFIX"*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

expected_fields_for_file() {
    case "$1" in
        c2-ips.txt) echo 4 ;;
        malicious-domains.txt) echo 4 ;;
        file-hashes.txt) echo 5 ;;
        malicious-publishers.txt) echo 4 ;;
        malicious-skill-patterns.txt) echo 3 ;;
        *) echo "" ;;
    esac
}

validate_ioc_content() {
    local ioc_file="$1"
    local content="$2"
    local expected
    expected=$(expected_fields_for_file "$ioc_file")
    [ -z "$expected" ] && return 0

    local bad
    bad=$(echo "$content" | awk -F'|' -v expected="$expected" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        NF != expected { bad += 1 }
        END { print bad + 0 }
    ')
    if [ "$bad" -gt 0 ]; then
        log "Rejected $ioc_file from upstream: $bad malformed line(s)"
        return 1
    fi
    return 0
}

if ! is_trusted_repo "$GITHUB_REPO" && [ "$ALLOW_UNTRUSTED_SOURCE" != "1" ]; then
    echo "ERROR: Refusing untrusted IOC source: $GITHUB_REPO"
    echo "Set OPENCLAW_ALLOW_UNTRUSTED_IOC_SOURCE=1 to override intentionally."
    exit 1
fi

log "IOC update started (check_only=$CHECK_ONLY auto=$AUTO_MODE source=$GITHUB_REPO)"

# ============================================================
# --check flag: report IOC freshness and exit
# ============================================================
if [ "$CHECK_ONLY" = true ]; then
    echo "=== IOC Freshness Check ==="
    if [ -f "$TIMESTAMP_FILE" ]; then
        LAST_UPDATE=$(cat "$TIMESTAMP_FILE")
        LAST_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$LAST_UPDATE" "+%s" 2>/dev/null || \
                     date -d "$LAST_UPDATE" "+%s" 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        AGE_DAYS=$(( (NOW_EPOCH - LAST_EPOCH) / 86400 ))
        echo "  Last update : $LAST_UPDATE"
        echo "  Age         : ${AGE_DAYS} day(s)"
        if [ "$AGE_DAYS" -gt "$OUTDATED_DAYS" ]; then
            echo "  Status      : OUTDATED (>${OUTDATED_DAYS} days) — run update-ioc.sh to refresh"
            log "IOC check: OUTDATED (${AGE_DAYS} days old)"
            exit 1
        else
            echo "  Status      : CURRENT (within ${OUTDATED_DAYS}-day window)"
            log "IOC check: CURRENT (${AGE_DAYS} days old)"
            exit 0
        fi
    else
        echo "  Last update : unknown (no timestamp file)"
        echo "  Status      : UNKNOWN — run update-ioc.sh to initialize"
        log "IOC check: no timestamp file found"
        exit 1
    fi
fi

# ============================================================
# 1. Check for upstream IOC updates from GitHub
# ============================================================
echo "=== Checking upstream IOC database ==="

IOC_FILES=("c2-ips.txt" "malicious-domains.txt" "file-hashes.txt" "malicious-publishers.txt" "malicious-skill-patterns.txt")
UPDATES_FOUND=0

# Track per-file diffs for summary
declare -a DIFF_SUMMARIES=()
# Track pending updates for interactive confirmation
declare -a PENDING_UPDATES=()
declare -A PENDING_CONTENT=() 2>/dev/null || true

for ioc_file in "${IOC_FILES[@]}"; do
    echo -n "  Checking $ioc_file... "
    REMOTE_CONTENT=$(curl -sL --connect-timeout 10 --max-time 30 "$GITHUB_REPO/$ioc_file" 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$REMOTE_CONTENT" ]; then
        echo "SKIP (unreachable)"
        continue
    fi

    # Check if remote contains error page (GitHub 404)
    if echo "$REMOTE_CONTENT" | grep -q "^404"; then
        echo "SKIP (not found)"
        continue
    fi

    if ! validate_ioc_content "$ioc_file" "$REMOTE_CONTENT"; then
        echo "SKIP (invalid format)"
        continue
    fi

    LOCAL_FILE="$IOC_DIR/$ioc_file"
    if [ -f "$LOCAL_FILE" ]; then
        LOCAL_HASH=$(shasum -a 256 "$LOCAL_FILE" | cut -d' ' -f1)
        REMOTE_HASH=$(echo "$REMOTE_CONTENT" | shasum -a 256 | cut -d' ' -f1)

        if [ "$LOCAL_HASH" != "$REMOTE_HASH" ]; then
            echo "UPDATE AVAILABLE"
            UPDATES_FOUND=$((UPDATES_FOUND + 1))

            # Compute diff summary (non-comment, non-blank lines added/removed)
            OLD_LINES=$(grep -v '^#' "$LOCAL_FILE" | grep -v '^$' | wc -l | tr -d ' ')
            NEW_LINES=$(echo "$REMOTE_CONTENT" | grep -v '^#' | grep -v '^$' | wc -l | tr -d ' ')
            DELTA=$((NEW_LINES - OLD_LINES))
            DELTA_STR="$DELTA"
            [ "$DELTA" -gt 0 ] && DELTA_STR="+$DELTA"
            DIFF_SUMMARIES+=("$ioc_file: $DELTA_STR entries (${OLD_LINES} -> ${NEW_LINES})")

            if [ "$AUTO_MODE" = true ]; then
                cp "$LOCAL_FILE" "$LOCAL_FILE.bak"
                echo "$REMOTE_CONTENT" > "$LOCAL_FILE"
                log "Auto-updated $ioc_file (was $LOCAL_HASH, now $REMOTE_HASH)"
                echo "    -> Auto-updated"
            else
                # Interactive mode: stage the update for confirmation
                PENDING_UPDATES+=("$ioc_file")
                PENDING_CONTENT["$ioc_file"]="$REMOTE_CONTENT"
                echo "    -> Pending (will confirm below)"
            fi
        else
            echo "UP TO DATE"
        fi
    else
        echo "NEW"
        UPDATES_FOUND=$((UPDATES_FOUND + 1))
        NEW_LINES=$(echo "$REMOTE_CONTENT" | grep -v '^#' | grep -v '^$' | wc -l | tr -d ' ')
        DIFF_SUMMARIES+=("$ioc_file: NEW (+${NEW_LINES} entries)")
        echo "$REMOTE_CONTENT" > "$LOCAL_FILE"
        log "Downloaded new $ioc_file"
        echo "    -> Downloaded"
    fi
done

echo ""

# ============================================================
# Interactive confirmation for pending updates
# ============================================================
if [ "$AUTO_MODE" = false ] && [ "${#PENDING_UPDATES[@]}" -gt 0 ]; then
    echo "=== Pending IOC Updates ==="
    for pf in "${PENDING_UPDATES[@]}"; do
        echo "  - $pf"
    done
    echo ""
    printf "Apply these updates? [y/N] "
    read -r answer
    if [[ "$answer" =~ ^[Yy] ]]; then
        for pf in "${PENDING_UPDATES[@]}"; do
            LOCAL_FILE="$IOC_DIR/$pf"
            cp "$LOCAL_FILE" "$LOCAL_FILE.bak" 2>/dev/null || true
            echo "${PENDING_CONTENT[$pf]}" > "$LOCAL_FILE"
            log "Updated $pf (user confirmed)"
            echo "  -> Updated: $pf"
        done
    else
        echo "  Skipped — no IOC files were modified."
        log "User declined IOC updates"
    fi
    echo ""
fi

# ============================================================
# 2. Fetch malicious publishers from ClawHub API
# ============================================================
fetch_clawhub_publishers() {
    local pub_file="$IOC_DIR/malicious-publishers.txt"
    local api_url="$GITHUB_REPO/malicious-publishers.txt"

    echo "=== Fetching ClawHub malicious publishers feed ==="
    echo -n "  Querying ClawHub publisher feed... "

    local remote
    remote=$(curl -sL --connect-timeout 10 --max-time 30 "$api_url" 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$remote" ]; then
        echo "SKIP (feed unreachable)"
        log "ClawHub publisher feed: unreachable"
        return
    fi

    if echo "$remote" | grep -q "^404"; then
        echo "SKIP (not found)"
        log "ClawHub publisher feed: 404"
        return
    fi

    # Extract publisher handles (first field, non-comment, non-blank)
    if ! validate_ioc_content "malicious-publishers.txt" "$remote"; then
        echo "SKIP (invalid feed format)"
        log "ClawHub publisher feed: invalid format"
        return
    fi

    local remote_handles
    remote_handles=$(echo "$remote" | grep -v '^#' | grep -v '^$' | cut -d'|' -f1)
    local remote_count
    remote_count=$(echo "$remote_handles" | grep -c '.' || echo 0)

    echo "OK ($remote_count publisher entries)"

    # Merge any new handles not already in local file
    if [ -f "$pub_file" ]; then
        local added=0
        while IFS= read -r handle; do
            [ -z "$handle" ] && continue
            if ! grep -qF "$handle" "$pub_file" 2>/dev/null; then
                if [ "$AUTO_MODE" = false ]; then
                    echo "$handle|clawhub-api|$(date -u +"%Y-%m-%d")|Added via ClawHub API feed" >> "$pub_file"
                else
                    echo "$handle|clawhub-api|$(date -u +"%Y-%m-%d")|Added via ClawHub API feed" >> "$pub_file"
                fi
                log "ClawHub feed: added new publisher handle: $handle"
                added=$((added + 1))
            fi
        done <<< "$remote_handles"

        if [ "$added" -gt 0 ]; then
            echo "  -> Merged $added new publisher handle(s) into malicious-publishers.txt"
            DIFF_SUMMARIES+=("malicious-publishers.txt (ClawHub API): +$added new handles")
            UPDATES_FOUND=$((UPDATES_FOUND + 1))
        else
            echo "  -> No new publisher handles to merge"
        fi
    fi
    echo ""
}

fetch_clawhub_publishers

# ============================================================
# 3. Live threat feed: scan active network for new C2 indicators
# ============================================================
echo "=== Scanning active network for undocumented connections ==="

# Get all non-local, non-Apple IPs from active connections
ACTIVE_IPS=$(lsof -i -nP 2>/dev/null | grep -E "node|openclaw" | grep -E "ESTABLISHED|SYN_SENT" | \
    awk '{print $9}' | grep -- '->' | sed 's/.*->//' | cut -d: -f1 | \
    grep -vE "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|localhost)" | \
    sort -u)

if [ -n "$ACTIVE_IPS" ]; then
    echo "  Active external connections from node/openclaw:"
    KNOWN_IPS=$(grep -v '^#' "$IOC_DIR/c2-ips.txt" 2>/dev/null | grep -v '^$' | cut -d'|' -f1)
    while IFS= read -r ip; do
        KNOWN=false
        for kip in $KNOWN_IPS; do
            if echo "$ip" | grep -qF -- "$kip" 2>/dev/null; then
                echo "    ALERT: $ip matches known C2: $kip"
                KNOWN=true
                break
            fi
        done
        if [ "$KNOWN" = false ]; then
            echo "    OK: $ip (not in C2 database)"
        fi
    done <<< "$ACTIVE_IPS"
else
    echo "  No external connections from node/openclaw processes"
fi

echo ""

# ============================================================
# 4. Scan installed skills for IOC matches
# ============================================================
echo "=== Checking installed skills against IOC database ==="

SKILLS_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}/workspace/skills"
THREATS_FOUND=0

if [ -d "$SKILLS_DIR" ]; then
    # Check skill names against malicious patterns
    if [ -f "$IOC_DIR/malicious-skill-patterns.txt" ]; then
        PATTERNS=$(grep -v '^#' "$IOC_DIR/malicious-skill-patterns.txt" | grep -v '^$' | cut -d'|' -f1)
        for skilldir in "$SKILLS_DIR"/*/; do
            SKILL_NAME=$(basename "$skilldir")
            [ "$SKILL_NAME" = "$SELF_DIR_NAME" ] && continue
            for pattern in $PATTERNS; do
                if echo "$SKILL_NAME" | grep -qiE "$pattern" 2>/dev/null; then
                    echo "  WARNING: Skill '$SKILL_NAME' matches malicious pattern: $pattern"
                    THREATS_FOUND=$((THREATS_FOUND + 1))
                    break
                fi
            done
        done
    fi

    # Check for known malicious publishers in skill files
    if [ -f "$IOC_DIR/malicious-publishers.txt" ]; then
        PUBLISHERS=$(grep -v '^#' "$IOC_DIR/malicious-publishers.txt" | grep -v '^$' | cut -d'|' -f1)
        for pub in $PUBLISHERS; do
            FOUND=$(grep -rl --exclude-dir="$SELF_DIR_NAME" "$pub" "$SKILLS_DIR" 2>/dev/null || true)
            if [ -n "$FOUND" ]; then
                echo "  CRITICAL: Known malicious publisher '$pub' found in: $FOUND"
                THREATS_FOUND=$((THREATS_FOUND + 1))
            fi
        done
    fi

    # Check for known malicious file hashes
    if [ -f "$IOC_DIR/file-hashes.txt" ]; then
        HASHES=$(grep -v '^#' "$IOC_DIR/file-hashes.txt" | grep -v '^$' | cut -d'|' -f1)
        for hash in $HASHES; do
            FOUND=$(find "$SKILLS_DIR" -type f -not -path "*/$SELF_DIR_NAME/*" -exec shasum -a 256 {} \; 2>/dev/null | grep "$hash" || true)
            if [ -n "$FOUND" ]; then
                echo "  CRITICAL: Known malicious file hash found: $FOUND"
                THREATS_FOUND=$((THREATS_FOUND + 1))
            fi
        done
    fi
fi

if [ "$THREATS_FOUND" -eq 0 ]; then
    echo "  CLEAN: No installed skills match known threats"
fi

echo ""

# ============================================================
# 5. Record update timestamp
# ============================================================
if [ "$UPDATES_FOUND" -gt 0 ]; then
    echo "$TIMESTAMP" > "$TIMESTAMP_FILE"
    log "Timestamp recorded: $TIMESTAMP"
else
    # Refresh timestamp even when already up to date so --check stays accurate
    if [ ! -f "$TIMESTAMP_FILE" ]; then
        echo "$TIMESTAMP" > "$TIMESTAMP_FILE"
    fi
fi

# ============================================================
# 6. Diff summary of what changed
# ============================================================
echo "=== Change Summary ==="
if [ "${#DIFF_SUMMARIES[@]}" -gt 0 ]; then
    for summary in "${DIFF_SUMMARIES[@]}"; do
        echo "  $summary"
    done
else
    echo "  No changes detected across all IOC files."
fi
echo ""

# ============================================================
# Summary
# ============================================================
echo "=== Summary ==="
echo "  IOC files checked: ${#IOC_FILES[@]}"
echo "  Updates applied  : $UPDATES_FOUND"
echo "  Threats found    : $THREATS_FOUND"
echo "  Last update      : $TIMESTAMP"
echo ""

if [ "$AUTO_MODE" = true ]; then
    log "IOC auto-update complete: $UPDATES_FOUND updates, $THREATS_FOUND threats"
    # In auto mode exit non-zero if threats found
    if [ "$THREATS_FOUND" -gt 0 ]; then
        exit 2
    fi
    exit 0
fi

log "IOC update complete: $UPDATES_FOUND updates, $THREATS_FOUND threats"
