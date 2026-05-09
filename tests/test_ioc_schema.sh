#!/usr/bin/env bash
# IOC files use pipe-delimited rows: <indicator>|<category>|<date>|<notes>.
# Validate the indicator (first field) per file:
#   c2-ips.txt              -> IPv4 dotted quad with optional CIDR
#   malicious-domains.txt   -> hostname OR github.com/<user> path
#   file-hashes.txt         -> sha1 (40 hex) or sha256 (64 hex)
#   malicious-publishers.txt-> non-empty token
#   malicious-skill-patterns.txt -> non-empty token
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib.sh"

TEST_NAME="IOC files match expected schema"
echo "TEST: $TEST_NAME"

IOC="$REPO_ROOT/ioc"

# Pipe-aware: pulls the first field, ignores comments/blank.
check_first_field() {
  local file="$1" rx="$2" label="$3"
  local n=0 bad=0 indicator
  while IFS= read -r line; do
    n=$((n+1))
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    indicator="${line%%|*}"
    if ! [[ "$indicator" =~ $rx ]]; then
      echo "  FAIL [$label:$n] indicator '$indicator' does not match $rx"
      bad=$((bad+1))
    fi
  done < "$file"
  if (( bad > 0 )); then
    _FAILED=1
  else
    pass "$label: all indicators valid"
  fi
}

IPV4='^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$'
HOST_OR_GH='^([A-Za-z0-9*]([A-Za-z0-9*\-]*[A-Za-z0-9*])?(\.[A-Za-z0-9*]([A-Za-z0-9*\-]*[A-Za-z0-9*])?)+)(/[A-Za-z0-9._\-]+)*$'
HASH='^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$'
NONEMPTY='^[^[:space:]]'

check_first_field "$IOC/c2-ips.txt"                  "$IPV4"        c2-ips
check_first_field "$IOC/malicious-domains.txt"       "$HOST_OR_GH"  domains
check_first_field "$IOC/file-hashes.txt"             "$HASH"        file-hashes
check_first_field "$IOC/malicious-publishers.txt"    "$NONEMPTY"    publishers
check_first_field "$IOC/malicious-skill-patterns.txt" "$NONEMPTY"   skill-patterns

finish_test
