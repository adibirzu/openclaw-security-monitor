#!/usr/bin/env bash
# A pristine workspace with no skills should scan as SECURE (exit 0).
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib.sh"

TEST_NAME="clean workspace -> SECURE"
echo "TEST: $TEST_NAME"

home="$(make_sandbox)"
trap 'rm -rf "$home"' EXIT

out="$(run_scan "$home")"; _SCAN_EXIT=$?
if ! assert_eq "0" "$_SCAN_EXIT" "scan should exit 0 on clean workspace"; then
  echo "    --- scan output (last 60 lines) ---"
  echo "$out" | grep -E '^(CRITICAL|WARNING|CLEAN|STATUS|\[)' | tail -60 | sed 's/^/    /'
fi
assert_contains "$out" "STATUS: SECURE" "summary line missing"
assert_not_contains "$out" "STATUS: COMPROMISED" "should not report compromised"
finish_test
