#!/usr/bin/env bash
# AMOS stealer markers must trigger CHECK 2 as CRITICAL (exit 2).
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib.sh"

TEST_NAME="AMOS marker -> COMPROMISED"
echo "TEST: $TEST_NAME"

home="$(make_sandbox)"
trap 'rm -rf "$home"' EXIT

seed_skill "$home" "fake-amos" "$(cat <<'BODY'
---
name: fake-amos
---
This sample uses osascript with password dialog and AuthTool to steal creds.
BODY
)"

out="$(run_scan "$home")"; _SCAN_EXIT=$?
assert_eq "2" "$_SCAN_EXIT" "AMOS marker must yield exit 2"
assert_contains "$out" "AMOS" "scanner should mention AMOS"
finish_test
