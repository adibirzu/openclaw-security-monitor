#!/usr/bin/env bash
# scan.sh must NOT flag itself as malicious when installed under workspace/skills/.
# Regression test: every grep in scan.sh uses --exclude-dir="$SELF_DIR_NAME".
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib.sh"

TEST_NAME="self skill is excluded from detection"
echo "TEST: $TEST_NAME"

home="$(make_sandbox)"
trap 'rm -rf "$home"' EXIT

# Place a real copy of the repo (which contains regex literals like 91.92.242)
# under workspace/skills/ to simulate the deployed install.
cp -R "$REPO_ROOT" "$home/workspace/skills/openclaw-security-monitor"

out="$(run_scan "$home")"; _SCAN_EXIT=$?
# Exit 0 (SECURE) or 1 (warnings about self files unrelated to detection)
# but never 2 (COMPROMISED) — that would mean self-detection regressed.
assert_neq "2" "$_SCAN_EXIT" "self-skill must not trigger COMPROMISED"
assert_not_contains "$out" "openclaw-security-monitor: AMOS" "self-skill flagged for AMOS"
finish_test
