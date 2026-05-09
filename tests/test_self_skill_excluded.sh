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

# Contract: no path under workspace/skills/openclaw-security-monitor must
# appear in any "found in" line. Host-environment findings on the runner
# (PATH hijack, etc.) are out of scope — the test isolates the self-exclusion
# behaviour of the SELF_DIR_NAME --exclude-dir guards in scan.sh.
self_path="$home/workspace/skills/openclaw-security-monitor"
if grep -qF -- "$self_path" <<<"$out"; then
  fail "self-skill cited in scan output (regex literals were detected as if malicious)"
  echo "    --- offending lines ---"
  grep -F -- "$self_path" <<<"$out" | head -10 | sed 's/^/    /'
else
  pass "self-skill correctly excluded from detection walks"
fi

finish_test
