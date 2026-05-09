#!/usr/bin/env bash
# Test helpers for openclaw-security-monitor.
# Sourced by every tests/test_*.sh.
#
# Public API:
#   make_sandbox            -> echos a fresh tmp OPENCLAW_HOME with workspace/skills/
#   seed_skill <home> <name> <body>
#   run_scan <home>         -> stdout of scan.sh, sets _SCAN_EXIT
#   assert_eq <expected> <actual> [msg]
#   assert_neq <a> <b> [msg]
#   assert_contains <haystack> <needle> [msg]
#   assert_not_contains <haystack> <needle> [msg]
#   pass [msg]   /  fail <msg>
#
# A test script is expected to set TEST_NAME, then call any number of
# assertions. The harness (tests/run.sh) tracks pass/fail by exit code.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="$REPO_ROOT/scripts/scan.sh"

_SCAN_EXIT=0
_FAILED=0

make_sandbox() {
  local d
  d="$(mktemp -d -t openclaw-test.XXXXXX)"
  mkdir -p "$d/workspace/skills" "$d/logs"
  echo "$d"
}

seed_skill() {
  local home="$1" name="$2" body="$3"
  local dir="$home/workspace/skills/$name"
  mkdir -p "$dir"
  printf '%s\n' "$body" > "$dir/SKILL.md"
}

# Usage:
#   out="$(run_scan "$home")" || true
#   _SCAN_EXIT=$?
run_scan() {
  local home="$1"
  OPENCLAW_HOME="$home" bash "$SCAN" 2>&1
}

assert_eq() {
  local expected="$1" actual="$2" msg="${3:-assert_eq}"
  if [[ "$expected" != "$actual" ]]; then
    echo "  FAIL: $msg"
    echo "    expected: $expected"
    echo "    actual:   $actual"
    _FAILED=1
    return 1
  fi
  return 0
}

assert_neq() {
  local a="$1" b="$2" msg="${3:-assert_neq}"
  if [[ "$a" == "$b" ]]; then
    echo "  FAIL: $msg (both = $a)"
    _FAILED=1
    return 1
  fi
}

assert_contains() {
  local haystack="$1" needle="$2" msg="${3:-assert_contains}"
  if ! grep -qF -- "$needle" <<<"$haystack"; then
    echo "  FAIL: $msg — needle not found: $needle"
    _FAILED=1
    return 1
  fi
}

assert_not_contains() {
  local haystack="$1" needle="$2" msg="${3:-assert_not_contains}"
  if grep -qF -- "$needle" <<<"$haystack"; then
    echo "  FAIL: $msg — unexpected needle: $needle"
    _FAILED=1
    return 1
  fi
}

pass() { echo "  ok: ${1:-pass}"; }
fail() { echo "  FAIL: ${1:-fail}"; _FAILED=1; }

# Tests should `exit $_FAILED` at the bottom (run.sh interprets non-zero as fail).
finish_test() { exit "$_FAILED"; }
