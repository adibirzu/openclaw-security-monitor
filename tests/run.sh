#!/usr/bin/env bash
# Test harness for openclaw-security-monitor.
# Runs every tests/test_*.sh sequentially. Each test is an independent process.
# Exit 0 if all pass, 1 otherwise. Prints a final summary.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

shopt -s nullglob
TESTS=( test_*.sh )
[[ ${#TESTS[@]} -gt 0 ]] || { echo "no tests found"; exit 1; }

passed=0
failed=0
failed_names=()

for t in "${TESTS[@]}"; do
  start=$(date +%s)
  if bash "$t"; then
    elapsed=$(( $(date +%s) - start ))
    echo "  PASS ($elapsed s)"
    passed=$((passed+1))
  else
    elapsed=$(( $(date +%s) - start ))
    echo "  FAIL ($elapsed s)"
    failed=$((failed+1))
    failed_names+=( "$t" )
  fi
  echo
done

echo "================================"
echo "results: $passed passed, $failed failed (of $((passed+failed)))"
if (( failed > 0 )); then
  printf '  - %s\n' "${failed_names[@]}"
  exit 1
fi
exit 0
