#!/usr/bin/env bash
# Dashboard hardening regression tests.
# Boots dashboard/server.js on an ephemeral port, exercises each defense.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib.sh"

TEST_NAME="dashboard hardening: DNS-rebinding, CSP nonce, token gate"
echo "TEST: $TEST_NAME"

if ! command -v node >/dev/null; then
  echo "  SKIP: node not installed"
  exit 0
fi

PORT=18800
SERVER="$REPO_ROOT/dashboard/server.js"

# Run with a tmp HOME so it doesn't read the user's logs.
TMPHOME="$(mktemp -d -t dashtest.XXXXXX)"
mkdir -p "$TMPHOME/.openclaw/logs" "$TMPHOME/.openclaw/workspace/skills"

# Use a non-default port to avoid collision with a running dashboard.
TEST_PORT=$(( (RANDOM % 1000) + 18801 ))

DASHBOARD_PORT="$TEST_PORT" DASHBOARD_TOKEN="testtok123" HOME="$TMPHOME" \
  node "$SERVER" >"$TMPHOME/server.log" 2>&1 &
SERVER_PID=$!
trap '{ kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null; rm -rf "$TMPHOME"; } >/dev/null 2>&1' EXIT

# wait for socket
for _ in $(seq 1 20); do
  if curl -sf -m1 -H "Host: 127.0.0.1:${TEST_PORT}" -H "Authorization: Bearer testtok123" "http://127.0.0.1:${TEST_PORT}/api/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

# 1. DNS-rebinding: bogus Host -> 421
code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Host: evil.example.com" \
  -H "Authorization: Bearer testtok123" \
  "http://127.0.0.1:${TEST_PORT}/api/status")
assert_eq "421" "$code" "bogus Host header must be rejected (421)"

# 2. Allowed Host with token -> 200
code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Host: 127.0.0.1:${TEST_PORT}" \
  -H "Authorization: Bearer testtok123" \
  "http://127.0.0.1:${TEST_PORT}/api/status")
assert_eq "200" "$code" "allowed Host + token -> 200"

# 3. Token gate: no token -> 401
code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Host: 127.0.0.1:${TEST_PORT}" \
  "http://127.0.0.1:${TEST_PORT}/api/status")
assert_eq "401" "$code" "missing token must yield 401"

# 4. CSP header has nonce, no 'unsafe-inline'
hdrs=$(curl -sI \
  -H "Host: 127.0.0.1:${TEST_PORT}" \
  -H "Authorization: Bearer testtok123" \
  "http://127.0.0.1:${TEST_PORT}/")
assert_contains "$hdrs" "Content-Security-Policy" "CSP header missing"
assert_contains "$hdrs" "nonce-" "CSP must use nonce"
assert_not_contains "$hdrs" "unsafe-inline" "CSP must not allow unsafe-inline"

# 5. index.html is served with nonce on inline <script> and <style>
body=$(curl -s \
  -H "Host: 127.0.0.1:${TEST_PORT}" \
  -H "Authorization: Bearer testtok123" \
  "http://127.0.0.1:${TEST_PORT}/")
assert_contains "$body" '<script nonce="' "<script> tag missing nonce"
assert_contains "$body" '<style nonce="' "<style> tag missing nonce"

finish_test
