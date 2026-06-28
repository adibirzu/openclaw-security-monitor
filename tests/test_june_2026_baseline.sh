#!/usr/bin/env bash
# A stale OpenClaw version must trigger the June 2026 advisory baseline.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib.sh"

TEST_NAME="June 2026 safe baseline flags stale OpenClaw"
echo "TEST: $TEST_NAME"

home="$(make_sandbox)"
bin="$home/bin"
mkdir -p "$bin"

cat > "$bin/openclaw" <<'SH'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then
  echo "2026.5.12"
  exit 0
fi
if [ "${1:-}" = "config" ] && [ "${2:-}" = "get" ]; then
  case "${3:-}" in
    gateway.auth.mode) echo "token" ;;
    gateway.bind) echo "localhost" ;;
    gateway.auth.token) echo "test-token" ;;
    gateway.port) echo "18789" ;;
    *) echo "" ;;
  esac
  exit 0
fi
exit 0
SH
chmod +x "$bin/openclaw"

out="$(PATH="$bin:$PATH" OPENCLAW_HOME="$home" bash "$SCAN" 2>&1)"
scan_exit=$?

assert_eq "2" "$scan_exit" "stale version exits compromised"
assert_contains "$out" "current safe baseline (v2026.5.26+)" "baseline finding emitted"
assert_contains "$out" "CVE-2026-53843" "June scope advisory included"
assert_contains "$out" "CVE-2026-53864" "June host env advisory included"

finish_test
