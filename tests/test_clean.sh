#!/usr/bin/env bash
# An empty workspace must produce zero skill-level findings.
# (Host-environment findings such as PATH hijack on GitHub runners are
# orthogonal — they relate to the runner's own filesystem, not the skill
# detection contract — so the assertion targets the *skill* surface only.)
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib.sh"

TEST_NAME="empty workspace -> no skill-level findings"
echo "TEST: $TEST_NAME"

home="$(make_sandbox)"
trap 'rm -rf "$home"' EXIT

out="$(run_scan "$home")"; _SCAN_EXIT=$?

# The contract: no skill in the seeded workspace ever appears in a "found in"
# line. The PATH on the test runner is out of scope.
skills_root="$home/workspace/skills"
if grep -qF -- "$skills_root" <<<"$out"; then
  fail "skill-level finding leaked into output for empty workspace"
  echo "    --- offending lines ---"
  grep -F -- "$skills_root" <<<"$out" | head -10 | sed 's/^/    /'
else
  pass "no path under $skills_root cited in scan output"
fi

# Must not flag a skill-level CRITICAL (these patterns are the ones tied to
# walked-skill content; environmental ones use other phrasing).
for pat in 'Known C2 IP found in:' 'AMOS/stealer markers found in:' 'Reverse shell patterns found in:' 'Exfiltration endpoints found in:' 'Skills attempting to modify memory'; do
  assert_not_contains "$out" "$pat" "skill-level critical fired on empty workspace: $pat"
done

finish_test
