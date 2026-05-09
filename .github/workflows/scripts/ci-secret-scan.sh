#!/usr/bin/env bash
# CI-side secret scanner. Mirrors the host secret-scan.sh but tuned for the repo
# (excludes IOC files which legitimately hold credential-shaped strings as detection patterns).
set -uo pipefail

LABELS=(
  AWS_ACCESS_KEY
  AWS_SECRET
  GH_PAT
  SLACK_TOKEN
  GOOGLE_API
  STRIPE
  OPENAI
  ANTHROPIC
  JWT_LIKE
  PRIVATE_KEY
  GENERIC_TOKEN_ASSIGN
  TELEGRAM_BOT
)
PATTERNS=(
  'AKIA[0-9A-Z]{16}'
  'aws.{0,20}(secret|access).{0,5}[A-Za-z0-9/+=]{40}'
  'gh[pousr]_[A-Za-z0-9_]{36,}'
  'xox[abprs]-[A-Za-z0-9-]{10,48}'
  'AIza[0-9A-Za-z_-]{35}'
  'sk_live_[0-9a-zA-Z]{24,}'
  'sk-[A-Za-z0-9]{32,}'
  'sk-ant-[A-Za-z0-9_-]{32,}'
  'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
  '-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'
  '(password|passwd|secret|token|api[_-]?key)[[:space:]]*[:=][[:space:]]*"[^"$]{16,}"'
  '[0-9]{8,10}:[A-Za-z0-9_-]{35,}'
)

# Scanner itself contains these regex literals.
# IOC dir contains pattern strings too. Exclude both from scan.
EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=node_modules
  --exclude-dir=ioc
  --exclude=ci-secret-scan.sh
  --exclude=*.lock
  --exclude=*.svg
  --exclude=*.png
  --exclude=*.jpg
  --exclude='check-29-plaintext-creds.sh'
  --exclude='check-16-env-leakage.sh'
  --exclude='scan.sh'
)

hits=0
for i in "${!LABELS[@]}"; do
  label="${LABELS[$i]}"
  rx="${PATTERNS[$i]}"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    echo "::error::[$label] $line"
    hits=$((hits+1))
  done < <(grep -REn "${EXCLUDES[@]}" -- "$rx" . 2>/dev/null || true)
done

if (( hits == 0 )); then
  echo "secret-scan: clean"
  exit 0
fi
echo "secret-scan: $hits suspicious matches"
exit 1
