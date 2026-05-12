# Changelog

## v5.4.0 — 2026-05-12

### Added — May 2026 advisory rollup coverage
- CHECK 42: Browser CDP / noVNC sandbox helper on non-loopback
  (CVE-2026-43575 noVNC auth bypass, CVE-2026-43581 CDP relay on 0.0.0.0).
  Inspects `lsof` listeners for chrome/chromium/novnc/websockify on
  non-loopback IPs, and port 9222 on any non-loopback interface.
- CHECK 43: Workspace `.env` overriding reserved `OPENCLAW_` runtime-control
  variables (CVE-2026-44114, CVE-2026-43531). Walks `workspace/` and
  `workspace/skills/` for `.env`/`.env.*` files containing
  `OPENCLAW_BUNDLED_PLUGINS_DIR`, `OPENCLAW_HOME`, `OPENCLAW_GATEWAY*`,
  `OPENCLAW_RUNTIME*`, `OPENCLAW_CONFIG`, `OPENCLAW_SKILLS_DIR`,
  `OPENCLAW_TRUSTED_PUBLISHERS`. CRITICAL.
- CHECK 44: Unquoted heredoc shell-expansion smuggling in skill shell
  scripts (CVE-2026-44115). awk-based parser finds `<<TAG` heredocs
  whose body contains `$(...)` or backticks, which bypass exec-allowlist
  analysis. WARN.
- New regression test `tests/test_dotenv_reserved_override.sh`.

### Notes
- `SAFE_BASELINE` stays at `2026.4.24` — every CVE in this rollup
  (CVE-2026-43575/43578/43581/43585, CVE-2026-44109/44110/44114/44115/44118,
  CVE-2026-44991..45002, CVE-2026-42433..42439, CVE-2026-43526..43584)
  is fixed in 2026.4.24 or earlier per the upstream advisories, so the
  existing CHECK 8 baseline gate already protects versions <= 2026.4.23.
  The new CHECK 42/43/44 add detection independent of version (so post-
  patch misconfiguration is still caught).
- Total check count: 41 → 44 (header banner updated).

## v5.3.3 — 2026-05-09

### Added
- `tests/` harness with 6 regression tests (`tests/run.sh`):
  - clean workspace -> SECURE
  - C2 IP detection
  - AMOS stealer marker detection
  - IOC schema validation (pipe-delimited indicator format)
  - self-skill exclusion (so deployed scanner doesn't flag itself)
  - dashboard hardening (host header, CSP nonce, token gate)
- GitHub Actions CI (`.github/workflows/ci.yml`): shellcheck, test harness,
  secret scan, log-file lint, version-sync verification across SKILL.md,
  scripts/scan.sh, .codex-plugin/plugin.json.
- Weekly IOC refresh workflow (`.github/workflows/weekly-ioc.yml`) — opens a PR
  every Sunday 04:00 UTC if upstream IOC feeds change.

### Changed (dashboard/server.js — security hardening)
- DNS-rebinding defense: reject requests whose Host header is not in the
  allow-list (`127.0.0.1:PORT`, `localhost:PORT`, `[::1]:PORT`) — returns 421.
- CSP no longer uses `'unsafe-inline'`. Each response generates a fresh nonce
  that is stamped onto inline `<script>` and `<style>` tags in `index.html`.
- Optional bearer-token auth via `DASHBOARD_TOKEN` env var (off by default,
  preserves UX). When set, requests must include `Authorization: Bearer <tok>`
  or `?token=<tok>`; missing/wrong token -> 401.
- `DASHBOARD_PORT` env var now overrides the default port 18800.
- Dropped deprecated `X-XSS-Protection` header.
- Added `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cache-Control: no-store`.

### Sub-tool versions
- `scripts/clawhub-scan.sh`: v1.2 -> v1.3 (aligned with the v5.3.3 bundle release;
  no behavioural change yet — placeholder bump so the bundle and helper drift in
  lockstep going forward).

### Notes
- No behavioural change to scan/remediation logic. The bump is purely to ship
  the CI + dashboard hardening with the version-sync gate satisfied.
