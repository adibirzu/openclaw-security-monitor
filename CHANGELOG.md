# Changelog

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
