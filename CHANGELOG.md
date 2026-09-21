# Changelog

All notable changes to loginscan are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]
### Changed
- Internal architecture refactor (no user-facing behaviour change):
  - Checks now receive a `CheckContext` (explicit HTTP + session observation) instead of
    reaching into the transport client; `HttpClient` is pure transport.
  - Check run-order is declared as data (`ORDER` per check) rather than a hardcoded list.
  - CWE/OWASP metadata is co-located with each check; plugins can declare `CWE`/`OWASP`/`ORDER`.
  - Split the CLI into `cli` (parser + dispatch), `resolve` (config) and `report_io` (output/gate).

## [1.2.0] - 2026-09-21
### Added
- Ruff + mypy configuration; the codebase is lint- and type-clean.
- Pre-commit hooks (ruff, mypy) and a CI lint/type-check job with coverage.
- Docs site (mkdocs-material), CONTRIBUTING / SECURITY / CODE_OF_CONDUCT, issue & PR templates.
- Observability & robustness: structured logging (`-v/-vv/--quiet`), transient-failure
  retries with backoff, `--header`/`--bearer`, `--proxy`, host scope-guard, and JUnit XML output.
- Stateful `session_fixation` check (needs `--password` for your own test account): flags a
  session id that is not rotated on login.

## [1.1.0] - 2026-09-21
### Added
- `ratelimit` now also probes **concurrently** (a synchronized burst) to catch
  rate limiters that count sequentially but let a simultaneous burst slip through
  (TOCTOU race). Thread-safe `HttpClient.burst()`.

## [1.0.0] - 2026-09-21
### Added
- Security score (0–100 + grade) with CWE / OWASP Top 10 references.
- SARIF 2.1.0 output and a reusable GitHub Action.
- Plugin architecture (`loginscan.checks` entry points) with `--only`/`--skip`/`--list-checks`.
- Config profiles (`--config`), baselines (`--baseline`/`--write-baseline`) and
  CI gates (`--fail-on`, `--min-score`).
- Whole-app scan (`--all-endpoints`) across every auth endpoint in an OpenAPI spec.
- CSRF-protected form support (cookie jar + auto token fetch) and JSON-token success detection.
- Checks: `csrf`, `jwt`, `open_redirect`, `verb`, `cors`, `cache`.

## [0.1.0] - 2026-09-18
### Added
- Initial release: `sqli`, `enumeration`, `ratelimit`, `cookies`, `session`, `headers`
  checks; `--site` and `--swagger` discovery; text / JSON / HTML reports;
  authorization gate and request budget.
