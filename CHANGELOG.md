# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 1 — Input Sanitization & Safety
- `sanitize_domain()`, `sanitize_ip()`, `sanitize_interlace_input()` functions for user-supplied input
- Configurable Axiom resolver paths (`AXIOM_RESOLVERS_PATH`, `AXIOM_RESOLVERS_TRUSTED_PATH`)

#### Phase 2 — Error Handling & Operational Robustness
- Numeric error codes for distinct failure categories
- Log rotation (`MAX_LOG_FILES`, `MAX_LOG_AGE_DAYS`) to prevent unbounded log growth
- Cleanup traps (`trap … EXIT`) for graceful shutdown and temp-file removal
- Structured JSON logging option (`STRUCTURED_LOGGING`)
- Pre-flight disk-space check (`MIN_DISK_SPACE_GB`)
- `validate_config` function to catch configuration errors before scanning starts

#### Phase 3 — Secrets & Configuration Security
- Environment-variable fallback pattern for all API keys (`SHODAN_API_KEY="${SHODAN_API_KEY:-}"`)
- Optional `secrets.cfg` file (gitignored) that is auto-sourced when present
- Docker secrets guidance — pass secrets at runtime via `-e` flags, not baked into the image
- Input validation hardening across configuration loading

#### Phase 4 — Testing Infrastructure
- `tests/` directory with `unit/`, `integration/`, and `fixtures/` sub-directories
- bats-core unit tests (`test_sanitize.bats`, `test_utils.bats`)
- `--source-only` flag in `reconftw.sh` to allow sourcing without execution (enables unit testing)
- `tests/run_tests.sh` runner script (`--all` for integration tests)
- GitHub Actions CI workflow (`tests.yml`) — ShellCheck + unit tests + integration matrix
- Makefile targets: `make test` (unit), `make test-all` (unit + integration)

#### Phase 5 — Modularization
- 8-module architecture under `modules/`:
  - `core.sh` — lifecycle, logging, notifications, cleanup
  - `modes.sh` — scan modes, argument parsing, help
  - `subdomains.sh` — all subdomain enumeration functions
  - `web.sh` — web analysis, fuzzing, JS checks
  - `vulns.sh` — vulnerability scanning functions
  - `osint.sh` — OSINT module functions
  - `axiom.sh` — Axiom/Ax fleet management helpers
  - `utils.sh` — shared utilities, sanitization, validation
- `reconftw.sh` reduced to a ~536-line entry point (sourcing, arg parsing, dispatch)

#### Phase 6 — Health Checks, Performance & Operational Modes
- `--health-check` flag — run system health check and exit (also used by Docker `HEALTHCHECK`)
- `--incremental` flag — only scan new findings since last run (`INCREMENTAL_MODE`)
- `--adaptive-rate` flag — automatically adjust rate limits on 429/503 errors (`ADAPTIVE_RATE_LIMIT`)
- `--dry-run` flag — show what would be executed without running commands
- Performance timing for scan stages
- Docker `HEALTHCHECK` directive in Dockerfile
- Cache configuration (`CACHE_MAX_AGE_DAYS`) for wordlists and resolvers

### Changed
- `reconftw.sh` refactored from monolithic script into modular entry point + 8 modules
- All `eval` usage on user input removed; replaced with safe alternatives
- All API key variables now use env-var fallback pattern (`${VAR:-}`) instead of hardcoded placeholders
- `reconftw.cfg` updated with new sections: incremental mode, adaptive rate limiting, cache, log rotation, structured logging, disk space check
- Makefile `lint` target now covers `modules/*.sh` in addition to `reconftw.sh` and `install.sh`
- Plugin/tool path references updated for modular layout

### Fixed
- Docker image no longer embeds secrets at build time
- Variable quoting issues across the codebase
- Potential command injection through unsanitized domain/path inputs

### Security
- All user-supplied input (domains, IPs, shell metacharacters) is sanitized before use
- `eval` removed from code paths handling user input
- Secrets management via environment variables and `secrets.cfg` (never committed)
- Docker runtime secrets pattern documented and enforced

[Unreleased]: https://github.com/six2dez/reconftw/compare/v3.2...HEAD
