# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**Modular Architecture**
- Split monolithic script into 8 focused modules under `modules/`:
  - `core.sh` — lifecycle, logging, notifications, cleanup
  - `modes.sh` — scan modes and argument parsing
  - `subdomains.sh` — subdomain enumeration
  - `web.sh` — web analysis, fuzzing, nuclei scans
  - `vulns.sh` — vulnerability scanning
  - `osint.sh` — OSINT functions
  - `axiom.sh` — Axiom fleet helpers
  - `utils.sh` — shared utilities
- Validation library at `lib/validation.sh` for input sanitization

**New CLI Flags**
- `--health-check` — system diagnostics before scanning
- `--dry-run` — preview commands without execution
- `--source-only` — source functions without running (for testing/scripting)

**Robustness Features**
- Circuit breaker pattern: auto-skip tools after repeated failures
- Checkpoint system: resume scans from last successful phase
- Adaptive rate limiting on 429/503 responses
- Disk space pre-flight check (`MIN_DISK_SPACE_GB`)
- Log rotation (`MAX_LOG_FILES`, `MAX_LOG_AGE_DAYS`)
- Cleanup traps for graceful shutdown

**Input Validation**
- `sanitize_domain()` strips dangerous characters and converts to lowercase
- `validate_file_exists()`, `validate_file_readable()` for `--list`, `--inscope`, etc.
- `validate_custom_function()` ensures `-c` targets exist before execution

**Testing**
- 100+ bats tests covering unit, integration, and security scenarios
- `tests/security/test_injection.bats` for command injection prevention
- `tests/mocks/` for offline testing
- Makefile targets: `make test`, `make lint`, `make test-security`

**Other**
- 6 new ASCII banners (#25-30)
- `secrets.cfg` support (gitignored) for API keys
- Performance timing summary at scan completion
- DEEP mode helpers: `should_run_deep_*()` functions

### Changed
- Main script reduced from ~7000 to ~500 lines (entry point only)
- Nuclei scans now use only URLs with protocol, avoiding duplicate scans
- All API keys use env-var fallback pattern (`${VAR:-}`)
- Interactsh process tracked by PID instead of `pkill -f`

### Fixed
- macOS compatibility: `stat`, `df`, `sed` commands now detect OS correctly
- Syntax error in `vulns.sh` (pipe at wrong line position)
- Timing summary crash when function names contained spaces
- Readonly variable error when re-sourcing the script
- Duplicate nuclei findings (domain vs URL targeting same host)

### Security
- Removed all `eval` on user input
- Input sanitization prevents shell metacharacter injection
- Secrets redacted from logs when `SHOW_COMMANDS=true`
- File permission checks for `secrets.cfg`

[Unreleased]: https://github.com/six2dez/reconftw/compare/v3.2...HEAD
