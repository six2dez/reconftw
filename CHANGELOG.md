# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**Parallelization Framework** (lib/parallel.sh)
- `parallel_run()` - Run commands in parallel with configurable job limit
- `parallel_funcs()` - Run bash functions in parallel subshells
- `parallel_passive_enum()` - Parallel passive subdomain enumeration
- `parallel_active_enum()` - Parallel active DNS checks
- `parallel_postactive_enum()` - Parallel TLS/analytics (after resolution)
- `parallel_brute_enum()` - Resource-limited parallel brute force
- `parallel_web_vulns()` - Parallel web vulnerability scanning
- `parallel_subdomains_full()` - Full parallelized subdomain orchestration

**Common Utilities Library** (lib/common.sh)
- `ensure_dirs()` - Create multiple directories safely
- `safe_backup()` - Backup files with timestamps
- `skip_notification()` - Standardized skip logging
- `count_lines()`, `safe_count()` - Safe line counting
- `dedupe_append()` - Append and deduplicate
- `run_tool()` - Execute with timeout and error handling
- `should_run_function()` - Checkpoint-aware function check

**Integration Tests**
- `tests/integration/test_full_flow.bats` - 17 tests for complete workflow
- `tests/integration/test_checkpoint.bats` - 20 tests for resume functionality
- Total test count: 164

**Refactored Functions**
- `subdomains_full()` decomposed into `_subdomains_init()`, `_subdomains_enumerate()`, `_subdomains_finalize()`
- `webprobe_*()` uses shared helpers `_run_httpx()`, `_process_httpx_output()`
- `--parallel` flag support for subdomain enumeration

### Fixed

**Security**
- Fixed unquoted variable in `file $1` → `file "$1"` (core.sh)
- Fixed unquoted AI command variables (modes.sh)  
- Fixed unquoted HTTPX_FLAGS (web.sh)
- Added NUMOFLINES validation with fallback to 0

**Parallelization Order**
- `sub_tls` and `sub_analytics` now run AFTER `sub_active` (require resolved subdomains)

### Changed

- Replaced 107 duplicate `mkdir -p` patterns with `ensure_dirs()`
- Replaced skip notification printf patterns with `skip_notification()`
- Module loading order updated to include lib/common.sh and lib/parallel.sh

---

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
- `--parallel` — run independent functions in parallel (faster, more RAM)
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
