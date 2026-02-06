# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v4.0] - 2026-02-06

### Added

**Modular Architecture**
- Split monolithic script into focused modules under `modules/`:
  - `core.sh` — lifecycle, logging, notifications, cleanup
  - `modes.sh` — scan modes and argument parsing
  - `subdomains.sh` — subdomain enumeration
  - `web.sh` — web analysis, fuzzing, nuclei scans
  - `vulns.sh` — vulnerability scanning
  - `osint.sh` — OSINT functions
  - `axiom.sh` — Axiom fleet helpers
  - `utils.sh` — shared utilities
- Validation library at `lib/validation.sh` for input sanitization.
- Shared libraries in `lib/common.sh` and `lib/parallel.sh`.

**New CLI and Runtime Modes**
- `--health-check` for system diagnostics.
- `--dry-run` to preview commands.
- `--parallel` to run independent functions in parallel.
- `--no-parallel` to force sequential mode.
- `--source-only` for sourcing/testing workflows.
- Continuous monitoring mode:
  - `--monitor`
  - `--monitor-interval <minutes>`
  - `--monitor-cycles <n>` (0 = infinite)
- `--report-only` to rebuild report artifacts from existing outputs.
- `--refresh-cache` to force cache refresh.
- `--export json|html|csv|all` export pipeline.

**Reporting and Output**
- Consolidated reporting artifacts:
  - `report/report.json`
  - `report/index.html`
  - `report/latest/report.json`
  - `report/latest/index.html`
- Export artifacts:
  - JSONL: `report/findings_normalized.jsonl`, `report/export_all.jsonl`
  - CSV: `report/subdomains.csv`, `report/webs.csv`, `report/hosts.csv`, `report/findings.csv`
- Delta sections and timeline in report outputs.
- Monitor history snapshots under `.incremental/history/<timestamp>/`.
- Per-cycle alert summary at `.incremental/history/<timestamp>/alerts.json`.
- Machine-readable run summary at `.log/perf_summary.json`.
- Structured JSON logging support (`STRUCTURED_LOGGING=true`) with function/subfunction start/end events.

**AI and Automation Enhancements**
- AI report generation integrated with local models via `reconftw_ai`.
- AI profiles: `executive`, `brief`, `bughunter`.
- Structured AI output artifact: `ai_result/reconftw_analysis.json`.
- Human AI report artifact: `ai_result/reconftw_analysis_<profile>_<timestamp>.md|txt`.
- New AI configuration controls:
  - `AI_EXECUTABLE`
  - `AI_PROMPTS_FILE`
  - `AI_MAX_CHARS_PER_FILE`
  - `AI_MAX_FILES_PER_CATEGORY`
  - `AI_REDACT`
  - `AI_ALLOW_MODEL_PULL`
  - `AI_STRICT`

**Configuration and Profiles**
- New profile configs:
  - `config/reconftw_quick.cfg`
  - `config/reconftw_full.cfg`
  - `config/reconftw_stealth.cfg`
- Port lists externalized for easier maintenance:
  - `config/tls_ports.txt`
  - `config/uncommon_ports_web.txt`
- Typed cache TTL controls:
  - `CACHE_MAX_AGE_DAYS_RESOLVERS`
  - `CACHE_MAX_AGE_DAYS_WORDLISTS`
  - `CACHE_MAX_AGE_DAYS_TOOLS`

**Recon and Enumeration Enhancements**
- ASN enumeration via `sub_asn()` using `asnmap`.
- New `ASN_ENUM` option and outputs:
  - `hosts/asn_numbers.txt`
  - `hosts/asn_cidrs.txt`
- Deep wildcard detection (`DEEP_WILDCARD_FILTER`) based on iterative wildcard checks.
- Time-based certificate filtering (`DNS_TIME_FENCE_DAYS`).
- Sensitive domain exclusion (`EXCLUDE_SENSITIVE`, `config/sensitive_domains.txt`).

**Progress and UX**
- Progress/ETA functions (`progress_init()`, `progress_step()`) integrated in recon flows.
- Better quick-rescan and monitor UX with adjusted totals and explicit cycle behavior.

**Testing and Tooling**
- Expanded BATS test coverage (unit/integration/security) and mocks.
- Integration tests for full flow and checkpoint behavior.
- Additional test helpers/scripts for artifact and mode validation.

### Changed

- Main script reduced to entry-point style with modular delegation.
- Module loading order updated to include shared libraries (`lib/common.sh`, `lib/parallel.sh`).
- Replaced repetitive utility patterns with centralized helpers:
  - `ensure_dirs()`
  - `skip_notification()`
  - `count_lines()`/`safe_count()`
  - `run_tool()`
  - `should_run_function()`
- Profile configuration behavior changed to override-only semantics (preserving preloaded secrets/env).
- Nuclei targeting adjusted to prioritize URL-with-protocol inputs and reduce duplicate host scans.
- Parallel scheduler improved with backpressure signals from adaptive rate limiting.
- Threading/performance tuning improved with `PERF_PROFILE` (`low|balanced|max`).

### Fixed

**Stability and Correctness**
- List mode (`-l`) now processes all targets reliably (FD-safe loops).
- Fixed syntax/runtime edge cases in module scripts.
- Corrected timing/perf summary handling edge cases.
- Resolved readonly/re-source issues in script lifecycle.
- Fixed duplicate findings/reporting edge cases.
- Corrected `sub_asn()` behavior to avoid redundant repeated runs.
- Corrected host matching in WAF/slow-host grouping to literal-safe comparisons.
- Parallel group failures now propagate correctly instead of being silently ignored.

**CI/CD and Docker**
- ShellCheck failures now fail CI (removed permissive `continue-on-error`).
- Added Docker nightly verification steps (`--help`, `--health-check`).
- Nightly image health-check failures now fail workflows.
- Docker image security improved by generating Axiom SSH keys at runtime via `Docker/entrypoint.sh` instead of build-time.

**Cross-platform/Operational Fixes**
- Improved macOS compatibility for `stat`, `df`, and `sed` behavior.
- Improved cache lifecycle behavior and runtime refresh handling.
- Progress totals now correctly account for quick-rescan skips and execution model differences.

### Security

- Removed unsafe `eval` usage on user-influenced input paths.
- Hardened input sanitization against shell metacharacter injection.
- Improved quoting and command construction across modules.
- Secrets handling hardened (`secrets.cfg` checks, env fallback patterns, log redaction with command tracing).
- Docker key handling moved to runtime generation to avoid shared-key risk across images.
