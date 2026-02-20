# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v4.0] - 2026-02-15

### Added
- `nuclei_dast` module: dedicated `nuclei -dast` pass over `webs/`, `url_extract`, and `gf/` candidates (outputs `nuclei_output/dast_json.txt`, `vulns/nuclei_dast.txt`).
- Portscan strategy `PORTSCAN_STRATEGY=naabu_nmap`: naabu pre-discovery + targeted nmap outputs (`hosts/naabu_open.txt`, `hosts/portscan_active_targeted.*`).
- Optional UDP scan: `PORTSCAN_UDP=true` produces `hosts/portscan_active_udp.*`.
- Monitor alert threshold `MONITOR_MIN_SEVERITY` (critical|high|medium|low|info).
- SSRF alternate protocol payload pass via `config/ssrf_payloads.txt` (output `vulns/ssrf_alt_protocols.txt`).
- Katana headless profile selection: `KATANA_HEADLESS_PROFILE=off|smart|full`.
- DEEP-only ffuf recursion: `FUZZ_RECURSION_DEPTH`.
- CDN origin discovery (best-effort) via `hakoriginfinder` with `CDN_BYPASS=true` (output `hosts/origin_ips.txt`).
- Password dictionary engine `cewler` (Python) with tuning knobs.
- Adaptive permutation wordlist: `PERMUTATIONS_WORDLIST_MODE=auto|full|short` with `PERMUTATIONS_SHORT_THRESHOLD=100`. Uses a curated 162-word list for large targets (>100 subs) and the full 849-word list for small targets or DEEP mode.
- Auto-detection of DNS resolver: `DNS_RESOLVER=auto|puredns|dnsx`. Two-step heuristic: (1) public local IP → puredns, (2) cloud metadata endpoint (169.254.169.254) → puredns, otherwise → dnsx. Handles cloud VPS with private IPs (AWS, GCP, DO, etc.) correctly. Configurable with `DNSX_THREADS` and `DNSX_RATE_LIMIT`.
- Global DNS resolution wrappers `_resolve_domains()` and `_bruteforce_domains()` in `modules/utils.sh` — all 16 puredns call sites now use these wrappers for consistent resolver selection.
- Cross-platform local IP detection via `_get_local_ip()` using default route (works on any macOS/Linux interface naming).
- DNS permutation benchmark script `benchmark_dns_permutations.sh` for comparing gotator, alterx, and ripgen.
- Built-in wordlists and patterns are now vendored in-repo under `data/` (wordlists: `data/wordlists/`, patterns: `data/patterns/`). Config exposes `DATA_DIR`, `WORDLISTS_DIR`, and `PATTERNS_DIR`.
- `--no-banner` to disable banner output (banner is on by default).
- `--no-report` to skip report generation/exports.
- `--gen-resolvers` to generate resolvers with `dnsvalidator`.
- `--force` to ignore cached module markers and re-run all phases.

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
- New integrated engines/tools:
  - `toxicache` for additional web cache poisoning coverage.
  - `postleaksNg` in `apileaks` for Postman leak discovery.
  - `favirecon` as `favirecon_tech` for favicon-based technology reconnaissance.
  - Praetorian integrations:
    - `fingerprintx` for service fingerprinting after host port discovery (`hosts/fingerprintx.[jsonl|txt]`).
    - `brutus` as optional spraying engine (`SPRAY_ENGINE=brutus`) with DEEP gating support.
    - `titus` and `noseyparker` as selectable GitHub repo secret engines (`SECRETS_ENGINE`).
    - `gato` as optional GitHub Actions audit module (`github_actions_audit`, output `osint/github_actions_audit.[json|txt]`).
    - `julius` as optional LLM endpoint probing module (`llm_probe`, output `webs/llm_probe.[jsonl|txt]`).
  - `TInjA` as the default `ssti` engine (`SSTI_ENGINE=TInjA`, with legacy fallback).
  - `second-order` as default `brokenLinks` engine (`BROKENLINKS_ENGINE=second-order`, with legacy fallback).
  - `ghleaks` in `github_leaks` for GitHub-wide secret search across all public repositories (combines GitHub Code Search API with gitleaks detection rules). Configurable via `GITHUB_LEAKS`, `GHLEAKS_THREADS`, and `--exhaustive` mode in DEEP.

**Progress and UX**
- Progress/ETA functions (`progress_init()`, `progress_step()`) integrated in recon flows.
- Better quick-rescan and monitor UX with adjusted totals and explicit cycle behavior.

**Testing and Tooling**
- Expanded BATS test coverage (unit/integration/security) and mocks.
- Integration tests for full flow and checkpoint behavior.
- Additional test helpers/scripts for artifact and mode validation.

**CI/CD and Docker**
- ShellCheck failures now fail CI (removed permissive `continue-on-error`).
- Added Docker nightly verification steps (`--help`, `--health-check`).
- Nightly image health-check failures now fail workflows.
- Docker image security improved by generating Axiom SSH keys at runtime via `Docker/entrypoint.sh` instead of build-time.

### Changed
- Fixed `webprobe_simple()` httpx merge bug (probe output now correctly merged with prior cache).
- Wrapped local `wafw00f` execution with `run_command` for dry-run/log consistency.
- `PORTSCAN_ACTIVE_OPTIONS` default no longer includes `--script vulners`; moved to `PORTSCAN_DEEP_OPTIONS`.
- `ssti`: if `TInjA` is missing, the module warns and skips (no automatic ffuf fallback).
- `iishortname`: uses `shortscan` only (sns removed).
- `nuclei_dast`: when vuln scanning is enabled (`VULNS_GENERAL=true`, e.g. `-a`), the DAST pass is force-enabled to avoid accidental coverage loss.
- Permutation engine simplified to gotator-only (benchmark showed gotator produces the best quality permutations with exclusive valid findings that other tools miss).
- DNS resolver auto-selection is evaluated once per run and cached (see `DNS_RESOLVER_SELECTED` via `init_dns_resolver()`).
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
- Output header now uses a banner-style H1 block with rules sized to the header text.
- Default exports now generate all report artifacts unless `--no-report` is set.
- Help output formatting uses proper color escapes (no literal `\033`).
- `--pretty` option removed (no longer supported).
- Health-check tool list updated to reflect actual runtime usage (`nmap`, `nmapurls`).
- Fixed duplicate findings/reporting edge cases.
- Corrected `sub_asn()` behavior to avoid redundant repeated runs.
- `sub_asn()` now requires `PDCP_API_KEY` before running `asnmap`, logs explicit skip reason when unset, and applies a 120s timeout guard when available.
- Corrected host matching in WAF/slow-host grouping to literal-safe comparisons.
- Parallel group failures now propagate correctly instead of being silently ignored.

**Cross-platform/Operational Fixes**
- Improved macOS compatibility for `stat`, `df`, and `sed` behavior.
- Improved cache lifecycle behavior and runtime refresh handling.
- Progress totals now correctly account for quick-rescan skips and execution model differences.

### Fixed

**Stability and Correctness**
- List mode (`-l`) now processes all targets reliably (FD-safe loops).
- Fixed syntax/runtime edge cases in module scripts.
- Corrected timing/perf summary handling edge cases.
- Resolved readonly/re-source issues in script lifecycle.
- `.log/*.txt` files are no longer empty (LOGFILE no longer overwritten by debug log).
- Incidents no longer show `\n` literals; debug log line only appears if non-empty.
- Passive mode no longer runs `webprobe_simple`/`webprobe_full`.
- Missing `webs/webs_new.txt` now handled safely.

**Dry-Run Mode**
- Wrapped 83 unwrapped command executions across all modules to respect `DRY_RUN` flag:
  - `osint.sh`: 24 commands (whois, dig, curl APIs, gitdorks_go, enumerepo, porch-pirate, postleaksNg, misconfig-mapper, exiftool, interlace git clone, Python tools: dorks_hunter, metagoofil, SwaggerSpy, EmailHarvester, LeakSearch, msftrecon, Scopify, Spoofy)
  - `subdomains.sh`: 15 commands (asnmap, dig zone transfer, curl APIs, hakip2host, csprecon, regulator, cloud enumeration)
  - `web.sh`: 20 commands (fav-up, favirecon, grpcurl, CMSeeK, JSA, getjswords, jsluice, wget, interlace/ffuf, curl WebSocket, pydictor, second-order)
  - `vulns.sh`: 6 commands (Corsy, Oralyzer, interlace/ffuf LFI, TInjA/legacy SSTI, interlace/ghauri SQLi, toxicache)
  - `core.sh`: 8 commands (tar/curl uploads, Telegram/Discord/Slack notifications, connectivity checks)
  - `modes.sh`: 8 commands (faraday-cli reporting)
  - `axiom.sh`: 3 commands (hakip2host, mapcidr)
- Added module-level dry-run command tracking and summaries in `lib/ui.sh`:
  - `ui_dryrun_track()`: Records commands during dry-run execution
  - `ui_dryrun_summary()`: Displays count + unique tool names at module completion
  - `ui_dryrun_reset()`: Clears tracking at module boundaries
- Dry-run summaries now show:
  - Normal mode: `[DRY-RUN] Would execute N commands: tool1, tool2, ...`
  - Verbose mode: Full command list with normalized single-line formatting
  - Quiet mode: No dry-run output
- Module lifecycle hooks (`_print_module_start()`, `_print_module_end()`) now reset and display dry-run summaries automatically
- Command normalization removes newlines/extra whitespace from multi-line command strings for cleaner display
- Dry-run command previews now redact sensitive CLI values (for example `-token-string`, API keys, and bearer tokens).
- Dry-run in parallel mode now aggregates commands emitted from child subshells, so module summaries reflect full command volume.
- Dry-run no longer produces noisy parser/file errors in guarded paths (`apileaks`, `sub_crt`, `prototype_pollution`, `fuzzparams`, `sub_tls`, `sub_permut`, `urlchecks`, `favirecon_tech`, `webcache`, `brokenLinks`, `ssti`).
- `test_ssl` now respects `run_command`, preventing real execution during dry-run.
- `sub_asn` now applies timeout fencing with kill semantics (`-k`) when timeout tooling is available and reports non-OK outcomes correctly.
- `subdomains` finalization now safely creates missing incremental files before counting to avoid stderr noise.
- Fixed benign non-zero paths (`anew`, optional pipelines) that were surfacing as false `ERR(1)` noise in logs.
- Hardened `sub_crt` JSON parsing to avoid noisy `jq` parse errors on malformed/empty upstream responses.
- Parallel job output now strips ANSI/control sequences before replaying tail/full logs, reducing report/export parser issues.
- Function/subfunction end log timestamps now use real end times (not reused start timestamps).
- Added heartbeat progress lines for long-running phases (`nuclei`, `ffuf/interlace`, `cmseek`, and selected passive collectors) to avoid "stuck" perception.
- Added `run_with_heartbeat_shell` for complex shell/redirection cases to keep heartbeat coverage in long-running URL collection paths.
- Skip/cache output now includes explicit reason hints (`config`, `noinput`, `cache`) while preserving existing summary counters.
- Parallel UI now defaults to a cleaner mode with aggregated progress snapshots (`X/Y`, `%`, elapsed, ETA) and reduced process-noise.
- In clean parallel UI mode, `Queue` lines are suppressed when pending count is `0` to keep terminal output compact.
- Added configurable parallel UX and sizing knobs in `reconftw.cfg` (`PARALLEL_UI_MODE`, progress visibility toggles, and per-group parallel sizes).
- Parallel batch summaries now include completion ratio (`completed/total`) to make long blocks easier to track.

**Parallel Execution and Status Reporting**
- Parallel aggregation now preserves per-function final badges (`OK/WARN/FAIL/SKIP/CACHE`) from module functions/subfunctions instead of inferring only from process exit code.
- Parallel batch summary lines now expose real counters for `ok/warn/fail/skip/cache`.
- Cache/skip messaging was normalized to avoid unformatted "already processed" lines and keep status output consistent.

### Removed
- Obsolete tool-based modules: `cors` (Corsy), `open_redirect` (Oralyzer), `prototype_pollution` (ppmap), favicon real-IP discovery (fav-up).
- Deprecated/removed config flags: `CORS`, `OPEN_REDIRECT`, `PROTO_POLLUTION`, `FAVICON`.
- Permutation engines `ripgen`, `alterx`, and `PERMUTATIONS_ENGINE=both` option. Gotator is now the only permutation engine (benchmark winner: best yield, exclusive findings, fastest).
- Legacy `PERMUTATIONS_OPTION` alias.

### Migration Notes
- Prefer Nuclei templates (and `nuclei_dast`) for CORS/open-redirect/prototype-pollution coverage.
- `PERMUTATIONS_ENGINE` now only accepts `gotator`. Remove any `ripgen`/`alterx`/`both` values from custom configs.
- If running from home/behind NAT, the resolver auto-detection will use dnsx automatically. Set `DNS_RESOLVER=puredns` to force puredns on VPS.

### Security
- Removed unsafe `eval` usage on user-influenced input paths.
- Hardened input sanitization against shell metacharacter injection.
- Improved quoting and command construction across modules.
- Secrets handling hardened (`secrets.cfg` checks, env fallback patterns, log redaction with command tracing).
- Docker key handling moved to runtime generation to avoid shared-key risk across images.
