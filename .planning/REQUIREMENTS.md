# Requirements: reconFTW v2.0 — Complete Core Migration

**Defined:** 2026-05-27
**Milestone:** v2.0 — Complete Core Migration (Bash → Go/Python)
**Core Value:** Run one command, get a complete recon picture of a target — passive, active, and vulnerability layers — with resumable checkpoints, structured output, and zero-touch tool orchestration.

**Source of truth:** `.planning/PROJECT.md` (16 + 1 = 17 deliverables). This file decomposes each deliverable into atomic, testable, user-centric REQ-IDs. Research findings synthesized in `.planning/research/SUMMARY.md`.

**Scope shape:** Full rewrite — preserve 100% of v1 functionality (30 Table Stakes + 20 Differentiators), add 7 EMG free wins, add MCP server (per user decision 2026-05-27).

---

## Requirements

### Decision & ADR (Deliverable #1)

- [ ] **DEC-01**: User can read a signed ADR (`.planning/decisions/0001-language.md`) that documents the language choice with evidence (Go vs Python comparison), before any production code is written
- [ ] **DEC-02**: Spike PoC implements an identical recon slice in BOTH Go and Python: passive subdomain enum (5-10 sources) + httpx probe + atomic JSONL writes + SIGINT kill-tree test
- [ ] **DEC-03**: Spike measures and records, per language: (a) dev velocity (LoC + hours-to-slice), (b) packaging footprint (binary size or venv size), (c) subprocess kill-tree correctness under interrupt, (d) memory under 5K concurrent subdomain hosts, (e) cross-platform pain (especially macOS arm64)
- [ ] **DEC-04**: ADR includes a pre-agreed tie-breaker rule (default: choose Go if metrics are within 25% noise band — single-binary distribution wins)
- [ ] **DEC-05**: After ADR signed, all dual-tracked research files (STACK/ARCHITECTURE) collapse to single-language sections; the other language is permanently out of scope for v2.x

### Architecture v2 Design (Deliverable #2)

- [ ] **ARCH-01**: Architecture v2 design doc (`.planning/decisions/0002-architecture-v2.md`) is signed BEFORE Foundation work starts; locks the contracts the rest of v2 depends on
- [ ] **ARCH-02**: TOML config schema fully specified in the doc (every section name; e.g. `subdomains.passive.enabled`, `web.fuzz.threads_max`, `axiom.enabled`)
- [ ] **ARCH-03**: Output tree shape locked: `workspaces/<target-id>/` with subdirs `inputs/`, `artefacts/` (typed JSONL), `raw/` (untyped tool output), `reports/`, `logs/`, plus `manifest.json`, `checkpoints.db`, `state.db`
- [ ] **ARCH-04**: Compat symlink layer specified: `Recon/<domain>/` populated by a "compat writer" with bash-shape filenames; maintained 6 months post-cutover, then dropped (documented in MIGRATION.md)
- [ ] **ARCH-05**: `Task` interface signed: `Name() / Module() / Enabled(cfg) / DependsOn() / Run(ctx, app) → Result`
- [ ] **ARCH-06**: `Backend` interface signed: `Exec(ctx, *Tool, args) (*Result, error) / Stream(ctx, *Tool, args) (<-chan Event, error) / HealthCheck(ctx) error / Capacity() int`
- [ ] **ARCH-07**: `AppContext` shape signed: `{Log, Cfg, Scheduler, Tools, Tree, Checkpoint, Notify, Target, UI}` — passed by pointer/reference into every Task; NO package-level state
- [ ] **ARCH-08**: Error class hierarchy designed: `ToolError`, `ToolTimeout`, `OutOfScope`, `AxiomFailure`, `ConfigError`, `ScopeError`, `ChecksumMismatch`
- [ ] **ARCH-09**: Failure isolation policy: `failure_policy = "best_effort" | "fail_fast"` configurable per module group; spine defaults to fail-fast, OSINT/vulns default to best-effort
- [ ] **ARCH-10**: CLI surface designed: subcommands primary (`reconftw recon`, `reconftw subs`); v1 short flags (`-r`, `-s`, `-p`, `-a`, `-d`, `-l`) preserved as deprecated aliases with warning for 2 minor versions
- [ ] **ARCH-11**: Test ring policy documented: unit (mock backend) / integration (real tools, gated) / smoke (cron) / property-based (scope, config parsing)
- [ ] **ARCH-12**: Logging policy: secret tagging at TYPE level (`Secret` in Go via `LogValuer` interface, OR pydantic `SecretStr` in Python); redaction at sink (slog handler / structlog processor); registered BEFORE first log line emitted

### Foundation / Scaffolding (Deliverable #3)

- [ ] **FOUND-01**: Errors package with typed hierarchy implemented and exported; new error types extend a base interface for wrapping/unwrapping
- [ ] **FOUND-02**: Logger emits structured logs (JSON for ingest, text for TTY); `Secret` type with auto-redaction; logger initialized before any other subsystem
- [ ] **FOUND-03**: Config loader implements 8-source precedence chain: defaults → `/etc/reconftw/config.toml` → `~/.config/reconftw/config.toml` → `./reconftw.toml` → `--config FILE` → `secrets.toml` → `RECONFTW_*` env → CLI flags. All validation runs at startup; fail-fast with config file:line in error
- [ ] **FOUND-04**: OutputTree implementation with `AtomicWriter` (tempfile + fsync + rename + fsync parent dir) at the scope-filter boundary; cannot be bypassed
- [ ] **FOUND-05**: SQLite checkpoint store (`workspaces/<target>/checkpoints.db`) tracks `(task_name, target, input_hash, status, started_at, finished_at, duration_ms, output_paths, error_class)`; idempotency on `input_hash` (config + wordlist + scope hash forces re-run on change)
- [ ] **FOUND-06**: Scheduler with bounded concurrency (`errgroup.SetLimit(N)` in Go OR `asyncio.TaskGroup` + `asyncio.Semaphore(N)` in Python); per-task timeout via context; heartbeat polling for long-running tasks
- [ ] **FOUND-07**: RateLimiter supporting per-tool, per-target, and global caps; configurable per `TOOLS.<name>.rate_limit` in TOML
- [ ] **FOUND-08**: ToolRegistry with self-registering tools (`func init() { Register(...) }` in Go OR `@register_tool` decorator in Python); discovers binaries at startup; warns on missing-but-required, fails on missing-and-critical
- [ ] **FOUND-09**: LocalBackend implements `Backend` interface; uses `Setpgid` + `WaitDelay` (Go) or `start_new_session=True` + `os.killpg` (Python) for EVERY subprocess; no raw `exec.Command` / `subprocess.Popen` allowed
- [ ] **FOUND-10**: Lint rule (golangci-lint custom check or ruff plugin) forbids raw subprocess invocation outside the Tool wrapper; CI gate
- [ ] **FOUND-11**: Notifier interface + log sink + Slack/Telegram/Discord stubs; all message bodies pass through redactor before send
- [ ] **FOUND-12**: Task interface + Registry with self-registration; tasks declare `DependsOn` for scheduler DAG building
- [ ] **FOUND-13**: UI module (`pkg/ui/` or `reconftw/ui/`) reproduces dot-fill format from `lib/ui.sh` verbatim: `[OK  ] task.name .......... 12s`; supports `OUTPUT_VERBOSITY=0/1/2` and `PARALLEL_LOG_MODE=summary|tail|full`; NO TUI library (no bubbletea/textual/rich Live)
- [ ] **FOUND-14**: CLI binary (cobra in Go / typer in Python) wires all subsystems; supports both subcommands and v1-style short flags with deprecation warnings
- [ ] **FOUND-15**: Test mocks shipped alongside real implementations: MockBackend (deterministic outputs), MockCheckpoint (in-memory), MockOutputTree (in-memory file system)
- [ ] **FOUND-16**: CI pipeline runs on every push: lint, gofmt/ruff format check, unit tests, integration smoke (with mock backend), `go test -race` (Go) or `mypy --strict` (Python); branch coverage gate at ≥75% on lib code

### Subdomains E2E (Deliverable #4)

- [x] **SUBD-01**: Passive subdomain enumeration uses ≥6 sources: subfinder, crt.sh (via `crt`), github-subdomains, gitlab-subdomains, urlfinder, hackertarget; outputs merged via `anew`-equivalent dedup
- [x] **SUBD-02**: Active brute force via `puredns` with wordlist validation, resolver health gate (abort if <N resolvers reachable), and wildcard filtering
- [x] **SUBD-03**: Subdomain permutations via `gotator`, `regulator`, `dnscewl`; memory-aware throttling (back-pressure when free RAM < threshold)
- [x] **SUBD-04**: DNS resolution via `dnsx` with per-batch timeout enforcement (default 4h via `DNS_RESOLVE_TIMEOUT`)
- [x] **SUBD-05**: Scope filter uses SINGLE canonical implementation (reconciles v1's `is_in_scope_host` / `domain_match_regex` split); cross-check unit test feeds same corpus through old/new and asserts equivalence
- [x] **SUBD-06**: Subdomain takeover detection via `subzy` and `dnstake`; outputs structured findings to `artefacts/findings.jsonl`
- [x] **SUBD-07**: S3/GCS/Azure bucket discovery via `s3scanner`; outputs `artefacts/buckets.jsonl`
- [x] **SUBD-08**: Per-subdomain geo info (country, city, ASN) via lookup against geolite/ipinfo
- [x] **SUBD-09**: ASN mapping via `asnmap`; outputs `artefacts/asns.jsonl`
- [x] **SUBD-10**: Zone transfer attempt (only if `ALLOW_TRANSFER=true` opt-in) — preserves v1 safety gate
- [x] **SUBD-11**: Output equivalence test: against 3+ canonical targets (e.g., `hackerone.com`, `tesla.com`), v2 outputs match bash v1 outputs modulo ordering and timing noise (same domain set ± 5% tolerance)

### Web E2E (Deliverable #5)

- [x] **WEB-01**: HTTP probe via `httpx` with tech detection, status codes, titles, response sizes; writes to `artefacts/hosts.jsonl`
- [x] **WEB-02**: Screenshots via `nuclei -headless -id screenshot`; diff detection across monitor runs; stored under `raw/screenshots/<hash>.png`
- [x] **WEB-03**: Web directory/file fuzz via `ffuf` with `FFUF_THREADS_MAX` cap respected; results in `artefacts/fuzz.jsonl`
- [ ] **WEB-04**: JS analysis: URL/secret extraction via `subjs`, `jsluice`, `mantra`, `JSA`; results structured per artifact type
- [ ] **WEB-05**: Source map extraction via `sourcemapper`; sources written to `raw/sourcemaps/<host>/`
- [x] **WEB-06**: Nuclei templated scanning with `NUCLEI_RATELIMIT` and per-tool thread cap; findings go to `artefacts/findings.jsonl` (SARIF-compatible schema)
- [ ] **WEB-07**: WAF detection via `wafw00f` + `cdncheck`; outputs to `artefacts/waf.jsonl`
- [ ] **WEB-08**: CDN/origin discovery via `hakoriginfinder`; outputs to `artefacts/origins.jsonl`
- [ ] **WEB-09**: CSP analysis via `csprecon`; surfaces subdomains found in CSP headers
- [ ] **WEB-10**: Favicon recon via `favirecon` + Shodan favicon hash lookup
- [ ] **WEB-11**: Virtual host discovery via `VhostFinder`
- [ ] **WEB-12**: 4xx bypass via `nomore403`
- [ ] **WEB-13**: IIS short filename scanner via `shortscan`
- [ ] **WEB-14**: URL discovery via `katana` + `urlfinder` + `waymore`; results deduplicated via `urless` / `p1radup`
- [ ] **WEB-15**: Reflection / parameter discovery via `Gxss` + `arjun`
- [x] **WEB-16**: Output equivalence test against 3+ canonical web targets

### Vulns E2E (Deliverable #6)

- [x] **VULN-01**: XSS scanning via `dalfox` with configurable payloads and rate limits; findings written with severity + confidence
- [x] **VULN-02**: SQLi scanning via `sqlmap` AND `ghauri` (both engines available, configurable preference); long-running tool heartbeat preserved
- [x] **VULN-03**: SSRF testing with collaborator/interactsh integration via `interactsh-client`
- [x] **VULN-04**: LFI testing via parameter fuzzing + payloads from `lfi_wordlist`
- [x] **VULN-05**: SSTI testing via `TInjA` and/or `SSTImap`
- [x] **VULN-06**: CRLF injection via `crlfuzz`
- [x] **VULN-07**: HTTP request smuggling via `smugglex` (Rust binary subprocess)
- [x] **VULN-08**: Command injection via `commix`
- [x] **VULN-09**: Web cache poisoning via `Web-Cache-Vulnerability-Scanner` + `toxicache`
- [x] **VULN-10**: gf pattern matching for known vuln signatures on URLs (XSS, SQLi, SSRF, LFI, RCE patterns)
- [x] **VULN-11**: Nuclei DAST mode with HTTP traffic replay
- [x] **VULN-12**: Second-order injection via `second-order`
- [x] **VULN-13**: 4xx bypass tests integrated with VULN flows
- [x] **VULN-14**: Output equivalence test against canonical vuln-bait target (controlled lab env)

### OSINT E2E (Deliverable #7)

- [x] **OSINT-01**: Domain info: whois, registration data, DNS records (NS/MX/TXT/SOA/DNSSEC)
- [x] **OSINT-02**: IP info: CIDR ranges (via `mapcidr`), ASN org lookups, geo data
- [x] **OSINT-03**: Email harvesting via `EmailHarvester`
- [x] **OSINT-04**: GitHub dorks via `dorks_hunter` + `gitdorks_go`
- [x] **OSINT-05**: GitHub leak scanning via `ghleaks` + `trufflehog`
- [x] **OSINT-06**: GitHub Actions audit via `gato` (workflow secrets exposure)
- [x] **OSINT-07**: Cloud bucket enumeration via `cloud_enum` (AWS S3, GCP, Azure Blob)
- [x] **OSINT-08**: Postman leaks via `porch-pirate` + `postleaksNg`
- [x] **OSINT-09**: Swagger/OpenAPI leaks via `sj` + `SwaggerSpy`
- [x] **OSINT-10**: Email spoofing posture via `Spoofy` (SPF/DMARC/DKIM)
- [x] **OSINT-11**: Microsoft tenant recon via `msftrecon`
- [x] **OSINT-12**: CMS fingerprint via `CMSeeK` + `favirecon`
- [x] **OSINT-13**: GraphQL introspection via `gqlspection`
- [x] **OSINT-14**: Custom wordlist generation via `cewler`
- [x] **OSINT-15**: Google dorking automation via `xnldorker`
- [x] **OSINT-16**: Output equivalence test against canonical target with known OSINT footprint

### Composite Modes (Deliverable #8)

- [ ] **MODE-01**: `reconftw recon` (alias `-r`) — runs passive subs → web probe → web analysis → OSINT, skipping vulns
- [ ] **MODE-02**: `reconftw all` (alias `-a`) — runs everything (recon + vulns)
- [ ] **MODE-03**: `reconftw passive` (alias `-p`) — passive-only sources, no active probing
- [ ] **MODE-04**: `reconftw zen` (alias `--zen`) — quiet mode with extra OPSEC (stealth profile)
- [ ] **MODE-05**: `reconftw deep` (alias `--deep`) — adds deep brute force + extended permutations
- [ ] **MODE-06**: `reconftw quick-rescan` — incremental diff vs last full scan
- [ ] **MODE-07**: `reconftw refresh-cache` — refresh cached data (DNS, ASN, geo)
- [ ] **MODE-08**: `reconftw gen-resolvers` — regenerate DNS resolver list via `dnsvalidator`
- [ ] **MODE-09**: V1 long-flag aliases (`--recon`, `--all`, `--passive`, `--subdomains`, `--web`, `--vulns`, `--osint`) preserved with deprecation warning
- [ ] **MODE-10**: `--target X` and `--list FILE` input methods work across all modes
- [ ] **MODE-11**: `--config FILE` overrides default `reconftw.toml` location
- [ ] **MODE-12**: `--dry-run` shows what would execute without invoking external tools

### Axiom Integration (Deliverable #9)

- [x] **AXIOM-01**: AxiomBackend implements `Backend` interface; shells to `axiom-scan` / `axiom-exec` (does NOT reinvent fleet provisioning)
- [x] **AXIOM-02**: `axiom_launch` provisions fleet with configurable sizing (`AXIOM_FLEET_COUNT`)
- [x] **AXIOM-03**: `axiom_shutdown` releases fleet at end of run (or on interrupt)
- [x] **AXIOM-04**: `axiom_selected` fleet target — uses Axiom's own selection
- [x] **AXIOM-05**: Resolver list propagation to fleet (`resolvers_update`)
- [x] **AXIOM-06**: Failover wrapper detects infrastructure failures (SSH timeout, fleet unreachable, partial-fleet); retries locally without losing work
- [x] **AXIOM-07**: `AXIOM_AUTO_FIX_HOSTKEY` repair logic preserved
- [x] **AXIOM-08**: `axiom_disable_runtime` flag disables axiom mid-run on failure, all subsequent module calls run locally
- [x] **AXIOM-09**: Output equivalence test: axiom vs local execution of same module produces equivalent output (same scope, same dedup)

### Monitor Mode (Deliverable #10)

- [ ] **MON-01**: `reconftw monitor --target X --interval 6h` runs scans on a configurable interval indefinitely
- [ ] **MON-02**: `--monitor-cycles N` runs N cycles then exits
- [ ] **MON-03**: Diff detection: each cycle compares findings against last cycle's baseline (stored in `state.db`)
- [ ] **MON-04**: `--incremental` mode: only re-runs functions affected by detected deltas
- [ ] **MON-05**: New findings trigger notifications via configured Notifier(s)
- [ ] **MON-06**: Findings dedup across monitor cycles (uses `artefacts/findings.jsonl` history with content hash)
- [ ] **MON-07**: Long-running mode respects `OUTPUT_VERBOSITY=0/1/2` for log volume control
- [ ] **MON-08**: Graceful shutdown on SIGINT/SIGTERM mid-cycle: completes current task, writes checkpoint, exits clean

### Reporting (Deliverable #11)

- [ ] **REPORT-01**: Canonical artefacts written as JSONL: `subdomains.jsonl`, `hosts.jsonl`, `urls.jsonl`, `findings.jsonl`, `notes.jsonl`
- [ ] **REPORT-02**: HTML report (`reports/report.html`) renders findings with no JavaScript dependencies required; all user-controlled values HTML-escaped to prevent XSS in the report itself
- [ ] **REPORT-03**: CSV exports per category (`reports/subdomains.csv`, etc.) for spreadsheet workflows
- [ ] **REPORT-04**: AI report opt-in via `AI_REPORT=true` config + API key (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`); all PII/secrets pass through redactor before API call
- [ ] **REPORT-05**: Faraday export (Faraday-compatible JSON format) for security platform integration
- [ ] **REPORT-06**: Risk-scored hotlist (`reports/hotlist.json`) — top N findings by severity × confidence × asset criticality
- [ ] **REPORT-07**: SARIF output (`reports/findings.sarif`) — industry-standard format for findings consumption by external tools (CodeQL, GitHub Code Scanning, etc.) — promoted from EMG-03
- [ ] **REPORT-08**: Reports rebuilt deterministically from `artefacts/` — `reconftw report` subcommand regenerates without re-running scans
- [ ] **REPORT-09**: Reports include workspace metadata: target, start/end time, config snapshot, tool versions used

### Notifications (Deliverable #12)

- [ ] **NOTIF-01**: Slack notifications via webhook URL; all message bodies pass through redactor before send (no API keys, no internal IPs, no secrets ever sent)
- [ ] **NOTIF-02**: Telegram bot notifications with same redaction guarantee
- [ ] **NOTIF-03**: Discord webhook notifications with same redaction
- [ ] **NOTIF-04**: Per-event notification rules: on-critical-finding, on-scan-complete, on-failure; configurable in TOML (`notifications.events`)
- [ ] **NOTIF-05**: Secret tagging in the type system enforces redaction at sink — there is NO opt-in raw mode; secrets cannot reach a notifier unredacted by API design
- [ ] **NOTIF-06**: Notification rate limit per channel (avoid flooding on critical findings burst)
- [ ] **NOTIF-07**: Notifier health check via `reconftw notify --test` — validates each configured channel reachable

### Installer & Deps (Deliverable #13)

- [ ] **INST-01**: Installer subcommand `reconftw install` (also: `reconftw install --health-check`) replaces the bash `install.sh`
- [ ] **INST-02**: Installer reads `tools.lock` as canonical pin source — ALL 70+ orchestrated tools versioned (Go tools by module@version, Python by name+version, system deps by name)
- [ ] **INST-03**: SHA-256 verification on installer bootstrappers (rustup-init.sh, uv installer) against pinned hashes
- [ ] **INST-04**: SHA-256 verification on pre-built tool binaries where vendor publishes hashes
- [ ] **INST-05**: Platform detection: Debian/Ubuntu (apt), RHEL/Fedora/CentOS (yum/dnf), Arch (pacman), macOS Intel (brew), macOS Apple Silicon (brew arm64)
- [ ] **INST-06**: Go tool installation via `go install <module>@<version>` for each Go-based tool from tools.lock
- [ ] **INST-07**: Python tool installation via `uv tool install <package>==<version>` with per-tool isolation
- [ ] **INST-08**: System dep installation via platform-appropriate package manager
- [ ] **INST-09**: Rust toolchain bootstrap (only if `smugglex` or other Rust deps enabled) via verified rustup-init
- [ ] **INST-10**: Post-install health check verifies every tool present on PATH and runnable (`--version` or equivalent)
- [ ] **INST-11**: Installer is idempotent: re-running installs only missing/outdated tools, doesn't duplicate work
- [ ] **INST-12**: Installer fails fast with clear error on unsupported platform; no partial-install state left behind

### Cross-Platform (Deliverable #14)

- [ ] **XPLAT-01**: Linux glibc support: Debian 12+, Ubuntu 24.04+, RHEL/Rocky 9+, Arch (rolling)
- [ ] **XPLAT-02**: Linux musl support: Alpine 3.20+ (static binary route)
- [ ] **XPLAT-03**: macOS Apple Silicon (arm64) — primary mac target
- [ ] **XPLAT-04**: macOS Intel (amd64)
- [ ] **XPLAT-05**: CI matrix runs build + unit + smoke test on every supported platform on each PR; weekly cron runs integration-full
- [ ] **XPLAT-06**: macOS binary signed with developer ID; notarized via Apple notarization service in CI from day 1
- [ ] **XPLAT-07**: Homebrew tap published for `brew install reconftw` on macOS
- [ ] **XPLAT-08**: Linux distribution: standalone binary download + tar.gz; optional `.deb`/`.rpm` packages
- [ ] **XPLAT-09**: ARM64 Linux support for cloud / Raspberry Pi deployments

### Docker (Deliverable #15)

- [ ] **DOCK-01**: Dockerfile updated with new binary baked in
- [ ] **DOCK-02**: Base image: distroless or minimal Ubuntu — chosen to minimize image size; documented in `Docker/README.md`
- [ ] **DOCK-03**: Multi-arch build (amd64 + arm64) via `docker buildx`
- [ ] **DOCK-04**: All 70+ orchestrated tools available in the image (installer runs at build time)
- [ ] **DOCK-05**: Image published to `ghcr.io/six2dez/reconftw` (and optionally Docker Hub) on every release
- [ ] **DOCK-06**: Image tagged with semantic version + `latest` + git SHA
- [ ] **DOCK-07**: Image runs as non-root user (security hardening) with selective elevation where required (raw sockets for naabu/nmap)

### MCP Server (Deliverable #17 — added 2026-05-27 per user decision)

- [ ] **MCP-01**: MCP server (`reconftw mcp serve`) implements the standard Model Context Protocol — listens on configurable transport (stdio for agent embedding, optional HTTP/SSE for remote)
- [ ] **MCP-02**: Exposes recon capabilities as MCP tools: `recon`, `subs`, `web`, `vulns`, `osint`, `monitor`, `report`
- [ ] **MCP-03**: Streaming JSONL findings via MCP resource subscription — agents can subscribe to live findings during long scans
- [ ] **MCP-04**: Authentication: API key required (TOML `mcp.api_key` or env `RECONFTW_MCP_API_KEY`); all credentials redacted in logs
- [ ] **MCP-05**: Resource limits: MCP requests cannot exceed configured `PARALLEL_MAX_JOBS`; MCP-driven scans share the global scheduler
- [ ] **MCP-06**: Findings exposed via MCP use the same SARIF-compatible schema as REPORT-07
- [ ] **MCP-07**: MCP enable/disable configurable in TOML (`mcp.enabled = true|false`); defaults to false so MCP is opt-in at config time
- [ ] **MCP-08**: OpenAPI schema published for MCP HTTP transport endpoints (promoted from EMG-15 — required by MCP)
- [ ] **MCP-09**: MCP-specific documentation: agent integration example, supported tools list, rate-limit guidance, security considerations
- [ ] **MCP-10**: MCP sandboxing: per-target scope passed through MCP cannot be widened via tool arguments — scope is fixed at MCP session start

### Cutover & Migration (Deliverable #16)

- [ ] **CUT-01**: Config migrator (`reconftw migrate --from-bash <reconftw.cfg> --to <reconftw.toml>`) reads v1 bash config line-by-line and emits TOML equivalent
- [ ] **CUT-02**: Migrator handles arithmetic expressions (`$(nproc) * 5`), duration strings (`6h`), quoted values, and array-like lists explicitly
- [ ] **CUT-03**: Migrator tested against a corpus of 20+ real-world `reconftw.cfg` files collected from GitHub issues and user contributions; ALL 20+ corpus configs migrate without errors
- [ ] **CUT-04**: Cutover is BLOCKED until CUT-03 passes — milestone v2.0 cannot ship if the migrator doesn't cover the corpus
- [ ] **CUT-05**: Migrator `--dry-run` shows preview of mapping decisions for user review
- [ ] **CUT-06**: Unknown config keys produce LOUD warnings ("⚠ unknown key X — needs human review"); NEVER silently drop them
- [ ] **CUT-07**: MIGRATION.md documents every breaking change: CLI flag changes, output tree changes, config key renames, default behavior changes
- [ ] **CUT-08**: Compat symlink writer maintains `Recon/<domain>/` populated with bash-shape filenames for 6 months post-cutover
- [ ] **CUT-09**: Beta period: `reconftw v2-beta` binary distributed for 1-2 months PRIOR to cutover; existing users opt in
- [ ] **CUT-10**: Beta-period feedback channel: GitHub Issues template "v2-beta-feedback" + monthly issue triage to community
- [ ] **CUT-11**: Bug-bug parity test: 3-5 canonical targets (e.g., `hackerone.com`, `tesla.com`, controlled lab) — full bash v1 + v2 runs side-by-side, automated diff compares structured outputs; equivalence within noise tolerance (timing, ordering)
- [ ] **CUT-12**: Cutover sign-off criteria documented: (a) CUT-03 migrator corpus passes, (b) CUT-11 parity test green, (c) beta period clean of P0/P1 issues, (d) user community survey or GitHub Discussions thread reaches sign-off threshold
- [ ] **CUT-13**: Cutover communication: README rewrite, GitHub release notes, social announcement on user comms channels
- [ ] **CUT-14**: V1 deprecation timeline: bash `main` becomes `archive/v1.x` branch frozen for 12 months post-cutover; security-critical bugfixes only in that window
- [ ] **CUT-15**: V1 → V2 rollback path documented: if v2 has critical issue in production, users can revert to v1 binary via documented procedure

### Cross-Cutting Quality Requirements (Apply to All Deliverables)

- [ ] **XCUT-01**: Performance — v2 throughput within 10% of bash v1 on canonical benchmark: full scan of a 1000-subdomain target on 8-core / 16GB host
- [ ] **XCUT-02**: Resource budget — Go binary <50MB stripped (if Go wins ADR) OR Python `uv tool` installed footprint <500MB (if Python wins). Memory ceiling under typical 5K-subdomain load: <2GB RSS
- [ ] **XCUT-03**: Test coverage — feature-parity coverage of v1's 351 bats test scenarios mapped to v2 tests; branch coverage ≥75% on lib code; ≥90% on critical paths (scheduler, scope filter, checkpoint, secret redaction)
- [ ] **XCUT-04**: CI policy — race detector mandatory on every Go test run; strict mypy on Python; lint zero-tolerance gate; integration-full split: unit+smoke per push, full-arch per nightly, real-tool integration weekly
- [ ] **XCUT-05**: Backwards compat — zero silent breakages; ALL behavior changes documented in MIGRATION.md with before/after examples
- [ ] **XCUT-06**: Documentation — godoc/sphinx API docs auto-generated from code; README rewritten with v2 examples + quickstart; INSTALL.md updated; CONTRIBUTING.md for new contributors
- [ ] **XCUT-07**: Logging hygiene — NO secrets in any log output ever; redaction tested per channel (file, stdout, stderr, notifier, debug); CI test asserts no known secret patterns leak under varied input
- [ ] **XCUT-08**: Supply chain — tools.lock pins all 70+ tools to specific versions with SHA-256 where supplied; CI verifies pins on update; 24-72h quarantine window for new tool versions before lockfile bump
- [x] **XCUT-09**: Observability — every long-running task emits heartbeat events; failed tasks emit structured error events with classification; CI test asserts heartbeat cadence

---

## Deferred to v2.1+

Acknowledged backlog. NOT in v2.0 roadmap. Documented to prevent scope creep.

### From research synthesis (EMG-* items NOT promoted)

| ID | Feature | Defer reason |
|----|---------|--------------|
| EMG-05 | Man page generation | UX polish; cobra/typer can generate later in v2.1 |
| EMG-06 | OpenTelemetry tracing (full) | Build hooks in Foundation; wire backend in v2.1 when consumer exists |
| EMG-08 | TTY-aware progress bar | Dot-fill UI is sufficient; bar adds dep + TTY edge cases |
| EMG-09 | Adaptive rate limiting (auto-throttle on 429) | Tool-output parsing fragile; needs separate design |
| EMG-10 | Per-host rate-limit fairness | Genuinely complex; needs design phase |
| EMG-14 | JSONL streaming during scan | Incremental on top of REPORT-01; nice-to-have |
| EMG-16 | Per-tool sandboxing (seccomp/AppArmor) | Defer until a concrete CVE forces it |
| EMG-17 | Findings dedup across runs (full) | Data model ready in v2.0; full dedup logic in v2.1 |
| EMG-18 | False-positive marking | Requires EMG-17 |
| EMG-19 | JUnit XML output | Niche use case |

### From v1 deferred backlog

| Category | Item | Status in v2 |
|----------|------|--------------|
| Architecture | ARCH-01 v1: split modules/web.sh | **Resolved by design in v2** — web module split into sub-modules per architecture |
| Architecture | ARCH-02 v1: file-based secret handling | **Resolved by design in v2** — TOML config + env + secret files; NEVER passed via CLI args |
| Scaling | SCALE-01 v1: memory-aware permutation throttling | **In v2 scope (SUBD-03 back-pressure)** |
| Scaling | SCALE-02 v1: resolver-file health gate | **In v2 scope (SUBD-02)** |
| Observability | OBS-01 v1: surface venv health | **In v2 scope (FOUND-08 ToolRegistry warns on missing)** |
| Observability | OBS-02 v1: structured JSONL by default | **In v2 scope (FOUND-02 logger structured by default)** |

---

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Active exploitation / payload delivery | reconFTW maps attack surface and flags candidate vulns; weaponized exploitation belongs in user-driven tooling |
| GUI / web dashboard | CLI-first by design. `reconftw-web/` and `web/` directories in working tree are separate experimentation, NOT part of v2.0 |
| Real-time streaming to dashboards | Output is file-based and post-run; live dashboards would require fundamentally different architecture |
| Multi-user collaboration | Single-operator CLI tool; team workflows handled by external systems (Faraday, custom aggregators) |
| Cloud SaaS hosting | Self-hosted CLI by design; Axiom is opt-in distributed execution, not managed hosting |
| Re-implementing wrapped tools | reconFTW orchestrates existing best-of-breed tools (subfinder, nuclei, httpx, …) rather than competing with them |
| Drop-in CLI compat with v1 | v2 redesigns freely; v1 short flags are deprecated aliases only (warned but functional for 2 minor versions) |
| Backporting v2 features to bash v1 | bash `main` is frozen; v2 features stay in v2 |
| Database-backed result storage (Postgres, etc.) | File-tree output is the design — reNgine's biggest source of bugs per research; SQLite is internal state only |
| Always-on background daemon | Cron + `--monitor` covers it; no init.d/systemd service shipped |
| Built-in proxy / MITM | Out of scope; users can pipe through their own proxy |
| Auto-submitting findings to bug bounty platforms | Out of scope; export to Faraday / JSON / SARIF and let user submit |
| Multi-tenant SaaS | Single-operator design |

---

## Traceability

Each REQ-ID maps to exactly one phase. Populated by roadmapper agent 2026-05-27.

**Coverage: 197/197 (100%)** — every REQ-ID above is mapped to a phase.

| Requirement | Phase | Status |
|-------------|-------|--------|
| DEC-01 | Phase 1 — Language ADR & Spike | Pending |
| DEC-02 | Phase 1 — Language ADR & Spike | Pending |
| DEC-03 | Phase 1 — Language ADR & Spike | Pending |
| DEC-04 | Phase 1 — Language ADR & Spike | Pending |
| DEC-05 | Phase 1 — Language ADR & Spike | Pending |
| ARCH-01 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-02 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-03 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-04 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-05 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-06 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-07 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-08 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-09 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-10 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-11 | Phase 2 — Architecture v2 Design | Pending |
| ARCH-12 | Phase 2 — Architecture v2 Design | Pending |
| FOUND-01 | Phase 3 — Foundation Kernel | Pending |
| FOUND-02 | Phase 3 — Foundation Kernel | Pending |
| FOUND-03 | Phase 3 — Foundation Kernel | Pending |
| FOUND-04 | Phase 3 — Foundation Kernel | Pending |
| FOUND-05 | Phase 3 — Foundation Kernel | Pending |
| FOUND-06 | Phase 3 — Foundation Kernel | Pending |
| FOUND-07 | Phase 3 — Foundation Kernel | Pending |
| FOUND-08 | Phase 3 — Foundation Kernel | Pending |
| FOUND-09 | Phase 3 — Foundation Kernel | Pending |
| FOUND-10 | Phase 3 — Foundation Kernel | Pending |
| FOUND-11 | Phase 3 — Foundation Kernel | Pending |
| FOUND-12 | Phase 3 — Foundation Kernel | Pending |
| FOUND-13 | Phase 3 — Foundation Kernel | Pending |
| FOUND-14 | Phase 3 — Foundation Kernel | Pending |
| FOUND-15 | Phase 3 — Foundation Kernel | Pending |
| FOUND-16 | Phase 3 — Foundation Kernel | Pending |
| SUBD-01 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-02 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-03 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-04 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-05 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-06 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-07 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-08 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-09 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-10 | Phase 4 — Subdomains E2E + Axiom | Complete |
| SUBD-11 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-01 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-02 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-03 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-04 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-05 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-06 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-07 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-08 | Phase 4 — Subdomains E2E + Axiom | Complete |
| AXIOM-09 | Phase 4 — Subdomains E2E + Axiom | Complete |
| WEB-01 | Phase 5 — Web Pipeline E2E | Complete |
| WEB-02 | Phase 5 — Web Pipeline E2E | Complete |
| WEB-03 | Phase 5 — Web Pipeline E2E | Complete |
| WEB-04 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-05 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-06 | Phase 5 — Web Pipeline E2E | Complete |
| WEB-07 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-08 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-09 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-10 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-11 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-12 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-13 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-14 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-15 | Phase 5 — Web Pipeline E2E | Pending |
| WEB-16 | Phase 5 — Web Pipeline E2E | Complete |
| VULN-01 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-02 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-03 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-04 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-05 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-06 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-07 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-08 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-09 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-10 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-11 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-12 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-13 | Phase 6 — Vulnerability Scanning E2E | Complete |
| VULN-14 | Phase 6 — Vulnerability Scanning E2E | Complete |
| OSINT-01 | Phase 7 — OSINT E2E | Complete |
| OSINT-02 | Phase 7 — OSINT E2E | Complete |
| OSINT-03 | Phase 7 — OSINT E2E | Complete |
| OSINT-04 | Phase 7 — OSINT E2E | Complete |
| OSINT-05 | Phase 7 — OSINT E2E | Complete |
| OSINT-06 | Phase 7 — OSINT E2E | Complete |
| OSINT-07 | Phase 7 — OSINT E2E | Complete |
| OSINT-08 | Phase 7 — OSINT E2E | Complete |
| OSINT-09 | Phase 7 — OSINT E2E | Complete |
| OSINT-10 | Phase 7 — OSINT E2E | Complete |
| OSINT-11 | Phase 7 — OSINT E2E | Complete |
| OSINT-12 | Phase 7 — OSINT E2E | Complete |
| OSINT-13 | Phase 7 — OSINT E2E | Complete |
| OSINT-14 | Phase 7 — OSINT E2E | Complete |
| OSINT-15 | Phase 7 — OSINT E2E | Complete |
| OSINT-16 | Phase 7 — OSINT E2E | Complete |
| MCP-01 | Phase 8 — MCP Server | Pending |
| MCP-02 | Phase 8 — MCP Server | Pending |
| MCP-03 | Phase 8 — MCP Server | Pending |
| MCP-04 | Phase 8 — MCP Server | Pending |
| MCP-05 | Phase 8 — MCP Server | Pending |
| MCP-06 | Phase 8 — MCP Server | Pending |
| MCP-07 | Phase 8 — MCP Server | Pending |
| MCP-08 | Phase 8 — MCP Server | Pending |
| MCP-09 | Phase 8 — MCP Server | Pending |
| MCP-10 | Phase 8 — MCP Server | Pending |
| MODE-01 | Phase 9 — Composite Modes | Pending |
| MODE-02 | Phase 9 — Composite Modes | Pending |
| MODE-03 | Phase 9 — Composite Modes | Pending |
| MODE-04 | Phase 9 — Composite Modes | Pending |
| MODE-05 | Phase 9 — Composite Modes | Pending |
| MODE-06 | Phase 9 — Composite Modes | Pending |
| MODE-07 | Phase 9 — Composite Modes | Pending |
| MODE-08 | Phase 9 — Composite Modes | Pending |
| MODE-09 | Phase 9 — Composite Modes | Pending |
| MODE-10 | Phase 9 — Composite Modes | Pending |
| MODE-11 | Phase 9 — Composite Modes | Pending |
| MODE-12 | Phase 9 — Composite Modes | Pending |
| MON-01 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| MON-02 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| MON-03 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| MON-04 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| MON-05 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| MON-06 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| MON-07 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| MON-08 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-01 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-02 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-03 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-04 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-05 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-06 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-07 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-08 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| REPORT-09 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| NOTIF-01 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| NOTIF-02 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| NOTIF-03 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| NOTIF-04 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| NOTIF-05 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| NOTIF-06 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| NOTIF-07 | Phase 10 — Monitor + Reporting + Notifications | Pending |
| INST-01 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-02 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-03 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-04 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-05 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-06 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-07 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-08 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-09 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-10 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-11 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| INST-12 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-01 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-02 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-03 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-04 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-05 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-06 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-07 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-08 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XPLAT-09 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| DOCK-01 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| DOCK-02 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| DOCK-03 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| DOCK-04 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| DOCK-05 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| DOCK-06 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| DOCK-07 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| CUT-01 | Phase 12 — Cutover & Migration | Pending |
| CUT-02 | Phase 12 — Cutover & Migration | Pending |
| CUT-03 | Phase 12 — Cutover & Migration | Pending |
| CUT-04 | Phase 12 — Cutover & Migration | Pending |
| CUT-05 | Phase 12 — Cutover & Migration | Pending |
| CUT-06 | Phase 12 — Cutover & Migration | Pending |
| CUT-07 | Phase 12 — Cutover & Migration | Pending |
| CUT-08 | Phase 12 — Cutover & Migration | Pending |
| CUT-09 | Phase 12 — Cutover & Migration | Pending |
| CUT-10 | Phase 12 — Cutover & Migration | Pending |
| CUT-11 | Phase 12 — Cutover & Migration | Pending |
| CUT-12 | Phase 12 — Cutover & Migration | Pending |
| CUT-13 | Phase 12 — Cutover & Migration | Pending |
| CUT-14 | Phase 12 — Cutover & Migration | Pending |
| CUT-15 | Phase 12 — Cutover & Migration | Pending |
| XCUT-01 | Phase 12 — Cutover & Migration (baseline est. Phase 3, validated per-module phase) | Pending |
| XCUT-02 | Phase 3 — Foundation Kernel | Pending |
| XCUT-03 | Phase 12 — Cutover & Migration (gate established Phase 3) | Pending |
| XCUT-04 | Phase 3 — Foundation Kernel (CI runs every phase) | Pending |
| XCUT-05 | Phase 12 — Cutover & Migration | Pending |
| XCUT-06 | Phase 12 — Cutover & Migration | Pending |
| XCUT-07 | Phase 3 — Foundation Kernel (lint + tested every phase) | Pending |
| XCUT-08 | Phase 11 — Installer + Cross-Platform + Docker | Pending |
| XCUT-09 | Phase 3 — Foundation Kernel (heartbeat tested every phase) | Complete |

---

## Decisions Made During Requirements Definition

These shaped REQ-IDs above. Captured for future reference.

| Decision | Source | Outcome |
|----------|--------|---------|
| Subcommands primary + v1 short flags as deprecated aliases (2 minor versions warning, then removed) | User answer 2026-05-27 | MODE-09, ARCH-10 |
| Config migrator REQUIRED + 20-corpus test gate on cutover | User answer 2026-05-27 | CUT-01 through CUT-06 |
| MCP server INCLUDED in v2.0 as deliverable #17 (mandatory, opt-in at config) | User answer 2026-05-27 | MCP-01 through MCP-10; OpenAPI schema promoted from EMG-15 |
| Cutover criterion: bug-bug parity test + 1-2m beta period | User answer 2026-05-27 | CUT-09 through CUT-12 |
| Output tree: new `workspaces/<target>/` layout + 6 months compat symlinks for `Recon/<domain>/` | Default (research recommendation) | ARCH-03, ARCH-04, CUT-08 |
| Installer: full rewrite in chosen lang, NOT bootstrap script | Default (research recommendation) | INST-01 through INST-12 |
| Failure isolation: config-driven `failure_policy` per stage (fail-fast for spine, best-effort for OSINT/vulns by default) | Default (research recommendation) | ARCH-09 |
| `PARALLEL_MAX_JOBS` default kept at v1's 4 (no silent change) | Default (research recommendation) | ARCH-02, MIGRATION.md note |
| Performance acceptance: within 10% of bash v1 throughput on canonical benchmark | Default | XCUT-01 |
| Resource budget: Go binary <50MB OR Python tool footprint <500MB; memory <2GB RSS at typical load | Default | XCUT-02 |
| Test parity: feature-parity coverage of 351 bats scenarios (NOT line-for-line port) + branch coverage gate | Default | XCUT-03 |
| CI strategy: per-push (lint+unit+smoke), nightly (full-arch matrix), weekly (real-tool integration) | Default | XCUT-04 |
| Secret tagging at TYPE level (Secret/SecretStr) — redaction at sink, NO opt-in raw mode | Pitfall #4 (top-5 impact) | FOUND-02, NOTIF-05, XCUT-07 |
| Every subprocess MUST use process-group kill (Setpgid+killpg / start_new_session+killpg); lint rule enforces | Pitfall #1 (top-5 impact) | FOUND-09, FOUND-10 |

---

*Requirements defined: 2026-05-27*
*Last updated: 2026-05-27 after milestone v2.0 initialization + roadmapper traceability population (197/197 REQ-IDs mapped to 12 phases)*
*Source: PROJECT.md (17 deliverables) + `.planning/research/SUMMARY.md` + user decisions 2026-05-27*
