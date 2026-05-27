# Roadmap: reconFTW v2.0 — Complete Core Migration (Bash → Go/Python)

## Overview

This milestone delivers a **complete rewrite** of reconFTW from Bash to a typed/compiled language (Go OR Python — decided by spike), preserving 100% of v1 functionality (70+ tools, 17 deliverables, all observable behavior). It is a **single mega-milestone** with no shippable interim releases — the 12 internal phases are the real checkpoints.

**Sequencing logic** (drives the order):

1. **ADR FIRST (Phase 1)** — Language choice blocks everything else. No production code until ADR signed.
2. **Architecture LOCKED SECOND (Phase 2)** — Contracts (TOML, output tree, Task/Backend/AppContext) must settle before Foundation builds against them.
3. **Foundation KERNEL THIRD (Phase 3)** — The 16-step build order from ARCHITECTURE.md §12: Errors → Logger → Config → OutputTree+Checkpoint+Scheduler → Tools → AppContext → CLI. CI from day 1.
4. **Subdomains + Axiom = same phase (Phase 4)** — Subs is the canonical reference port AND where Axiom provides most value. Output-equivalence test (vs bash v1) at end gates the rest.
5. **Module ports sequential where required** — Web before Vulns (vulns consumes web outputs). OSINT independent (can be calendar-parallel with Web/Vulns).
6. **MCP server (Phase 8)** — Its own phase, runs after Foundation; calendar-parallel-capable with later module ports.
7. **Composite modes (Phase 9)** — Only after 4-7 done (they compose the ported underlying modules).
8. **Monitor + Reporting + Notifications LATE (Phase 10)** — Need all modules + findings data model stable + dedup-ready data.
9. **Installer + XPlat + Docker grouped (Phase 11)** — Single packaging phase.
10. **Cutover LAST (Phase 12)** — CUT-04 explicitly blocks cutover until migrator corpus test passes. CUT-11 parity + CUT-12 sign-off close the milestone.

**Parallelization within phases:** Plans inside a phase can execute concurrently where independent (per `config.json:parallelization=true`). Granularity is **coarse** — broader phases consistent with single-maintainer cadence.

**Total v2.0 requirements:** 197 REQ-IDs across 17 deliverables (16 PROJECT.md + MCP). All mapped below; 100% coverage.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Language ADR & Spike** — Identical recon slice in BOTH Go and Python; measured comparison; signed ADR before any production code
- [ ] **Phase 2: Architecture v2 Design** — Lock TOML schema, output tree, Task/Backend/AppContext/Error interfaces, CLI surface, test policy, failure isolation — Foundation depends on these
- [ ] **Phase 3: Foundation Kernel** — Errors + Logger + Config + OutputTree + Checkpoint + Scheduler + Tools + AppContext + CLI + Mocks + CI from day 1
- [ ] **Phase 4: Subdomains E2E + Axiom Integration** — Canonical reference port; passive+brute+permut+dnsx+scope+takeover+buckets+geo+ASN with Axiom distributed execution; output-equivalence test gates phase end
- [ ] **Phase 5: Web Pipeline E2E** — Probe + screenshots + fuzz + JS + nuclei + WAF + sourcemaps + favicon + CSP + vhost + 4xx-bypass + URL discovery + 20-function surface with parity test
- [ ] **Phase 6: Vulnerability Scanning E2E** — XSS + SQLi + SSRF + LFI + SSTI + CRLF + smuggling + cmdi + nuclei-DAST + cache poisoning + gf patterns + 4xx-bypass
- [ ] **Phase 7: OSINT E2E** — Domain/IP info + emails + GitHub dorks/leaks/actions + cloud enum + Postman + Swagger + Spoofy + msftrecon + CMSeeK + GraphQL + Google dorks
- [ ] **Phase 8: MCP Server** — Model Context Protocol server exposing recon modes as MCP tools; auth + redaction + scope sandboxing + OpenAPI schema; opt-in in config
- [ ] **Phase 9: Composite Modes** — `recon`, `all`, `passive`, `zen`, `deep`, `quick-rescan`, `refresh-cache`, `gen-resolvers` + v1 short-flag aliases with deprecation warnings
- [ ] **Phase 10: Monitor Mode + Reporting + Notifications** — Monitor loop + diff detection + incremental + JSON/HTML/CSV/AI/Faraday/hotlist/SARIF reports + Slack/Telegram/Discord notifications consolidated
- [ ] **Phase 11: Installer + Cross-Platform + Docker** — `reconftw install` (replaces install.sh) + tools.lock for 70+ tools + SHA-256 verification + Linux/macOS/ARM64 + Docker multi-arch
- [ ] **Phase 12: Cutover & Migration** — Config migrator (corpus-tested) + MIGRATION.md + compat symlinks + beta period + bug-bug parity test + community sign-off + cutover

## Phase Details

### Phase 1: Language ADR & Spike
**Goal**: Pick Go or Python via measurable spike (identical recon slice in both, head-to-head comparison) and ship a signed ADR before any production code is written.
**Depends on**: Nothing (first phase)
**Requirements**: DEC-01, DEC-02, DEC-03, DEC-04, DEC-05
**Success Criteria** (what must be TRUE):
  1. A signed ADR exists at `.planning/decisions/0001-language.md` documenting the language choice with evidence; the file is committed to `rewrite/v2` (DEC-01)
  2. Two PoC implementations exist under `spike/go/` and `spike/python/` — each implements the same recon slice (passive subdomain enum from ≥5 sources + httpx probe + atomic JSONL writes + SIGINT kill-tree test); both build and run on the maintainer's machine (DEC-02)
  3. The ADR contains measured numbers, not opinions: dev velocity (LoC + hours), packaging footprint (binary or venv size), kill-tree correctness under SIGINT (parent killed, all children dead within 10s), RSS under 5K concurrent subdomain hosts, and cross-platform pain notes (especially macOS arm64) (DEC-03)
  4. The ADR contains a pre-agreed tie-breaker rule (e.g., "choose Go if metrics within 25% noise band — single-binary distribution wins") and explicitly invokes or rejects it (DEC-04)
  5. After ADR signed, `STACK.md` and `ARCHITECTURE.md` are collapsed to the chosen language only; the other language is permanently removed from research files (DEC-05)
**Plans**: TBD

### Phase 2: Architecture v2 Design
**Goal**: Lock every contract the rest of v2 depends on — TOML schema, output tree shape, interfaces (Task/Backend/AppContext), error hierarchy, CLI surface, test policy, failure isolation, logging policy — in a signed architecture doc, so Foundation can build against stable contracts.
**Depends on**: Phase 1
**Requirements**: ARCH-01, ARCH-02, ARCH-03, ARCH-04, ARCH-05, ARCH-06, ARCH-07, ARCH-08, ARCH-09, ARCH-10, ARCH-11, ARCH-12
**Success Criteria** (what must be TRUE):
  1. `.planning/decisions/0002-architecture-v2.md` exists, signed, committed to `rewrite/v2` (ARCH-01)
  2. The doc fully specifies the TOML config schema (every section: `subdomains.passive.enabled`, `web.fuzz.threads_max`, `axiom.enabled`, `notifications.slack.webhook`, `mcp.enabled`, etc.) and the output tree layout (`workspaces/<target-id>/` with `inputs/`, `artefacts/`, `raw/`, `reports/`, `logs/`, `manifest.json`, `checkpoints.db`, `state.db`) plus the 6-month compat-symlink layer for `Recon/<domain>/` (ARCH-02, ARCH-03, ARCH-04)
  3. The doc contains signed signatures for `Task`, `Backend`, `AppContext`, and the error class hierarchy (`ToolError`, `ToolTimeout`, `OutOfScope`, `AxiomFailure`, `ConfigError`, `ScopeError`, `ChecksumMismatch`) plus the per-stage `failure_policy` model (ARCH-05, ARCH-06, ARCH-07, ARCH-08, ARCH-09)
  4. The doc specifies the CLI surface (subcommands `reconftw recon|subs|web|...` primary; v1 short flags `-r/-s/-p/-a/-d/-l` preserved as deprecated aliases with 2-minor-version warning window) and the test-ring policy (unit / integration / smoke / property-based) (ARCH-10, ARCH-11)
  5. The doc specifies the logging policy with type-level secret tagging (Go `Secret`+`LogValuer` OR Python `SecretStr`) and sink-level redaction registered BEFORE first log line (ARCH-12)
**Plans**: TBD

### Phase 3: Foundation Kernel
**Goal**: Ship the kernel — typed errors, structured logger with redaction, layered config loader, atomic output tree, SQLite checkpoint, bounded scheduler, tool registry with kill-tree-safe LocalBackend, AppContext, CLI binary, test mocks, and CI gate — so module ports can begin against a stable foundation.
**Depends on**: Phase 2
**Requirements**: FOUND-01, FOUND-02, FOUND-03, FOUND-04, FOUND-05, FOUND-06, FOUND-07, FOUND-08, FOUND-09, FOUND-10, FOUND-11, FOUND-12, FOUND-13, FOUND-14, FOUND-15, FOUND-16, XCUT-02, XCUT-04, XCUT-07, XCUT-09
**Success Criteria** (what must be TRUE):
  1. `reconftw --help` runs against the kernel binary; the CLI is wired to the configured subsystems (typed errors, structured logger, layered config loader with 8-source precedence, scheduler, tool registry, output tree, checkpoint store, notifier stubs, UI dot-fill); empty `reconftw run` against a mock target writes a `workspaces/<target>/manifest.json` and exits 0 (FOUND-01, FOUND-02, FOUND-03, FOUND-13, FOUND-14)
  2. Atomic writes verified: a SIGKILL injected between `tempfile + fsync` and `rename` leaves the original target file intact (test asserts no torn output); SQLite checkpoint store records `(task_name, target, input_hash, status, timings, output_paths, error_class)` and re-running with same input_hash skips the task (FOUND-04, FOUND-05)
  3. Subprocess safety enforced: every subprocess uses `Setpgid`+`WaitDelay` (Go) or `start_new_session=True`+`os.killpg` (Python); a lint rule (custom golangci-lint check or ruff plugin) forbids raw `exec.Command`/`subprocess.Popen` outside the Tool wrapper and fails CI on violation; an integration test starts a slow mock tool and SIGINT-kills the parent — all children dead within 10s (FOUND-09, FOUND-10)
  4. Scheduler enforces bounded concurrency via semaphore (max_jobs default 4), per-task timeout via context, and heartbeat events at configurable cadence; rate limiter supports per-tool/per-target/global caps from TOML; tool registry self-registers tools via `func init()` (Go) or `@register_tool` (Python) and emits structured warnings on missing-but-required tools and structured errors on missing-and-critical; notifier interface + log sink + Slack/Telegram/Discord stubs are wired through the redactor — no message body can reach a notifier with unredacted secrets (FOUND-06, FOUND-07, FOUND-08, FOUND-11, FOUND-12, XCUT-09)
  5. Test mocks ship alongside real implementations (MockBackend deterministic; MockCheckpoint in-memory; MockOutputTree in-memory FS); CI on every push runs lint + format-check + unit + integration smoke + `-race` (Go) or `mypy --strict` (Python); branch coverage gate ≥75% on lib code is enforced (no merge below threshold); Go binary stripped is <50MB (if Go won) OR Python `uv tool` installed footprint is <500MB (if Python won) at the end of Foundation; no secret patterns leak in test logs under varied input (CI test asserts) (FOUND-15, FOUND-16, XCUT-02, XCUT-04, XCUT-07)
**Plans**: TBD

### Phase 4: Subdomains E2E + Axiom Integration
**Goal**: Port the subdomain pipeline end-to-end (passive + brute + permutations + dnsx + scope + takeover + buckets + geo + ASN) with Axiom distributed execution as a swappable Backend, validated against bash v1 output on 3+ canonical targets — this is the canonical reference port that proves the kernel works.
**Depends on**: Phase 3
**Requirements**: SUBD-01, SUBD-02, SUBD-03, SUBD-04, SUBD-05, SUBD-06, SUBD-07, SUBD-08, SUBD-09, SUBD-10, SUBD-11, AXIOM-01, AXIOM-02, AXIOM-03, AXIOM-04, AXIOM-05, AXIOM-06, AXIOM-07, AXIOM-08, AXIOM-09
**Success Criteria** (what must be TRUE):
  1. Running `reconftw subs --target hackerone.com` produces `workspaces/hackerone.com/artefacts/subdomains.jsonl`; the subdomain set is within ±5% of the v1 bash run output on the same target (SUBD-11 equivalence test green); passive sources include ≥6 of subfinder/crt.sh/github-subdomains/gitlab-subdomains/urlfinder/hackertarget (SUBD-01, SUBD-11)
  2. Active enumeration works end-to-end: brute via `puredns` with wordlist + resolver-health gate (abort if <N resolvers reachable), permutations via `gotator`/`regulator`/`dnscewl` with memory-aware back-pressure, DNS resolution via `dnsx` with per-batch timeout, ALL output filtered through a SINGLE canonical scope implementation (reconciling v1's split `is_in_scope_host`/`domain_match_regex`); a cross-check unit test feeds the same corpus through old and new scope filters and asserts equivalence (SUBD-02, SUBD-03, SUBD-04, SUBD-05)
  3. Takeover/buckets/ASN/geo flows write structured findings: subzy+dnstake → `artefacts/findings.jsonl` (takeover candidates), s3scanner → `artefacts/buckets.jsonl`, asnmap → `artefacts/asns.jsonl`, per-subdomain geo → `artefacts/hosts.jsonl`; zone transfer is gated by `ALLOW_TRANSFER=true` opt-in (preserves v1 safety gate) (SUBD-06, SUBD-07, SUBD-08, SUBD-09, SUBD-10)
  4. Axiom Backend implementation is swappable at construction: `reconftw subs --target X --axiom` provisions a fleet (`axiom_launch` with configurable count), runs the pipeline distributed, releases the fleet at end (`axiom_shutdown`), and produces an artefact set equivalent (same scope, same dedup) to the local run — output-equivalence test green (AXIOM-01, AXIOM-02, AXIOM-03, AXIOM-04, AXIOM-09)
  5. Axiom resilience features work: resolver list propagation to fleet (`resolvers_update`), failover wrapper detects infrastructure failures (SSH timeout, fleet unreachable, partial-fleet) and retries locally without losing work, `AXIOM_AUTO_FIX_HOSTKEY` repair logic preserved, `axiom_disable_runtime` flag disables axiom mid-run and all subsequent calls run locally (AXIOM-05, AXIOM-06, AXIOM-07, AXIOM-08)
**Plans**: TBD

### Phase 5: Web Pipeline E2E
**Goal**: Port the web analysis pipeline end-to-end (probe + screenshots + fuzz + JS analysis + nuclei + WAF + CDN/origin + CSP + favicon + vhost + 4xx-bypass + IIS short filenames + URL discovery + reflection/param discovery — the 20-function v1 surface), validated against bash v1 output on 3+ canonical targets.
**Depends on**: Phase 4
**Requirements**: WEB-01, WEB-02, WEB-03, WEB-04, WEB-05, WEB-06, WEB-07, WEB-08, WEB-09, WEB-10, WEB-11, WEB-12, WEB-13, WEB-14, WEB-15, WEB-16
**Success Criteria** (what must be TRUE):
  1. Running `reconftw web --target hackerone.com` produces `workspaces/hackerone.com/artefacts/hosts.jsonl` (httpx with tech/status/title/size), `artefacts/fuzz.jsonl` (ffuf with `FFUF_THREADS_MAX` cap respected), `artefacts/findings.jsonl` (nuclei SARIF-compatible with `NUCLEI_RATELIMIT` honored), and `raw/screenshots/<hash>.png` with diff-detection support; the host set and finding count are within parity tolerance of v1 (WEB-01, WEB-02, WEB-03, WEB-06, WEB-16)
  2. JS analysis flows ship: subjs+jsluice+mantra+JSA extract URLs and secrets to structured artefacts; sourcemapper extracts source maps to `raw/sourcemaps/<host>/`; URL discovery via katana+urlfinder+waymore deduplicated via urless/p1radup; reflection/param discovery via Gxss+arjun feeds vulns phase (WEB-04, WEB-05, WEB-14, WEB-15)
  3. Infrastructure analysis flows ship: WAF detection via wafw00f+cdncheck → `artefacts/waf.jsonl`, CDN/origin discovery via hakoriginfinder → `artefacts/origins.jsonl`, CSP analysis via csprecon surfaces new subdomains, favicon recon via favirecon+Shodan favicon hash, vhost discovery via VhostFinder (WEB-07, WEB-08, WEB-09, WEB-10, WEB-11)
  4. Bypass and IIS flows ship: 4xx bypass via nomore403, IIS short filename scanner via shortscan; outputs structured to `artefacts/findings.jsonl` with proper severity/confidence tagging (WEB-12, WEB-13)
  5. Output equivalence test green against 3+ canonical web targets (e.g., `hackerone.com`, `tesla.com`, controlled lab) — v2 output matches v1 modulo ordering/timing noise within ±5% tolerance for host/URL/finding counts (WEB-16)
**Plans**: TBD
**UI hint**: yes

### Phase 6: Vulnerability Scanning E2E
**Goal**: Port the vulnerability scanning pipeline end-to-end (XSS, SQLi, SSRF, LFI, SSTI, CRLF, smuggling, command injection, nuclei DAST, cache poisoning, gf patterns, second-order, 4xx bypass) — with long-running tool heartbeats and structured findings; validated against a controlled lab target.
**Depends on**: Phase 5
**Requirements**: VULN-01, VULN-02, VULN-03, VULN-04, VULN-05, VULN-06, VULN-07, VULN-08, VULN-09, VULN-10, VULN-11, VULN-12, VULN-13, VULN-14
**Success Criteria** (what must be TRUE):
  1. Running `reconftw vulns --target <lab>` produces structured findings to `artefacts/findings.jsonl` (SARIF-compatible) with severity, confidence, and reference fields per finding; XSS via dalfox, SQLi via sqlmap AND ghauri (both engines configurable), SSRF with interactsh-client collaborator, LFI via parameter fuzz + `lfi_wordlist`, SSTI via TInjA/SSTImap, CRLF via crlfuzz (VULN-01, VULN-02, VULN-03, VULN-04, VULN-05, VULN-06)
  2. Long-running tool flows preserve heartbeat semantics: sqlmap/dalfox/nuclei-DAST emit periodic heartbeat events (cadence configurable per FOUND-06 scheduler); a scan with a slow tool does NOT appear stuck in the UI (VULN-02, VULN-11)
  3. Advanced flows ship: HTTP request smuggling via smugglex (Rust binary subprocess wrapped via Tool interface), command injection via commix, web cache poisoning via Web-Cache-Vulnerability-Scanner + toxicache, second-order injection via second-order; all use the FOUND-09 process-group kill-tree safety pattern (VULN-07, VULN-08, VULN-09, VULN-12)
  4. Pattern matching + DAST flows ship: gf pattern matching for XSS/SQLi/SSRF/LFI/RCE signatures on URLs (consuming Phase 5 web outputs), nuclei DAST mode with HTTP traffic replay; 4xx bypass tests integrated into vuln workflows (VULN-10, VULN-11, VULN-13)
  5. Output equivalence test green against a controlled lab target (vuln-bait environment) — finding type set matches v1 modulo timing/payload variability; no silent missing categories (VULN-14)
**Plans**: TBD

### Phase 7: OSINT E2E
**Goal**: Port the OSINT collection pipeline end-to-end (domain/IP info, emails, GitHub dorks/leaks/actions audit, cloud bucket enum, Postman/Swagger leaks, email spoofing posture, Microsoft tenant recon, CMS fingerprint, GraphQL, custom wordlists, Google dorks) — validated against a canonical target with known OSINT footprint.
**Depends on**: Phase 5 (calendar-parallel with Phase 6 possible; depends on Foundation + Subdomains for target context, NOT on Web/Vulns directly)
**Requirements**: OSINT-01, OSINT-02, OSINT-03, OSINT-04, OSINT-05, OSINT-06, OSINT-07, OSINT-08, OSINT-09, OSINT-10, OSINT-11, OSINT-12, OSINT-13, OSINT-14, OSINT-15, OSINT-16
**Success Criteria** (what must be TRUE):
  1. Running `reconftw osint --target hackerone.com` produces `workspaces/hackerone.com/artefacts/` populated with domain info (whois + DNS records NS/MX/TXT/SOA/DNSSEC), IP info (CIDR ranges via mapcidr, ASN org lookups, geo data), email harvest via EmailHarvester, and email spoofing posture (SPF/DMARC/DKIM) via Spoofy (OSINT-01, OSINT-02, OSINT-03, OSINT-10)
  2. GitHub OSINT flows ship: dorks via dorks_hunter+gitdorks_go, leak scanning via ghleaks+trufflehog, Actions workflow secrets audit via gato; cloud bucket enumeration via cloud_enum (AWS S3, GCP, Azure Blob); all secrets in tool output pass through the FOUND-02 redactor before being written to logs or notifier (OSINT-04, OSINT-05, OSINT-06, OSINT-07)
  3. API/SaaS leak flows ship: Postman leaks via porch-pirate+postleaksNg, Swagger/OpenAPI leaks via sj+SwaggerSpy, GraphQL introspection via gqlspection; outputs structured to per-category JSONL artefacts (OSINT-08, OSINT-09, OSINT-13)
  4. Identity/fingerprint flows ship: Microsoft tenant recon via msftrecon, CMS fingerprint via CMSeeK+favirecon, custom wordlist generation via cewler, Google dorking automation via xnldorker (OSINT-11, OSINT-12, OSINT-14, OSINT-15)
  5. Output equivalence test green against a canonical target with known OSINT footprint — the artefact category set matches v1; no silent missing sources; per-category finding counts within tolerance (OSINT-16)
**Plans**: TBD

### Phase 8: MCP Server
**Goal**: Ship a Model Context Protocol server (`reconftw mcp serve`) that exposes recon modes as MCP tools with authentication, secret redaction, resource limits, scope sandboxing, and an OpenAPI schema — opt-in in config (default off) to preserve user choice.
**Depends on**: Phase 3 (Foundation kernel for AppContext, scheduler, redactor); calendar-parallel-capable with phases 5/6/7 module ports since MCP exposes the same internal APIs they build
**Requirements**: MCP-01, MCP-02, MCP-03, MCP-04, MCP-05, MCP-06, MCP-07, MCP-08, MCP-09, MCP-10
**Success Criteria** (what must be TRUE):
  1. `reconftw mcp serve --transport stdio` starts an MCP server speaking the standard protocol; `reconftw mcp serve --transport http --port N` exposes the same server over HTTP/SSE; an MCP client (e.g., Claude Desktop or `mcp-cli`) can connect and list tools (MCP-01)
  2. The server exposes recon capabilities as MCP tools: `recon`, `subs`, `web`, `vulns`, `osint`, `monitor`, `report`; calling each MCP tool invokes the corresponding internal handler (same code path as the CLI subcommand) and respects the global scheduler — MCP requests cannot exceed `PARALLEL_MAX_JOBS` (MCP-02, MCP-05)
  3. Authentication is enforced: API key required (TOML `mcp.api_key` or env `RECONFTW_MCP_API_KEY`); all credentials pass through the FOUND-02 redactor in any log line emitted by the MCP server; per-target scope passed at MCP session start is fixed for the session and cannot be widened by tool arguments (MCP-04, MCP-10)
  4. Streaming + schema work: MCP clients can subscribe to findings via MCP resource subscription during long scans (live JSONL feed); findings use the same SARIF-compatible schema as Phase 10's REPORT-07 output; an OpenAPI schema is published for the HTTP transport endpoints (MCP-03, MCP-06, MCP-08)
  5. Opt-in + docs: `mcp.enabled = false` is the default in the TOML config (MCP is opt-in at config time); `docs/mcp.md` exists with agent integration example, supported tools list, rate-limit guidance, and security considerations (MCP-07, MCP-09)
**Plans**: TBD

### Phase 9: Composite Modes
**Goal**: Ship the composite workflow modes (`recon`, `all`, `passive`, `zen`, `deep`, `quick-rescan`, `refresh-cache`, `gen-resolvers`) that orchestrate Phases 4-7 module pipelines — plus v1 short-flag aliases with deprecation warnings to ease v1 user migration.
**Depends on**: Phases 4, 5, 6, 7 (composes their pipelines)
**Requirements**: MODE-01, MODE-02, MODE-03, MODE-04, MODE-05, MODE-06, MODE-07, MODE-08, MODE-09, MODE-10, MODE-11, MODE-12
**Success Criteria** (what must be TRUE):
  1. Running `reconftw recon --target hackerone.com` runs passive subs → web probe → web analysis → OSINT (skipping vulns) and produces the expected artefact set; `reconftw all --target X` runs everything (recon + vulns); `reconftw passive --target X` runs passive-only sources with NO active probing of the target (verified by network-test); `--zen` activates the stealth profile (lower rate limits, opsec defaults); `--deep` enables extended brute force + permutations (MODE-01, MODE-02, MODE-03, MODE-04, MODE-05)
  2. Stateful modes work: `reconftw quick-rescan --target X` reads previous workspace state, runs an incremental diff vs last full scan, and reports new artefacts only; `reconftw refresh-cache --target X` refreshes DNS/ASN/geo cached data; `reconftw gen-resolvers` regenerates the DNS resolver list via dnsvalidator (MODE-06, MODE-07, MODE-08)
  3. V1 long-flag aliases preserved: `--recon`/`--all`/`--passive`/`--subdomains`/`--web`/`--vulns`/`--osint` all work and print a one-line "deprecated: use `reconftw <subcommand>` instead — will be removed in v2.2" warning to stderr; v1 short flags (`-r`, `-s`, `-p`, `-a`, `-d`, `-l`) behave the same way (MODE-09)
  4. Universal CLI surface works across all modes: `--target X` for single target, `--list FILE` for multi-target batch (one per line), `--config FILE` overrides the default `reconftw.toml` location, `--dry-run` shows what would execute (subprocess invocations printed but not run) (MODE-10, MODE-11, MODE-12)
  5. CLI deprecation warnings tested: a unit test asserts every deprecated v1 alias prints the warning to stderr exactly once per invocation; a unit test asserts the warning text references the replacement subcommand and the removal version (MODE-09)
**Plans**: TBD

### Phase 10: Monitor Mode + Reporting + Notifications
**Goal**: Ship the long-running monitor loop with diff detection + incremental re-runs + notification triggers; the full reporting suite (JSON/HTML/CSV/AI/Faraday/hotlist/SARIF); and consolidate Slack/Telegram/Discord notifications with secret redaction guarantees — the findings data model and dedup-ready storage are now stable, so monitor + reporting + notification consolidation all happen together.
**Depends on**: Phases 4, 5, 6, 7, 9 (needs all module pipelines + composite modes to monitor and report on)
**Requirements**: MON-01, MON-02, MON-03, MON-04, MON-05, MON-06, MON-07, MON-08, REPORT-01, REPORT-02, REPORT-03, REPORT-04, REPORT-05, REPORT-06, REPORT-07, REPORT-08, REPORT-09, NOTIF-01, NOTIF-02, NOTIF-03, NOTIF-04, NOTIF-05, NOTIF-06, NOTIF-07
**Success Criteria** (what must be TRUE):
  1. Monitor loop works: `reconftw monitor --target X --interval 6h` runs scans on the configured interval indefinitely; `--monitor-cycles N` runs N cycles then exits; each cycle compares findings against the last cycle's baseline (stored in `state.db`); `--incremental` re-runs only functions affected by detected deltas; SIGINT mid-cycle completes the current task, writes checkpoint, exits clean; long-running mode respects `OUTPUT_VERBOSITY=0/1/2` for log volume control (MON-01, MON-02, MON-03, MON-04, MON-07, MON-08)
  2. Findings dedup + notification triggers work: dedup across monitor cycles uses `artefacts/findings.jsonl` history with content hash; new findings trigger notifications via configured Notifier(s); a unit test asserts that re-running the same scan does NOT trigger notifications for unchanged findings (MON-05, MON-06)
  3. Full reporting suite ships: canonical artefacts written as JSONL (`subdomains.jsonl`/`hosts.jsonl`/`urls.jsonl`/`findings.jsonl`/`notes.jsonl`); HTML report (`reports/report.html`) renders findings with no JS dependencies required AND all user-controlled values HTML-escaped (XSS in the report cannot be triggered by malicious tool output); CSV exports per category for spreadsheet workflows; reports rebuilt deterministically from `artefacts/` via `reconftw report` subcommand WITHOUT re-running scans; reports include workspace metadata (target, start/end time, config snapshot, tool versions used) (REPORT-01, REPORT-02, REPORT-03, REPORT-08, REPORT-09)
  4. AI/security-platform/SARIF outputs ship: AI report (opt-in via `AI_REPORT=true` + `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) — all PII/secrets pass through the redactor before the API call; Faraday-compatible JSON export for security platform integration; risk-scored hotlist `reports/hotlist.json` (top N by severity × confidence × asset criticality); SARIF output `reports/findings.sarif` for CodeQL/GitHub Code Scanning consumption (REPORT-04, REPORT-05, REPORT-06, REPORT-07)
  5. Notifications consolidated: Slack/Telegram/Discord notifications work with FOUND-02-grade redaction (secret tagging in the type system means NO opt-in raw mode — secrets cannot reach a notifier unredacted by API design); per-event rules configurable in TOML (`notifications.events = ["on-critical-finding", "on-scan-complete", "on-failure"]`); per-channel rate limit prevents flooding on critical-finding burst; `reconftw notify --test` validates each configured channel reachable (NOTIF-01, NOTIF-02, NOTIF-03, NOTIF-04, NOTIF-05, NOTIF-06, NOTIF-07)
**Plans**: TBD
**UI hint**: yes

### Phase 11: Installer + Cross-Platform + Docker
**Goal**: Replace `install.sh` with a `reconftw install` subcommand reading from a `tools.lock` manifest pinning all 70+ orchestrated tools with SHA-256 verification; support Linux (Debian/Ubuntu/RHEL/Arch — glibc + musl + ARM64) + macOS (Apple Silicon + Intel) with signed/notarized binaries; ship updated multi-arch Docker image — the packaging story is the single clearest win of the rewrite, so it ships as one phase.
**Depends on**: Phases 4, 5, 6, 7 (need stable subprocess + AppContext + binary to install); calendar-parallel-capable with Phase 9/10
**Requirements**: INST-01, INST-02, INST-03, INST-04, INST-05, INST-06, INST-07, INST-08, INST-09, INST-10, INST-11, INST-12, XPLAT-01, XPLAT-02, XPLAT-03, XPLAT-04, XPLAT-05, XPLAT-06, XPLAT-07, XPLAT-08, XPLAT-09, DOCK-01, DOCK-02, DOCK-03, DOCK-04, DOCK-05, DOCK-06, DOCK-07, XCUT-08
**Success Criteria** (what must be TRUE):
  1. `reconftw install` runs end-to-end on a clean machine: reads `tools.lock` (pins ALL 70+ orchestrated tools — Go tools by `module@version`, Python tools by name+version, system deps by name); installs Go tools via `go install <module>@<version>`, Python tools via `uv tool install <package>==<version>` with per-tool isolation, system deps via platform-appropriate package manager (apt/yum/dnf/pacman/brew); the installer is idempotent (re-running installs only missing/outdated tools), fails fast with a clear error on unsupported platform, and never leaves partial-install state behind (INST-01, INST-02, INST-06, INST-07, INST-08, INST-11, INST-12)
  2. Supply-chain hygiene: SHA-256 verification on installer bootstrappers (rustup-init.sh, uv installer) against pinned hashes; SHA-256 verification on pre-built tool binaries where vendor publishes hashes; Rust toolchain bootstrap (only if `smugglex` or other Rust deps enabled) via verified rustup-init; CI verifies pins on update; 24-72h quarantine window for new tool versions before lockfile bump (documented in the lockfile update workflow) (INST-03, INST-04, INST-09, XCUT-08)
  3. Platform detection + health check: installer correctly detects Debian/Ubuntu (apt), RHEL/Fedora/CentOS (yum/dnf), Arch (pacman), macOS Intel (brew), macOS Apple Silicon (brew arm64); post-install `reconftw install --health-check` verifies every tool present on PATH and runnable (`--version` or equivalent) — and CI matrix runs install + smoke on every supported platform on every PR (INST-05, INST-10, XPLAT-05)
  4. Cross-platform binaries: Linux glibc (Debian 12+, Ubuntu 24.04+, RHEL/Rocky 9+, Arch rolling), Linux musl (Alpine 3.20+ — static binary), macOS arm64 (primary), macOS amd64, ARM64 Linux (cloud / Raspberry Pi) all build + run with passing smoke test; macOS binary is signed with developer ID + notarized via Apple notarization service in CI from day 1; Homebrew tap published for `brew install reconftw`; Linux distribution offers standalone binary + tar.gz + optional `.deb`/`.rpm` packages (XPLAT-01, XPLAT-02, XPLAT-03, XPLAT-04, XPLAT-06, XPLAT-07, XPLAT-08, XPLAT-09)
  5. Docker image ships: Dockerfile updated with new binary baked in; base image (distroless or minimal Ubuntu) chosen to minimize size — documented in `Docker/README.md`; multi-arch build (amd64 + arm64) via `docker buildx`; all 70+ orchestrated tools available in the image (installer runs at build time); image published to `ghcr.io/six2dez/reconftw` on every release, tagged with semantic version + `latest` + git SHA; image runs as non-root user with selective elevation where required for raw sockets (DOCK-01, DOCK-02, DOCK-03, DOCK-04, DOCK-05, DOCK-06, DOCK-07)
**Plans**: TBD

### Phase 12: Cutover & Migration
**Goal**: Replace bash `main` with `rewrite/v2` via a corpus-tested config migrator (`reconftw.cfg` → TOML), a 1-2-month beta period with community feedback, an automated bug-bug parity test against canonical targets, MIGRATION.md, a 6-month compat-symlink window for `Recon/<domain>/`, and explicit sign-off criteria — cutover is BLOCKED until CUT-04 passes and CUT-12 sign-off is met.
**Depends on**: Phases 9, 10, 11 (need composite modes, monitor+reporting+notifications, installer/xplat/docker all green before cutover can start)
**Requirements**: CUT-01, CUT-02, CUT-03, CUT-04, CUT-05, CUT-06, CUT-07, CUT-08, CUT-09, CUT-10, CUT-11, CUT-12, CUT-13, CUT-14, CUT-15, XCUT-01, XCUT-03, XCUT-05, XCUT-06
**Success Criteria** (what must be TRUE):
  1. Config migrator works against the corpus and BLOCKS cutover otherwise: `reconftw migrate --from-bash <reconftw.cfg> --to <reconftw.toml>` reads v1 bash config line-by-line and emits TOML equivalent; the migrator handles arithmetic expressions (`$(nproc) * 5`), duration strings (`6h`), quoted values, and array-like lists explicitly; tested against a corpus of 20+ real-world `reconftw.cfg` files collected from GitHub issues and user contributions, ALL 20+ corpus configs migrate without errors; `--dry-run` shows preview of mapping decisions; unknown config keys produce LOUD warnings (`⚠ unknown key X — needs human review`) and are NEVER silently dropped; CUT-04 explicitly gates cutover — v2.0 cannot ship if the migrator doesn't cover the corpus (CUT-01, CUT-02, CUT-03, CUT-04, CUT-05, CUT-06)
  2. Beta period + parity test gate cutover: `reconftw v2-beta` binary distributed for 1-2 months PRIOR to cutover with existing users opting in; GitHub Issues template `v2-beta-feedback` exists and monthly issue triage happens; bug-bug parity test runs full bash v1 + v2 side-by-side against 3-5 canonical targets (e.g., `hackerone.com`, `tesla.com`, controlled lab) with automated diff comparing structured outputs — equivalence within noise tolerance (timing, ordering) is green; cutover sign-off criteria documented and met: (a) CUT-03 migrator corpus passes, (b) CUT-11 parity test green, (c) beta period clean of P0/P1 issues, (d) community survey or GitHub Discussions thread reaches sign-off threshold (CUT-09, CUT-10, CUT-11, CUT-12)
  3. Performance + coverage gates met: v2 throughput within 10% of bash v1 on canonical benchmark (full scan of a 1000-subdomain target on 8-core / 16GB host); feature-parity coverage of v1's 351 bats test scenarios mapped to v2 tests; branch coverage ≥75% on lib code AND ≥90% on critical paths (scheduler, scope filter, checkpoint, secret redaction); XCUT-01 and XCUT-03 baselines from Foundation are validated and locked in here (XCUT-01, XCUT-03)
  4. Migration documentation + compat ships: MIGRATION.md documents every breaking change (CLI flag changes, output tree changes, config key renames, default behavior changes) with before/after examples; zero silent breakages — all behavior changes appear in MIGRATION.md; compat symlink writer maintains `Recon/<domain>/` populated with bash-shape filenames for 6 months post-cutover (then dropped per documented timeline); v1 → v2 rollback path documented: if v2 has a critical issue in production, users can revert to v1 binary via a documented procedure; v1 deprecation timeline: bash `main` becomes `archive/v1.x` branch frozen for 12 months post-cutover with security-critical bugfixes only; README rewrite + GitHub release notes + social announcement on user comms channels; godoc/sphinx API docs auto-generated; INSTALL.md updated; CONTRIBUTING.md updated for new contributors (CUT-07, CUT-08, CUT-13, CUT-14, CUT-15, XCUT-05, XCUT-06)
  5. Cutover lands: `main` branch now points to v2; the `rewrite/v2` long-running branch is merged or fast-forwarded; the milestone `complete-milestone` ceremony has run; PROJECT.md "What This Is" + "Current Milestone" reflect post-cutover reality; STATE.md reports milestone v2.0 status `complete`
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12

Calendar parallelization (within constraint that dependencies are met):
- Phase 7 (OSINT) can run calendar-parallel with Phase 6 (Vulns) — both depend on Phase 5 only
- Phase 8 (MCP) can run calendar-parallel with Phases 5/6/7 — depends on Phase 3 only
- Phase 11 (Installer/XPlat/Docker) can run calendar-parallel with Phases 9/10 once Phases 4-7 are done

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Language ADR & Spike | 4/5 | In Progress|  |
| 2. Architecture v2 Design | 0/? | Not started | - |
| 3. Foundation Kernel | 0/? | Not started | - |
| 4. Subdomains E2E + Axiom Integration | 0/? | Not started | - |
| 5. Web Pipeline E2E | 0/? | Not started | - |
| 6. Vulnerability Scanning E2E | 0/? | Not started | - |
| 7. OSINT E2E | 0/? | Not started | - |
| 8. MCP Server | 0/? | Not started | - |
| 9. Composite Modes | 0/? | Not started | - |
| 10. Monitor Mode + Reporting + Notifications | 0/? | Not started | - |
| 11. Installer + Cross-Platform + Docker | 0/? | Not started | - |
| 12. Cutover & Migration | 0/? | Not started | - |

## Coverage

**v2.0 requirements:** 197 total, 197 mapped (100%)

| Requirement | Phase |
|-------------|-------|
| DEC-01 | Phase 1 |
| DEC-02 | Phase 1 |
| DEC-03 | Phase 1 |
| DEC-04 | Phase 1 |
| DEC-05 | Phase 1 |
| ARCH-01 | Phase 2 |
| ARCH-02 | Phase 2 |
| ARCH-03 | Phase 2 |
| ARCH-04 | Phase 2 |
| ARCH-05 | Phase 2 |
| ARCH-06 | Phase 2 |
| ARCH-07 | Phase 2 |
| ARCH-08 | Phase 2 |
| ARCH-09 | Phase 2 |
| ARCH-10 | Phase 2 |
| ARCH-11 | Phase 2 |
| ARCH-12 | Phase 2 |
| FOUND-01 | Phase 3 |
| FOUND-02 | Phase 3 |
| FOUND-03 | Phase 3 |
| FOUND-04 | Phase 3 |
| FOUND-05 | Phase 3 |
| FOUND-06 | Phase 3 |
| FOUND-07 | Phase 3 |
| FOUND-08 | Phase 3 |
| FOUND-09 | Phase 3 |
| FOUND-10 | Phase 3 |
| FOUND-11 | Phase 3 |
| FOUND-12 | Phase 3 |
| FOUND-13 | Phase 3 |
| FOUND-14 | Phase 3 |
| FOUND-15 | Phase 3 |
| FOUND-16 | Phase 3 |
| SUBD-01 | Phase 4 |
| SUBD-02 | Phase 4 |
| SUBD-03 | Phase 4 |
| SUBD-04 | Phase 4 |
| SUBD-05 | Phase 4 |
| SUBD-06 | Phase 4 |
| SUBD-07 | Phase 4 |
| SUBD-08 | Phase 4 |
| SUBD-09 | Phase 4 |
| SUBD-10 | Phase 4 |
| SUBD-11 | Phase 4 |
| AXIOM-01 | Phase 4 |
| AXIOM-02 | Phase 4 |
| AXIOM-03 | Phase 4 |
| AXIOM-04 | Phase 4 |
| AXIOM-05 | Phase 4 |
| AXIOM-06 | Phase 4 |
| AXIOM-07 | Phase 4 |
| AXIOM-08 | Phase 4 |
| AXIOM-09 | Phase 4 |
| WEB-01 | Phase 5 |
| WEB-02 | Phase 5 |
| WEB-03 | Phase 5 |
| WEB-04 | Phase 5 |
| WEB-05 | Phase 5 |
| WEB-06 | Phase 5 |
| WEB-07 | Phase 5 |
| WEB-08 | Phase 5 |
| WEB-09 | Phase 5 |
| WEB-10 | Phase 5 |
| WEB-11 | Phase 5 |
| WEB-12 | Phase 5 |
| WEB-13 | Phase 5 |
| WEB-14 | Phase 5 |
| WEB-15 | Phase 5 |
| WEB-16 | Phase 5 |
| VULN-01 | Phase 6 |
| VULN-02 | Phase 6 |
| VULN-03 | Phase 6 |
| VULN-04 | Phase 6 |
| VULN-05 | Phase 6 |
| VULN-06 | Phase 6 |
| VULN-07 | Phase 6 |
| VULN-08 | Phase 6 |
| VULN-09 | Phase 6 |
| VULN-10 | Phase 6 |
| VULN-11 | Phase 6 |
| VULN-12 | Phase 6 |
| VULN-13 | Phase 6 |
| VULN-14 | Phase 6 |
| OSINT-01 | Phase 7 |
| OSINT-02 | Phase 7 |
| OSINT-03 | Phase 7 |
| OSINT-04 | Phase 7 |
| OSINT-05 | Phase 7 |
| OSINT-06 | Phase 7 |
| OSINT-07 | Phase 7 |
| OSINT-08 | Phase 7 |
| OSINT-09 | Phase 7 |
| OSINT-10 | Phase 7 |
| OSINT-11 | Phase 7 |
| OSINT-12 | Phase 7 |
| OSINT-13 | Phase 7 |
| OSINT-14 | Phase 7 |
| OSINT-15 | Phase 7 |
| OSINT-16 | Phase 7 |
| MCP-01 | Phase 8 |
| MCP-02 | Phase 8 |
| MCP-03 | Phase 8 |
| MCP-04 | Phase 8 |
| MCP-05 | Phase 8 |
| MCP-06 | Phase 8 |
| MCP-07 | Phase 8 |
| MCP-08 | Phase 8 |
| MCP-09 | Phase 8 |
| MCP-10 | Phase 8 |
| MODE-01 | Phase 9 |
| MODE-02 | Phase 9 |
| MODE-03 | Phase 9 |
| MODE-04 | Phase 9 |
| MODE-05 | Phase 9 |
| MODE-06 | Phase 9 |
| MODE-07 | Phase 9 |
| MODE-08 | Phase 9 |
| MODE-09 | Phase 9 |
| MODE-10 | Phase 9 |
| MODE-11 | Phase 9 |
| MODE-12 | Phase 9 |
| MON-01 | Phase 10 |
| MON-02 | Phase 10 |
| MON-03 | Phase 10 |
| MON-04 | Phase 10 |
| MON-05 | Phase 10 |
| MON-06 | Phase 10 |
| MON-07 | Phase 10 |
| MON-08 | Phase 10 |
| REPORT-01 | Phase 10 |
| REPORT-02 | Phase 10 |
| REPORT-03 | Phase 10 |
| REPORT-04 | Phase 10 |
| REPORT-05 | Phase 10 |
| REPORT-06 | Phase 10 |
| REPORT-07 | Phase 10 |
| REPORT-08 | Phase 10 |
| REPORT-09 | Phase 10 |
| NOTIF-01 | Phase 10 |
| NOTIF-02 | Phase 10 |
| NOTIF-03 | Phase 10 |
| NOTIF-04 | Phase 10 |
| NOTIF-05 | Phase 10 |
| NOTIF-06 | Phase 10 |
| NOTIF-07 | Phase 10 |
| INST-01 | Phase 11 |
| INST-02 | Phase 11 |
| INST-03 | Phase 11 |
| INST-04 | Phase 11 |
| INST-05 | Phase 11 |
| INST-06 | Phase 11 |
| INST-07 | Phase 11 |
| INST-08 | Phase 11 |
| INST-09 | Phase 11 |
| INST-10 | Phase 11 |
| INST-11 | Phase 11 |
| INST-12 | Phase 11 |
| XPLAT-01 | Phase 11 |
| XPLAT-02 | Phase 11 |
| XPLAT-03 | Phase 11 |
| XPLAT-04 | Phase 11 |
| XPLAT-05 | Phase 11 |
| XPLAT-06 | Phase 11 |
| XPLAT-07 | Phase 11 |
| XPLAT-08 | Phase 11 |
| XPLAT-09 | Phase 11 |
| DOCK-01 | Phase 11 |
| DOCK-02 | Phase 11 |
| DOCK-03 | Phase 11 |
| DOCK-04 | Phase 11 |
| DOCK-05 | Phase 11 |
| DOCK-06 | Phase 11 |
| DOCK-07 | Phase 11 |
| CUT-01 | Phase 12 |
| CUT-02 | Phase 12 |
| CUT-03 | Phase 12 |
| CUT-04 | Phase 12 |
| CUT-05 | Phase 12 |
| CUT-06 | Phase 12 |
| CUT-07 | Phase 12 |
| CUT-08 | Phase 12 |
| CUT-09 | Phase 12 |
| CUT-10 | Phase 12 |
| CUT-11 | Phase 12 |
| CUT-12 | Phase 12 |
| CUT-13 | Phase 12 |
| CUT-14 | Phase 12 |
| CUT-15 | Phase 12 |
| XCUT-01 | Phase 12 |
| XCUT-02 | Phase 3 |
| XCUT-03 | Phase 12 |
| XCUT-04 | Phase 3 |
| XCUT-05 | Phase 12 |
| XCUT-06 | Phase 12 |
| XCUT-07 | Phase 3 |
| XCUT-08 | Phase 11 |
| XCUT-09 | Phase 3 |

**Cross-cutting placement rationale:**
- **XCUT-01** (perf benchmark) → Phase 12 (final assertion); baseline established Phase 3, validated per-module phase
- **XCUT-02** (resource budget Go <50MB OR Python <500MB) → Phase 3 (locked at Foundation)
- **XCUT-03** (test coverage ≥75% lib, ≥90% critical paths) → Phase 12 (final validation); gate set up Phase 3
- **XCUT-04** (CI policy race detector + mypy + coverage gate) → Phase 3 (set up at Foundation, runs every phase)
- **XCUT-05** (zero silent breakages → MIGRATION.md) → Phase 12 (MIGRATION.md is the artifact)
- **XCUT-06** (docs: README + INSTALL.md + CONTRIBUTING.md + auto-gen API docs) → Phase 12 (final docs)
- **XCUT-07** (logging hygiene — no secrets in logs) → Phase 3 (FOUND-02 + lint rule; tested every phase)
- **XCUT-08** (supply chain tools.lock) → Phase 11 (where INST-02/03/04 live)
- **XCUT-09** (observability heartbeat) → Phase 3 (scheduler emits heartbeats; tested every phase)

---
*Roadmap created: 2026-05-27*
*Total v2.0 requirements: 197 across 12 phases (100% coverage). Granularity: coarse. Parallelization: yes (within constraints).*
