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
10. **Cutover LAST (Phase 14)** — CUT-04 explicitly blocks cutover until migrator corpus test passes. CUT-11 parity + CUT-12 sign-off close the milestone.

**Parallelization within phases:** Plans inside a phase can execute concurrently where independent (per `config.json:parallelization=true`). Granularity is **coarse** — broader phases consistent with single-maintainer cadence.

**Total v2.0 requirements:** 197 REQ-IDs across 17 deliverables (16 PROJECT.md + MCP). All mapped below; 100% coverage.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Language ADR & Spike** — Identical recon slice in BOTH Go and Python; measured comparison; signed ADR before any production code
- [x] **Phase 2: Architecture v2 Design** — Lock TOML schema, output tree, Task/Backend/AppContext/Error interfaces, CLI surface, test policy, failure isolation — Foundation depends on these (completed 2026-05-28)
- [x] **Phase 3: Foundation Kernel** — Errors + Logger + Config + OutputTree + Checkpoint + Scheduler + Tools + AppContext + CLI + Mocks + CI from day 1 (completed 2026-05-28)
- [ ] **Phase 4: Subdomains E2E + Axiom Integration** — Canonical reference port; passive+brute+permut+dnsx+scope+takeover+buckets+geo+ASN with Axiom distributed execution; output-equivalence test gates phase end (gap closure in progress)
- [x] **Phase 5: Web Pipeline E2E** — Probe + screenshots + fuzz + JS + nuclei + WAF + sourcemaps + favicon + CSP + vhost + 4xx-bypass + URL discovery + 20-function surface with parity test (completed 2026-06-03)
- [x] **Phase 6: Vulnerability Scanning E2E** — XSS + SQLi + SSRF + LFI + SSTI + CRLF + smuggling + cmdi + nuclei-DAST + cache poisoning + gf patterns + 4xx-bypass (completed 2026-06-09)
- [x] **Phase 7: OSINT E2E** — Domain/IP info + emails + GitHub dorks/leaks/actions + cloud enum + Postman + Swagger + Spoofy + msftrecon + CMSeeK + GraphQL + Google dorks *(9/9 plans: 7 original + 07-08/07-09 gap-closure; DoD-2 accepted; all 3 code-review gaps closed + re-verified passed 2026-06-10)*
- [ ] **Phase 8: MCP Server** — Model Context Protocol server exposing recon modes as MCP tools; auth + redaction + scope sandboxing + OpenAPI schema; opt-in in config
- [x] **Phase 9: Composite Modes** — `recon`, `all`, `passive`, `zen`, `deep`, `quick-rescan`, `refresh-cache`, `gen-resolvers` + v1 short-flag aliases with deprecation warnings (completed 2026-06-11)
- [x] **Phase 10: Monitor Mode + Reporting + Notifications** — Monitor loop + diff detection + incremental + JSON/HTML/CSV/AI/Faraday/hotlist/SARIF reports + Slack/Telegram/Discord notifications consolidated (completed 2026-06-12)
- [ ] **Phase 11: Installer + Cross-Platform + Docker** — `reconftw install` (replaces install.sh) + tools.lock for 70+ tools + SHA-256 verification + Linux/macOS/ARM64 + Docker multi-arch
- [ ] **Phase 12: Integration Hardening** — Wire subsystems end-to-end: store ingest (done) + in-scan notifications + resume/checkpoint + monitor diff + global rate limiter + AI/Ollama
- [ ] **Phase 13: Domain Parity** — Close bash-vs-Go gaps: subs (PTR/hakip2host/dnsregs/csprecon/dsieve) + vulns (spraying/SSRF-OOB) + osint (LeakSearch/Scopify/repo-secrets) + web (portscan/nerva/wordlists/url_ext)
- [ ] **Phase 14: Cutover & Migration** — Config migrator (corpus-tested) + MIGRATION.md + compat symlinks + beta period + bug-bug parity test + community sign-off + `main`→Go, bash→legacy branch

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

**Plans**: 9 plans (7 executed + 2 gap-closure)
Plans:

- [x] 02-01-PLAN.md — ADR skeleton + verify-0002.sh + interfaces_check/
- [x] 02-02-PLAN.md — §2 TOML Configuration Schema (all v1 flags, [legacy] aliases, per-key validation)
- [x] 02-03-PLAN.md — §3 Output Tree Layout + §4 Compat Symlink Layer
- [x] 02-04-PLAN.md — §5 Interface Signatures + §6 Error Class Hierarchy + §7 Failure Policy
- [x] 02-05-PLAN.md — §8 CLI Surface + §9 Test Ring Policy + §10 Logging Policy
- [x] 02-06-PLAN.md — Integration pass: §1 Overview + TL;DR + Glossary + Consequences
- [x] 02-07-PLAN.md — Pre-sign gate + sign-off ceremony (checkpoint: autonomous: false)

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

**Plans**: 7 plans (split from initial 6 per revision iter 1, Blockers 2 + 3)
Plans:
**Wave 1**

- [x] 03-01-PLAN.md — Errors + Logger + Secret + Redactor + scaffold internal/core/ + CI seed + spike/python/ cleanup

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 03-02-PLAN.md — Config loader (koanf 8-source) + per-key validation + snapshot writer

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 03-03-PLAN.md — Output tree (AtomicWriter) + Checkpoint store (modernc/sqlite WAL) + CompatWriter skeleton + interface introductions (W15) + snapshot migration (W19) + per-file 90% coverage (W20)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 03-04-PLAN.md — Backend interface + LocalBackend (kill-tree) + AxiomBackend stub + ToolRegistry (with Critical tier per Blocker 5) + RateLimiter + FOUND-10 lint rule (AST scan per Blocker 8). Scheduler moved to Plan 05.

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 03-05-PLAN.md — Task interface (final, no placeholders per Blocker 4) + Scheduler (moved from old Plan 04) + AppContext + UI (dot-fill + lib/ui.sh behavior map per W13) + Notifier stubs + noop.demo

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 03-06-PLAN.md — CLI binary (cmd/reconftw: 15 subcommands + v1 aliases + version + health-check + hidden kernel-demo per W16) + parseEarlyFlags (W14) + Makefile XCUT-02 ldflags

**Wave 7** *(blocked on Wave 6 completion)*

- [x] 03-07-PLAN.md — Test mocks (FOUND-15) + tools.lock seed (10 Phase 4 tools, 3 critical per Blocker 5) + integration smoke + XCUT-02 binary-size gate + Phase 3 acceptance + interfaces_check real-import upgrade

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

**Plans**: 12 plans (8 original + 4 gap-closure plans 04-08..04-11)
Plans:
**Wave 0** *(new — kernel-contract foundations before any Task code)*

- [x] 04-00-PLAN.md — Missing config fields (MinResolvers/MinFreeMemGB/FailoverThreshold) + Tool.InputFlag + tools.lock to 25 + staging contract doc

**Wave 1** *(blocked on Wave 0)*

- [x] 04-01-PLAN.md — Demo scaffold delete + JSONL schemas + MergeStage helper + 6 passive Tasks (staging files) + SUBD-05 scope cross-check

**Wave 2** *(parallel — blocked on Wave 1)*

- [x] 04-02-PLAN.md — Active DNS resolution Tasks + SubBruteTask with in-Run() resolver gate + extend MergeStage for resolved stage
- [x] 04-03-PLAN.md — Shared extractor packages (favicon/JS/analytics) + SubScrapingTask/Analytics/NSDelegation (staging files + temp-file subjs→jsluice)

**Wave 3** *(blocked on Wave 2)*

- [x] 04-04-PLAN.md — Permutation Tasks with gopsutil OS memory back-pressure (not runtime.ReadMemStats) + SubRecursivePassive/Brute

**Wave 4** *(blocked on Wave 3)*

- [x] 04-05-PLAN.md — Takeover + Buckets + ASN + Geo (real City+ASN via ipinfo) + ZoneTransfer (in-Run gate)

**Wave 5** *(blocked on Wave 4 — depends on 04-05's enrichment Task registrations)*

- [x] 04-06-PLAN.md — Real AxiomBackend (Tool.InputFlag split) + FailoverBackend (safe Stream) + sequential 5-stage RunStage + filterByModuleAndEnabled

**Wave 6** *(blocked on Wave 5)*

- [x] 04-07-PLAN.md — Frozen-replay parity harness (real v1-captured fixtures) + AXIOM-09 equivalence test + phase acceptance checkpoint

**Gap Closure Wave 1**

- [x] 04-08-PLAN.md — GAP-1: crt arg fix (positional) + full real-tool arg audit across all 10 stage files (per-tool grep acceptance criteria) + tagged smoke test (realtools build tag)

**Gap Closure Wave 2** *(blocked on 04-08)*

- [x] 04-09-PLAN.md — GAP-2: passive stage best_effort policy (subdomains.passive module name) + ScopeError re-propagation via errors.Is(err, coreerrors.ErrScope) + TestPassiveSoftFail; owns the stageSpec.module struct change in stub_subcommands.go

**Gap Closure Wave 3** *(blocked on 04-09 — shares stub_subcommands.go, sequenced after 04-09's stageSpec change)*

- [x] 04-10-PLAN.md — GAP-3: StageProgress UI infrastructure (internal/core/ui/progress.go, unexported test hooks only) + wire subs pipeline around the existing RunStage loop (does not touch stageSpec)

**Gap Closure Wave 4** *(blocked on 04-08 + 04-09 + 04-10 — human gate)*

- [ ] 04-11-PLAN.md — Live parity sign-off re-attempt: bash v1 vs Go v2 ±5% per-category on hackerone.com + tesla.com (autonomous: false)

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

**Plans**: 10 plans (7 original + 3 gap-closure plans 05-09..05-11)
Plans:
**Wave 1**

- [x] 05-01-PLAN.md — Housekeeping (WEB-02 stale text fix) + web package scaffold + HTTPXTask (DAG root) + tools.lock 17 new entries + web subcommand RunE wiring

**Wave 2** *(parallel — blocked on Wave 1)*

- [x] 05-02-PLAN.md — NucleiTask (WEB-06) + ScreenshotTask (WEB-02; nuclei-headless) + FfufTask (WEB-03)
- [x] 05-03-PLAN.md — Infra Tasks (WEB-07/08/09/10/11): wafw00f/cdncheck/hakoriginfinder/csprecon/favirecon/VhostFinder + extractor siblings waf/csp/favicon.ExtractWeb
- [x] 05-04-PLAN.md — URL discovery (WEB-14): katana/urlfinder/waymore/urldedup + JS Tasks (WEB-04/05): subjs/jsluice/mantra/JSA/sourcemapper + extractor extensions js/secrets/urls/sourcemap

**Wave 3** *(blocked on Wave 2)*

- [x] 05-05-PLAN.md — Bypass + param: nomore403 (WEB-12) + shortscan (WEB-13) + Gxss/arjun (WEB-15)

**Wave 4** *(blocked on Wave 3)*

- [x] 05-06-PLAN.md — Frozen-replay parity harness (D-W7) + fixtures + DoD-1 smoke test all 23 tools (D-W9)

**Wave 5** *(blocked on Wave 4 — human gate)*

- [x] 05-07-PLAN.md — DoD-2 seeded-local E2E run + fixture population + VPS/Axiom parity sign-off (autonomous: false)

**Gap Closure Wave 1** *(independent — run after 05-07 or in parallel with open waves)*

- [x] 05-09-PLAN.md — TDD RED→GREEN: multi-writer test + staging contract (CR-01/CR-02/CR-05/WR-01/WR-03-jsa-fanout/WR-03-shortscan-fallback); go test ./... GREEN at wave end

**Gap Closure Wave 2** *(blocked on 05-09)*

- [x] 05-10-PLAN.md — Stage ordering: split 4 stages into 8; wire per-stage MergeStage calls (CR-04)

**Gap Closure Wave 3** *(blocked on 05-09 + 05-10)*

- [x] 05-11-PLAN.md — Localized fixes + behavioral tests: CR-03 jsa (direct exec + TestJSAUsesDirectExec), CR-06 hakoriginfinder (TestHakoriginfinderPerHostAttribution), CR-07 timeouts, WR-02..WR-09 (incl. checkHostsFileReadable rename), IN-01, IN-02

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

**Plans**: 10 plans
Plans:
**Wave 1**

- [x] 06-01-PLAN.md — vulns package scaffold + GFTask (gf-classify DAG root, D-V4/D-V5) + findings schema extension + tools.lock 18 vuln tools + newVulnsCmd RunE wire

**Wave 2** *(parallel — blocked on Wave 1)*

- [x] 06-02-PLAN.md — XSSTask (dalfox+Gxss, VULN-01) + CRLFTask (crlfuzz, VULN-06)
- [x] 06-03-PLAN.md — SQLiTask dual-engine sqlmap+ghauri (VULN-02) + CMDITask commix (VULN-08)
- [x] 06-04-PLAN.md — LFITask ffuf+lfi_wordlist (VULN-04) + SSTITask TInjA/SSTImap engine switch (VULN-05)
- [x] 06-05-PLAN.md — SSRFTask qsreplace+ffuf + interactsh-client per-task OOB session (VULN-03)

**Wave 3** *(parallel — blocked on Wave 2)*

- [x] 06-06-PLAN.md — SmugglingTask smugglex (VULN-07) + WebCacheTask WCVS+toxicache (VULN-09) + SecondOrderTask (VULN-12)
- [x] 06-07-PLAN.md — NucleiDASTTask -duc heartbeat (VULN-11) + FuzzparamsTask + Bypass4xxTask nomore403 (VULN-13)
- [x] 06-08-PLAN.md — D-V3 orphans: GraphQLTask + GRPCTask + LLMTask + WebsocketTask + TestSSLTask + FrayTask

**Wave 4** *(blocked on Wave 3)*

- [x] 06-09-PLAN.md — dag_test.go cycle guard + frozen-replay parity harness + DoD-1 realtools smoke 18 tools (VULN-14)

**Wave 5** *(human gate — blocked on Wave 4)*

- [x] 06-10-PLAN.md — vulns-smoke.sh + DoD-2 lab E2E sign-off + Phase 6 acceptance (autonomous: false)

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

**Plans**: 7 plans

**Wave 1**

- [x] 07-01-PLAN.md — osint package scaffold (doc/record/merge), OSINTConfig additive extension + OSINT.Enabled default-ON (D-O9), tools.lock expansion, newOSINTCmd RunE + modules.go blank import

**Wave 2** *(parallel; blocked on Wave 1)*

- [x] 07-02-PLAN.md — domain_info (OSINT-01) + ip_info (OSINT-02) + emails (OSINT-03) + spoofy/mail_hygiene (OSINT-10)
- [x] 07-03-PLAN.md — GitHub cluster: dorks+gitdorks (OSINT-04) + repos+leaks ghleaks/trufflehog REDACTED (OSINT-05) + gato actions (OSINT-06)
- [x] 07-04-PLAN.md — cloud_enum (OSINT-07) + postman REDACTED (OSINT-08) + swagger REDACTED (OSINT-09) + misconfig fold (D-O10)
- [x] 07-05-PLAN.md — msftrecon (OSINT-11) + CMSeeK/favirecon (OSINT-12) + gqlspection (OSINT-13) + cewler (OSINT-14) + xnldorker (OSINT-15) + metadata fold (D-O10)

**Wave 3** *(blocked on Wave 2)*

- [x] 07-06-PLAN.md — dag_test + frozen-replay parity harness (D-O6) + DoD-1 realtools argv smoke over 24 Phase 7 tools (OSINT-16)

**Wave 4** *(human gate; blocked on Wave 3)*

- [x] 07-07-PLAN.md — osint-smoke.sh + DoD-2 real dev-Mac E2E + category-presence soft gate + Phase 7 acceptance (autonomous: false) — ACCEPTED, maintainer approved 2026-06-10 (VERDICT: PASS, 8 osint-class findings, XCUT-07 CLEAN)

**Wave 5** *(gap-closure — 07-REVIEW.md; run `/gsd-execute-phase 7 --gaps-only`)*

- [x] 07-08-PLAN.md — GAP-01: split osint into sequential stages (github_repos pre-stage before github_leaks) + stage-order-vs-DependsOn guard test (OSINT-05) — DONE 2026-06-10 (osintStages() shared with TestOSINTStageOrderHonorsDependsOn; full `go test ./...` green)
- [x] 07-09-PLAN.md — GAP-02/03: backward-compatible Backend env seam (ExecEnv/StreamEnv) → gato authenticated via registered-secret GH_TOKEN + redact/omit raw gato side-file (OSINT-06, XCUT-07)

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

**Plans**: 6 plans in 5 waves
Plans:

**Wave 0** *(prerequisites — SDK dep + filterByModuleAndEnabled relocation + SDK assumption verification)*

- [x] 08-00-PLAN.md — go-sdk v1.6.1 in go.mod + FilterByModuleAndEnabled → internal/core/task/filter.go + SDK assumptions A1-A6 spike

**Wave 1** *(parallel — blocked on Wave 0)*

- [x] 08-01-PLAN.md — SARIF 2.1.0 findings schema package (internal/core/findings/): types + mapper + tests (D-04)
- [x] 08-02-PLAN.md — MCP infrastructure: SessionRegistry + BearerAuthMiddleware + SessionScope/CheckScope (D-05, D-06, D-07)

**Wave 2** *(blocked on Wave 0 + Wave 1)*

- [x] 08-03-PLAN.md — Shared handler extraction: RunOptions + BootReconApp + RunSubsAsync/RunWebAsync/RunVulnsAsync/RunOSINTAsync (D-02, MCP-02)

**Wave 3** *(blocked on Wave 2)*

- [x] 08-04-PLAN.md — MCP server core (MCPServer + 7 tools + resources) + cmd/reconftw/mcp.go + docs/openapi.json (MCP-01, MCP-03, MCP-07, MCP-08)

**Wave 4** *(human gate — blocked on Wave 3)*

- [ ] 08-05-PLAN.md — Integration test (TestMCPToolList) + docs/mcp.md + human verification checkpoint (MCP-01, MCP-09)

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

**Plans**: 4 plans in 3 waves
Plans:
**Wave 1**

- [x] 09-01-PLAN.md — ConfigTransform hook in RunOptions/BootReconApp + ApplyZenProfile/ApplyDeepProfile config transforms (MODE-04, MODE-05)

**Wave 2** *(parallel — blocked on Wave 1)*

- [x] 09-02-PLAN.md — Composite subcommands (recon/all/passive/zen/deep) + RunCompositeAsync + commonAfterBoot + passive hard-guard (MODE-01, MODE-02, MODE-03, MODE-04, MODE-05, MODE-12)
- [x] 09-03-PLAN.md — v1 alias dispatch (translateV1Args) + batch (--list) + unconditional redaction wiring (MODE-09, MODE-10, MODE-11, MODE-12)

**Wave 3** *(blocked on Wave 2)*

- [x] 09-04-PLAN.md — Stateful modes (gen-resolvers/refresh-cache/quick-rescan) + root.go registration (MODE-06, MODE-07, MODE-08)

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

**Plans**: 5 plans in 4 waves
Plans:
**Wave 1** *(prerequisite sqlc query — blocks report path)*

- [x] 10-01-PLAN.md — GetLatestCompletedScanForTarget sqlc query + querier.go interface (REPORT-08, REPORT-09, MON-03)

**Wave 2** *(parallel — blocked on Wave 1)*

- [x] 10-02-PLAN.md — Real Slack/Telegram/Discord webhook dispatchers + DigestCoalescer + EventFilter + boot.go wiring + reconftw notify --test (NOTIF-01..07)
- [x] 10-03-PLAN.md — internal/core/report/ package (renderer + html + csv + sarif + hotlist + faraday + ai) + real reconftw report subcommand (REPORT-01..09)

**Wave 3** *(blocked on Wave 2 — composes notifier + report)*

- [x] 10-04-PLAN.md — RunMonitorAsync loop + diff + dedup + SIGINT + incremental + real reconftw monitor subcommand (MON-01..08)

**Wave 4** *(human gate — blocked on Wave 3)*

- [x] 10-05-PLAN.md — Full build+test gate + human acceptance verification (all 24 REQ-IDs)

### Phase 11: Installer + Cross-Platform + Docker

**Goal**: Replace `install.sh` with a `reconftw install` subcommand reading from a `tools.lock` manifest pinning all 70+ orchestrated tools with SHA-256 verification; support Linux (Debian/Ubuntu/RHEL/Arch — glibc + musl + ARM64) + macOS (Apple Silicon + Intel) via a Homebrew source-build tap (XPLAT-06 re-scoped per D-06 — no Apple notarization day-1); ship updated multi-arch Docker image — the packaging story is the single clearest win of the rewrite, so it ships as one phase.
**Depends on**: Phases 4, 5, 6, 7 (need stable subprocess + AppContext + binary to install); calendar-parallel-capable with Phase 9/10
**Requirements**: INST-01, INST-02, INST-03, INST-04, INST-05, INST-06, INST-07, INST-08, INST-09, INST-10, INST-11, INST-12, XPLAT-01, XPLAT-02, XPLAT-03, XPLAT-04, XPLAT-05, XPLAT-06, XPLAT-07, XPLAT-08, XPLAT-09, DOCK-01, DOCK-02, DOCK-03, DOCK-04, DOCK-05, DOCK-06, DOCK-07, XCUT-08
**Success Criteria** (what must be TRUE):

  1. `reconftw install` runs end-to-end on a clean machine: reads `tools.lock` (pins ALL 70+ orchestrated tools — Go tools by `module@version`, Python tools by name+version, system deps by name); installs Go tools via `go install <module>@<version>`, Python tools via `uv tool install <package>==<version>` with per-tool isolation, system deps via platform-appropriate package manager (apt/yum/dnf/pacman/brew); the installer is idempotent (re-running installs only missing/outdated tools), fails fast with a clear error on unsupported platform, and never leaves partial-install state behind (INST-01, INST-02, INST-06, INST-07, INST-08, INST-11, INST-12)
  2. Supply-chain hygiene: SHA-256 verification on installer bootstrappers (rustup-init.sh, uv installer) against pinned hashes; SHA-256 verification on pre-built tool binaries where vendor publishes hashes; Rust toolchain bootstrap (only if `smugglex` or other Rust deps enabled) via verified rustup-init; CI verifies pins on update; 24-72h quarantine window for new tool versions before lockfile bump (documented in the lockfile update workflow) (INST-03, INST-04, INST-09, XCUT-08)
  3. Platform detection + health check: installer correctly detects Debian/Ubuntu (apt), RHEL/Fedora/CentOS (yum/dnf), Arch (pacman), macOS Intel (brew), macOS Apple Silicon (brew arm64); post-install `reconftw install --health-check` verifies every tool present on PATH and runnable (`--version` or equivalent) — and CI matrix runs install + smoke on every supported platform on every PR (INST-05, INST-10, XPLAT-05)
  4. Cross-platform binaries: Linux glibc (Debian 12+, Ubuntu 24.04+, RHEL/Rocky 9+, Arch rolling), Linux musl (Alpine 3.20+ — static binary), macOS arm64 (primary), macOS amd64, ARM64 Linux (cloud / Raspberry Pi) all build + run with passing smoke test; macOS distributed via Homebrew tap (six2dez/homebrew-reconftw) with source-build formula — sidesteps Gatekeeper (XPLAT-06 re-scoped per D-06: no Apple Developer ID/notarization day-1); Homebrew tap published for `brew install reconftw`; Linux distribution offers standalone binary + tar.gz + optional `.deb`/`.rpm` packages (XPLAT-01, XPLAT-02, XPLAT-03, XPLAT-04, XPLAT-06, XPLAT-07, XPLAT-08, XPLAT-09)
  5. Docker image ships: Dockerfile updated with new binary baked in; base image (debian:bookworm-slim — distroless rejected, see Docker/README.md) chosen per D-07; multi-arch build (amd64 + arm64) via `docker buildx`; all 95+ orchestrated tools available in the image (installer runs at build time non-interactively); image published to `ghcr.io/six2dez/reconftw` on every release, tagged with semantic version + `latest` + git SHA; image runs as non-root user (reconftw) with setcap on naabu+nmap for raw sockets (DOCK-01, DOCK-02, DOCK-03, DOCK-04, DOCK-05, DOCK-06, DOCK-07)

**Plans**: 6 plans in 5 waves
Plans:

**Wave 1**

- [ ] 11-01-PLAN.md — tools.lock inventory audit + schema extension (version/sha256/pip_package/repo_url/cargo_package) + add 15+ missing tools (naabu, notify, grpcurl, inscope, smap, cent, brutespray, dsieve, roboxtractor, xnLinkFinder, nmapurls, subwiz, dnsvalidator, interlace, LeakSearch) + XPLAT-06 reconciliation in REQUIREMENTS.md + ROADMAP.md

**Wave 2** *(blocked on Wave 1)*

- [ ] 11-02-PLAN.md — internal/installer/ package: all per-kind handlers (go/python/system/go_clone/python_venv/rust) + bootstrap (Go+uv+Rust SHA-256 verified) + platform detection + D-04 version probe + errors.ChecksumMismatch reuse

**Wave 3** *(blocked on Wave 2)*

- [ ] 11-03-PLAN.md — cmd/reconftw/install.go real command (stub removed) + --health-check reconciliation with healthcheck.go runHealthCheck() + scripts/update-tools-lock.sh (XCUT-08 quarantine workflow)

**Wave 4** *(parallel — blocked on Wave 3)*

- [ ] 11-04-PLAN.md — .goreleaser.yaml (glibc+musl+darwin, nfpm .deb/.rpm, checksums.txt) + .github/workflows/release.yml (goreleaser-action@v7, fetch-depth:0) + Homebrew tap formula template (D-06 source-build)
- [ ] 11-05-PLAN.md — Docker/Dockerfile multi-stage rewrite (builder+final, setcap in final, non-root reconftw) + .github/workflows/docker_nightly.yml extension (ghcr.io, multi-arch, semver+sha tags) + Docker/README.md

**Wave 5** *(blocked on Wave 4 — human gate)*

- [ ] 11-06-PLAN.md — ci.yml XPLAT-05 platform-smoke matrix (ubuntu-latest/22.04 + macos-latest/13) + Phase 11 acceptance checkpoint (autonomous: false)

### Phase 12: Integration Hardening

**Goal**: Make every "implemented" v2 subsystem actually connect end-to-end, eliminating the silent-failure integration bugs surfaced by the bash-vs-Go audit. The pipeline must populate the queryable store (so `report`/SARIF/AI/hotlist/monitor read real data), notifications must fire during ordinary scans (not only `monitor`), resume must survive across runs, the monitor must produce real diffs, the global rate limiter must be enforced, and AI reporting must support a local (Ollama) provider. This is the "make it work, not just build" phase — cheap wiring fixes with outsized user impact.
**Depends on**: Phases 3, 9, 10 (kernel scheduler/checkpoint/store + composite modes + monitor/reporting/notifications must exist to wire together)
**Requirements**: INTEG-01, INTEG-02, INTEG-03, INTEG-04, INTEG-05, INTEG-06
**Success Criteria** (what must be TRUE):

  1. Store population: after `reconftw all/recon/web/vulns/osint --target X`, the shared `store.db` holds a completed scan with findings/hosts/urls linked to the target; `reconftw report --target X` renders HTML/SARIF/CSV/hotlist with real data (was: "no completed scan found" hard error). *(DONE this session — `internal/core/ingest` + hand-authored `internal/store/sqlc/schema.{sql,go}`; verified E2E)* (INTEG-01)
  2. In-scan notifications: Slack/Telegram/Discord fire during recon/all/web/vulns/osint runs (scan-start + completion + critical-finding events), not only under `monitor`; `soft_enabled` / `send_zip_notify` / event routing honored (INTEG-02)
  3. Resume across runs: a second invocation against the same target resumes from checkpoints instead of a fresh timestamped workspace; `--force` / `Advanced.Diff` bypasses checkpoints as documented; InputHash invalidates on cfg/wordlist/target change (INTEG-03)
  4. Monitor diff/incremental: the monitor loop produces real cross-cycle diffs (reading the now-populated store) and the incremental re-feed consumes `TargetListPath` (INTEG-04)
  5. Global rate limiter: the central limiter is enforced (`pickLimiter` no longer a no-op) so `*_RATELIMIT` / adaptive-rate settings actually throttle (INTEG-05)
  6. AI reporting: provider default is coherent and a local Ollama path works; no unexpected cloud egress of recon data by default (INTEG-06)

**Plans**: 5 plans in 3 waves (INTEG-01 landed pre-plan)
Plans:

**Landed pre-plan**

- [x] Store ingest (INTEG-01) — landed pre-plan this session (`internal/core/ingest`, `internal/store/sqlc/schema.{sql,go}`, `persistScanToStore` wiring across all 5 handlers)

**Wave 1** *(parallel — independent files)*

- [x] 12-01-PLAN.md — INTEG-03 resume across runs: stable per-target workspace + wired InputHash (target+cfgSnapshot+TargetListPath+wordlists) + `--force`/`Advanced.Diff` checkpoint bypass
- [x] 12-02-PLAN.md — INTEG-06 AI provider default + local Ollama path; coherent default (ollama+llama3:8b), no unexpected cloud egress by default
- [x] 12-03-PLAN.md — INTEG-05 global rate limiter enforced: `pickLimiter` builds per-tool + global RPS from config (Runner already calls `Limiter.Wait`)

**Wave 2** *(blocked on 12-01 common.go + 12-02 config.go)*

- [x] 12-04-PLAN.md — INTEG-02 in-scan notifications: scan-start/complete/critical-finding fire during recon/all/web/vulns/osint via the INTEG-01 finalization seam; best-effort, `soft_enabled`/`enabled`/routing honored (`send_zip_notify` deferred → Phase 14)

**Wave 3** *(blocked on 12-01 hash + 12-04 common.go)*

- [x] 12-05-PLAN.md — INTEG-04 monitor diff/incremental: diff reads shared `<dataDir>/store.db` + incremental re-feed consumes `TargetListPath` (seeds new assets + hash-forced re-execution)

### Phase 13: Domain Parity

**Goal**: Close the per-domain capability gaps between bash and Go found in the parity audit so a `recon`/`all` run reaches ≥95% functional parity with bash v1. Prioritize subdomains (the foundation — lowest at ~70%, with dead code), then vulns/osint/web. Genuinely niche or rarely-run capabilities may ship post-cutover if documented, since bash remains available on the legacy branch.
**Depends on**: Phase 12 (integration seams must be solid before adding capability surface)
**Requirements**: PAR-01, PAR-02, PAR-03, PAR-04
**Success Criteria** (what must be TRUE):

  1. Subdomains parity: PTR sweep wired (or dead code removed), hakip2host reverse-IP, `subdomains_dnsregs` records artefact, csprecon in the subs pipeline, dsieve top-N recursion, resolve stage best-effort (not fail-fast); default-on alignment with bash (tls/recursive) (PAR-01)
  2. Vulns parity: password spraying implemented (brutespray/brutus), SSRF OOB auto-starts interactsh when `COLLAB_SERVER` unset (PAR-02)
  3. OSINT parity: LeakSearch (passwords), Scopify, titus/noseyparker repo-secret engines, WHOISXML reverse-IP, metadata/ip_info corrected (PAR-03)
  4. Web parity: active portscan (naabu/nmap), nerva service fingerprint, `.well-known` pivots, roboxtractor/getjswords/pydictor wordlists, `url_ext` sensitive-extension bucketing (PAR-04)
  5. A refreshed parity audit shows ≥95% capability coverage on recon/all; any deferred capability is listed in MIGRATION.md as post-cutover (all)

**Plans**: 8 plans in 3 waves
Plans:

- [x] 13-01-PLAN.md — Subs resolve core: dnsregs artefact + subdomains_ips.txt + folded hakip2host reverse-IP; resolve best-effort degrade; delete dead SubPTRTask; tls/reverse-ip default-on; tools.lock (nmap/nerva/brutus/Scopify/titus; noseyparker deferred to Ph14)
- [ ] 13-02-PLAN.md — Subs pipeline: csprecon in the discovery stage + dsieve top-N recursion
- [ ] 13-03-PLAN.md — Web active portscan (naabu/nmap) + nerva service fingerprint
- [ ] 13-04-PLAN.md — Web light producers: url_ext bucketing + .well-known pivots + roboxtractor/getjswords wordlists (pydictor deferred)
- [ ] 13-05-PLAN.md — OSINT: LeakSearch passwords + Scopify + ip_info WHOISXML reverse-IP/IP-target
- [ ] 13-06-PLAN.md — OSINT: github repo-secret engines (titus/noseyparker + trufflehog)
- [ ] 13-07-PLAN.md — Vulns: password spraying (brutespray/brutus) + SSRF OOB interactsh auto-start
- [ ] 13-08-PLAN.md — Pipeline wiring (all stage-list sites) + capability parity audit (>=95%)

### Phase 14: Cutover & Migration

**Goal**: Replace bash `main` with `rewrite/v2` via a corpus-tested config migrator (`reconftw.cfg` → TOML), a 1-2-month beta period with community feedback, an automated bug-bug parity test against canonical targets, MIGRATION.md, a 6-month compat-symlink window for `Recon/<domain>/`, and explicit sign-off criteria — cutover is BLOCKED until CUT-04 passes and CUT-12 sign-off is met.
**Depends on**: Phases 11, 12, 13 (installer/xplat/docker + integration hardening + domain parity all green before cutover can start)
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
| 2. Architecture v2 Design | 7/7 | Complete   | 2026-05-28 |
| 3. Foundation Kernel | 7/7 | Complete   | 2026-05-28 |
| 4. Subdomains E2E + Axiom Integration | 11/12 | In Progress|  |
| 5. Web Pipeline E2E | 10/10 | Complete   | 2026-06-03 |
| 6. Vulnerability Scanning E2E | 10/10 | Complete    | 2026-06-09 |
| 7. OSINT E2E | 7/7 | Complete   | 2026-06-10 |
| 8. MCP Server | 5/6 | In Progress|  |
| 9. Composite Modes | 4/4 | Complete    | 2026-06-11 |
| 10. Monitor Mode + Reporting + Notifications | 5/5 | Complete    | 2026-06-12 |
| 11. Installer + Cross-Platform + Docker | 0/6 | Not started | - |
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
| CUT-01 | Phase 14 |
| CUT-02 | Phase 14 |
| CUT-03 | Phase 14 |
| CUT-04 | Phase 14 |
| CUT-05 | Phase 14 |
| CUT-06 | Phase 14 |
| CUT-07 | Phase 14 |
| CUT-08 | Phase 14 |
| CUT-09 | Phase 14 |
| CUT-10 | Phase 14 |
| CUT-11 | Phase 14 |
| CUT-12 | Phase 14 |
| CUT-13 | Phase 14 |
| CUT-14 | Phase 14 |
| CUT-15 | Phase 14 |
| XCUT-01 | Phase 14 |
| XCUT-02 | Phase 3 |
| XCUT-03 | Phase 14 |
| XCUT-04 | Phase 3 |
| XCUT-05 | Phase 14 |
| XCUT-06 | Phase 14 |
| XCUT-07 | Phase 3 |
| XCUT-08 | Phase 11 |
| XCUT-09 | Phase 3 |

**Cross-cutting placement rationale:**

- **XCUT-01** (perf benchmark) → Phase 14 (final assertion); baseline established Phase 3, validated per-module phase
- **XCUT-02** (resource budget Go <50MB OR Python <500MB) → Phase 3 (locked at Foundation)
- **XCUT-03** (test coverage ≥75% lib, ≥90% critical paths) → Phase 14 (final validation); gate set up Phase 3
- **XCUT-04** (CI policy race detector + mypy + coverage gate) → Phase 3 (set up at Foundation, runs every phase)
- **XCUT-05** (zero silent breakages → MIGRATION.md) → Phase 14 (MIGRATION.md is the artifact)
- **XCUT-06** (docs: README + INSTALL.md + CONTRIBUTING.md + auto-gen API docs) → Phase 14 (final docs)
- **XCUT-07** (logging hygiene — no secrets in logs) → Phase 3 (FOUND-02 + lint rule; tested every phase)
- **XCUT-08** (supply chain tools.lock) → Phase 11 (where INST-02/03/04 live)
- **XCUT-09** (observability heartbeat) → Phase 3 (scheduler emits heartbeats; tested every phase)

---
*Roadmap created: 2026-05-27*
*Total v2.0 requirements: 197 across 12 phases (100% coverage). Granularity: coarse. Parallelization: yes (within constraints).*
