# Phase 3 — Foundation Kernel — Acceptance Gate

**Certified:** 2026-05-28
**Phase status:** Complete
**Plan count:** 7 plans (renumbered from initial 6 per revision-iter-1 split — Blockers 2/3)
**REQ-IDs delivered:** FOUND-01..16 + XCUT-02 + XCUT-04 + XCUT-07 + XCUT-09 (20 REQ-IDs)

## ROADMAP Success Criteria Verification

### Success Criterion 1: CLI wired to all subsystems

> `reconftw --help` runs against the kernel binary; the CLI is wired to the configured subsystems (typed errors, structured logger, layered config loader with 8-source precedence, scheduler, tool registry, output tree, checkpoint store, notifier stubs, UI dot-fill); empty `reconftw run` against a mock target writes a `workspaces/<target>/manifest.json` and exits 0 (FOUND-01, FOUND-02, FOUND-03, FOUND-13, FOUND-14)

**VERIFIED** via:

- Plan 01 SUMMARY (errors + logger + Secret + Redactor + RedactingHandler)
- Plan 02 SUMMARY (config loader 8-source: defaults → /etc → ~/.config → ./reconftw.toml → --config → secrets.toml → env → CLI; 475 koanf tags / 182 validate tags / 9 Secret fields)
- Plan 03 SUMMARY (OutputTree + AtomicWriter + checkpoint.Store + W15 Interface introductions for plan-07 mock substitution)
- Plan 04 SUMMARY (Backend + LocalBackend + ToolRegistry + RateLimiter + FOUND-10 lint; Tool.Critical field added per Blocker 5)
- Plan 05 SUMMARY (Task interface + AppContext + Scheduler + UI + Notifier + noop.demo)
- Plan 06 SUMMARY (CLI binary — 15 subcommands + v1 aliases + version + health-check + hidden kernel-demo per W16)
- Plan 07 Task 3 integration smoke test (`TestKernelDemoEndToEnd`) — exit 0 verified; workspaces/example.com-*/artefacts/demo.jsonl + checkpoints.db produced

**CONTEXT default resolution:** "reconftw run" interpreted as hidden `kernel-demo` subcommand per CONTEXT D-05 (W16) authorizing the hidden subcommand per ADR §0 D-07 non-breaking addition. Phase 4 plan-01 deletes the hidden subcommand + the Phase 3 demo task.

### Success Criterion 2: Atomic writes + checkpoint idempotency

> Atomic writes verified... SQLite checkpoint store records (task_name, target, input_hash, status, timings, output_paths, error_class) and re-running with same input_hash skips the task (FOUND-04, FOUND-05)

**VERIFIED** via:

- Plan 03 Task 1: FOUND-04 atomicity test (`TestFOUND04Atomicity` — hook simulation) + smoke `TestFOUND04SubprocessSIGKILL` (Ring 3 real subprocess SIGKILL between fsync and rename; SUMMARY 03-03 lines 150-160)
- Plan 03 Task 3: SQLite checkpoint store + InputHash + WAL mode + idempotency tests (`TestCheckpointStoreDoneAfterComplete`, `TestCheckpointStoreDoneDifferentHash`)
- Plan 05 Task 1: Scheduler `runOne` honors `Checkpoint.Done` (skips when true) + `Begin` → run → `Complete` ordering per ADR §3.4 6-step (asserted by `TestCheckpointSkipOnHit`)
- Plan 07 Task 3: integration smoke test asserts checkpoint row exists after kernel-demo invocation
- 7-class error classification populated via `classifyError` (ToolError / ToolTimeout / OutOfScope / AxiomFailure / ConfigError / ScopeError / ChecksumMismatch / Unknown)

### Success Criterion 3: Subprocess safety enforced

> Every subprocess uses `Setpgid`+`WaitDelay` + lint rule forbids raw `exec.Command` + SIGINT-kill test within 10s passes (FOUND-09, FOUND-10)

**VERIFIED** via:

- Plan 04 Task 1: LocalBackend.Exec/Stream — `Setpgid: true` + `WaitDelay=5s` + `cmd.Cancel` SIGTERM-to-group + supplementary group-SIGKILL goroutine (`WaitDelay+500ms`), ports spike/go/internal/proc/proc.go verbatim
- Plan 04 Task 1 smoke: `TestKillTreeWithin10s` — bash + 2 sleep grandchildren reaped in **~101ms** (10s SLA cleared by 99x) via `syscall.Kill(pid, 0) == ESRCH` liveness probe per W17
- Plan 04 Task 3: FOUND-10 AST scan — `golang.org/x/tools/go/packages` + `ast.Inspect` walks every package under `./internal/...`; `TestFOUND10_NoRawSubprocessOutsideBackend` (zero violations in kernel) + `TestFOUND10_FixtureDetected` (positive-detection against testdata/violating.go); upgrade to golangci-lint v2 custom plugin is a deferred Phase 4+ ticket per Plan 04 SUMMARY

### Success Criterion 4: Scheduler + RateLimiter + ToolRegistry + Notifier

> Scheduler enforces bounded concurrency... rate limiter supports per-tool/per-target/global caps; tool registry self-registers tools via `func init()`; warns on missing-but-required; structured errors on missing-and-critical; notifier interface + log sink + Slack/Telegram/Discord stubs wired through redactor (FOUND-06, FOUND-07, FOUND-08, FOUND-11, FOUND-12, XCUT-09)

**VERIFIED** via:

- Plan 05 Task 1 Scheduler: `errgroup.SetLimit` + failure_policy fork (`errgroup.WithContext` for fail_fast vs `new(errgroup.Group)` for best_effort per ADR §7.2; `TestFailureMatrixFailFast` + `TestFailureMatrixBestEffort` pass)
- Plan 05 Task 1 heartbeat: XCUT-09 heartbeat goroutine — `task_heartbeat` slog event at configurable cadence; first emission at 2*cadence; sync.Once-guarded teardown; `goleak.VerifyTestMain` ensures no orphan goroutines
- Plan 04 Task 2: RateLimiter on `golang.org/x/time/rate.Limiter` — per-tool + global RPS gating
- Plan 04 Task 2: ToolRegistry with `MissingRequired()` (union of both tiers) + `MissingCritical()` (Critical=true filter) per Blocker 5
- Plan 07 Task 2: tools.lock seed with 10 Phase 4 tools — 3 critical (subfinder, httpx, dnsx) + 7 required-but-not-critical (crt, puredns, gotator, anew, asnmap, s3scanner, subzy); health-check exits 1 on missing-critical (FAIL), exits 0 with WARN on missing-required
- Plan 05 Task 2 Notifier: `Notifier` interface + `Multi` + `LogSink` + Slack/Telegram/Discord stubs returning nil; all sinks log via the wired logger so RedactingHandler scrubs registered secrets at handler boundary; `TestXCUT07NotifierRedactsRegisteredSecret` + `TestXCUT07StubsRedactRegisteredSecret` confirm
- Plan 05 Task 1 Task interface + Registry + topo sort: 3-color DFS cycle detection returns `*coreerrors.ConfigError` per ADR §6 PITFALL NOTE (`TestCycleDetection` confirms)

### Success Criterion 5: Test mocks + CI gate + binary size + sentinel

> Test mocks ship; CI on every push runs lint + format-check + unit + integration smoke + `-race`; branch coverage gate ≥75% on lib code; Go binary stripped <50MB; XCUT-07 sentinel test asserts no secret patterns leak (FOUND-15, FOUND-16, XCUT-02, XCUT-04, XCUT-07)

**VERIFIED** via:

- Plan 07 Task 1: MockBackend + MockCheckpoint + MockOutputTree shipped in `internal/core/testutil/`; each satisfies the corresponding interface via `var _ <Interface> = (*Mock<X>)(nil)` compile-time assertions (the W15 enforcement gates). Fixture directory seeded with `subfinder/example.com.txt` (6 lines) + `httpx/hosts.jsonl` (3 records). 81.1% package coverage.
- Plan 01 + Plan 07 Task 3: CI yaml ships 6 jobs — `lint` (gofumpt + golangci-lint), `unit` (`go test -race -short` + XCUT-07 sentinel gate), `integration` (`go test -race` + XCUT-04 ≥75% gate + W20 per-file ≥90% on critical paths), `smoke` (`go test -race -tags smoke`), `binary-size` (unconditional after Plan 06 main.go; Plan 07 removed `hashFiles` gate), `integration-smoke` (`TestKernelDemoEndToEnd` + interfaces_check + verify-0002.sh)
- Plan 01 Task 3 + Plan 05 Task 2: XCUT-07 sentinel `test_sentinel_value_not_a_real_key_abc123` (BINDING per ADR §10.4 line 2582) — `TestXCUT07Sentinel` (log package) + `TestXCUT07NotifierRedactsRegisteredSecret` + `TestXCUT07StubsRedactRegisteredSecret` — verifies redactor catches the sentinel across 4 attack surfaces
- Plan 07 Task 3: stripped binary measured at **10.4 MB** (10,854,962 bytes) — XCUT-02 50 MB budget cleared by 80%

## Measurements (2026-05-28)

| Metric | Value | Gate | Status |
|--------|-------|------|--------|
| Binary size (stripped, `-ldflags=-s -w -trimpath`) | **10.4 MB** (10,854,962 bytes) | <50 MB (XCUT-02) | **PASS** (80% margin) |
| Kill-tree timing (smoke; bash + 2 grandchildren via syscall.Kill liveness probe) | **~101 ms** | <10 s (FOUND-09) | **PASS** (99x margin) |
| Heartbeat cadence (XCUT-09) | configurable; default 30 s; tested at 50 ms in unit tests | configurable | **PASS** |
| Branch coverage on `internal/core/...` (combined) | **86.9%** | ≥75% (XCUT-04) | **PASS** (+12 pp margin) |
| Per-file coverage — `log/redactor.go` | **100.0%** | ≥90% (W20) | **PASS** |
| Per-file coverage — `log/redacting_handler.go` | **100.0%** | ≥90% (W20) | **PASS** |
| Per-file coverage — `output/atomic.go` | **91.2%** | ≥90% (W20) | **PASS** |
| Per-file coverage — `output/scope.go` | **97.0%** | ≥90% (W20) | **PASS** |
| Per-file coverage — `checkpoint/store.go` | **90.0%** | ≥90% (W20) | **PASS** |
| XCUT-07 sentinel test | 0 leaks across 4 attack surfaces | 0 leaks | **PASS** |
| tools.lock entries | 10 (3 critical, 7 non-critical) | ≥5 (CONTEXT default (b)) | **PASS** |
| interfaces_check BINDING compile gate | exits 0 against real packages | required | **PASS** |
| `verify-0002.sh` (ADR pre-sign gate) | exits 0 | required | **PASS** |
| Total Go packages in v2 kernel | 14 (errors, log, config, output, checkpoint, backend, backend/lint, task, scheduler, appctx, notifier, ui, testutil, cmd/reconftw + cmd/interfaces_check + modules/demo) | n/a | n/a |
| Total commits across Phase 3 | 7 plans × ~6 commits/plan = ~42 commits + 1 per-phase commit | n/a | n/a |

## CONTEXT Decision Verification (D-01..D-05)

| Decision | Verified by |
|----------|-------------|
| D-01: All 15 v2 subcommands surfaced | Plan 06 SUMMARY § "D-01 — 15 v2 Subcommands Visible" table (16 visible + 1 hidden = 17 total) + `TestRootListsFifteenSubcommandsPlusVersion` |
| D-02: Stub `RunE` returns phase-pointer + exit 64 | `cmd/reconftw/stub.go` `stubNotImplemented` + `TestStubNotImplementedFormat` + `TestEveryStubReturnsExit64` |
| D-03: All v1 deprecated aliases wired | `cmd/reconftw/root.go` `addV1DeprecatedAliases` (23 MarkDeprecated calls covering 14 distinct Flag entries → 20 alias forms) + `TestDeprecationWarningLongAliases` + `TestDeprecationWarningShortAliases` |
| D-04: `version` + `health-check` fully working | `cmd/reconftw/version.go` + `cmd/reconftw/healthcheck.go` + `TestVersionSubcommandOutput` + `TestHealthCheckCriticalFail` (Blocker 5 — exit 1) |
| D-05 (W16): Hidden `kernel-demo` subcommand | `cmd/reconftw/kernel_demo.go` (Hidden:true) + `TestKernelDemoSubcommandHidden` + `TestKernelDemoNotInHelp` + Plan 07 Task 3 `TestKernelDemoEndToEnd` integration |

## REQ-ID Traceability

| REQ-ID | Description | Implementation | Test gate |
|--------|-------------|----------------|-----------|
| FOUND-01 | Typed error hierarchy | `internal/core/errors/errors.go` | `errors_test.go` (100% coverage) |
| FOUND-02 | Structured logger with redaction | `internal/core/log/` | `TestXCUT07Sentinel` (Plan 01) |
| FOUND-03 | Config loader (8-source) | `internal/core/config/` | `TestEightSourcePrecedence` (Plan 02) |
| FOUND-04 | OutputTree + AtomicWriter | `internal/core/output/` | `TestFOUND04Atomicity` + `TestFOUND04SubprocessSIGKILL` |
| FOUND-05 | Checkpoint store (SQLite WAL) | `internal/core/checkpoint/` | `TestCheckpointStoreWALMode` + idempotency tests |
| FOUND-06 | Scheduler (failure_policy fork) | `internal/core/scheduler/` | `TestFailureMatrixFailFast` + `TestFailureMatrixBestEffort` |
| FOUND-07 | RateLimiter | `internal/core/backend/ratelimiter.go` | `ratelimiter_test.go` |
| FOUND-08 | ToolRegistry + Critical tier | `internal/core/backend/registry.go` + Plan 07 `tools.lock` + `registry_seed.go` | `TestRegistrySeed_*` (Plan 07) + `TestToolRegistry_MissingCritical_FiltersByCriticalBool` |
| FOUND-09 | LocalBackend kill-tree (Setpgid + WaitDelay) | `internal/core/backend/local.go` | smoke `TestKillTreeWithin10s` (~101 ms) |
| FOUND-10 | Lint rule forbids raw `exec.Command` | `internal/core/backend/lint/` | `TestFOUND10_NoRawSubprocessOutsideBackend` + `TestFOUND10_FixtureDetected` |
| FOUND-11 | Notifier + LogSink + Slack/Telegram/Discord stubs | `internal/core/notifier/` | `TestXCUT07StubsRedactRegisteredSecret` |
| FOUND-12 | Task interface + Registry + topo sort | `internal/core/task/` | `TestCycleDetection` + `TestNoAnyPlaceholderInTaskOrScheduler` |
| FOUND-13 | UI dot-fill printer | `internal/core/ui/` | `TestUIMappingDocumented` + 15 dot-fill tests |
| FOUND-14 | CLI binary (cobra root + subcommands) | `cmd/reconftw/` | Plan 06 test suite (Plan 06 SUMMARY § Verification Results) |
| FOUND-15 | Test mocks (MockBackend/MockCheckpoint/MockOutputTree) | `internal/core/testutil/` | `mock_*_test.go` + interface assertions |
| FOUND-16 | CI pipeline on every push | `.github/workflows/ci.yml` | 6 jobs (lint, unit, integration, integration-smoke, binary-size, smoke) |
| XCUT-02 | Binary <50 MB stripped | Makefile + CI binary-size job | **10.4 MB** measured |
| XCUT-04 | CI policy (race + lint + ≥75% coverage) | `.github/workflows/ci.yml` integration job | 86.9% coverage on internal/core/ |
| XCUT-07 | Logging hygiene CI gate | Sentinel test through every sink | `TestXCUT07Sentinel|TestSentinel` |
| XCUT-09 | Heartbeat cadence (observability) | `internal/core/scheduler/heartbeat.go` | `TestHeartbeatCadenceForLongRunningTask` + goleak |

## Test-Ring Summary

| Ring | Frequency | Phase 3 tests delivered |
|------|-----------|-------------------------|
| Ring 1 (unit) | every push | 250+ unit tests across 14 packages |
| Ring 2 (integration) | every push | `TestKernelDemoEndToEnd` (Plan 07) + checkpoint integration tests (Plan 03) |
| Ring 3 (smoke, build-tagged) | every PR + weekly cron | `TestFOUND04SubprocessSIGKILL` (Plan 03) + `TestKillTreeWithin10s` (Plan 04) + `TestLocalBackend_*_ContextCancelled_*` (Plan 04) |
| Ring 4 (property-based, rapid) | every push | `TestLoadRoundtrip_Property` (Plan 02 config fuzz) + `TestNoAnyPlaceholderInTaskOrScheduler` (Plan 05 AST gate) |

## Open Items Carried to Phase 4

- **Phase 4 plan-01 ACCEPTANCE** (per Plan 05 + 06 SUMMARYs):
  1. Delete `internal/modules/demo/noop.go` + `internal/modules/demo/noop_test.go` — replaced by `internal/modules/subdomains/passive.go` (real subdomains.passive Task)
  2. Delete `cmd/reconftw/kernel_demo.go` + `cmd/reconftw/kernel_demo_test.go` + `cmd/reconftw/integration_smoke_test.go` references to them — replaced by real subs subcommand
  3. Update `cmd/reconftw/modules.go` blank import line from `internal/modules/demo` to `internal/modules/subdomains`
  4. Replace stubbed `subs` RunE with real subdomains pipeline (Backend.Exec + Tree.Append)
- **Phase 10 (Notifications)**: replace Slack/Telegram/Discord stubs with real `retryablehttp.Client` dispatch; the `TODO(phase-10)` markers in each stub file are explicit hand-off points
- **Phase 11 (Installer + Cross-Platform + Docker)**:
  - Extend `tools.lock` from 10 to 70+ tools per `.planning/codebase/STACK.md`
  - Add SHA-256 verification per INST-02..04
  - Add cross-platform CI matrix (macos-latest, arm64 runners) per XPLAT-05
- **Phase 12 (Cutover + Migration)**:
  - Implement `CompatWriter.WriteCompat` body per ADR §4.4 (currently a no-op skeleton)
  - Extend `V1ToV2Mapping` from 3 seed entries to the full v1 output-shape table (40+ entries)
  - Add top-level `Recon/<domain>` AtomicSymlink to `workspaces/<target-id>/_compat/`
- **Future iteration / deferred ticket**: promote FOUND-10 lint rule from test-based AST scan to a real golangci-lint v2 custom plugin if violations accumulate (no signal yet that the test-based approach is insufficient)
- **Phase 4+**: `internal/core/config/snapshot.go` was migrated to use `output.WriteFile` (W19) and the `TODO(plan-03)` marker removed. A future plan may add a `LoadOptions.SkipValidation` flag if cmd/reconftw needs to re-load snapshots for diagnostics (per Plan 02 SUMMARY decisions).

## Phase 3 Final Code Inventory

| Path | Purpose | Coverage | Phase added |
|------|---------|----------|-------------|
| `internal/core/errors/` | 7-class typed error hierarchy (FOUND-01) | 100.0% | 03-01 |
| `internal/core/log/` | slog + Secret + RedactingHandler (FOUND-02) | 94.9% | 03-01 |
| `internal/core/config/` | koanf 8-source loader + validate + snapshot (FOUND-03) | 84.3% | 03-02 |
| `internal/core/output/` | OutputTree + AtomicWriter + scope + manifest + compat (FOUND-04) | 83.4% | 03-03 |
| `internal/core/checkpoint/` | SQLite-backed task idempotency (FOUND-05) | 88.8% | 03-03 |
| `internal/core/backend/` | Backend + LocalBackend + AxiomBackend + ToolRegistry + RateLimiter + Runner (FOUND-07..10) | 87.4% | 03-04 (+ tools.lock seed 03-07) |
| `internal/core/backend/lint/` | FOUND-10 AST scan | n/a | 03-04 |
| `internal/core/task/` | Task interface + Registry + topo sort (FOUND-12) | 100.0% | 03-05 |
| `internal/core/scheduler/` | Bounded concurrency + failure_policy + heartbeat (FOUND-06, XCUT-09) | 93.6% | 03-05 |
| `internal/core/appctx/` | AppContext + Target + Boot (dependency kernel) | 93.3% | 03-05 |
| `internal/core/notifier/` | Notifier + LogSink + Slack/Telegram/Discord stubs (FOUND-11) | 85.0% | 03-05 |
| `internal/core/ui/` | Dot-fill printer + PARALLEL_LOG_MODE (FOUND-13) | 83.6% | 03-05 |
| `internal/core/testutil/` | MockBackend + MockCheckpoint + MockOutputTree (FOUND-15) | 81.1% | 03-07 |
| `internal/modules/demo/` | noop.demo Task (Phase 3 acceptance only — deleted Phase 4 plan-01) | 85.7% | 03-05 |
| `cmd/reconftw/` | CLI binary (ADR §10.3 init order; 15 subcommands + 1 hidden) | 71.0% | 03-06 (+ integration smoke 03-07) |
| `cmd/interfaces_check/` | BINDING signature delta detector (real packages + assertions) | n/a | 03-01 relocated + 03-07 upgraded |
| `.github/workflows/ci.yml` | 6 CI jobs (lint, unit, integration, integration-smoke, binary-size, smoke) | n/a | 03-01 + 03-03 + 03-07 |
| `Makefile` | v2 Go targets (build, test, test-integration, test-smoke, integration-smoke, lint, fmt, check, coverage, ci) | n/a | 03-01 (+ integration-smoke 03-07) |
| `tools.lock` | 10 Phase 4 tools (3 critical, 7 required) | n/a | 03-07 |
| `.golangci.yml` | golangci-lint v2.12.2 config | n/a | 03-01 |

**Phase 3 is COMPLETE.** Phase 4 (Subdomains E2E + Axiom Integration) inherits a populated `backend.Default`, ready-to-import `internal/core/testutil` mocks, an active CI pipeline (`lint` + `unit` + `integration` + `integration-smoke` + `binary-size` + `smoke`), and a BINDING signature delta detector (`cmd/interfaces_check/` + `verify-0002.sh`) that catches any ADR §5 drift at compile time.
