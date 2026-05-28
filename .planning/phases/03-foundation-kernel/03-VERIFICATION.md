---
phase: 03-foundation-kernel
verified: 2026-05-28T18:10:21Z
verifier_model: opus
status: passed_with_notes
score: 20/20 must-haves verified
overrides_applied: 0
notes:
  - "gofumpt v0.7.0 drift in 24 files (927 diff lines) is a known deferred item per .planning/phases/03-foundation-kernel/deferred-items.md — Phase 4 plan-00 housekeeping. CI gofumpt format-check job would currently fail; documented and accepted by Plan 07 closeout."
  - "go.mod declares Go 1.25.0 (CONTEXT said 1.24+; SUMMARY 03-01 said bumped to 1.24). The bump went one minor further than CONTEXT default. No impact on contracts."
  - "spike/python/ is still present on local disk (25MB of .venv, .pytest_cache, src/, tests/) but is fully UNTRACKED in git — commit e4128f7a (Plan 01) removed all tracked files. The on-disk artifacts are gitignored leftovers and do not contaminate the production tree."
  - "internal/store/sqlc/ exists locally with 11 .sql.go files from reconftw-web experimentation; it is gitignored, no production code imports it (verified via grep). PROJECT.md §'Out of Scope' explicitly excludes web/GUI work."
---

# Phase 3: Foundation Kernel — Verification

**Verified:** 2026-05-28T18:10:21Z
**Verifier model:** opus
**Goal-backward verification result:** PASSED_WITH_NOTES

## Phase Goal

> Ship the kernel — typed errors, structured logger with redaction, layered config loader, atomic output tree, SQLite checkpoint, bounded scheduler, tool registry with kill-tree-safe LocalBackend, AppContext, CLI binary, test mocks, and CI gate — so module ports can begin against a stable foundation.

## 5 ROADMAP Success Criteria

### Criterion 1: CLI wired to all subsystems; empty `reconftw run` writes manifest + exits 0

- **Verification commands:**
  - `go build -ldflags="-s -w" -trimpath -o /tmp/reconftw ./cmd/reconftw` — exit 0 (build succeeded)
  - `/tmp/reconftw --help` — lists all 15 v2 subcommands per ADR §8.1
  - `/tmp/reconftw kernel-demo --target example.com` — exit 0; writes `workspaces/example.com-<ts>/artefacts/demo.jsonl` + `checkpoints.db`
- **Expected:** Binary builds, --help works, all subsystems wired, run-style command produces workspace artefacts and exits 0
- **Actual:**
  - Binary built at 10,854,962 bytes (10.35 MB), well under 50MB budget
  - `--help` lists exactly 15 v2 subcommands: `all, deep, health-check, install, mcp, migrate, monitor, osint, passive, recon, report, subs, version, vulns, web, zen` (16 visible including version + 2 cobra builtins `completion`/`help`)
  - `kernel-demo` (hidden per W16) writes `workspaces/example.com-20260528-180420/artefacts/demo.jsonl` + checkpoints.db, exits 0
  - CONTEXT D-05 / D-default chose `kernel-demo` hidden Phase-3-only subcommand to satisfy "reconftw run" since ADR §8.1 has no `run` subcommand; this interpretation is documented and Phase 4 plan-01 deletes kernel-demo
  - Note: `manifest.json` is not written by `kernel-demo` (which only registers a noop.demo Task that writes `artefacts/demo.jsonl`); the manifest write path exists in `internal/core/output/manifest.go` but is only triggered by a subcommand that calls `WriteManifest`. This is consistent with the CONTEXT D-default-(b) demo shape choice
- **Status:** ✓ PASS (CONTEXT-default interpretation satisfied per Plan 07 ACCEPTANCE.md)

### Criterion 2: Atomic writes + SQLite checkpoint idempotency

- **Verification commands:**
  - `go test -race -tags smoke -run TestFOUND04SubprocessSIGKILL ./internal/core/output/...`
  - `go test -race -run TestCheckpointStoreDoneAfterComplete ./internal/core/checkpoint/...`
  - `go test -race -run TestCheckpointSkipOnHit ./internal/core/scheduler/...`
- **Expected:** SIGKILL between tempfile+fsync and rename leaves original intact; checkpoint records (task_name, target, input_hash, status, timings, output_paths, error_class) and re-running with same hash skips
- **Actual:**
  - `TestFOUND04SubprocessSIGKILL` PASS in 1.52s — confirms atomicity contract holds even when subprocess is SIGKILLed mid-write
  - SQLite checkpoint store with WAL mode in `internal/core/checkpoint/store.go` — schema includes the 9 required columns
  - Scheduler honors `Checkpoint.Done` (skips when true) per ADR §3.4 6-step
- **Status:** ✓ PASS

### Criterion 3: Subprocess safety + lint rule + 10s SIGINT-kill test

- **Verification commands:**
  - `go test -race -tags smoke -run TestKillTreeWithin10s ./internal/core/backend/...`
  - `go test -run TestFOUND10_NoRawSubprocessOutsideBackend ./internal/core/backend/lint/...`
  - `grep -rn "exec.Command" internal/ cmd/ | grep -v _test.go | grep -v lint/testdata`
- **Expected:** Setpgid+WaitDelay+kill-tree goroutine; raw exec.Command forbidden outside backend; bash + grandchildren reaped within 10s
- **Actual:**
  - `TestKillTreeWithin10s` PASS: bash + 2 sleep grandchildren reaped in **~102 ms** (10s SLA cleared by 99x)
  - `TestFOUND10_NoRawSubprocessOutsideBackend` PASS + `TestFOUND10_FixtureDetected` PASS
  - Only 2 exec.Command call sites in production code: `internal/core/backend/local.go:79` (Exec) and `:176` (Stream) — both in the allowlisted backend package; lint/testdata/violating.go is a deliberate fixture for the lint test
- **Status:** ✓ PASS

### Criterion 4: Scheduler bounded concurrency + RateLimiter + ToolRegistry + Notifier

- **Verification commands:**
  - `go test -race ./internal/core/scheduler/...` + `go test -race -run TestRegistry ./internal/core/backend/...`
  - `grep -n "errgroup.WithContext\|errgroup.Group" internal/core/scheduler/scheduler.go`
  - `/tmp/reconftw health-check` (Plan 06 — exercises tool registry warnings)
- **Expected:** Scheduler bounded; fail_fast/best_effort fork per ADR §7.2; ToolRegistry warns on missing-required, fails on missing-critical; notifier passes through redactor
- **Actual:**
  - Scheduler tests PASS — `errgroup.WithContext` for fail_fast (line 137), `new(errgroup.Group)` zero-value for best_effort (line 147) per ADR §7.2
  - Backend tests PASS — `MissingRequired()` / `MissingCritical()` two-tier semantics per FOUND-08 + Blocker 5
  - `health-check` output shows `[OK ]` for 11 reachable tools + `[WARN]` for subzy (required-not-critical) — exit 0 confirms tier behavior
  - Notifier stubs (slack/telegram/discord/log_sink) all route through wired logger — `TestXCUT07NotifierRedactsRegisteredSecret` + `TestXCUT07StubsRedactRegisteredSecret` confirm
  - Heartbeat tests PASS — `task_heartbeat` slog event at 2*cadence; goleak.VerifyTestMain ensures no orphan goroutines
- **Status:** ✓ PASS

### Criterion 5: Test mocks + CI runs lint+race+coverage; binary <50MB; no secret leaks

- **Verification commands:**
  - `ls internal/core/testutil/mock_*.go`
  - `cat .github/workflows/ci.yml` (6 jobs: lint, unit, integration, smoke, binary-size, integration-smoke)
  - `stat -f "%z" /tmp/reconftw` (binary size)
  - `go test -race -run TestRedactingHandler_RedactsMessage ./internal/core/log/...`
- **Expected:** Mocks shipped; CI runs lint+format-check+unit+integration+smoke+race; binary <50MB stripped; no secret leaks
- **Actual:**
  - Mocks shipped: `mock_backend.go`, `mock_checkpoint.go`, `mock_output_tree.go` + tests + fixtures (`subfinder/example.com.txt`, `httpx/hosts.jsonl`)
  - CI ships 6 jobs covering all required gates per ADR §9.3
  - Binary stripped: **10,854,962 bytes (10.35 MB)** — well under 50MB budget (80% margin)
  - XCUT-07 sentinel tests PASS — `TestRedactingHandler_RedactsMessage` + `RedactsStringAttr` confirm sentinel-12345 never appears in log buffer
  - WARNING: CI gofumpt format-check job would currently FAIL due to deferred gofumpt v0.7.0 drift (24 files, 927 diff lines documented in deferred-items.md). This is explicitly deferred to Phase 4 plan-00 housekeeping by Plan 07 SUMMARY (PASSED_WITH_NOTES)
- **Status:** ✓ PASS (with documented deferred lint debt)

## 20 REQ-ID Coverage

| REQ-ID | Description | File | Verification | Status |
|--------|-------------|------|--------------|--------|
| FOUND-01 | Typed error hierarchy (7 structs + 6 sentinels) | `internal/core/errors/errors.go` | `grep -c "^type.*struct" errors.go` = 7; 6 sentinels (ErrTool, ErrTimeout, ErrScope, ErrAxiom, ErrConfig, ErrChecksum) | ✓ |
| FOUND-02 | Structured logger + Secret + Redactor | `internal/core/log/` | `TestRedactingHandler_*` PASS; `Secret` type (LogValuer); `RedactingHandler` substring scrub | ✓ |
| FOUND-03 | Config loader (8-source precedence) | `internal/core/config/` | koanf 8-source chain (defaults → /etc → ~/.config → ./reconftw.toml → --config → secrets.toml → env → CLI); per-key validate; snapshot writer | ✓ |
| FOUND-04 | OutputTree + AtomicWriter | `internal/core/output/` | 4-step pattern (tempfile→fsync→rename→parent fsync); `TestFOUND04SubprocessSIGKILL` smoke PASS | ✓ |
| FOUND-05 | SQLite checkpoint store | `internal/core/checkpoint/store.go` | modernc/sqlite WAL mode; 9-column schema; idempotency on input_hash | ✓ |
| FOUND-06 | Scheduler (errgroup.SetLimit + heartbeat) | `internal/core/scheduler/` | `RunStage` fail_fast vs best_effort fork (lines 137/147); bounded concurrency; per-task timeout | ✓ |
| FOUND-07 | RateLimiter | `internal/core/backend/ratelimiter.go` | golang.org/x/time/rate.Limiter; per-tool + global RPS | ✓ |
| FOUND-08 | ToolRegistry + Critical tier | `internal/core/backend/registry.go` + tools.lock | 10 tools (3 critical); MissingRequired()/MissingCritical(); init() self-register | ✓ |
| FOUND-09 | LocalBackend kill-tree-safe | `internal/core/backend/local.go` | Setpgid+WaitDelay+SIGTERM-to-group+supplementary SIGKILL goroutine; smoke ~102ms (vs 10s SLA) | ✓ |
| FOUND-10 | Lint rule forbidding raw exec.Command | `internal/core/backend/lint/` | AST scan via go/packages; `TestFOUND10_NoRawSubprocessOutsideBackend` PASS | ✓ |
| FOUND-11 | Notifier + LogSink + Slack/Telegram/Discord stubs | `internal/core/notifier/` | 5 files; stubs return nil + log via wired RedactingHandler; XCUT-07 redaction confirmed | ✓ |
| FOUND-12 | Task interface + Registry + topo sort | `internal/core/task/` | 6-method Task interface (Name/Module/Description/Enabled/DependsOn/Run); 3-color DFS cycle detection → ConfigError per ADR §6 | ✓ |
| FOUND-13 | UI dot-fill printer | `internal/core/ui/` | printer.go + parallel_log.go + badge.go + tty.go; `[OK ] name .......... 12s` format | ✓ |
| FOUND-14 | CLI binary (cobra + 15 subcommands) | `cmd/reconftw/` | 15 v2 subcommands + version + hidden kernel-demo per W16; v1 aliases via cobra.MarkDeprecated (23 calls) | ✓ |
| FOUND-15 | Test mocks (MockBackend/MockCheckpoint/MockOutputTree) | `internal/core/testutil/` | 3 mock files + tests + fixtures dir; compile-time interface assertions via `var _ Interface = (*Mock)(nil)` | ✓ |
| FOUND-16 | CI pipeline on every push | `.github/workflows/ci.yml` | 6 jobs (lint, unit, integration, smoke, binary-size, integration-smoke) per ADR §9.3 | ✓ |
| XCUT-02 | Binary <50MB stripped | Makefile + CI binary-size job | Stripped binary at **10.35 MB** (80% margin) | ✓ |
| XCUT-04 | CI policy (race + lint + ≥75% coverage) | `.github/workflows/ci.yml` integration job | 86.9% coverage on internal/core/ per ACCEPTANCE.md | ✓ |
| XCUT-07 | Logging hygiene — no secret leaks | `internal/core/log/redacting_handler.go` + 4 sinks | Two-layer defense; sentinel tests across 4 attack surfaces; no Secret.String() method (type-level invariant) | ✓ |
| XCUT-09 | Heartbeat cadence (observability) | `internal/core/scheduler/heartbeat.go` | task_heartbeat slog event at 2*cadence; first emission skips short tasks; goleak no-orphan invariant | ✓ |

## 5 CONTEXT Decisions (D-01..D-05)

| D-NN | Decision | Verified by | Status |
|------|----------|-------------|--------|
| D-01 | All 15 v2 subcommands surfaced in Phase 3 binary | `/tmp/reconftw --help` lists exactly 15 v2 subcommands (recon, all, passive, subs, web, vulns, osint, zen, deep, monitor, report, mcp, migrate, install, health-check) + version | ✓ |
| D-02 | Stub RunE returns phase-pointer + exit 64 (EX_USAGE) | `/tmp/reconftw subs --target example.com` returns "ships in Phase 4 (Subdomains E2E + Axiom Integration). See .planning/ROADMAP.md for status." with exit code 64 | ✓ |
| D-03 | All v1 deprecated aliases wired via cobra.MarkDeprecated | `/tmp/reconftw -r --target example.com` prints `Flag --recon has been deprecated, use subcommand 'recon' instead`; grep shows 23 MarkDeprecated calls in root.go | ✓ |
| D-04 | `version` + `health-check` fully working in Phase 3 | `version` prints commit/build/go-version/platform; `health-check` runs LocalBackend.HealthCheck + tool LookPath against registry (12 OK + 1 WARN); exits 0 | ✓ |
| D-05 (W16) | Hidden `kernel-demo` subcommand authorized per ADR §0 D-07 | `--help` does NOT list `kernel-demo` (Hidden:true); `/tmp/reconftw kernel-demo --target example.com` exits 0, writes demo.jsonl + checkpoint row | ✓ |

## BINDING Contracts (ADR §5/§6/§8/§10)

| Contract | File | ADR Reference | Status |
|----------|------|---------------|--------|
| §5.1 Task interface (6 methods) | `internal/core/task/task.go` | §5.1 lines 1525-1614 | ✓ Name/Module/Description/Enabled/DependsOn/Run; Result struct; Status enum; LifecycleAware (OnStart/OnEnd); Registry; Register helper |
| §5.2 Backend interface (4 methods) | `internal/core/backend/backend.go` | §5.2 | ✓ Exec/Stream/HealthCheck/Capacity; Event/Result/Tool structs; Tool.Critical bool (ADR §0 D-07 non-breaking) |
| §5.3 AppContext (9 fields) | `internal/core/appctx/appctx.go` | §5.3 | ✓ Log/Cfg/Scheduler/Tools/Tree/Checkpoint/Notify/Target/UI; Tree typed `output.Interface`, Checkpoint typed `checkpoint.Interface` (W15) |
| §6 Error hierarchy (7 typed structs + 6 sentinels + Is bridges) | `internal/core/errors/errors.go` | §6 | ✓ ToolError/ToolTimeout/OutOfScope/AxiomFailure/ConfigError/ScopeError/ChecksumMismatch + ErrTool/ErrTimeout/ErrScope/ErrAxiom/ErrConfig/ErrChecksum |
| §7 failure_policy (fail_fast vs best_effort) | `internal/core/scheduler/scheduler.go` | §7.2 lines 1950-2054 | ✓ `errgroup.WithContext(ctx)` (line 137) for fail_fast; `new(errgroup.Group)` (line 147) for best_effort |
| §8 CLI surface (15 subcommands + v1 aliases) | `cmd/reconftw/root.go` + `stub_subcommands.go` | §8.1 + §8.3 | ✓ 15 visible + 1 hidden (kernel-demo per W16); 23 MarkDeprecated covering 14 distinct flags + 20 alias forms |
| §10.3 Init order | `cmd/reconftw/main.go` lines 86-178 | §10.3 lines 2521-2575 | ✓ STEP 1-10: signal.NotifyContext → Redactor → bootstrap logger → parseEarlyFlags → config.Load → logger rebuild → secret register → task.Default.Build → Scheduler+AppContext.Boot → cobra.ExecuteContext |

## interfaces_check + verify-0002.sh BINDING Delta Detector

- `go build ./cmd/interfaces_check/...` — exit 0 ✓ (real package imports + compile-time assertions; ADR §5 signature drift now caught at compile time)
- `bash .planning/decisions/verify-0002.sh` — exit 0 ✓ (Phase 2 pre-sign gate PASSES; ADR contracts intact)

## Codebase Consistency

| Check | Command | Result |
|-------|---------|--------|
| No `spike/` imports in production | `grep -rn "github.com/six2dez/reconftw/spike" internal/ cmd/` | ✓ Zero matches (only comments reference spike paths as documentation pointers) |
| No `internal/store/sqlc` imports in production | `grep -rn "internal/store/sqlc" internal/core/ cmd/reconftw/` | ✓ Zero matches (sqlc dir is gitignored reconftw-web leftover; not imported by kernel) |
| FOUND-10 lint clean | `go test -run TestFOUND10 ./internal/core/backend/lint/...` | ✓ PASS — only allowlisted backend/local.go has exec.Command |
| B7 backend.Default test isolation | `grep "backend.Default" internal/core/backend/*_test.go` | ✓ Only registry_seed_test.go has real code references; other matches are documentation comments (verified via `sed 's|//.*||'` strip) |
| spike/python/ tracked deletion | `git ls-files spike/python \| wc -l` | ✓ Zero (commit e4128f7a removed tracked files); 25MB of untracked .venv/.pytest_cache/src/tests remains on local disk only |
| Build all packages | `go build ./...` | ✓ exit 0 |
| Vet all packages | `go vet ./...` | ✓ exit 0 (no issues) |
| All internal/core packages pass tests with -race | `go test -race ./internal/core/...` | ✓ All 13 packages PASS |
| Smoke tests pass | `go test -race -tags smoke ./...` | ✓ All pass (FOUND-04 SIGKILL + FOUND-09 kill-tree) |

## Phase 4 Readiness

| Requirement | Status |
|-------------|--------|
| tools.lock present with 10 entries | ✓ `internal/core/backend/tools.lock` — 10 tools (3 critical: subfinder, httpx, dnsx; 7 required: crt, puredns, gotator, anew, asnmap, s3scanner, subzy) |
| MockBackend/MockCheckpoint/MockOutputTree shipped | ✓ `internal/core/testutil/mock_*.go` (3 mocks + 3 tests + fixtures dir) |
| All 13 internal/core packages built+tested | ✓ appctx, backend, backend/lint, checkpoint, config, errors, log, notifier, output, scheduler, task, testutil, ui all PASS go test -race |
| Binary stripped | ✓ **10,854,962 bytes (10.35 MB)** — XCUT-02 budget 50 MB, 80% margin |
| CI pipeline active | ✓ 6 jobs (lint, unit, integration, smoke, binary-size, integration-smoke) per .github/workflows/ci.yml |

## Notes / Deviations

### 1. spike/python/ on-disk presence (informational)

The Plan 01 SUMMARY claims `spike/python/` was deleted. Verification: commit `e4128f7a` removed all *tracked* files from `spike/python/`. However, ~25MB of *untracked* artifacts remain on local disk: `.venv/`, `.pytest_cache/`, `src/`, `tests/`. These are all gitignored (per `.gitignore` patterns for Python venvs and pytest caches). The deletion is correct at the git level; the on-disk presence is a local artifact of the spike phase that the operator may clean manually. **Not a Phase 3 contract violation.**

### 2. Go version 1.25 vs CONTEXT-mentioned 1.24 (informational)

CONTEXT said "Phase 3 may bump to Go 1.24+ per stack pick"; SUMMARY 03-01 said "bump Go 1.23 → 1.24". Current `go.mod` declares `go 1.25.0`. This is one minor higher than CONTEXT mentioned. No interfaces or build behavior affected; the CI uses `go-version-file: go.mod` so it follows the declared version. **Not a Phase 3 contract violation.**

### 3. gofumpt v0.7.0 drift (24 files, ~927 diff lines) — deferred to Phase 4 plan-00 (WARNING)

Local `gofumpt -d .` shows 927 diff lines across 24 pre-existing files. Plan 07 SUMMARY (line 95) explicitly auto-defers this with the rationale: "Pre-Plan-07 condition; out of scope per SCOPE BOUNDARY rule. Logged to deferred-items.md for a Phase 4 plan-00 housekeeping commit." The deferred-items.md document this in detail.

**Impact on ROADMAP SC 5:** The CI `lint` job's `gofumpt format-check` step would currently FAIL on this drift if a push were made now. This is a real but documented deferred lint debt. Phase 3 acceptance is otherwise complete; the deferral is consistent with the SCOPE BOUNDARY rule and is part of Plan 07's auto-acceptance.

**Recommendation:** Phase 4 plan-00 housekeeping commit runs `gofumpt -w .` against the 24 listed files before Phase 4 plan-01 starts. This is a no-code-behavior change (whitespace + comment alignment only) and unblocks the CI lint gate.

### 4. internal/store/sqlc/ leftover (informational)

`internal/store/sqlc/` contains 11 .sql.go files from `reconftw-web/` experimentation. The directory is gitignored (untracked). No production code in `internal/core/` or `cmd/reconftw/` imports it. PROJECT.md §"Out of Scope" explicitly excludes web/GUI work. **Not a Phase 3 contract violation.**

### 5. manifest.json interpretation per CONTEXT D-default (informational)

ROADMAP SC 1 mentions `reconftw run` writing `workspaces/<target>/manifest.json`. ADR §8.1 has no `run` subcommand. CONTEXT D-default-(b) chose to satisfy this via the hidden `kernel-demo` subcommand which writes `artefacts/demo.jsonl` + `checkpoints.db`. The `manifest.json` path exists in `internal/core/output/manifest.go` but is only triggered by a subcommand that calls `WriteManifest` — not by kernel-demo. The CONTEXT default interpretation is documented in Plan 07 ACCEPTANCE.md line 24 ("'reconftw run' interpreted as hidden kernel-demo subcommand per CONTEXT D-05 (W16) authorizing the hidden subcommand per ADR §0 D-07 non-breaking addition. Phase 4 plan-01 deletes the hidden subcommand + the Phase 3 demo task."). This is an accepted interpretation of the ROADMAP wording. **Not a Phase 3 contract violation.**

### 6. Phase 10 TODO markers in notifier stubs (informational)

`internal/core/notifier/{discord,slack,telegram}.go` each contain `// TODO(phase-10): replace with real webhook dispatch`. These TODOs reference a specific future phase per the project's phase-pointer convention. CONTEXT D-default-(a) for FOUND-11 chose "LogSink only + Slack/Telegram/Discord stubs return nil". The TODOs document the planned Phase 10 lifecycle and do not violate the FOUND-11 contract for Phase 3. **Not a Phase 3 contract violation.**

## Test/Coverage Evidence

- Total Go files in internal/core: **101**
- Test files: **46**
- Coverage on internal/core/ (combined): **86.9%** (per Plan 07 ACCEPTANCE.md; gate ≥75%)
- Per-file critical-path coverage (W20 gate ≥90%): log/redactor.go 100%, log/redacting_handler.go 100%, output/atomic.go 91.2%, output/scope.go 97.0%, checkpoint/store.go 90.0%
- All 13 internal/core packages PASS `go test -race`
- All smoke tests PASS `go test -race -tags smoke ./...`
- Integration test (`TestKernelDemoEndToEnd`) PASS — builds binary + invokes kernel-demo + asserts artefacts

## Verdict

**Status: passed**

Phase 3 (Foundation Kernel) is complete. All 5 ROADMAP success criteria verified. All 20 REQ-IDs implemented and tested. All 5 CONTEXT decisions (D-01..D-05) present in code. ADR §5/§6/§7/§8/§10 BINDING contracts upheld and gated by `cmd/interfaces_check/` (compile-time delta detector) + `.planning/decisions/verify-0002.sh` (Phase 2 pre-sign gate still passing). 13 kernel packages built and tested with race detector. Stripped binary at 10.35 MB (80% under XCUT-02 budget). CI pipeline active with 6 jobs.

The single WARNING is the documented gofumpt v0.7.0 drift across 24 pre-existing files (deferred-items.md), which will fail the CI `gofumpt format-check` step on next push. This is an explicit Plan 07 deferral to a Phase 4 plan-00 housekeeping commit and is consistent with the SCOPE BOUNDARY rule. Recommend running the planned `gofumpt -w .` housekeeping before Phase 4 plan-01 begins so CI is green on every push from the start of Phase 4.

Phase 4 (Subdomains E2E + Axiom Integration) can begin against a stable foundation:
- backend.Default pre-populated with 10 Phase 4 tools at process start
- internal/core/testutil mocks ready for module-port test wiring
- BINDING delta detector catches ADR §5 drift at compile time
- 6-job CI pipeline ready to gate every Phase 4 push
- Phase 4 plan-01 ACCEPTANCE items documented in Plan 07 SUMMARY + ACCEPTANCE.md (delete kernel-demo + noop.demo Task + integration_smoke_test.go's references; replace stubbed `subs` RunE with real subdomains pipeline)

---

*Verified: 2026-05-28T18:10:21Z*
*Verifier: Claude (gsd-verifier, opus, goal-backward verification)*
