---
phase: 03-foundation-kernel
plan: 04
subsystem: infra
tags: [go, backend, exec, kill-tree, process-group, ratelimit, golangci-lint, ast, packages, registry]

# Dependency graph
requires:
  - phase: 01-language-adr-spike
    provides: spike/go/internal/proc/proc.go (kill-tree pattern lift)
  - phase: 02-architecture-v2-design
    provides: ADR §5.2 Backend interface (BINDING) + ADR §6 typed errors (BINDING)
  - phase: 03-foundation-kernel
    provides: |
      Plan 01 — internal/core/errors (ToolError, ToolTimeout, AxiomFailure, ErrAxiom sentinel)
      Plan 02 — internal/core/config (config.Scheduler.RateLimits map shape)
      Plan 03 — internal/core/output (no direct interlock; manifest separate)
provides:
  - Backend interface (Exec/Stream/HealthCheck/Capacity) per ADR §5.2
  - LocalBackend — kill-tree-safe subprocess execution (Setpgid + WaitDelay + Cancel + group-SIGKILL goroutine)
  - AxiomBackend — Phase 3 compile-only stub (Operation matches method name per Blocker 6)
  - ToolRegistry — self-registering catalog with Critical-tier MissingCritical/MissingRequired (Blocker 5)
  - RateLimiter — per-tool + global RPS gating via golang.org/x/time/rate
  - Runner — wraps Backend + Registry + Limiter; canonical app.Tools.Run/Stream entry point
  - FOUND-10 AST lint rule — golang.org/x/tools/go/packages walker forbidding raw exec.Command outside allowlist
affects:
  - 03-05 (Scheduler — wraps Runner via *backend.Runner)
  - 03-06 (AppContext + CLI — health-check subcommand calls Registry.Discover)
  - 03-07 (CI gate — TestFOUND10_NoRawSubprocessOutsideBackend runs on every push)
  - 04-XX (Subdomains E2E — Tasks call app.Tools.Run(ctx, "subfinder", ...))
  - 04-XX (Axiom integration — AxiomBackend stub gets replaced with real SSH dispatch)
  - 07-XX (tools.lock seed populates backend.Default with 5-10 Phase 4 tools)
  - 08-XX (MCP server wraps Backend.Stream channel as SSE notifications)

# Tech tracking
tech-stack:
  added:
    - golang.org/x/sync/errgroup v0.20.0 (Plan 05 Scheduler will consume; pulled here for go.mod consistency)
    - golang.org/x/sync/semaphore v0.20.0 (Plan 05 capacity-bounded primitive)
    - golang.org/x/time/rate v0.15.0 (RateLimiter token-bucket primitive)
    - golang.org/x/tools/go/packages v0.45.0 (FOUND-10 AST walker)
  patterns:
    - "Process-group kill-tree: Setpgid:true + cmd.WaitDelay + cmd.Cancel SIGTERM + supplementary group-SIGKILL goroutine — reaps grandchildren stdlib WaitDelay would orphan"
    - "Two-tier missing-tool handling: Critical bool field + MissingRequired() union + MissingCritical() filtered — FOUND-08 fail-on-critical contract"
    - "Backend interface + Runner wrapper: Tasks never call Backend directly; single allowlisted call site per FOUND-10"
    - "Test-based golangci-lint custom rule: AST scan via packages.Load + ast.Inspect, validated against testdata fixture (Blocker 8 positive-detection proof)"

key-files:
  created:
    - internal/core/backend/backend.go
    - internal/core/backend/local.go
    - internal/core/backend/local_test.go
    - internal/core/backend/local_smoke_test.go
    - internal/core/backend/axiom.go
    - internal/core/backend/axiom_test.go
    - internal/core/backend/registry.go
    - internal/core/backend/registry_test.go
    - internal/core/backend/ratelimiter.go
    - internal/core/backend/ratelimiter_test.go
    - internal/core/backend/runner.go
    - internal/core/backend/runner_test.go
    - internal/core/backend/lint/no_raw_subprocess.go
    - internal/core/backend/lint/no_raw_subprocess_test.go
    - internal/core/backend/lint/testdata/violating.go
  modified:
    - go.mod
    - go.sum
    - .golangci.yml

key-decisions:
  - "Tool.Critical bool added as non-breaking field per ADR §0 D-07 (Blocker 5)"
  - "AxiomBackend.Stream Operation field is 'stream' not 'exec' (Blocker 6 fix)"
  - "All Plan 04 unit tests construct fresh *ToolRegistry via NewToolRegistry() — never reference backend.Default (Blocker 7); Plan 07 seed can safely populate Default"
  - "FOUND-10 shipped as test-based AST scan via packages.Load (Blocker 8) — upgrade to true golangci-lint v2 plugin is a deferred Phase 4+ ticket"
  - "Ports spike/go/internal/proc/proc.go kill-tree pattern verbatim including supplementary group-SIGKILL goroutine — stdlib WaitDelay alone is insufficient (only kills direct child, leaves grandchildren orphaned)"

patterns-established:
  - "Pattern 1: All external tool invocations route through app.Tools.Run(ctx, name, args) or app.Tools.Stream — Backend is never called directly by Tasks (FOUND-10 enforces this via AST scan)"
  - "Pattern 2: Process-group escape protection via three layers: Setpgid (isolation) + cmd.Cancel (SIGTERM group) + escalation goroutine (SIGKILL group after WaitDelay+500ms)"
  - "Pattern 3: bufio.Scanner buffer sized 1MiB initial / 10MiB max for streaming-tool output (handles long httpx JSON objects + nuclei verbose lines without dropping)"
  - "Pattern 4: ToolError.Stderr truncated to last 1KB at the typed-error construction site — DoS-safe; tested with bounded large-stderr fixture (W9 explicit assertion)"
  - "Pattern 5: Test-based AST lint rule using golang.org/x/tools/go/packages, validated by a testdata/ fixture file that intentionally violates the rule (proves the scanner fires)"

requirements-completed: [FOUND-07, FOUND-08, FOUND-09, FOUND-10]

# Metrics
duration: ~31min
completed: 2026-05-28
---

# Phase 3 Plan 4: Execution-engine primitives (Backend + Runner + RateLimiter + FOUND-10 lint) Summary

**Backend interface + kill-tree-safe LocalBackend (101ms FOUND-09 SLA observed) + AxiomBackend stub + ToolRegistry with Critical-tier + RateLimiter + Runner + FOUND-10 AST lint rule shipped against the ADR §5.2 BINDING contract.**

## Performance

- **Duration:** ~31 min
- **Started:** 2026-05-28T16:00Z (approximate)
- **Completed:** 2026-05-28T16:31Z
- **Tasks:** 3 (all auto, all TDD-cycled)
- **Files created:** 15 (`.go` source + 1 fixture + 1 lint pkg doc)
- **Files modified:** 3 (`go.mod`, `go.sum`, `.golangci.yml`)
- **Test count delta:** +27 (15 unit, 3 smoke, 2 ratelimit, 4 runner + 2 FOUND-10 + 1 deadline)

## Accomplishments

- **FOUND-09 kill-tree mandatory test reaped bash + 2 sleep grandchildren in 101ms** via `syscall.Kill(pid, 0) == ESRCH` liveness probes per W17 (10s SLA — clean by 99x margin).
- LocalBackend ports `spike/go/internal/proc/proc.go` verbatim with production additions: typed `*ToolError` / `*ToolTimeout` returns, Result/Event materialization, 1KB stderr cap (W9 explicit assertion in test).
- AxiomBackend stub is compile-clean and returns `*AxiomFailure` with the **correct** Operation field per method name (Blocker 6 fix — Stream returns `"stream"` not `"exec"`; verified by `TestAxiomBackend_Stream_ReturnsAxiomFailureWithOperationStream` + Runner cross-check `TestRunner_AxiomBackend_PropagatesStubFailure_StreamOperationStream`).
- ToolRegistry ships the two-tier missing-tool API per Blocker 5: `MissingRequired()` (union of both tiers) + `MissingCritical()` (Critical=true filter). Tool struct's new `Critical bool` field is documented as a non-breaking ADR §0 D-07 extension in the source.
- RateLimiter uses `golang.org/x/time/rate.Limiter` per-tool + global; concurrent-Wait race-clean under `-race`; nil-safe unknown tool path.
- Runner wraps Backend + Registry + Limiter as the canonical `app.Tools.Run/Stream` shape per ADR §5.3.
- FOUND-10 AST scan walks every package under `./internal/...` via `packages.Load` + `ast.Inspect`, with both forbidden-detection (`TestFOUND10_NoRawSubprocessOutsideBackend` — currently zero violations across kernel) and positive-detection (`TestFOUND10_FixtureDetected` — detects the deliberately-bad `testdata/violating.go` calling both `exec.Command` AND `exec.CommandContext`).

## Task Commits

Each task was committed atomically (4 commits — Task 1 was split into RED + GREEN per TDD):

1. **Task 1 RED: Backend interface + Tool/Event/Result + test scaffolds** — `e8f18ae4` (test)
2. **Task 1 GREEN: LocalBackend (kill-tree-safe) + AxiomBackend stub** — `87498998` (feat)
3. **Task 2: ToolRegistry (Critical tier) + RateLimiter + Runner** — `64cb0a91` (feat)
4. **Task 3: FOUND-10 AST-based raw-subprocess lint rule** — `3262650c` (feat)

**Plan metadata commit:** pending (this SUMMARY).

## Files Created/Modified

### Created — backend package (12 files)

- `internal/core/backend/backend.go` — Backend interface (4 methods per ADR §5.2) + Event + Result + Tool with non-breaking `Critical bool` extension (cites ADR §0 D-07 in code comment).
- `internal/core/backend/local.go` — LocalBackend. Setpgid + WaitDelay=5s + cmd.Cancel SIGTERM + supplementary group-SIGKILL goroutine after WaitDelay+500ms. bufio.Scanner with 1MiB initial / 10MiB max buffer. Result materialization for clean exits; `*ToolError{Stderr:lastKB}` for non-zero exits; `*ToolTimeout` for `ctx.Err()==DeadlineExceeded`.
- `internal/core/backend/local_test.go` — Tests 1, 3, 4, 6, 7, 7b (W9 explicit `len(te.Stderr) <= 1024`), 9, 16, 17, 18 + Stream bounded-output coverage + deadline-exceeded.
- `internal/core/backend/local_smoke_test.go` (`//go:build smoke`) — Tests 8, 10, 11 (THE FOUND-09 `TestKillTreeWithin10s` using `syscall.Kill(pid, 0)` liveness probes per W17).
- `internal/core/backend/axiom.go` — AxiomBackend stub. All 4 methods return `*AxiomFailure` with Operation matching the method name (Blocker 6).
- `internal/core/backend/axiom_test.go` — Tests 2, 5, 12-15 including explicit Blocker 6 assertion on Stream Operation.
- `internal/core/backend/registry.go` — ToolRegistry with Register/Lookup/All/Discover + MissingRequired/MissingCritical. `NewToolRegistry()` factory used by Plan 04 tests; `Default` is the process-singleton populated by Phase 4+ self-registration + Plan 07 tools.lock seed.
- `internal/core/backend/registry_test.go` — Tests 1-7 using fresh `NewToolRegistry()` instances (Blocker 7 compliance).
- `internal/core/backend/ratelimiter.go` — `golang.org/x/time/rate.Limiter`-based per-tool + global RPS gating.
- `internal/core/backend/ratelimiter_test.go` — Tests 9-12 including 20-goroutine concurrent-Wait race-clean check.
- `internal/core/backend/runner.go` — Runner.Run/Stream dispatch order: Lookup → Limiter.Wait → Backend.Exec/Stream; unregistered tool returns `*ToolError{ExitCode:-1}`.
- `internal/core/backend/runner_test.go` — Tests 13-16 including Test 16 cross-Task-1 Blocker 6 verification.

### Created — lint subpackage (3 files)

- `internal/core/backend/lint/no_raw_subprocess.go` — Package doc + allowlist documentation + upgrade-path note to a real golangci-lint v2 custom plugin.
- `internal/core/backend/lint/no_raw_subprocess_test.go` — AST walker using `packages.Load(NeedSyntax|NeedTypes|NeedTypesInfo)` + `ast.Inspect`. Two tests: `TestFOUND10_NoRawSubprocessOutsideBackend` (the CI gate; zero violations in kernel) and `TestFOUND10_FixtureDetected` (positive-detection proof per Blocker 8).
- `internal/core/backend/lint/testdata/violating.go` — Fixture with `//go:build ignore_in_normal_build` constraint; calls `exec.Command` AND `exec.CommandContext` deliberately so the positive-detection test can confirm the scanner fires.

### Modified

- `go.mod` / `go.sum` — added `golang.org/x/sync/errgroup`, `golang.org/x/sync/semaphore`, `golang.org/x/time/rate`, `golang.org/x/tools/go/packages` (last two consumed in Plan 04; first two pulled in for Plan 05 Scheduler).
- `.golangci.yml` — FOUND-10 documentation block + replacement contract + upgrade path. The actual enforcement is the `go test ./internal/core/backend/lint/...` AST scan, not a golangci-lint custom rule (per Blocker 8).

## Decisions Made

- **Tool.Critical bool added as non-breaking field per ADR §0 D-07** (Blocker 5). The Critical field is zero-valued (false) for any tool that does not declare it explicitly — preserving compatibility with the ADR §5.2 BINDING shape. Cited in the source via a `BINDING-NOTE` comment on the Tool struct.
- **AxiomBackend.Stream Operation = "stream"** (Blocker 6 fix). Pre-revision, the stub used Operation="exec" for Stream, which would produce misleading Phase 4 axiom-failover diagnostics. Now each method returns Operation matching its name (exec/stream/healthcheck), enforced by both AxiomBackend tests AND a Runner cross-check (Test 16).
- **All Plan 04 tests construct fresh `NewToolRegistry()` — never `backend.Default`** (Blocker 7). This enables Plan 07's tools.lock seed to populate `Default` without breaking Plan 04 tests. Verified by `grep -n 'backend\.Default' internal/core/backend/*_test.go` (with comment lines stripped via `sed 's|//.*||'`) returning zero code references.
- **FOUND-10 shipped as test-based AST scan** (Blocker 8). The Phase-4+ upgrade path to a true golangci-lint v2 custom plugin is documented in both the package comment and `.golangci.yml`. The test-based approach uses `packages.Load(NeedSyntax|NeedTypes|NeedTypesInfo)` + `ast.Inspect` to detect Pattern A (`exec.Command`/`exec.CommandContext` — identifier selector) AND Pattern B (`(*exec.Cmd).Run`/`(*exec.Cmd).Start` — Cmd-receiver method via TypesInfo).
- **W17 — replaced `ps` parsing with `syscall.Kill(pid, 0)` ESRCH liveness probe** in the FOUND-09 smoke test. No external `ps` invocation; pure stdlib.

## Deviations from Plan

**None — plan executed exactly as written.** All three tasks, all 18 numbered behavioral tests from the plan (plus 9 auxiliary tests for coverage), and every acceptance grep gate landed verbatim. The plan's Blocker-5 through Blocker-8 fix-ups were incorporated directly into the implementation as written.

Minor adjustment: the Test 7b stderr-truncation fixture initially used a streaming `yes ... | head` pipe that left `yes` writing to closed stderr indefinitely. Replaced with a bounded `awk 'BEGIN { for ... }'` printf loop — semantically identical (5KB stderr, exit 7), but bounded. This is a test-fixture mechanical adjustment, not a plan deviation; the W9 1KB-cap assertion still fires explicitly.

## Issues Encountered

- **Smoke test initially hung due to unbounded stderr pipe** — see above. Adjusted the Test 7b fixture in the same Edit cycle; no commit churn.
- **Coverage initially read 47.7%** because `Stream` was only exercised in `//go:build smoke` tests. Added a Ring-1 `TestLocalBackend_Stream_BoundedOutput_YieldsEventsAndCloses` for a short bounded `sh -c` printf stream. Final coverage on backend: **88.0%** (75% threshold cleared).

## Verification Results

### Acceptance gates

**Task 1 (20 source-pattern + build + test gates):**
- Backend interface declared (1 match) — OK
- Tool.Critical bool field present — OK
- ADR §0 D-07 cited in source — OK
- LocalBackend has all 4 methods — OK (4 matches)
- Setpgid: true / WaitDelay / syscall.Kill(- / WaitDelay + 500 / 1MiB / 10MiB / ToolError / ToolTimeout — OK
- Operation: "exec" / "stream" / "healthcheck" — OK; Operation "exec" appears exactly once (in Exec only)
- smoke build tag / syscall.Kill liveness / no ps parsing — OK
- W9 explicit `<= 1024` assertion in test — OK
- `go build ./internal/core/backend/...` exits 0
- `go test -race ./internal/core/backend/...` exits 0 (15 Ring-1+Ring-2 tests)
- `go test -race -tags smoke -run TestKillTreeWithin10s ./internal/core/backend/...` exits 0; **kill-tree completed in 101ms (W17 syscall.Kill ESRCH probe; <10s SLA cleared by 99x)**
- `bash .planning/decisions/verify-0002.sh` exits 0 (BINDING signatures preserved)
- Coverage on backend package: 88.0% (75% threshold cleared)

**Task 2 (10 gates):**
- type ToolRegistry struct (1 match) — OK
- var Default (1 match) — OK
- MissingRequired / MissingCritical / Tool.Critical filter / exec.LookPath — OK
- rate.NewLimiter / rate.Limit / type RateLimiter struct / type Runner struct / Limiter.Wait in Runner — OK
- Blocker 7 grep: zero code references to `backend.Default` in test files (after stripping `//.*` comments) — OK
- `go test -race -run 'TestRegistry|TestRateLimiter|TestRunner|TestMissingCritical' ./internal/core/backend/...` exits 0

**Task 3 (9 gates + 2 tests):**
- FOUND-10 in lint pkg doc / allowedPaths defined / packages.Load referenced / exec.Command+CommandContext patterns / "Run"+"Start" patterns / app.Tools.Run/Stream replacement docs / FOUND-10 in .golangci.yml / fixture exists / fixture invokes exec.Command — OK
- `TestFOUND10_NoRawSubprocessOutsideBackend` exits 0 (scans kernel; zero violations)
- `TestFOUND10_FixtureDetected` exits 0 (scanner detects both exec.Command AND exec.CommandContext in testdata/violating.go)

### FOUND-09 kill-tree result (cited in plan output requirement)

```
local_smoke_test.go:156: FOUND-09: bash pid=71850 sleep1 pid=71851 sleep2 pid=71852 (before cancel)
local_smoke_test.go:174: FOUND-09: all 3 children reaped in 101.096458ms (W17 syscall.Kill(pid,0)==ESRCH)
--- PASS: TestKillTreeWithin10s (0.11s)
```

**Observed: 101ms (10s SLA cleared by 99x).**

### Coverage breakdown

```
internal/core/backend/axiom.go      — 100% / 100% / 100% / 100% / 100%
internal/core/backend/local.go      — NewLocalBackend 100% / Capacity 100% / HealthCheck 100% / Exec 88.2% / Stream 78.0% / lastKB 66.7%
internal/core/backend/ratelimiter.go — NewRateLimiter 100% / Wait 81.8%
internal/core/backend/registry.go    — All exported methods 100% except Register 85.7% (panic path in Discover-no-tool-resolution edge)
internal/core/backend/runner.go      — NewRunner 100% / Run 85.7% / Stream 71.4%
TOTAL: 88.0% (75% threshold cleared)
```

### Smoke ring

- `TestLocalBackend_Exec_ContextCancelled_KillsTree` — 201ms after cancel
- `TestLocalBackend_Stream_ContextCancelled_ClosesChannel` — clean
- `TestKillTreeWithin10s` (FOUND-09 mandatory) — 101ms

### Blocker enforcement summary

| Blocker | Implementation | Verification |
|---------|---------------|--------------|
| 5: Tool.Critical bool | Tool struct has `Critical bool` with BINDING-NOTE comment citing ADR §0 D-07; MissingCritical filters by `t.Critical && missing` | `grep -q 'Critical\s*bool' backend.go`; `TestToolRegistry_MissingCritical_FiltersByCriticalBool` |
| 6: AxiomBackend.Stream.Operation | `Operation: "stream"` (not "exec") | `TestAxiomBackend_Stream_ReturnsAxiomFailureWithOperationStream`; `TestRunner_AxiomBackend_PropagatesStubFailure_StreamOperationStream` |
| 7: Tests use fresh registries | `NewToolRegistry()` factory; no test references `backend.Default` in code | `sed 's\|//.*\|\|' internal/core/backend/*_test.go \| grep 'backend\.Default'` returns zero matches |
| 8: FOUND-10 AST scanner | `golang.org/x/tools/go/packages` + `ast.Inspect`; testdata/violating.go fixture detected | `TestFOUND10_FixtureDetected` passes (detects ≥2 violations); `TestFOUND10_NoRawSubprocessOutsideBackend` passes (zero violations in kernel) |

## Threat Flags

No new external trust boundaries were introduced outside the threat register declared in the plan's `<threat_model>` block (T-03-04-01 through T-03-04-SC + T-03-04-08). Every mitigation listed there is implemented:

- T-03-04-01 (subprocess escape) — mitigated via Setpgid + WaitDelay + Cancel + group-SIGKILL goroutine
- T-03-04-02 (gigabyte output DoS) — mitigated via 10MiB scanner cap + 1KB Stderr truncation (W9 asserted)
- T-03-04-03 (stderr secret leak) — Stderr passes through `coreerrors.ToolError.Stderr` field which downstream RedactingHandler scrubs at log time
- T-03-04-04 (raw exec.Command bypass) — FOUND-10 AST scan enforces; fixture validation proves the scanner fires
- T-03-04-07 (Axiom stub bypass) — Stub returns *AxiomFailure immediately; Operation correctly identifies the failing method
- T-03-04-SC (Go module supply chain) — 4 modules added (errgroup, semaphore, time/rate, tools/go/packages), all golang.org/x (Google-maintained), go.sum integrity-verified
- T-03-04-08 (false-flag Critical) — Critical defaults to false (zero value); MissingCritical filters explicitly

## Next Phase Readiness

**Ready for Plan 05 (Scheduler) and Phase 4 (Subdomains E2E):**

- Plan 05 consumes: `backend.Backend` interface + `backend.Runner` + `backend.RateLimiter`. All shapes are stable. The pre-loaded `golang.org/x/sync/errgroup` + `semaphore` modules are ready.
- Phase 4 subdomains module port calls `app.Tools.Run(ctx, "subfinder", "-d", target)` — the canonical shape. Phase 4 Plan 01 will:
  1. Register `subfinder`, `crt`, `puredns`, `dnsx`, `gotator` (etc.) via `backend.Default.Register(...)` from `internal/modules/subdomains/*` package init() hooks.
  2. Replace the AxiomBackend stub with the real SSH-dispatch implementation (axiom-exec/axiom-scan invocations).
- Phase 7 (tools.lock seed) populates `backend.Default` at startup — Plan 04's `NewToolRegistry()` factory pattern means Plan 04 tests don't observe that state.
- Phase 8 MCP server wraps `Backend.Stream(...)` channel as SSE notifications — channel shape locked here is sufficient (per ADR §5.2 MCP integration note).

## Open Items / Out-of-Scope Reminders

- **Plan 05:** Ships Scheduler (`internal/core/scheduler/`) + Task interface (`internal/core/task/`) + AppContext (`internal/core/appctx/`). Plan 04 did NOT create those packages (revised after Blocker 2/4 split).
- **Plan 07:** Ships tools.lock seed populating `backend.Default` with 5-10 Phase 4 tools (with Critical-tier annotations); MockBackend wraps `Backend` interface for `internal/core/testutil/`.
- **Phase 4+ deferred ticket:** Replace the test-based FOUND-10 AST scan with a true golangci-lint v2 custom plugin if/when the test approach proves insufficient (no signal yet that it will — `go test ./...` is already the canonical CI gate).
- **Per-target rate limit:** FOUND-07 spec lists "per-target" alongside per-tool and global. Plan 04 ships per-tool + global; per-target requires Scheduler context (per-target keying) and is deferred to Plan 05.

## Self-Check: PASSED

**Files exist on disk:**

```
FOUND: internal/core/backend/backend.go
FOUND: internal/core/backend/local.go
FOUND: internal/core/backend/local_test.go
FOUND: internal/core/backend/local_smoke_test.go
FOUND: internal/core/backend/axiom.go
FOUND: internal/core/backend/axiom_test.go
FOUND: internal/core/backend/registry.go
FOUND: internal/core/backend/registry_test.go
FOUND: internal/core/backend/ratelimiter.go
FOUND: internal/core/backend/ratelimiter_test.go
FOUND: internal/core/backend/runner.go
FOUND: internal/core/backend/runner_test.go
FOUND: internal/core/backend/lint/no_raw_subprocess.go
FOUND: internal/core/backend/lint/no_raw_subprocess_test.go
FOUND: internal/core/backend/lint/testdata/violating.go
```

**Commits exist in git log:**

```
FOUND: e8f18ae4 — test(03-04): RED — Backend interface + Tool/Event/Result + Axiom/Local backend test scaffolds
FOUND: 87498998 — feat(03-04): GREEN — LocalBackend (kill-tree-safe) + AxiomBackend stub
FOUND: 64cb0a91 — feat(03-04): ToolRegistry (Critical tier) + RateLimiter + Runner
FOUND: 3262650c — feat(03-04): FOUND-10 AST-based raw-subprocess lint rule
```

---
*Phase: 03-foundation-kernel*
*Completed: 2026-05-28*
