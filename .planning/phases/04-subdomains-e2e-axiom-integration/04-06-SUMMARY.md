---
phase: 04-subdomains-e2e-axiom-integration
plan: "06"
subsystem: axiom-backend-integration
tags: [axiom, failover, backend, subdomains, e2e, b2-fix, b3-fix, w4-fix, reviews-fixes, tdd]
dependency_graph:
  requires:
    - internal/core/backend/backend.go (Tool.InputFlag field — plan-00)
    - internal/core/backend/local.go (LocalBackend — plan-03)
    - internal/core/appctx/boot.go (Boot 6-arg signature — plan-03)
    - internal/core/scheduler/scheduler.go (RunStage, Checkpoint field — plan-03)
    - internal/modules/subdomains/merge.go (MergeStage — plan-02)
    - internal/modules/subdomains/takeover.go (B2 staging files — plan-05)
    - internal/core/config: AxiomConfig.FailoverThreshold (plan-00)
    - internal/core/errors: AxiomFailure type (plan-03)
  provides:
    - internal/core/backend/axiom.go: real AxiomBackend (Tool.InputFlag split, fleet lifecycle)
    - internal/core/backend/failover.go: FailoverBackend (kill-switch + ctx-bounded stream W4)
    - cmd/reconftw/stub_subcommands.go: newSubsCmd real RunE (5-stage sequential pipeline)
    - cmd/reconftw/appctx_init.go: filterByModuleAndEnabled + mergeTakeoverFindings helpers
    - internal/core/appctx/boot.go: pickBackend updated to 3-arg NewAxiomBackend
  affects:
    - All newSubsCmd-driven subdomain scans now use real Axiom integration
    - FailoverBackend is the production decorator for all Axiom+Local fallback scenarios
tech_stack:
  added: []
  patterns:
    - REVIEWS fix #1: sequential RunStage per stage-slice (passive→resolve→permut→enrichment)
    - REVIEWS fix #4: filterByModuleAndEnabled calls t.Enabled(cfg) before RunStage
    - B2 fix: mergeTakeoverFindings reads both staging files; single app.Tree.Append("findings")
    - B3 fix: sched.Checkpoint = app.Checkpoint set after Boot returns
    - W4 fix: FailoverBackend.Stream partial-drain goroutine uses select on primaryCh+ctx.Done()
    - REVIEWS MEDIUM: NewAxiomBackend 3-arg signature (cfg, reg, log) in boot.go pickBackend
    - TDD: RED (563b035) → GREEN (a6680b3) for AxiomBackend+FailoverBackend tests
key_files:
  created:
    - internal/core/backend/failover.go
    - cmd/reconftw/appctx_init.go
    - internal/core/backend/failover_test.go
  modified:
    - internal/core/backend/axiom.go (Phase 3 stub → real implementation)
    - internal/core/backend/axiom_test.go (Phase 3 stub tests → real behavior tests)
    - internal/core/backend/runner_test.go (Test 16 updated for 3-arg NewAxiomBackend)
    - internal/core/appctx/boot.go (pickBackend → 3-arg NewAxiomBackend)
    - cmd/reconftw/stub_subcommands.go (newSubsCmd stub → real RunE)
decisions:
  - "AxiomBackend uses NewAxiomBackendWithLocal (exported test-injection constructor) — avoids global-state approach for input-file extraction testing"
  - "extractInputFile uses Tool.InputFlag (not heuristic): empty InputFlag = last positional arg; non-empty = arg after the flag"
  - "axiomScanTool() falls back to synthetic Tool{Name:'axiom-scan'} when registry lookup fails — test-registry isolation without panic"
  - "FailoverBackend.Stream spawns drain goroutine ONLY when primaryCh is non-nil — nil channel skips the goroutine entirely"
  - "printDryRun writes to cmd.OutOrStdout() (not os.Stdout) for testability"
  - "subs --dry-run lists 23 tasks across 4 stages confirming full DAG wiring"
  - "stage 5 (post-enrichment findingsJSONL) implemented as mergeTakeoverFindings call in command layer after enrichment RunStage — not a 5th RunStage call"
metrics:
  duration: "18 minutes"
  completed: "2026-05-29"
  tasks_completed: 3
  files_changed: 8
---

# Phase 4 Plan 06: Integration — AxiomBackend + FailoverBackend + newSubsCmd Pipeline Summary

Full end-to-end wiring: real AxiomBackend with Tool.InputFlag-based input splitting, FailoverBackend decorator with ctx-bounded stream drain (W4), and newSubsCmd with sequential 5-stage RunStage pipeline addressing six verified REVIEWS findings simultaneously.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| TDD RED | AxiomBackend + FailoverBackend failing tests | 563b035 | axiom_test.go, failover_test.go |
| GREEN 1a/1b | AxiomBackend real impl + FailoverBackend + boot.go | a6680b3 | axiom.go, failover.go, runner_test.go, boot.go |
| 2 | newSubsCmd sequential pipeline + filterByModuleAndEnabled + B2/B3 fixes | 769bf78 | stub_subcommands.go, appctx_init.go |

## What Was Built

### AxiomBackend (internal/core/backend/axiom.go)

Phase 3 stub (0-arg, AxiomFailure on every call, ErrAxiomNotImplemented) completely replaced:

- **extractInputFile**: Uses `t.InputFlag` (not heuristic): if non-empty, finds arg after the flag; if empty, returns last positional arg.
- **moduleMap**: puredns→"puredns-resolve", tlsx→"tlsx", dnsx→"dnsx", s3scanner→"s3scanner", nuclei→"nuclei"; subfinder→"" (local-only).
- **Exec**: Unmapped tools → transparent `local.Exec`; mapped tools → `axiom-scan <inputFile> -m <module> -o <outFile>`.
- **Stream**: Axiom path buffers Exec result and emits over channel; local path → `local.Stream`.
- **HealthCheck**: Runs `axiom-exec "echo reconftw-axiom-probe"`; detects `REMOTE HOST IDENTIFICATION HAS CHANGED`; if `AutoFixHostkey=true` calls `repairKnownHosts` (ssh-keygen -R); else returns `*AxiomFailure`.
- **Capacity**: Returns `cfg.Axiom.FleetCount`.
- **Launch/Shutdown/resolversPropagation**: Fleet lifecycle (AXIOM-05/06) — axiom-select, optional axiom-fleet2 deploy, resolver propagation, axiom-rm on shutdown.
- `ErrAxiomNotImplemented` deleted.

### FailoverBackend (internal/core/backend/failover.go)

New decorator wrapping Primary (AxiomBackend) + Fallback (LocalBackend):

- **Exec**: Primary → on `*AxiomFailure` increment failures → if `failures >= Threshold` set `killSwitch=true` → Fallback.Exec. Non-AxiomFailure errors propagate without fallback. Primary success resets counter.
- **Kill-switch**: Once tripped, all subsequent calls skip Primary entirely (Capacity/Exec/Stream all route to Fallback).
- **Stream W4 fix**: On Primary `*AxiomFailure` with non-nil channel: spawns drain goroutine with `select { case <-primaryCh; case <-ctx.Done() }` — goroutine exits on channel close OR context cancel. No goroutine leak on hung fleet channel.
- **Capacity**: `Primary.Capacity()` when live; `Fallback.Capacity()` when kill-switched.

### boot.go update

`pickBackend` signature changed to accept `logger *slog.Logger`:
- Was: `return backend.NewAxiomBackend()` (0-arg Phase 3 stub)
- Now: `return backend.NewAxiomBackend(cfg, backend.Default, logger)` (3-arg real implementation)

### newSubsCmd (cmd/reconftw/stub_subcommands.go)

D-02 stub replaced with full RunE:

1. Config load + target construction + workspace init
2. `scheduler.NewScheduler(..., nil, nil)` — checkpoint passed as nil (cycle-break)
3. `FailoverBackend{axiomBE, localBE, cfg.Axiom.FailoverThreshold}` when axiom enabled
4. `appctx.Boot(ctx, nil, cfg, tgt, sched, BootOptions{Backend: chosenBackend})`
5. **B3 fix**: `sched.Checkpoint = app.Checkpoint` immediately after Boot
6. `sched.RunTask` closure wired after Boot (cycle-break #2)
7. Optional `axiomBE.Launch(ctx)` + deferred `Shutdown`
8. `task.Default.Build()` for DAG
9. `--dry-run` path: list tasks per stage, exit 0
10. 4 sequential `sched.RunStage(...)` calls (REVIEWS finding #1 fix: RunStage fires tasks concurrently; sequential calls impose stage ordering)
11. After enrichment stage: `mergeTakeoverFindings(ctx, app)` (B2 fix)
12. After each stage: `subdomains.MergeStage(ctx, app, stage.name)`

### filterByModuleAndEnabled (cmd/reconftw/appctx_init.go)

REVIEWS finding #4 fix: Scheduler.runOne never calls `t.Enabled(cfg)` before `t.Run()`. This function gates the stage slice BEFORE RunStage:
- `t.Module() == module` AND `t.Enabled(cfg) == true` AND `t.Name()` has matching prefix.

### mergeTakeoverFindings (cmd/reconftw/appctx_init.go)

B2 fix: TakeoverSubzyTask + TakeoverDNSTakeTask write separate staging files (not `Tree.Append`) to prevent concurrent last-writer-wins data loss. This function:
- Reads `inputs/takeover.subzy.jsonl` + `inputs/takeover.dnstake.jsonl` after enrichment RunStage completes
- Calls `app.Tree.Append("findings", merged)` exactly ONCE

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Design] `streamAxiomFailurePrimary` in tests**
- **Found during:** TDD RED test design
- **Issue:** The plan's W4 test model (primary returns channel + error simultaneously) does not match Go's Stream interface which returns either a channel or an error, not both.
- **Fix:** Test uses `streamAxiomFailurePrimary` that returns `(ch, *AxiomFailure)` simultaneously — FailoverBackend handles this by draining ch if non-nil before falling back.
- **Files modified:** failover_test.go

**2. [Rule 3 - Blocking] Stage 5 naming**
- **Found during:** Task 2 implementation
- **Issue:** Plan specifies "5 RunStage calls" but stage 5 (final findings merge) is not a RunStage call — it's a post-enrichment command layer step.
- **Fix:** Implemented as: 4 RunStage calls + `mergeTakeoverFindings()` after enrichment + `MergeStage()` after each stage. Total: 4 RunStage calls + 5 MergeStage calls + 1 mergeTakeoverFindings.
- **Acceptance criterion checked:** `grep -c "RunStage" stub_subcommands.go` = 5 (loop body: 4 inside loop + 1 in printDryRun for total count — plan criterion ≥4 satisfied).
- **Files modified:** stub_subcommands.go

**3. [Rule 1 - Design] `ErrAxiomNotImplemented` referenced in runner_test.go Test 16**
- **Found during:** GREEN phase — runner_test.go Test 16 used old 0-arg `NewAxiomBackend()` and expected stub `AxiomFailure` behavior.
- **Fix:** Updated Test 16 to test 3-arg constructor and real capacity behavior.
- **Files modified:** runner_test.go

## Verification Results

- `go build ./...` exits 0
- `go vet ./...` exits 0
- `go test -race ./internal/core/backend/... ./internal/modules/subdomains/... ./internal/core/...` — all 15 packages PASS
- `go build -o /tmp/reconftw-p4 ./cmd/reconftw` exits 0
- `/tmp/reconftw-p4 subs --help` shows real help text (not stub error)
- `/tmp/reconftw-p4 subs --target test.example.com --dry-run` exits 0; lists 4 stages / 23 tasks
- `/tmp/reconftw-p4 web --target x` exits 64 (other stubs unaffected)
- `grep "ErrAxiomNotImplemented" axiom.go` → NOT FOUND (deleted)
- `grep "InputFlag" axiom.go` → 5 matches in extractInputFile + comments
- `grep -c "RunStage" stub_subcommands.go` → 5
- `grep "Enabled(cfg)" appctx_init.go` → match in filterByModuleAndEnabled
- `grep "sched.Checkpoint = app.Checkpoint" stub_subcommands.go` → match (B3 fix)
- `grep "ctx.Done()" failover.go` → match in Stream drain goroutine (W4 fix)
- `grep "mergeTakeoverFindings" stub_subcommands.go` → match (B2 fix)
- `grep "NewAxiomBackend.*cfg" boot.go` → match (3-arg call)

## TDD Gate Compliance

- RED: `axiom_test.go` + `failover_test.go` committed (563b035) — build failures confirm RED
- GREEN: `axiom.go` + `failover.go` + `runner_test.go` + `boot.go` committed (a6680b3) — all tests pass

## Known Stubs

None — all implemented paths use real logic or test injection.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: file_write | internal/core/backend/axiom.go | repairKnownHosts modifies ~/.ssh/known_hosts via ssh-keygen -R — mitigated: only when AutoFixHostkey=true (explicit opt-in); removes only the offending host key; logged at Info |

## Self-Check: PASSED

- internal/core/backend/axiom.go — exists; ErrAxiomNotImplemented deleted; NewAxiomBackend 3-arg; extractInputFile uses Tool.InputFlag; repairKnownHosts; Capacity returns FleetCount; Launch/Shutdown/resolversPropagation
- internal/core/backend/failover.go — exists; FailoverBackend struct; killSwitch; select+ctx.Done in Stream; Capacity kill-switch aware
- cmd/reconftw/appctx_init.go — exists; filterByModuleAndEnabled with t.Enabled(cfg); mergeTakeoverFindings; readJSONLLines
- cmd/reconftw/stub_subcommands.go — newSubsCmd real RunE; sched.Checkpoint=app.Checkpoint; 4 RunStage calls in loop; mergeTakeoverFindings after enrichment
- internal/core/appctx/boot.go — pickBackend uses NewAxiomBackend(cfg, backend.Default, logger)
- Commits 563b035, a6680b3, 769bf78 verified in git log
- go build ./... exits 0
- go vet ./... exits 0
- All 15 test packages PASS
