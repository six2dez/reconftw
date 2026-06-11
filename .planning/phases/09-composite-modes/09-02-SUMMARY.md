---
phase: "09"
plan: "02"
subsystem: composite-modes
tags: [composite, handlers, passive-guard, dry-run, d-01, d-09, d-10]
dependency_graph:
  requires: [09-01-SUMMARY.md, 08-04-SUMMARY.md]
  provides: [composite-handlers, passive-backend, composite-subcommands]
  affects: [cmd/reconftw, internal/mcp/handlers, internal/core/backend, internal/core/appctx]
tech_stack:
  added: []
  patterns:
    - D-01 boot-once composite model (single BootReconApp, single Checkpoint lifecycle)
    - D-09 PassiveBackend hard-guard (ErrPassiveViolation defense-in-depth)
    - D-10 secret redaction in dry-run (Redactor built in commonAfterBoot)
    - T-09-02-03 Axiom lifecycle: RunCompositeAsync sole owner of Launch+Shutdown
    - T-09-02-04 Checkpoint lifecycle: RunCompositeAsync sole owner of Close
key_files:
  created:
    - internal/core/backend/passive.go
    - internal/mcp/handlers/composite.go
    - cmd/reconftw/composite_subcommands.go
    - cmd/reconftw/composite_test.go
  modified:
    - internal/core/errors/errors.go
    - internal/core/appctx/boot.go
    - internal/mcp/handlers/common.go
    - cmd/reconftw/stub_subcommands.go
    - cmd/reconftw/root_test.go
    - cmd/reconftw/stub_test.go
decisions:
  - "PassiveBackend wraps any Backend (not LocalBackend directly) keeping the guard composable and LocalBackend clean; wired via BootOptions.PassiveMode → appctx.Boot"
  - "commonAfterBoot omits axiomBE.Launch/defer Shutdown entirely (T-09-02-03); RunCompositeAsync is sole owner for composite; single-pipeline handlers are unchanged"
  - "ModeZen and ModeDeep use the same pipeline groups as ModeRecon/ModeAll; profile transformation applied by caller via ConfigTransform before Boot (D-03: mode wins over file config)"
  - "isBestEffortModule returns false only for 'subdomains' (fail-fast spine); all web/osint/vulns stages are best_effort"
  - "CompositePipelinePrefixes exported for pipeline-order test assertions without requiring test workspaces"
metrics:
  duration: "~11 minutes"
  completed: "2026-06-11"
  tasks_completed: 4
  files_created: 4
  files_modified: 6
---

# Phase 9 Plan 02: Composite Modes Handler Summary

Single BootReconApp call drives recon/all/passive/zen/deep composite pipelines; PassiveBackend hard-guard blocks active tools with ErrPassiveViolation per D-09.

## What Was Built

### Task 1: PassiveBackend + ErrPassiveViolation (D-09)

**`internal/core/errors/errors.go`**: Added `ErrPassiveViolation` sentinel and `PassiveViolation` struct with `Is()` bridge enabling `errors.Is(err, ErrPassiveViolation)` traversal.

**`internal/core/backend/passive.go`** (NEW): `PassiveBackend` wraps any `Backend` interface. `isActiveTool()` hard-blocks puredns, massdns, naabu, nmap, dalfox, sqlmap, commix, ffuf, nuclei, httpx, gato — by exact name and prefix-before-hyphen. All four methods (Exec/ExecEnv/Stream/StreamEnv) check before delegating to Inner. HealthCheck and Capacity pass through unconditionally.

**`internal/core/appctx/boot.go`**: Added `PassiveMode bool` to `BootOptions`. In `Boot()`: when true and inner backend is not already a `*PassiveBackend`, wraps it (idempotent guard).

**`internal/mcp/handlers/common.go`**: Added `PassiveMode bool` to `RunOptions`. Passed through to `appctx.BootOptions` in `BootReconApp`.

### Task 2: Composite Handler (`internal/mcp/handlers/composite.go`)

Five constants: `ModeRecon=0`, `ModeAll=1`, `ModePassive=2`, `ModeZen=3`, `ModeDeep=4`.

Stage group functions returning `[]compositeStageGroup`:
- `subsPassiveStages()` — subs-passive only (ModePassive primary guard)
- `subsReconStages()` — passive + resolve + discovery (no brute/permut)
- `subsAllStages()` — all 5 subs stage groups (passive → resolve → discovery → permut → enrichment)
- `webStageGroups()` — 8 web stages (probe → waf → analysis → urls-fetch → js-extract → js-analyze → urls-dedup → bypass)
- `osintStageGroupsComposite()` — wraps `osintHandlerStages()` into compositeStageGroup
- `vulnsStageGroupsComposite()` — 4 vulns stage groups

`compositePipelineStages(mode)` maps modes to stage group slices. `CompositePipelinePrefixes(mode)` exported for test assertions.

`RunCompositeAsync`:
- Single `BootReconApp` call (D-01)
- Single `defer app.Checkpoint.Close()` (T-09-02-04)
- Calls `opts.AfterBoot` if non-nil (wires sched.RunTask and log routing; no axiom calls)
- DryRun early return
- Wires `sched.Checkpoint = app.Checkpoint`
- Builds full task DAG once
- ONE `axiomBE.Launch(ctx)` + ONE `defer axiomBE.Shutdown(...)` (T-09-02-03)
- Stage loop: `sched.RunStage` + `compositeStagePostMerge` + `ProgressSink`
- `compositeFinalMerge` after all stage groups

`isBestEffortModule(module)`: returns `module != "subdomains"` — subs resolve is fail-fast spine; everything else is best_effort.

### Task 3: CLI Composite Subcommands (`cmd/reconftw/composite_subcommands.go`)

**`commonAfterBoot`**: Extracted from the four near-identical afterBoot closures in `runSubsCmd`/`runWebCmd`/`runVulnsCmd`/`runOSINTCmd`. Key changes:
- Omits `axiomBE.Launch()` and `defer axiomBE.Shutdown()` (T-09-02-03 — composite RunCompositeAsync owns those)
- Builds and populates `dryRunCapture{Tasks, Cfg, Rdct}` on dry-run for D-10

**`dryRunCapture`** struct holds captured task list, config, and redactor.

Five constructors replacing stub exit-64 bodies:
- `newReconCmd()` — ModeRecon, no ConfigTransform, passiveMode=false
- `newAllCmd()` — ModeAll, no ConfigTransform, passiveMode=false
- `newPassiveCmd()` — ModePassive, no ConfigTransform, passiveMode=true (enables D-09 backend guard)
- `newZenCmd()` — ModeZen, ConfigTransform=`config.ApplyZenProfile`, passiveMode=false
- `newDeepCmd()` — ModeDeep, ConfigTransform=`config.ApplyDeepProfile`, passiveMode=false

All five support `--list` batch mode via `runCompositeList` → `runBatch`.

`printCompositeDryRun`: calls per-pipeline printers in pipeline order with rdct available for D-10 redaction of future tool-arg output.

### Task 4: Stub Cleanup + Tests

**`stub_subcommands.go`**: Removed recon/all/passive/zen/deep from `phasePointers` map and deleted the 5 stub `newXCmd()` functions (replaced by composite_subcommands.go).

**`root_test.go`**: Removed "recon", "all", "passive", "zen", "deep" from `TestEveryStubReturnsExit64` (4 stubs remain: monitor/report/migrate/install).

**`stub_test.go`**: Updated `TestPhasePointersCoverAllStubs` to expect only the 4 remaining stubs.

**`composite_test.go`** (NEW): 5 tests:
1. `TestReconPipelineOrder` — ModeRecon has subs+web+osint prefixes, NO vulns, in correct order
2. `TestAllPipelineIncludesVulns` — ModeAll is superset of ModeRecon + adds vulns after osint
3. `TestPassiveModeBlocksActiveTool` — 11 subtests verifying ErrPassiveViolation for all active tools
4. `TestCompositeDryRun` — all 5 subcommands exit cleanly with --dry-run
5. `TestDryRunRedactsSecrets` — 3 subtests verifying dry-run section ordering for recon/all/passive

## Deviations from Plan

### Auto-fixed Issues

None.

### Clarifications Applied

**1. [Rule 2 - Missing type] `config.ProfileTransformFn` not exported**
- **Found during:** Task 3 implementation
- **Issue:** Plan referenced `config.ProfileTransformFn` as the ConfigTransform parameter type, but the config package only exports `ApplyZenProfile`/`ApplyDeepProfile` functions as `func(*Config)` — no named type alias exists.
- **Fix:** Used `func(*config.Config)` inline type throughout `composite_subcommands.go` (matches `RunOptions.ConfigTransform` field type exactly).
- **Files modified:** `cmd/reconftw/composite_subcommands.go`
- **No commit needed:** Working-tree change only per orchestrator instructions.

**2. [Rule 3 - Unused import] `backend` import removed**
- **Found during:** Task 3 compilation
- **Issue:** `composite_subcommands.go` initially imported `internal/core/backend` (not needed since axiom lifecycle moved entirely to `RunCompositeAsync`).
- **Fix:** Removed the import.
- **Files modified:** `cmd/reconftw/composite_subcommands.go`

**3. [Rule 3 - Test interface mismatch] cobra.Command.SetErr signature**
- **Found during:** Task 4 test compilation
- **Issue:** Initial `TestCompositeDryRun` used a `func() interface{SetErr(*bytes.Buffer), ...}` interface, but `cobra.Command.SetErr` accepts `io.Writer` not `*bytes.Buffer`.
- **Fix:** Replaced the interface-based helper with a simple `runDryRunCmd(cmd *cobra.Command, args []string)` helper function.
- **Files modified:** `cmd/reconftw/composite_test.go`

## Build Verification

```
go build ./...    # PASS
go vet ./...      # PASS  
go test ./cmd/reconftw/... ./internal/mcp/handlers/...  # all PASS
go test ./...     # all PASS (29 packages)
```

## Self-Check

- `internal/core/backend/passive.go` — FOUND
- `internal/mcp/handlers/composite.go` — FOUND
- `cmd/reconftw/composite_subcommands.go` — FOUND
- `cmd/reconftw/composite_test.go` — FOUND
- All 5 new tests PASS
- Full test suite PASS (29 packages, 0 failures)

## Self-Check: PASSED
