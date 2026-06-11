---
phase: 09-composite-modes
plan: "01"
subsystem: config-transforms
tags:
  - config
  - zen
  - deep
  - mcp-handlers
  - profiles
dependency_graph:
  requires:
    - internal/core/config (config.Load, Defaults, *Config struct)
    - internal/core/appctx (Boot, BootOptions, NewTarget)
    - internal/core/task (Task interface, Default registry)
    - internal/core/scheduler (Scheduler, NewScheduler)
    - internal/core/backend (FailoverBackend, AxiomBackend, LocalBackend)
    - internal/core/output (WorkspaceInit)
  provides:
    - internal/core/config.ApplyZenProfile (stealth/minimal-noise config transform)
    - internal/core/config.ApplyDeepProfile (extended brute + fuzz config transform)
    - internal/mcp/handlers.RunOptions.ConfigTransform (hook applied before Boot)
    - internal/mcp/handlers.BootReconApp (wires ConfigTransform between Load and Boot)
    - internal/core/task.FilterByModuleAndEnabled (exported for mcp/handlers visibility)
  affects:
    - cmd/reconftw/stub_subcommands.go (uses filterByModuleAndEnabled shim → now task.FilterByModuleAndEnabled)
    - cmd/reconftw/appctx_init.go (updated to forwarding shim for task.FilterByModuleAndEnabled)
tech_stack:
  added:
    - internal/mcp/handlers package (6 files: common.go, subs.go, web.go, vulns.go, osint.go, handlers_test.go)
    - internal/core/task/filter.go (FilterByModuleAndEnabled + MatchesAnyPrefix, exported)
    - internal/core/config/profiles.go (ApplyZenProfile, ApplyDeepProfile)
    - internal/core/config/profiles_test.go (19 assertions + stacking test)
  patterns:
    - Pure in-memory config transform functions (no I/O, no exec, stackable)
    - ConfigTransform hook in RunOptions (nil = no-op, backward-compatible)
    - TDD RED/GREEN/REFACTOR flow for both tasks
key_files:
  created:
    - internal/mcp/handlers/common.go
    - internal/mcp/handlers/subs.go
    - internal/mcp/handlers/web.go
    - internal/mcp/handlers/vulns.go
    - internal/mcp/handlers/osint.go
    - internal/mcp/handlers/handlers_test.go
    - internal/core/task/filter.go
    - internal/core/config/profiles.go
    - internal/core/config/profiles_test.go
  modified:
    - cmd/reconftw/appctx_init.go (forwarding shim update)
decisions:
  - "ConfigTransform hook placed between config.Load and appctx.Boot inside BootReconApp (D-02/Pitfall 5)"
  - "task.FilterByModuleAndEnabled exported to resolve cmd/reconftw visibility barrier (Pitfall 7)"
  - "appctx_init.go updated to forwarding shim; stub_subcommands.go unchanged (backward-compatible)"
  - "nil ConfigTransform is no-op (zero value of func type) — all existing callers compile without change"
metrics:
  duration: "~10 minutes"
  completed: "2026-06-11"
  tasks_completed: 2
  tasks_total: 2
  files_created: 9
  files_modified: 1
---

# Phase 09 Plan 01: ConfigTransform Hook + Zen/Deep Profile Functions Summary

**One-liner:** ConfigTransform hook in RunOptions wires zen/deep in-memory config overrides (ApplyZenProfile/ApplyDeepProfile) applied after config.Load and before appctx.Boot.

## What Was Built

### Task 1: ConfigTransform field in RunOptions + BootReconApp wiring (D-02)

Added `ConfigTransform func(*config.Config)` to `RunOptions` in `internal/mcp/handlers/common.go`. The field is applied inside `BootReconApp` between `config.Load` and `appctx.Boot`:

```go
if opts.ConfigTransform != nil {
    opts.ConfigTransform(cfg)
}
```

This is the injection point required by D-02/D-03 (Pitfall 5 in RESEARCH.md): applying transforms after Boot means `appctx.Boot` already wired stale concurrency limits (MaxJobs etc.) from the pre-transform values.

Also brought the entire `internal/mcp/handlers` package (from untracked main-repo state) into the worktree: `common.go`, `subs.go`, `web.go`, `vulns.go`, `osint.go`, `handlers_test.go`.

**Auto-fix (Rule 1):** `task.FilterByModuleAndEnabled` was package-private in `cmd/reconftw`, causing `internal/mcp/handlers` to fail compilation. Created `internal/core/task/filter.go` exporting `FilterByModuleAndEnabled` and `MatchesAnyPrefix`. Updated `cmd/reconftw/appctx_init.go` to a forwarding shim. This was a blocking compilation bug.

### Task 2: ApplyZenProfile and ApplyDeepProfile (D-02/D-03/MODE-04/MODE-05)

Created `internal/core/config/profiles.go` with two pure exported functions:

**`ApplyZenProfile(cfg *Config)`** — 12 fields set:
- `Advanced.PerfProfile = "low"`, `Concurrency.MaxJobs = 2`
- `Web.Probe.RateLimit = 30`, `Web.Nuclei.RateLimit = 15`
- `Web.Fuzz.RateLimit = 10`, `Web.Fuzz.Threads = 5`
- `Subdomains.Brute.Enabled = false`, `Subdomains.Permut.Enabled = false`
- `Web.Portscan.ActiveEnabled = false`, `Vulns.Enabled = false`
- `Output.Verbosity = 0`, `OSINT.GitHub.ActionsAudit.Enabled = false`

**`ApplyDeepProfile(cfg *Config)`** — 6 fields set:
- `Advanced.Deep = true`
- `Subdomains.Recursive.BruteEnabled = true`, `Subdomains.Recursive.PassiveEnabled = true`
- `Subdomains.Permut.WordlistMode = "full"`, `Web.Fuzz.RecursionDepth = 4`
- `Web.Portscan.Naabu.Ports = "--top-ports 10000"`

Created `internal/core/config/profiles_test.go` with exhaustive per-field assertions (12 zen + 7 deep) plus `TestZenDeepStackable` verifying D-03 stacking behavior.

## Verification Results

```
go build ./...                                        PASS
go test ./internal/core/config/... -run TestApply    PASS (TestApplyZenProfile, TestApplyDeepProfile, TestZenDeepStackable)
go test ./internal/mcp/handlers/... -count=1         PASS (7 tests)
go test ./... -race -count=1                         PASS (all packages)
grep "ConfigTransform" internal/mcp/handlers/common.go  shows field declaration + if-check
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Exported task.FilterByModuleAndEnabled to resolve compilation barrier**
- **Found during:** Task 1 (BootReconApp compile)
- **Issue:** `task.FilterByModuleAndEnabled` was only defined as `filterByModuleAndEnabled` (package-private) in `cmd/reconftw/appctx_init.go`. The `internal/mcp/handlers` package cannot import `cmd/reconftw` (circular). This caused all handler files (`subs.go`, `web.go`, `vulns.go`, `osint.go`) to fail compilation.
- **Fix:** Created `internal/core/task/filter.go` exporting `FilterByModuleAndEnabled` and `MatchesAnyPrefix`. Updated `cmd/reconftw/appctx_init.go` to a forwarding shim delegating to the exported functions. This matches the main-repo (untracked) state exactly.
- **Files modified:** `internal/core/task/filter.go` (new), `cmd/reconftw/appctx_init.go` (updated)
- **Commit:** 2a5fb2e5

**2. [Rule 1 - Bug] Brought untracked mcp/handlers package into worktree**
- **Found during:** Task 1 setup
- **Issue:** The plan listed `files_modified: internal/mcp/handlers/common.go` but this file did not exist in the worktree (worktree is based on commit 33c82f11 which predates the untracked Phase 8 MCP work in the main repo).
- **Fix:** Copied all 6 handler files from the main-repo working directory (`common.go`, `subs.go`, `web.go`, `vulns.go`, `osint.go`, `handlers_test.go`) into the worktree, then added the `ConfigTransform` field. Content is identical to the main-repo versions except for the new field.
- **Files modified:** All 6 handler files (new in worktree)
- **Commit:** 2a5fb2e5

## TDD Gate Compliance

- **Task 1 RED/GREEN:** `TestConfigTransformAppliedBeforeBoot` and `TestConfigTransformNilIsNoOp` written and verified before adding `ConfigTransform` field. Tests pass green after implementation.
- **Task 2 RED:** `profiles_test.go` committed (commit 1c0d682) before `profiles.go` existed — compile-time failure confirmed RED.
- **Task 2 GREEN:** `profiles.go` committed (commit 3e63992) — all 19 assertions pass.

## Known Stubs

None. All 12 zen fields and 6 deep fields are fully implemented with exact values verified against `defaults.go` and RESEARCH.md Q2.

## Threat Flags

None. All changes are pure in-memory transforms on an already-loaded `*Config`. No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries.

## Self-Check

- [x] `internal/mcp/handlers/common.go` exists and contains `ConfigTransform func(*config.Config)` field
- [x] `internal/mcp/handlers/common.go` contains `if opts.ConfigTransform != nil { opts.ConfigTransform(cfg) }` between Load and Boot
- [x] `internal/core/config/profiles.go` exists with `ApplyZenProfile` and `ApplyDeepProfile`
- [x] `internal/core/config/profiles_test.go` contains `TestApplyZenProfile`, `TestApplyDeepProfile`, `TestZenDeepStackable`
- [x] `go build ./...` passes
- [x] `go test ./internal/core/config/... -run TestApply` passes
- [x] `go test ./internal/mcp/handlers/... -count=1` passes
- [x] Task 1 commit: 2a5fb2e5
- [x] Task 2 RED commit: 1c0d682
- [x] Task 2 GREEN commit: 3e63992
