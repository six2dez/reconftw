---
phase: 02-architecture-v2-design
plan: "04"
subsystem: architecture-adr
tags: [interfaces, error-hierarchy, failure-policy, go, adr]
dependency_graph:
  requires: [02-01, 02-02, 02-03]
  provides: [task-interface, backend-interface, appctx-struct, error-hierarchy, failure-policy]
  affects: [phase-03-foundation, phase-04-subdomains, phase-05-web, phase-06-vulns, phase-07-osint, phase-08-mcp]
tech_stack:
  added: []
  patterns:
    - Hybrid sentinel + typed-struct error pattern (errors.Is + errors.As)
    - errgroup.WithContext for fail_fast vs zero-value errgroup for best_effort
    - AppContext dependency kernel (no package-level globals)
    - BINDING godoc annotation on interface types
key_files:
  created: []
  modified:
    - .planning/decisions/0002-architecture-v2.md
    - interfaces_check/main.go
decisions:
  - "Task interface has exactly 6 methods: Name/Module/Description/Enabled/DependsOn/Run"
  - "Backend interface has exactly 4 methods: Exec/Stream/HealthCheck/Capacity"
  - "AppContext is a single pointer-to-struct (not decomposed per-role contexts)"
  - "Error hierarchy uses hybrid sentinel+struct: errors.Is for category, errors.As for metadata"
  - "failure_policy is per-module-group (not per-task or per-backend)"
  - "Registry.Build() must do topological sort cycle detection; circular DependsOn = ConfigError"
  - "ConfigError.Message must NEVER include raw secret values"
  - "Backend.Stream() shape is sufficient for Phase 8 MCP; no protocol-level change anticipated"
  - "interfaces_check/main.go uses interface{} placeholders for cross-package types to compile standalone"
metrics:
  duration: "~28 minutes"
  completed: "2026-05-28"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 2
  commits: 2
---

# Phase 2 Plan 4: Interface Signatures, Error Hierarchy, Failure Policy — Summary

ADR 0002 §5/§6/§7 fully populated with binding Go interface definitions, 7-class error
struct hierarchy with sentinel bridges, and per-module-group failure policy with errgroup
mapping; `interfaces_check/main.go` updated to compile-verify the contracts.

## What Was Built

### Task 1 — §5 Interface Signatures (ARCH-05, ARCH-06, ARCH-07)

**§5.1 Task Interface** — 6-method interface with full godoc, BINDING annotation, and
supporting types:
- `Task interface` with `Name/Module/Description/Enabled/DependsOn/Run` (6 methods)
- `Result struct` (Status, Duration, Outputs, Stats)
- `Status type` + 4 constants (done/errored/cancelled/skipped)
- `Registry struct` with `Default` singleton + `Register(t Task)` (panic on dup)
- `LifecycleAware interface` (OnStart/OnEnd — checked via type assertion by Scheduler)

**§5.2 Backend Interface** — 4-method interface with concrete types (no interface{}):
- `Backend interface` with `Exec/Stream/HealthCheck/Capacity` (4 methods)
- `Event struct` (Line []byte, Source string, IsErr bool)
- `Result struct` (Stdout, Stderr []byte, ExitCode int, Duration time.Duration)
- `Tool struct` (Name, Path, Version string; DefaultArgs []string; Timeout time.Duration)
- Stream() godoc notes: Phase 8 MCP annotation + goroutine-leak drain requirement

**§5.3 AppContext Struct** — 9-field dependency kernel:
- `Log *slog.Logger, Cfg *config.Config, Scheduler *scheduler.Scheduler`
- `Tools *backend.Runner, Tree *output.OutputTree, Checkpoint *checkpoint.Store`
- `Notify notifier.Notifier, Target *Target, UI *ui.Printer`
- `Target struct` (Domain, IsCIDR, IsIP bool, Scope []string, WorkDir string)
- Explicit NO-globals note: explains v1 anti-pattern (global bash vars) vs v2 solution

### Task 2 — §6 Error Hierarchy, §7 Failure Policy, interfaces_check (ARCH-08, ARCH-09)

**§6 Error Class Hierarchy** — 6 sentinels + 7 typed structs:
- Sentinels: `ErrTool, ErrTimeout, ErrScope, ErrAxiom, ErrConfig, ErrChecksum`
- Structs: `ToolError, ToolTimeout, OutOfScope, AxiomFailure, ConfigError, ScopeError, ChecksumMismatch`
- Each struct implements `Error() string`, `Unwrap() error` (where applicable), and
  `Is(target error) bool` sentinel bridge pattern
- Pitfall notes from threat model embedded:
  - T-02-04-02: ConfigError.Message must NEVER include raw secret values
  - T-02-04-03: Registry.Build() must detect circular DependsOn at startup
  - T-02-04-05: AxiomFailure.Inner must not carry raw credentials

**§7 Failure Policy Model** — TOML config + Scheduler Go snippet:
- v1→v2 mapping table (CONTINUE_ON_TOOL_ERROR → best_effort, recon() spine → fail_fast)
- TOML [scheduler] section with global default + [scheduler.overrides] per module
- Scheduler Go snippet: `FailurePolicy type`, `PolicyBestEffort/PolicyFailFast constants`,
  `Scheduler struct` (maxConcurrent, sem, policies, log), `runStage()` function showing
  both branches (errgroup.WithContext for fail_fast vs zero-value errgroup for best_effort)
- Checkpoint interaction documented (cancelled fail_fast tasks do not write sentinel)

**interfaces_check/main.go** — compile-only ADR verification binary:
- Full `Task interface` (6 methods), `Backend interface` (4 methods)
- `AppContext struct` (9 fields with interface{} placeholders for standalone compile)
- `Status, Result, Event, ExecResult, Tool, FailurePolicy` supporting types
- `go build -o /tmp/... ./interfaces_check/...` exits 0

## Commits

| Hash | Message | Files |
|------|---------|-------|
| f0408909 | docs(02-04): populate §5 Interface Signatures (Task, Backend, AppContext) | .planning/decisions/0002-architecture-v2.md |
| 0b45a1d3 | docs(02-04): populate §6 error hierarchy, §7 failure policy; update interfaces_check | .planning/decisions/0002-architecture-v2.md, interfaces_check/main.go |

## Verification Results

| Check | Result |
|-------|--------|
| `grep 'type Task interface'` ADR | PASS |
| `grep 'type Backend interface'` ADR | PASS |
| `grep 'type AppContext struct'` ADR | PASS |
| `grep 'type ToolError struct'` ADR | PASS |
| `grep 'PolicyBestEffort\|PolicyFailFast'` ADR | PASS |
| `go build ./interfaces_check/...` | PASS |
| No STUB in §5 body | PASS |
| No STUB in §6 body | PASS |
| No STUB in §7 body | PASS |
| All 7 error types present | PASS |
| 20 type definitions total (≥ 12) | PASS |
| ARCH-05/06/07/08/09 all referenced | PASS |

## Requirements Satisfied

| Requirement | Status |
|-------------|--------|
| ARCH-05 — Task interface signed | Satisfied |
| ARCH-06 — Backend interface signed | Satisfied |
| ARCH-07 — AppContext shape signed | Satisfied |
| ARCH-08 — 7-class error hierarchy | Satisfied |
| ARCH-09 — failure_policy model | Satisfied |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Worktree path resolution vs main repo path**
- **Found during:** Task 1
- **Issue:** The Edit tool resolved `.planning/decisions/0002-architecture-v2.md` against the
  main repo working tree (`/Users/six2dez/Tools/reconftw/.planning/`) not the worktree's
  copy (`/Users/six2dez/Tools/reconftw/.claude/worktrees/agent-a12183e60911af035/.planning/`).
  The first Edit wrote to the wrong file; git in the worktree saw no changes.
- **Fix:** Applied all edits using the explicit worktree absolute path
  (`/Users/six2dez/Tools/reconftw/.claude/worktrees/agent-a12183e60911af035/.planning/...`).
  Restored the main repo file with `git checkout --` to leave it clean.
- **Files modified:** `.planning/decisions/0002-architecture-v2.md` (worktree copy)
- **No commit needed for fix** — the Task 1 commit captured the correct worktree-path content.

## Known Stubs

None in §5, §6, or §7. Remaining stubs in §1, §8-§12, and Consequences sections are
intentional (Wave 2 / Wave 3 stubs out of scope for this plan).

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced.
This plan produced documentation only (ADR sections + compile-check Go file). The threat
model mitigations from the plan's `<threat_model>` are all embedded in the ADR text:
- T-02-04-01: OutOfScope enforced at OutputTree.Append boundary (noted in §6 OutOfScope godoc)
- T-02-04-02: ConfigError.Message secret-leak pitfall note (§6)
- T-02-04-03: Registry.Build() cycle detection requirement (§6)
- T-02-04-04: Backend.Stream() drain requirement in godoc (§5.2)
- T-02-04-05: AxiomFailure.Inner credential note (§6)

## Self-Check: PASSED

| Item | Result |
|------|--------|
| ADR file exists at `.planning/decisions/0002-architecture-v2.md` | FOUND |
| `interfaces_check/main.go` exists | FOUND |
| `SUMMARY.md` exists | FOUND |
| Task 1 commit `f0408909` | FOUND |
| Task 2 commit `0b45a1d3` | FOUND |
| `go build ./interfaces_check/...` | PASS |
| `type Task interface` in ADR | FOUND |
| `type Backend interface` in ADR | FOUND |
| `type AppContext struct` in ADR | FOUND |
| `type ToolError struct` in ADR | FOUND |
| `PolicyBestEffort` in ADR | FOUND |
| `failure_policy` TOML snippet in ADR | FOUND |
