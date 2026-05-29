---
phase: 04-subdomains-e2e-axiom-integration
plan: "04"
subsystem: subdomains-permut-recursive
tags: [subdomains, permutation, recursive, memory-backpressure, staging-contract, tdd, subd-03, gopsutil]
dependency_graph:
  requires:
    - internal/modules/subdomains/merge.go (MergeStage writes resolved.merged.txt — plan-02)
    - internal/core/config: SubPermut.MinFreeMemGB, SubPermut.Enabled, SubPermut.IAEnabled, SubPermut.RegexEnabled, SubRecursive.PassiveEnabled, SubRecursive.PassiveDepth, SubRecursive.BruteEnabled (plan-00)
    - internal/core/task: Register, StatusSkipped, StatusDone (phase 3)
    - internal/core/backend: Runner.Stream (XCUT-09 — plan-00)
  provides:
    - internal/modules/subdomains/permut.go: SubPermutTask + SubRegexPermutTask + SubDNSCewlTask + SubIAPermutTask
    - internal/modules/subdomains/recursive.go: SubRecursivePassiveTask + SubRecursiveBruteTask
    - internal/modules/subdomains/sysinfo/sysinfo.go: MemProvider interface + OSMemProvider
  affects:
    - Command layer (plan-06) must include subdomains.permut.dnscewl in permut RunStage
tech_stack:
  added:
    - github.com/shirou/gopsutil/v3 v3.24.5 (OS available memory query — SUBD-03 REVIEWS fix)
  patterns:
    - SUBD-03 memory back-pressure: memCheck() polls sysinfo.MemProvider.Available() every 5s; returns false on ctx cancel → caller returns StatusSkipped (NOT silent drop)
    - Injectable MemProvider via pointer-task MemProv field; tests type-assert *SubPermutTask to set it
    - t.Cleanup restores MemProv=nil so registry pointer modifications don't leak across test cases
    - Staging file naming: inputs/permut.<tool>.txt, inputs/recursive.<type>.txt
key_files:
  created:
    - internal/modules/subdomains/permut.go
    - internal/modules/subdomains/recursive.go
    - internal/modules/subdomains/sysinfo/sysinfo.go
    - internal/modules/subdomains/sysinfo/sysinfo_test.go
    - internal/modules/subdomains/permut_test.go
    - internal/modules/subdomains/recursive_test.go
  modified:
    - go.mod (gopsutil/v3 added)
    - go.sum (gopsutil/v3 checksums)
decisions:
  - "Pointer-receiver tasks (*SubPermutTask etc.) registered so tests can inject MemProv via type assertion without global state mutation"
  - "t.Cleanup(func(){ ptsk.MemProv = nil }) pattern restores registry after TestPermutMemGateWaitsOnLowMemory so Test 2 uses real OSMemProvider"
  - "SubDNSCewlTask returns StatusSkipped (not StatusErrored) when binary not found — non-critical per tools.lock annotation"
  - "SubRecursivePassiveTask limits to PassiveDepth entries from resolved.merged.txt (first N), not dsieve filtering — simpler and equivalent for v2"
  - "memCheck() gate disabled when MinFreeMemGB == 0; conservative: returns 0 on gopsutil error (back-pressure engages on unknown state)"
metrics:
  duration: "12 minutes"
  completed: "2026-05-29"
  tasks_completed: 2
  files_changed: 8
---

# Phase 4 Plan 04: Permutation Stage + OS Memory Back-Pressure Summary

gopsutil-based OS memory provider (REVIEWS fix), 6 permutation/recursive Tasks using staging files including SubDNSCewlTask (B1 fix — SUBD-03 all three named tools), chunk/wait back-pressure behavior preventing silent permutation drops.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | TDD RED: sysinfo.MemProvider tests | 7465448 | sysinfo/sysinfo_test.go |
| 1 (GREEN) | sysinfo MemProvider + OSMemProvider | 5609363 | sysinfo/sysinfo.go, go.mod, go.sum |
| 2 (RED) | TDD RED: 14 permut/recursive tests | 65f34ff | permut_test.go, recursive_test.go |
| 2 (GREEN) | 6 permut/recursive Tasks implementation | 3a68d6e | permut.go, recursive.go |

## What Was Built

**Task 1 — sysinfo.MemProvider interface + OSMemProvider:**
- `MemProvider` interface with `Available() uint64` — injectable for test isolation
- `OSMemProvider` calls `gopsutil/v3/mem.VirtualMemory().Available` — correct OS metric
  (NOT `runtime.ReadMemStats.Sys - Alloc` which measures Go heap delta, not OS free RAM)
- `MemAvailable()` package-level convenience for production use
- On error: returns 0 (conservative — back-pressure engages; never OOM-proceed on unknown state)
- Added `github.com/shirou/gopsutil/v3 v3.24.5` to go.mod

**Task 2 — 6 permutation/recursive Tasks:**

Permut tasks (permut.go):
- `SubPermutTask` (subdomains.permut): gotator via Stream (XCUT-09); SUBD-03 memory gate
- `SubRegexPermutTask` (subdomains.permut.regex): regulator; gate; writes permut.regex.txt
- `SubDNSCewlTask` (subdomains.permut.dnscewl): **B1 fix — third SUBD-03 D-01 tool** (gotator + regulator + dnscewl); -f flag per tools.lock; StatusSkipped if binary missing (non-critical)
- `SubIAPermutTask` (subdomains.permut.ia): subwiz IA wordlist; gated by IAEnabled + Enabled
- `memCheck()` helper: MinFreeMemGB=0 disables gate; polls every 5s; ctx cancel → false → caller returns StatusSkipped (NOT silent drop — SUBD-11 parity preservation)

Recursive tasks (recursive.go):
- `SubRecursivePassiveTask` (subdomains.recursive.passive): subfinder per top-N subdomains from resolved.merged.txt; up to PassiveDepth entries
- `SubRecursiveBruteTask` (subdomains.recursive.brute): puredns bruteforce via Stream per subdomain; writes recursive.brute.txt

All 6 tasks: DependsOn()=nil; no barrier Tasks; no app.Tree.Append; no cfg.Axiom branching.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] t.Cleanup to restore MemProv after test injection**
- **Found during:** Task 2 test run (TestPermutProceedsWithSufficientMemory timed out 30s)
- **Issue:** TestPermutMemGateWaitsOnLowMemory set `ptsk.MemProv = zeroMemProvider{}` on the registered pointer in `task.Default`. Since subsequent tests use the same registered instance, Test 2 also blocked forever in memCheck.
- **Fix:** Added `t.Cleanup(func() { ptsk.MemProv = nil })` after injection so the registry pointer is restored after Test 1 completes.
- **Files modified:** `internal/modules/subdomains/permut_test.go`
- **Commit:** 3a68d6e

**2. [Rule 3 - Blocking] Mock type name conflicts with resolve_test.go**
- **Found during:** Task 2 RED test build
- **Issue:** `mockStreamBackend` in resolve_test.go (uses `lines []string` field) conflicted with the `mockStreamBackend` in permut_test.go (uses `result *backend.Result`). Also `splitLines` was redeclared.
- **Fix:** Renamed to `permutStreamBackend` and `permutSplitLines` in permut_test.go.
- **Files modified:** `internal/modules/subdomains/permut_test.go`
- **Commit:** 65f34ff

## Verification Results

- `go test -race ./internal/modules/subdomains/sysinfo/...` exits 0 (4 tests PASS)
- `go test ./internal/modules/subdomains/... -run "TestPermut|TestRecursive"` exits 0 (14 tests PASS)
- `go test ./internal/modules/subdomains/... ./internal/core/...` exits 0 (15 packages PASS)
- `go vet ./...` exits 0 (no issues)
- `go build -o /dev/null ./...` exits 0
- `grep "ReadMemStats" internal/modules/subdomains/permut.go` → comments only (no code)
- `grep "sysinfo\." internal/modules/subdomains/permut.go` → match (correct provider used)
- `grep "SubDNSCewlTask" internal/modules/subdomains/permut.go` → match (B1 fix registered)
- `grep "app.Tree.Append" internal/modules/subdomains/permut.go internal/modules/subdomains/recursive.go` → comments only (staging contract preserved)
- `grep "barrier" internal/modules/subdomains/recursive.go` → comment only (no barrier tasks)

## TDD Gate Compliance

- Task 1 RED: `sysinfo/sysinfo_test.go` committed (7465448) — 4 tests fail (no source file)
- Task 1 GREEN: `sysinfo/sysinfo.go` committed (5609363) — all 4 tests pass
- Task 2 RED: `permut_test.go` + `recursive_test.go` committed (65f34ff) — 14 tests fail (tasks not registered)
- Task 2 GREEN: `permut.go` + `recursive.go` committed (3a68d6e) — all 14 tests pass

## Self-Check: PASSED

- internal/modules/subdomains/sysinfo/sysinfo.go — exists; VirtualMemory used; no ReadMemStats in code
- internal/modules/subdomains/permut.go — exists; 4 tasks; SubDNSCewlTask present; sysinfo.OSMemProvider used; no Tree.Append code
- internal/modules/subdomains/recursive.go — exists; SubRecursivePassiveTask + SubRecursiveBruteTask; no Tree.Append code
- go.mod — github.com/shirou/gopsutil/v3 v3.24.5 present
- Commits 7465448, 5609363, 65f34ff, 3a68d6e verified in git log
