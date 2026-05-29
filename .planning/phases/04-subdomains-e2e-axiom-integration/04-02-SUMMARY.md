---
phase: 04-subdomains-e2e-axiom-integration
plan: "02"
subsystem: subdomains-active-dns
tags: [subdomains, active-dns, brute-force, staging-contract, tdd, subd-02, xcut-09]
dependency_graph:
  requires:
    - internal/modules/subdomains/passive.go (SubdomainRecord, writeStagingFile helpers — plan-01)
    - internal/modules/subdomains/merge.go (MergeStage — plan-01, extended here)
    - internal/core/config: SubDNSResolve, SubBrute.MinResolvers, Paths.Resolvers, Paths.SubsWordlist (plan-00)
    - internal/core/backend: Runner.Stream (XCUT-09 — plan-00)
    - internal/core/task: Register, Default, StatusSkipped (phase 3)
  provides:
    - internal/modules/subdomains/resolve.go: 6 active DNS resolution Tasks
    - internal/modules/subdomains/brute.go: SubBruteTask + SubResolversHealthTask
    - internal/modules/subdomains/merge.go: MergeStage extended with merged.txt output
  affects:
    - internal/modules/subdomains/scope_crosscheck_test.go (containsWord helper fix)
tech_stack:
  added: []
  patterns:
    - Stream pattern for puredns/dnsx: app.Tools.Stream drains channel line by line (XCUT-09)
    - Resolver health gate in Run() not Enabled(): Scheduler never calls Enabled(); runtime guards must live in Run()
    - merged.txt contract: MergeStage writes inputs/<stage>.merged.txt after Tree.Append for downstream Tasks
    - Staging file naming: inputs/resolved.<tool>.txt mirrors inputs/passive.<tool>.txt from plan-01
key_files:
  created:
    - internal/modules/subdomains/resolve.go
    - internal/modules/subdomains/brute.go
    - internal/modules/subdomains/resolve_test.go
    - internal/modules/subdomains/brute_test.go
  modified:
    - internal/modules/subdomains/merge.go (merged.txt write added)
    - internal/modules/subdomains/scope_crosscheck_test.go (containsWord helper bug fix)
decisions:
  - "SubActiveTask uses puredns resolve toolName for Stream but writes resolved.active.txt to keep the staging name descriptive (resolve.go lines 161-170)"
  - "SubTLSTask.Enabled gates on cfg.Subdomains.TLSPivot.Enabled (not Passive.Enabled) — TLS pivot is a separate config dimension"
  - "SubBruteTask resolver gate: in Run() not only Enabled() — REVIEWS finding #4 fix; Enabled() still returns false for config-disabled brute"
  - "MergeStage merged.txt write is non-fatal on error — Tree.Append success is the critical path; merged.txt is a convenience file for downstream tools"
  - "containsWord helper in scope_crosscheck_test.go fixed to use dot-segment semantics (strings.HasPrefix/HasSuffix) instead of brittle index arithmetic"
metrics:
  duration: "15 minutes"
  completed: "2026-05-29"
  tasks_completed: 2
  files_changed: 6
---

# Phase 4 Plan 02: Active DNS Resolution + Brute-Force Tasks Summary

6 active DNS resolution Tasks + SubBruteTask + SubResolversHealthTask registered with per-tool staging file writes and in-Run() SUBD-02 resolver health gate; MergeStage extended to write merged.txt for downstream Task consumption; Stream used for puredns/dnsx (XCUT-09).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | TDD RED: 6 resolution Task tests | f888395 | resolve_test.go |
| 1 (GREEN) | 6 resolution Tasks implementation | af60dd1 | resolve.go |
| 2 (RED) | TDD RED: SubBrute + SubResolversHealth tests | 4b81358 | brute_test.go |
| 2 (GREEN) | SubBrute + SubResolversHealth + MergeStage merged.txt | a2309e0 | brute.go, merge.go, scope_crosscheck_test.go |

## What Was Built

**Task 1 — 6 active DNS resolution Tasks:**
- `SubActiveTask` (subdomains.active): puredns resolve against passive.merged.txt via Stream; writes `inputs/resolved.active.txt`
- `SubTLSTask` (subdomains.tls): tlsx SAN/CN extraction via Stream; writes `inputs/resolved.tls.txt`
- `SubNoerrorTask` (subdomains.noerror): dnsx NOERROR filter via Stream; writes `inputs/resolved.noerror.txt`
- `SubDNSTask` (subdomains.dns): dnsx multi-record (A/AAAA/CNAME/NS/MX) via Exec; writes `inputs/resolved.dns.txt`
- `SubSRVTask` (subdomains.srv): dnsx SRV enum via Exec; writes `inputs/resolved.srv.txt`
- `SubPTRTask` (subdomains.ptr): puredns reverse PTR from `inputs/asn.ips.txt` via Stream; writes `inputs/resolved.ptr.txt`
- All Tasks: DependsOn() = nil (sequential RunStage ordering via command layer); Module() = "subdomains"; no Tree.Append; no barrier tasks; no cfg.Axiom branching (D-05)
- `runStreamTask` / `runExecTask` helpers to share the drain-and-write pattern

**Task 2 — SubBruteTask + SubResolversHealthTask + MergeStage merged.txt:**
- `SubResolversHealthTask` (subdomains.resolvers.health): counts non-empty lines in cfg.Paths.Resolvers; returns StatusSkipped when count < cfg.Subdomains.Brute.MinResolvers
- `SubBruteTask` (subdomains.brute): SUBD-02 resolver health gate in Run() (independent of Enabled() since Scheduler never calls Enabled()); selects big wordlist when cfg.Advanced.Deep; runs puredns bruteforce via Stream; writes `inputs/resolved.brute.txt`
- `MergeStage` extended: after Tree.Append, writes `inputs/<stage>.merged.txt` (plain newline-delimited hostnames) for downstream Tasks (passive.merged.txt → resolution Tasks; resolved.merged.txt → permutation Tasks in plan-04)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed containsWord helper in scope_crosscheck_test.go**
- **Found during:** Task 2 full test suite run
- **Issue:** `containsWord("subdomains.noerror", "barrier")` returned `true` because the old implementation used index arithmetic `s[len(s)-len(word)-1] == '.'` which accidentally matched position 10 (the `.` between "subdomains" and "noerror") for the word "barrier" (7 chars → index 10). This caused `TestPassiveTasksRegistered` to fail with "unexpected barrier task registered: subdomains.noerror" after the new resolve Tasks were added to the registry.
- **Fix:** Rewrote `containsWord` to use dot-segment semantics: `contains(s, "."+word+".")`, `strings.HasPrefix(s, word+".")`, `strings.HasSuffix(s, "."+word)`. Added `strings` import to the test file.
- **Files modified:** `internal/modules/subdomains/scope_crosscheck_test.go`
- **Commit:** a2309e0

## Verification Results

- `go build -o /dev/null ./...` exits 0
- `go test -race ./internal/modules/subdomains/... ./internal/core/...` — all 14 packages PASS
- `grep -c "task.Register" internal/modules/subdomains/resolve.go` = 6
- `grep "Tree.Append" internal/modules/subdomains/resolve.go` → no code calls (comments only)
- `grep "Tree.Append" internal/modules/subdomains/brute.go` → no code calls
- `grep "barrier" internal/modules/subdomains/resolve.go` → no matches
- `grep "Tools.Stream" internal/modules/subdomains/resolve.go` → match in runStreamTask
- `grep "MinResolvers" internal/modules/subdomains/brute.go` → match in Run() body (not only Enabled)
- `grep "StatusSkipped" internal/modules/subdomains/brute.go` → 2 matches (health task + brute task)
- `grep "merged.txt" internal/modules/subdomains/merge.go` → match in writeMergedTxt call

## TDD Gate Compliance

- Task 1 RED: `resolve_test.go` committed (f888395) — 6 tests fail, tasks not registered
- Task 1 GREEN: `resolve.go` committed (af60dd1) — all 6 tests pass
- Task 2 RED: `brute_test.go` committed (4b81358) — 6 tests fail, tasks not registered, merged.txt not written
- Task 2 GREEN: `brute.go` + `merge.go` committed (a2309e0) — all tests pass

## Self-Check: PASSED

- internal/modules/subdomains/resolve.go — exists; 6 tasks; 6 init() calls; no Tree.Append code calls; Tools.Stream used
- internal/modules/subdomains/brute.go — exists; SubBruteTask + SubResolversHealthTask; MinResolvers in Run(); StatusSkipped for gate; no Tree.Append
- internal/modules/subdomains/merge.go — exists; writeMergedTxt helper added; merged.txt written post-Append
- internal/modules/subdomains/resolve_test.go — exists; 6 tests all PASS
- internal/modules/subdomains/brute_test.go — exists; 6 tests all PASS
- Commits f888395, af60dd1, 4b81358, a2309e0 verified in git log
