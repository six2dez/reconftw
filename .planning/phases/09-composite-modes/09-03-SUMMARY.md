---
phase: 09-composite-modes
plan: "03"
subsystem: alias-dispatch-batch
tags:
  - v1-alias
  - translateV1Args
  - batch
  - cli
  - D-08
  - D-07
  - D-10
dependency_graph:
  requires:
    - cmd/reconftw/main.go (run() function, parseEarlyFlags, registerSecrets)
    - cmd/reconftw/root.go (addV1DeprecatedAliases, MarkDeprecated wiring)
    - internal/core/config (Config struct)
    - internal/core/log (Redactor, RedactingHandler)
  provides:
    - translateV1Args(args []string) []string — rewrites v1 flag forms to v2 subcommand invocations
    - runBatch(ctx, listFile, run) — sequential batch processing per D-07
    - readTargetList(path) — validates + reads target list from file
    - printBatchSummary(w, results) — per-target outcome table
    - main.go run() wiring — translateV1Args + rootCmd.SetArgs(translated) between parseEarlyFlags and ExecuteContext
  affects:
    - cmd/reconftw/main.go (STEP 10: translated args set before ExecuteContext; D-10 bootstrap logger comment)
tech_stack:
  added:
    - cmd/reconftw/alias.go (translateV1Args, v1SubcommandFlags map, knownSubcmds set)
    - cmd/reconftw/alias_test.go (TestTranslateV1Args 15 table cases, TestTranslateV1ArgsNoDoubleSubcmd, TestTranslateV1ArgsFirstWinsOnMultipleModFlags, TestTranslateV1ArgsGlobalAliasesOnly, TestV1DeprecationWarningContainsRemovalVersion, TestV1DeprecationWarningAllLongFlags)
    - cmd/reconftw/batch.go (batchResult, readTargetList, runBatch, printBatchSummary)
    - cmd/reconftw/batch_test.go (8 tests: TestReadTargetList, TestReadTargetListMissingFile, TestReadTargetListDirectory, TestBatchAllSucceed, TestBatchExitsNonZeroOnAnyFailure, TestBatchContinuesOnError, TestPrintBatchSummary, TestBatchEmptyListReturnsNoError, TestBatchMissingListFile)
  patterns:
    - Pre-cobra linear arg scan (mirrors parseEarlyFlags in main.go)
    - First-wins on multiple mode flags (documented in alias.go header)
    - Pitfall-4 double-insertion guard (check args[0] against knownSubcmds before injecting)
    - Sequential batch loop with continue-on-error and aggregate exit (D-07)
    - io.Writer for printBatchSummary (testable without os.File dependency)
key_files:
  created:
    - cmd/reconftw/alias.go
    - cmd/reconftw/alias_test.go
    - cmd/reconftw/batch.go
    - cmd/reconftw/batch_test.go
  modified:
    - cmd/reconftw/main.go (STEP 10 wiring + D-10 bootstrap logger comment)
decisions:
  - "translateV1Args placed in alias.go (not inlined in main.go) to keep the pure-function testable without the rest of run() state"
  - "Pitfall-4 guard scans for first non-flag token then checks knownSubcmds — handles interleaved global flags like -d example.com -r correctly"
  - "printBatchSummary uses io.Writer not *os.File to allow bytes.Buffer capture in tests"
  - "D-10 main.go: added comment at bootstrap logger creation (lines 94-100) documenting RedactingHandler is unconditional; composite dry-run fmt.Fprintf redaction is Plan 09-02 scope"
metrics:
  duration: "~15 minutes"
  completed: "2026-06-11"
  tasks_completed: 2
  tasks_total: 2
  files_created: 4
  files_modified: 1
---

# Phase 09 Plan 03: V1 Alias Translation + Batch Processing Summary

**One-liner:** translateV1Args pre-cobra rewrite dispatches v1 flag forms to v2 subcommands while preserving MarkDeprecated warnings; runBatch provides sequential --list processing with continue-on-error and aggregate exit.

## What Was Built

### Task 1: translateV1Args + main.go wiring + alias_test.go (D-08 / MODE-09)

Created `cmd/reconftw/alias.go` with:

**`translateV1Args(args []string) []string`** — pure string rewrite function:
- Scans for first non-flag token; if it is a known v2 subcommand, skips mode injection (Pitfall-4 double-insertion guard)
- Scans full args for first v1 mode flag (first-wins on multiple mode flags like `--recon --all`)
- If mode flag found and no subcommand at position 0: prepends v2 subcommand name; original flag left in slice so cobra's `MarkDeprecated` still fires (MODE-09 warning requirement)
- Second pass: global alias rewrites `-d X → --target X`, `-l X → --list X`, `-v → --axiom`

**`v1SubcommandFlags`** map — 11 entries covering all 9 mode flags with short + long forms.

**`knownSubcmds`** set — 19 entries including all v2 subcommands plus completion/help.

Wired in `cmd/reconftw/main.go` `run()` STEP 10:
```go
translated := translateV1Args(os.Args[1:])
rootCmd := newRootCmd(app, cfg)
rootCmd.SetArgs(translated)
return rootCmd.ExecuteContext(ctx)
```

Also added D-10 documentation comment at the bootstrap logger creation in STEP 3, noting that `log.New(&log.Config{}, redactor)` always wraps with `RedactingHandler` regardless of TTY/quiet/dry-run path.

`alias_test.go` covers:
- 15 table-driven `TestTranslateV1Args` cases covering all 9 mode flags, empty input, no-double-insertion, global aliases
- `TestTranslateV1ArgsNoDoubleSubcmd` for Pitfall-4 guard
- `TestTranslateV1ArgsFirstWinsOnMultipleModFlags`
- `TestTranslateV1ArgsGlobalAliasesOnly` (subcommand-first + -d/-v)
- `TestV1DeprecationWarningContainsRemovalVersion` (cobra emits "deprecated" + subcommand name)
- `TestV1DeprecationWarningAllLongFlags` for all 9 mode flags

Existing `TestDeprecationWarningLongAliases` and `TestDeprecationWarningShortAliases` both continue to pass — the translated args still contain the original flag, so MarkDeprecated fires.

### Task 2: runBatch + readTargetList + printBatchSummary + batch_test.go (D-07 / MODE-10)

Created `cmd/reconftw/batch.go` with:

**`batchResult{Target string, Err error}`** — per-target outcome.

**`readTargetList(path string) ([]string, error)`**:
- `os.Stat` check before `os.Open` (T-09-03-02 path traversal mitigation)
- Rejects directories
- `bufio.Scanner` line-by-line read
- Strips blank lines and `#` comment lines

**`runBatch(ctx context.Context, listFile string, run func(ctx, target) error) ([]batchResult, error)`**:
- Calls `readTargetList` then iterates sequentially (D-07: no cross-target concurrency)
- On error: `slog.Warn("batch_target_failed", ...)` and continues (continue-on-error)
- Calls `printBatchSummary(os.Stderr, results)` after all targets complete
- Returns `fmt.Errorf("batch: %d of %d target(s) failed", ...)` if any target failed

**`printBatchSummary(w io.Writer, results []batchResult)`**:
- `── batch summary` header (mirrors `printSubsSummary` border style)
- Per-target row: `%-40s  OK|FAIL`
- Footer with total/ok/failed counts

`batch_test.go` covers 9 tests including all 5 behavior cases from the plan.

## Verification Results

```
go build ./...                                                    PASS
go test ./cmd/reconftw/... -run "TestTranslateV1Args|TestBatch|TestReadTarget|TestDeprecationWarning" -count=1 -v   PASS (all subtests)
go test ./... -race -count=1                                      PASS (all packages)
grep "translated := translateV1Args" cmd/reconftw/main.go         line 183 (exactly one)
grep "rootCmd.SetArgs(translated)" cmd/reconftw/main.go           line 185 (exactly one)
```

## Deviations from Plan

### Minor adjustments

**1. [Rule 2 - Missing critical] Added `TestReadTargetListDirectory` and `TestBatchEmptyListReturnsNoError`**
- **Found during:** Task 2 test implementation
- **Issue:** Plan behavior tests did not cover directory-as-path (T-09-03-02) or empty list edge case (D-07 boundary)
- **Fix:** Added two extra tests beyond the 5 specified; both are correctness requirements for the threat mitigation and batch loop boundary
- **Files modified:** `cmd/reconftw/batch_test.go`

**2. [Style] `printBatchSummary` uses `io.Writer` instead of `*os.File`**
- **Found during:** Task 2 implementation
- **Issue:** The plan specified `io.Writer` for testability; `printSubsSummary` (analog) uses `*os.File` but that's a test antipattern
- **Fix:** Used `io.Writer` as specified in the plan; `runBatch` passes `os.Stderr` (satisfies same interface)
- **Files modified:** `cmd/reconftw/batch.go`

## Known Stubs

None. All functions are fully implemented with no placeholder values or hardcoded returns.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes introduced. Threat mitigations T-09-03-01 through T-09-03-05 implemented as specified in the plan's threat model.

## Self-Check

- [x] `cmd/reconftw/alias.go` exists with `translateV1Args` function
- [x] `cmd/reconftw/alias.go` contains `v1SubcommandFlags` map and `knownSubcmds` set
- [x] `cmd/reconftw/main.go` contains `translated := translateV1Args(os.Args[1:])` (line 183)
- [x] `cmd/reconftw/main.go` contains `rootCmd.SetArgs(translated)` (line 185)
- [x] `cmd/reconftw/batch.go` exists with `runBatch`, `readTargetList`, `printBatchSummary`
- [x] `cmd/reconftw/alias_test.go` contains `TestTranslateV1Args` with 15 table cases
- [x] `cmd/reconftw/batch_test.go` contains all 5 required behavior tests
- [x] `go build ./...` passes
- [x] `go test ./cmd/reconftw/... -run "TestTranslateV1Args|TestBatch|TestReadTarget|TestDeprecationWarning"` passes
- [x] `go test ./... -race -count=1` green (all packages)
- [x] Existing `TestDeprecationWarningLongAliases` and `TestDeprecationWarningShortAliases` still pass

## Self-Check: PASSED
