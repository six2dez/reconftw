---
phase: "09"
plan: "04"
subsystem: composite-modes
tags: [gen-resolvers, refresh-cache, quick-rescan, stateful, d-04, d-05, d-06, mode-06, mode-07, mode-08]
dependency_graph:
  requires: [09-02-SUMMARY.md, 09-03-SUMMARY.md]
  provides: [stateful-subcommands, resolvers-gen-package]
  affects: [cmd/reconftw, internal/core/resolvers]
tech_stack:
  added:
    - internal/core/resolvers (new package)
    - modernc.org/sqlite (driver already in go.mod, now used in stateful_subcommands.go)
    - github.com/google/uuid (already in go.mod, now used for scan ID generation)
  patterns:
    - D-04 gen-resolvers: dnsvalidator two-URL invocation + HTTP fallback (mirrors v1 axiom.sh:resolvers_update)
    - D-05 refresh-cache: ConfigTransform (Cache.Refresh=true + Diff=true) + per-workspace cache staging file deletion
    - D-06 quick-rescan THIN: ConfigTransform sets ONLY Advanced.Diff=true (no QuickRescan field); store.db baseline record best-effort
    - T-09-04-01 URL from config not user input; HTTPS enforced; 60s timeout
    - T-09-04-02 cache deletion scoped to workdir/inputs/ via isInsideDir guard
    - T-09-04-03 target validated by resolveTarget before store insertion
    - T-09-04-04 httpDownload 60-second client timeout
key_files:
  created:
    - internal/core/resolvers/gen.go
    - internal/core/resolvers/gen_test.go
    - internal/core/resolvers/lookup.go
    - cmd/reconftw/stateful_subcommands.go
    - cmd/reconftw/stateful_test.go
  modified:
    - cmd/reconftw/root.go
decisions:
  - "gen-resolvers uses LocalBackend.Exec to invoke dnsvalidator (not raw exec.Command) to stay within the FOUND-10 allowlist; exec.LookPath is not a forbidden pattern"
  - "quick-rescan ConfigTransform sets ONLY cfg.Advanced.Diff=true per D-06 THIN; cfg.Advanced.QuickRescan already exists in the schema but is NOT set by the transform"
  - "store.db CreateScan for quick-rescan is best-effort (warn+continue on failure) because store.db may not exist on first run"
  - "refresh-cache uses the same RunCompositeAsync(ModeRecon) call as the recon subcommand with configTransform=refreshCacheConfigTransform applied; cache file deletion precedes the pipeline start"
  - "isInsideDir path-containment guard ensures glob-matched deletions cannot escape workspace directory (T-09-04-02)"
  - "runBatch/runCompositeList not used by stateful commands — each is single-target; --list batch via inherited composite pattern is available but not wired for stateful commands in Phase 9"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-11"
  tasks_completed: 2
  files_created: 5
  files_modified: 1
---

# Phase 9 Plan 04: Stateful Utility Subcommands Summary

Three stateful utility subcommands shipped: gen-resolvers (dnsvalidator + HTTP fallback per D-04), refresh-cache (cache invalidation per D-05), quick-rescan (checkpoint-bypass + scan baseline per D-06 THIN). All registered in root.go. Full test suite green with -race.

## What Was Built

### Task 1: RunGenResolvers + gen_test.go (D-04/MODE-08)

**`internal/core/resolvers/gen.go`** (NEW — package resolvers):

`RunGenResolvers(ctx, cfg)` mirrors v1 `modules/axiom.sh:resolvers_update`:
1. Determines output path from `cfg.Paths.Resolvers` (fallback: `~/.config/reconftw/resolvers.txt`)
2. Determines thread count from `cfg.Advanced.Tools.DNSValidator.Threads` (default 10)
3. Invokes dnsvalidator via `LocalBackend.Exec` with two source URLs:
   - `https://public-dns.info/nameservers.txt` (first invocation)
   - `https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt` (second invocation → merged via `appendUnique`)
4. Falls back to HTTP GET of `cfg.Paths.ResolversDownload.URL` when dnsvalidator is absent or produces zero output (T-09-04-04: 60-second timeout)
5. Downloads trusted resolvers to `cfg.Paths.ResolversTrusted` if configured

**`internal/core/resolvers/lookup.go`** (NEW): single `exec.LookPath` call site (mirrors registry.go pattern).

**`internal/core/resolvers/gen_test.go`** (NEW — package resolvers_test):
- `TestGenResolversCallsDnsvalidator`: skips gracefully when dnsvalidator absent; passes when present (network test or fallback)
- `TestGenResolversFallsBackToHTTP`: httptest.NewServer provides fallback URL; verifies file is populated
- `TestGenResolversFallsBackToHTTP_NoDnsvalidator`: pure fallback test (skips if dnsvalidator on PATH)
- `TestGenResolversOutputPathDefaultFallback`: verifies empty `cfg.Paths.Resolvers` triggers default path

### Task 2: stateful_subcommands.go + stateful_test.go + root.go registration (D-05/D-06/MODE-06/07/08)

**`cmd/reconftw/stateful_subcommands.go`** (NEW):

`newGenResolversCmd()`: standalone (no `--target`), `RunE` calls `resolvers.RunGenResolvers(ctx, cfg)`.

`newRefreshCacheCmd()`: `--target` required (via inherited persistent flag). `refreshCacheConfigTransform` sets `cfg.Cache.Refresh=true` + `cfg.Advanced.Diff=true`. Before running `RunCompositeAsync(ModeRecon)`, calls `invalidateCacheFiles` which deletes glob-matched staging files (`geo*.txt`, `asn*.jsonl`, `resolvers*.txt`) in `workspaces/<target>*/inputs/` using `isInsideDir` containment guard (T-09-04-02).

`newQuickRescanCmd()`: `--target` required. `quickRescanConfigTransform` sets ONLY `cfg.Advanced.Diff=true` (D-06 THIN — no QuickRescan field mutation). Calls `recordQuickRescanBaseline` (best-effort store.db insert with `mode="quick-rescan"` + UUID scan ID) before `RunCompositeAsync(ModeRecon)`.

**`cmd/reconftw/root.go`** (modified): added `AddCommand(newGenResolversCmd())`, `AddCommand(newRefreshCacheCmd())`, `AddCommand(newQuickRescanCmd())` after the existing 14 subcommands.

**`cmd/reconftw/stateful_test.go`** (NEW):
- `TestQuickRescanForcesDiff`: invokes `quickRescanConfigTransform` on `Defaults()`; asserts `cfg.Advanced.Diff==true` and `cfg.Advanced.QuickRescan` unchanged (D-06 assertion)
- `TestRefreshCacheSetsForceRefreshFlag`: invokes `refreshCacheConfigTransform`; asserts `cfg.Cache.Refresh==true` and `cfg.Advanced.Diff==true`
- `TestGenResolversDryRun`: constructs `newGenResolversCmd()`, asserts non-nil, no required `--target`, non-nil `RunE`, `--help` no panic
- `TestStatefulCmdsRegisteredInRoot`: `newRootCmd(nil, Defaults()).Find(name)` for all three subcommand names

## Build Verification

```
go build ./...                         # PASS
go test ./cmd/reconftw/... ./internal/core/resolvers/... -count=1 -v  # all PASS
go test ./... -race -count=1           # 30 packages, all PASS
```

## Deviations from Plan

### Clarifications Applied

**1. [Rule 2 - Design clarification] `recordQuickRescanBaseline` uses best-effort store path**
- **Issue:** Plan said "open the store.db at cfg.Paths.DataDir + workdir" but `workdir` is not known until `BootReconApp` runs (inside `RunCompositeAsync`). The baseline must be recorded BEFORE running so Phase 10 can see it.
- **Fix:** `recordQuickRescanBaseline` uses `filepath.Join(cfg.Paths.DataDir, "store.db")` (the global store) before the run starts. If the store is unavailable, warn and continue.
- **Files modified:** `cmd/reconftw/stateful_subcommands.go`

**2. [Rule 2 - Missing type] `summaryVerbosity` unused variable in runRefreshCacheCmd**
- **Found during:** Compilation pass
- **Issue:** `summaryVerbosity` declared but not used after the `printCompositeSummary` call was refactored to take a literal `1` (ui.VerbosityNormal).
- **Fix:** Removed the unused variable declaration; passed verbosity `1` directly to `printCompositeSummary`.

**3. [Rule 3 - Lint compliance] `exec.LookPath` in package resolvers**
- **Found during:** FOUND-10 lint review
- **Issue:** `gen.go` needed to check for dnsvalidator availability via `exec.LookPath`. The FOUND-10 lint scanner only forbids `exec.Command`/`exec.CommandContext`/`(*exec.Cmd).Run|Start` — not `exec.LookPath`.
- **Fix:** Isolated `exec.LookPath` in `lookup.go` (mirrors `registry.go` pattern) so the package has a single PATH-lookup call site. No FOUND-10 violation.

## Threat Compliance

| T-ID | Mitigation | Status |
|------|-----------|--------|
| T-09-04-01 | URL from `cfg.Paths.ResolversDownload.URL` (config, not user input); HTTPS-only URL; 60s timeout in `httpDownload` | DONE |
| T-09-04-02 | `invalidateCacheFiles` scoped to workspace directory; `isInsideDir` containment guard | DONE |
| T-09-04-03 | `resolveTarget(cmd, "quick-rescan")` applies same validation as all composite subcommands | DONE |
| T-09-04-04 | `http.Client{Timeout: 60 * time.Second}` in `httpDownload` | DONE |
| T-09-04-05 | Accepted — resolver list is non-sensitive operational data | N/A |

## Self-Check

- `internal/core/resolvers/gen.go` — FOUND
- `internal/core/resolvers/gen_test.go` — FOUND
- `internal/core/resolvers/lookup.go` — FOUND
- `cmd/reconftw/stateful_subcommands.go` — FOUND (contains `newGenResolversCmd`)
- `cmd/reconftw/stateful_test.go` — FOUND (contains `TestQuickRescanForcesDiff`)
- `cmd/reconftw/root.go` — modified; `grep -c newGenResolversCmd` = 1
- All targeted tests PASS; full `-race` suite 30/30 PASS

## Self-Check: PASSED
