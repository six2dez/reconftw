---
phase: 03-foundation-kernel
plan: 03
subsystem: foundation-kernel
tags: [output, checkpoint, atomic-writer, scope-filter, manifest, compat, sqlite, found-04, found-05]
dependency_graph:
  requires:
    - .planning/decisions/0002-architecture-v2.md (BINDING §3.1, §3.2, §3.3, §3.4, §3.5, §4.1-§4.4, §6)
    - .planning/phases/03-foundation-kernel/03-01-SUMMARY.md (errors + log shipped)
    - .planning/phases/03-foundation-kernel/03-02-SUMMARY.md (config shipped — consumed via output.WriteFile in W19 migration)
  provides:
    - internal/core/output/WriteJSONL (atomic 4-step JSONL writer)
    - internal/core/output/WriteFile (atomic 4-step byte-blob writer)
    - internal/core/output/AtomicSymlink (atomic temp-then-rename symlink swap)
    - internal/core/output/OutputTree (workspaces/<target-id>/ tree + scope-filter-at-Append boundary)
    - internal/core/output/ScopeFilter + DefaultScopeFilter (anchored hostname check — v1 fix)
    - internal/core/output/Manifest + WriteManifest + WorkspaceInit + WorkspaceFinalize
    - internal/core/output/CompatWriter (skeleton + V1ToV2Mapping seed table for Phase 12)
    - internal/core/output/Interface (W15 — *OutputTree satisfies it)
    - internal/core/checkpoint/Store (SQLite-backed task idempotency; WAL mode; modernc/sqlite driver)
    - internal/core/checkpoint/Interface (W15 — *Store satisfies it)
    - internal/core/checkpoint/InputHash (SHA-256 over task, target, cfg_slice, wordlists.lock)
  affects:
    - go.mod (modernc.org/sqlite v1.51.0 direct dep + 9 transitive)
    - go.sum (lock entries; mattn/go-sqlite3 NEVER added per RESEARCH.md blacklist)
    - internal/core/config/snapshot.go (W19: inline atomic helper removed; delegates to output.WriteFile)
    - .github/workflows/ci.yml (W20: XCUT-03 per-file ≥90% gate step added to integration job)
    - Makefile (W20: coverage-critical target)
    - scripts/coverage-critical.sh (W20: local per-file gate script)
tech_stack:
  added:
    - modernc.org/sqlite v1.51.0 (pure-Go SQLite — preserves XCUT-02 single-binary promise; CGO-based driver remains forbidden per RESEARCH.md)
    - modernc.org/libc v1.72.3 (transitive)
    - modernc.org/mathutil v1.7.1 (transitive)
    - modernc.org/memory v1.11.0 (transitive)
    - github.com/dustin/go-humanize v1.0.1 (transitive)
    - github.com/google/uuid v1.6.0 (transitive)
    - github.com/mattn/go-isatty v0.0.20 (transitive — IS NOT mattn/go-sqlite3)
    - github.com/ncruces/go-strftime v1.0.0 (transitive)
    - github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec (transitive)
  patterns:
    - 4-step AtomicWriter (tempfile + fsync + rename + parent-dir fsync) — the ONLY sanctioned write path for artefacts/, reports/, inputs/, manifest.json (per ADR §3.5; FOUND-04 atomicity test gate)
    - FOUND-04 hook seam (writeJSONLWithHook + writeFileWithHook) — production callers pass nil; tests pass a hook that returns an error AFTER tempfile fsync but BEFORE rename to simulate SIGKILL at the most atomicity-critical moment
    - Ring 3 subprocess SIGKILL (atomic_smoke_test.go) — build-tagged `smoke`; spawns a child invoking writeJSONLWithHook with a slow hook, parent SIGKILLs after 1.5s, asserts target survives
    - Anchored hostname scope check (host == base || strings.HasSuffix(host, "."+base)) — mirrors v1 lib/validation.sh:is_in_scope_host; closes the "examplecom.evil.org" substring false-positive bug
    - Scope-filter-at-Append-boundary — OutputTree parses each JSONL line, extracts the scope-relevant field per ADR §3.2 dispatch table (subdomain / host / url / findings host-or-url), rejects the WHOLE batch with *errors.OutOfScope if any line fails; Task code cannot bypass
    - SQLite WAL mode (PRAGMA journal_mode=WAL + busy_timeout=5000 + foreign_keys=1 via DSN params) — concurrent reads, single concurrent writer per ADR §3.4
    - INSERT OR REPLACE Begin (upsert) — re-run-after-error path; replaces the row with status=in-progress and refreshed started_at
    - 7-class error classification via stderrors.As walk in classifyError — populates the error_class column from the typed-error hierarchy
    - SHA-256 input_hash with null-byte separators between fields — prevents prefix-collision attacks (task="ab" target="" must not collide with task="a" target="b")
    - W15 Interface introductions with compile-time assertions (var _ Interface = (*Concrete)(nil)) — adding a method to Interface forces a compile error across every implementation including Plan 07 mocks
    - W19 atomic-helper consolidation — config/snapshot.go delegates to output.WriteFile; no two copies of the 4-step pattern coexist in the kernel
key_files:
  created:
    - internal/core/output/atomic.go
    - internal/core/output/atomic_test.go
    - internal/core/output/atomic_internal_test.go
    - internal/core/output/atomic_smoke_test.go (build tag `smoke`)
    - internal/core/output/scope.go
    - internal/core/output/scope_test.go
    - internal/core/output/tree.go
    - internal/core/output/tree_test.go
    - internal/core/output/manifest.go
    - internal/core/output/manifest_test.go
    - internal/core/output/init.go
    - internal/core/output/compat.go
    - internal/core/output/compat_test.go
    - internal/core/output/interface.go
    - internal/core/output/interface_test.go
    - internal/core/checkpoint/store.go
    - internal/core/checkpoint/store_test.go
    - internal/core/checkpoint/migrations.go
    - internal/core/checkpoint/hash.go
    - internal/core/checkpoint/hash_test.go
    - internal/core/checkpoint/coverage_test.go
    - internal/core/checkpoint/interface.go
    - internal/core/checkpoint/interface_test.go
    - scripts/coverage-critical.sh
  modified:
    - go.mod (modernc.org/sqlite + 8 transitive)
    - go.sum (lock entries)
    - internal/core/config/snapshot.go (W19: inline helper removed; delegates to output.WriteFile)
    - .github/workflows/ci.yml (W20: per-file gate step)
    - Makefile (W20: coverage-critical target)
    - .gitignore (un-anchored `output/` rule was shadowing internal/core/output — fixed to `/output/`)
  deleted: []
decisions:
  - "Hook seam over OS injection for FOUND-04 unit ring: writeJSONLWithHook and writeFileWithHook expose a `hook func(tmpName string) error` parameter that production callers pass nil to. Tests pass a hook returning a sentinel error AFTER the tempfile fsync but BEFORE rename. The hook is the canonical SIGKILL-between-fsync-and-rename simulation. Real subprocess SIGKILL lives in atomic_smoke_test.go (build tag `smoke`) per W12."
  - "REPLACE semantics for OutputTree.Append: per ADR §3.2 ('merged set written at end of Task'), Tasks dedup their findings in-memory and call Append once with the full batch. The kernel does NOT auto-append/merge across calls; the boundary atomic write is REPLACE."
  - "Per-artefact scope dispatch table inside OutputTree.Append: subdomain → subdomains.jsonl, host → hosts.jsonl, url (URL form) → urls.jsonl, host-or-url fallback → findings.jsonl. Other artefacts (notes.jsonl, future schemaless) pass through with only a JSON syntax check. This matches ADR §3.2 schemas exactly."
  - "modernc.org/sqlite DSN PRAGMAs: WAL + busy_timeout(5000) + foreign_keys(1). db.Ping() called immediately after Open() to force the PRAGMA to apply (lazy connections defer it otherwise). TestCheckpointStoreWALMode verifies PRAGMA journal_mode returns 'wal'."
  - "INSERT OR REPLACE on Begin (rather than ON CONFLICT DO UPDATE): functionally identical for the PRIMARY KEY (task_name, target, input_hash) constraint; INSERT OR REPLACE has broader SQLite version compatibility. The Begin call is naturally the re-run-after-error path — re-Begin resets status to in-progress and refreshes started_at."
  - "Null-byte separators between fields in InputHash: SHA-256 over `task \\0 target \\0 cfg \\0 wordlists` — closes the prefix-collision attack (task='ab' target='' would otherwise concat identically to task='a' target='b'). TestInputHashPrefixCollisionSafe is the gate."
  - "Atomic helper refactor for W20 coverage gate: writeJSONLLines and writeFilePayload extracted as small unit-testable helpers (io.Writer + syncableWriter interfaces) so the deep error-wrap branches that OS injection cannot easily produce can be covered by stub-based tests. Final atomic.go average: 91.16% (≥90% gate)."
  - "interfaces_check/main.go disposition unchanged this plan: still compiles and passes verify-0002.sh. Phase 4 plan-01 will delete it per Phase 3 D-default (keep until end of Phase 3 then delete)."
  - "spike/go/internal/output/atomic.go was the canonical reference for AtomicWriter; NOT imported — code is ported to internal/core/output/ per Phase 1 D-03 hermetic-spike rule. Material additions over the spike: WriteFile API (byte-blob analogue), syncParentDir extraction with APFS ENOTSUP/EINVAL carve-out, error wrapping per ADR §6 idioms, the FOUND-04 hook seam."
metrics:
  duration: 22m 20s
  completed_date: 2026-05-28T16:08:33Z
  tasks: 5
  commits: 10
  files_created: 24
  files_modified: 6
  coverage_log: 94.9%
  coverage_output: 83.4%
  coverage_checkpoint: 88.8%
  coverage_config: 84.3%
  coverage_atomic_go: 91.16%
  coverage_scope_go: 92.20%
  coverage_checkpoint_store_go: 90.03%
  coverage_redactor_go: 100.0%
  coverage_redacting_handler_go: 100.0%
  go_test_files: 11
  go_source_files: 12
  test_count_estimate: 67
---

# Phase 3 Plan 03: Output Tree + Checkpoint Store Summary

**One-liner:** Atomic JSONL writer (4-step pattern, FOUND-04 hook-simulation + Ring 3 subprocess SIGKILL gates) + workspace tree + anchored scope filter + manifest + compat skeleton + SQLite-backed checkpoint store (modernc/sqlite, WAL mode, BEGIN IMMEDIATE), with W15 interface introductions, W19 config-snapshot migration, and W20 per-file ≥90% coverage CI gate.

## Tasks Completed

| Task | Name                                                                          | Commits              | Files                                                                                                                                                                                |
| ---- | ----------------------------------------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | RED: failing tests for AtomicWriter + FOUND-04 atomicity                      | `91b7e70`            | internal/core/output/atomic_test.go, .gitignore (unblock internal/core/output)                                                                                                       |
| 1    | GREEN: implement AtomicWriter (WriteJSONL + WriteFile) per ADR §3.5           | `8365eb2`            | internal/core/output/atomic.go, atomic_smoke_test.go, atomic_internal_test.go                                                                                                        |
| 2    | RED: failing tests for OutputTree + ScopeFilter + Manifest                    | `799b884`            | scope_test.go, tree_test.go, manifest_test.go                                                                                                                                        |
| 2    | GREEN: implement OutputTree + ScopeFilter + Manifest + WorkspaceInit          | `f35d7b4`            | scope.go, tree.go, manifest.go, init.go, tree_test.go (shadow-var fix)                                                                                                               |
| 3    | RED: failing tests for checkpoint Store + InputHash                           | `6a4dd85`            | store_test.go, hash_test.go                                                                                                                                                          |
| 3    | GREEN: implement SQLite checkpoint Store with WAL + InputHash                 | `b30b559`            | store.go, migrations.go, hash.go, coverage_test.go, go.mod, go.sum                                                                                                                   |
| 4    | RED: failing tests for CompatWriter + AtomicSymlink                           | `e90802e`            | compat_test.go                                                                                                                                                                       |
| 4    | GREEN: implement CompatWriter skeleton + AtomicSymlink                        | `e321364`            | compat.go                                                                                                                                                                            |
| 5    | RED: failing interface-shape gates (W15)                                      | `258183e`            | checkpoint/interface_test.go, output/interface_test.go                                                                                                                               |
| 5    | GREEN: W15 interfaces + W19 snapshot migration + W20 per-file gate            | `90c628a`            | checkpoint/interface.go, output/interface.go, config/snapshot.go (W19), atomic.go (W20 refactor), atomic_internal_test.go, .github/workflows/ci.yml, Makefile, scripts/coverage-critical.sh |

## Acceptance Verification

### Whole-plan automated verification (from PLAN.md `<verification>` block)

- `go build ./internal/core/output/... ./internal/core/checkpoint/...` → **exit 0**
- `go build ./...` → **exit 0**
- `go vet ./internal/core/output/... ./internal/core/checkpoint/...` → **exit 0**
- `go vet ./...` → **exit 0**
- `go test -race ./internal/core/output/... ./internal/core/checkpoint/...` → **PASS** (full packages green; 67+ test functions)
- `go test -race -tags smoke ./internal/core/output/...` → **PASS** (Ring 3 subprocess SIGKILL test green; W12 mandate)
- `! grep -q mattn/go-sqlite3 go.sum` → **confirmed** (forbidden lib not in deps; modernc/sqlite is the sole SQLite driver)
- `grep -q modernc.org/sqlite go.sum` → **confirmed** (sanctioned lib present)
- FOUND-04 hook-simulation gate: `go test -race -run TestFOUND04Atomicity ./internal/core/output/...` → **PASS**
- FOUND-04 subprocess SIGKILL gate: `go test -race -run TestFOUND04SubprocessSIGKILL -tags smoke ./internal/core/output/...` → **PASS**
- ScopeFilter anchored gate (v1 fix): `go test -race -run TestScopeAnchored ./internal/core/output/...` → **PASS**
- Checkpoint WAL test: `go test -race -run TestCheckpointStoreWALMode ./internal/core/checkpoint/...` → **PASS**
- Checkpoint idempotency tests: `go test -race -run 'TestCheckpointStoreDoneAfterComplete|TestCheckpointStoreDoneDifferentHash' ./internal/core/checkpoint/...` → **PASS**
- Crash recovery: `go test -race -run TestCheckpointStoreCrashRecovery ./internal/core/checkpoint/...` → **PASS**
- Concurrent Begin under WAL: `go test -race -run TestCheckpointStoreConcurrentBegin ./internal/core/checkpoint/...` → **PASS**
- Coverage on `internal/core/output/atomic.go`: **91.16%** (XCUT-03 ≥90% gate)
- Coverage on `internal/core/output/scope.go`: **92.20%** (XCUT-03 ≥90% gate)
- Coverage on `internal/core/checkpoint/store.go`: **90.03%** (XCUT-03 ≥90% gate)
- Coverage on `internal/core/log/redactor.go`: **100.00%** (XCUT-03 ≥90% gate; from Plan 01)
- Coverage on `internal/core/log/redacting_handler.go`: **100.00%** (XCUT-03 ≥90% gate; from Plan 01)
- Coverage on `internal/core/output/...` package: **83.4%** (XCUT-04 ≥75% gate)
- Coverage on `internal/core/checkpoint/...` package: **88.8%** (XCUT-04 ≥75% gate)
- Coverage on `internal/core/config/...` package: **84.3%** (no regression after W19 migration)
- `bash .planning/decisions/verify-0002.sh` → **ALL CHECKS PASSED — safe to sign**
- W19 acceptance: `grep -q 'output\.WriteFile' internal/core/config/snapshot.go` AND `! grep -q 'atomicWriteFile' internal/core/config/snapshot.go` → both pass
- W20 acceptance: `grep -q 'XCUT-03\|Critical-path coverage' .github/workflows/ci.yml` AND `[ -f scripts/coverage-critical.sh ]` AND `grep -q 'coverage-critical' Makefile` → all pass
- W15 acceptance: `grep -q 'var _ Interface = (\*Store)(nil)' internal/core/checkpoint/interface.go` AND `grep -q 'var _ Interface = (\*OutputTree)(nil)' internal/core/output/interface.go` → both pass

### Per-task acceptance (selected highlights)

**Task 1 — AtomicWriter + FOUND-04:**
- `grep -c 'func WriteJSONL' internal/core/output/atomic.go` → **1**
- `grep -c 'func WriteFile' internal/core/output/atomic.go` → **1**
- `grep -q 'CreateTemp\|os\.Rename\|parent\.Sync\|syncParentDir\|defer os\.Remove' internal/core/output/atomic.go` → all 5 patterns present
- `grep -q 'ADR §3\.5\|spike.*atomic' internal/core/output/atomic.go` → cite present
- 11 behaviour tests + 14 internal-package coverage tests + 2 smoke tests (subprocess SIGKILL + child helper) — all PASS
- atomic.go avg coverage: 91.16% (W20 gate ≥90%)

**Task 2 — OutputTree + Scope + Manifest:**
- `grep -c 'type OutputTree struct' tree.go` → 1; `type Manifest struct` manifest.go → 1; `type ScopeFilter interface` scope.go → 1
- `grep -c 'OutOfScope{' tree.go` → 1 (rejection path returns the typed error)
- `grep -q '\^\[a-zA-Z0-9\.-\]+\$' scope.go` → canonical domain regex REUSED from spike + v1 per ADR §"Reused Assets"
- `grep -q 'anchored\|substring\|false positive' scope.go` → v1 fix comment present
- `grep -q 'WriteFile\|WriteJSONL' manifest.go` → manifest uses atomic write
- 14 OutputTree + 11 Scope (incl. rapid property test) + 6 Manifest tests — all PASS

**Task 3 — Checkpoint Store + InputHash:**
- `grep -c 'modernc.org/sqlite' store.go` → 3 (doc comment + import + module path)
- `grep -q 'journal_mode(WAL)' store.go` → WAL mode active
- `grep -q 'PRIMARY KEY (task_name, target, input_hash)' migrations.go` → ADR §3.4 PK mandate
- `grep -q 'sha256\.New\|sha256\.Sum256' hash.go` → SHA-256 used
- `grep -c 'func.*Store.*Begin\|Complete\|Done' store.go` → 3 main API methods
- `grep -q 'classifyError\|errorClass' store.go` → 7-class error_class population
- 16 store tests + 4 hash tests + 10 classifyError class tests — all PASS
- store.go avg coverage: 90.03% (W20 gate ≥90%)

**Task 4 — CompatWriter:**
- `grep -c 'func AtomicSymlink' compat.go` → 1; `type CompatWriter struct` → 1; `V1ToV2Mapping` → 1 mapping table
- `grep -q 'Phase 12\|cutover' compat.go` → skeleton comment present (documents Phase 3 vs Phase 12 split)
- 7 tests covering AtomicSymlink (basic, overwrite, concurrent), CompatWriter skeleton (dir creation, root-respect), and V1ToV2Mapping (3 required entries; artefacts/ path shape) — all PASS

**Task 5 — W15 + W19 + W20:**
- `grep -c 'type Interface interface' checkpoint/interface.go output/interface.go` → 2
- `var _ Interface = (*Store)(nil)` and `var _ Interface = (*OutputTree)(nil)` compile-time assertions present
- W19: `grep -q 'output\.WriteFile' config/snapshot.go` AND `! grep -q 'atomicWriteFile' config/snapshot.go` → both pass; all 14 Plan 02 snapshot tests still PASS
- W20: scripts/coverage-critical.sh executable; passes locally (`OK: all critical files at or above 90.0%`)
- W20 CI yaml step present in integration job (looped per-file gate)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `.gitignore` `output/` rule shadowed `internal/core/output/`**
- **Found during:** Task 1 first `git add` after writing atomic_test.go
- **Issue:** The repo-root `.gitignore` had an unanchored `output/` pattern (intended to ignore generated build/output directories at root), which matched `internal/core/output/` at any nesting depth.
- **Fix:** Changed to `/output/` (anchored to repo root only); added an explanatory comment pointing at Plan 03-03. Same file still ignores the legacy `Recon/` outputs.
- **Files modified:** .gitignore
- **Commit:** `91b7e70`

**2. [Rule 1 - Bug] Shadow-variable bug in TestOutputTreeRejectsOutOfScope hid the errors.Is gate**
- **Found during:** Task 2 first run after implementing tree.go
- **Issue:** The test did `body, err := os.ReadFile(...)` after the `err := tree.Append(...)` line, shadowing the outer `err`. By the time `if !stderrors.Is(err, coreerrors.ErrScope)` ran, `err` was the (nil) ReadFile error rather than the OutOfScope from Append.
- **Fix:** Renamed the inner variable to `readErr` and reordered the assertion so the errors.Is check runs against the right value. Implementation unchanged.
- **Commit:** `f35d7b4`

**3. [Rule 2 - Critical] atomic.go coverage was 85.98% — below the W20 90% gate**
- **Found during:** Task 5 acceptance check (`scripts/coverage-critical.sh`)
- **Issue:** The deep error-wrap branches in `writeJSONLWithHook` and `writeFileWithHook` (write-line-failed, write-newline-failed, chmod-failed, sync-failed) are very difficult to trigger through OS injection. Initial coverage stalled at 85-86%.
- **Fix:** Refactored two tight internal seams without changing public API or behaviour:
  - `writeJSONLLines(io.Writer, [][]byte) error` — the per-line write loop, exposed for stub-based testing via a `failingWriter` returning errors on the Nth Write call.
  - `writeFilePayload(syncableWriter, []byte, FileMode) error` — the write+chmod+sync sequence, exposed via a narrow `syncableWriter` interface so a stub can return errors per-operation.
  - Five new internal tests cover the line-write fail, newline-write fail, chmod fail, sync fail, and success paths of the helpers.
- **Result:** atomic.go avg coverage rose 85.98% → 91.16%; all three critical paths now ≥90%.
- **Commit:** `90c628a`

**4. [Rule 1 - Bug] go mod tidy removed modernc.org/sqlite before store.go imported it**
- **Found during:** Task 3 setup (between `go get` and store.go write)
- **Issue:** `go mod tidy` after `go get modernc.org/sqlite` removed the dep because no source file imported it yet. The transient state failed the `grep modernc.org/sqlite go.sum` check.
- **Fix:** Wrote store.go's import-driver block first (`_ "modernc.org/sqlite"`), then re-ran `go mod tidy`. Module retained correctly.
- **Commit:** `b30b559`

### Out-of-scope discoveries

None. All changes are within the plan scope.

### Issues Not Auto-fixed

None.

## Authentication / Manual Gates

None. The plan introduces no third-party API calls or installer touchpoints. The one new Go dependency (`modernc.org/sqlite`) installed via `go get` against the module proxy with `go.sum` checksum verification (transitive dependency lock).

## Threat Model Coverage

| Threat ID | Disposition | Status |
|-----------|-------------|--------|
| T-03-03-01 (Out-of-scope finding written to artefacts) | mitigate | OutputTree.Append parses each line as JSON, extracts the scope-relevant field per ADR §3.2 dispatch table, rejects the WHOLE batch with `*errors.OutOfScope` if any value is out of scope. `TestOutputTreeRejectsOutOfScope` + per-artefact scope tests (subdomains/hosts/urls/findings) are the gates. |
| T-03-03-02 (Torn write on crash) | mitigate | Implemented in `internal/core/output/atomic.go` — 4-step pattern (tempfile + fsync + rename + parent-dir fsync). `TestFOUND04Atomicity` (Ring 1 hook simulation) + `TestFOUND04SubprocessSIGKILL` (Ring 3 real subprocess SIGKILL) are the gates. |
| T-03-03-03 (Manifest config_hash leaks raw config) | mitigate | Plan 03 ships `Manifest.ConfigHash string` only; the raw config goes to `inputs/config.snapshot.toml` (Plan 02's WriteSnapshot redacts secrets explicitly per the W10 audit list). |
| T-03-03-04 (Symlink path traversal) | mitigate | `AtomicSymlink` uses `os.CreateTemp(filepath.Dir(link), ...)` — the temp slot is constrained to the same directory as the target link. The 4-step pattern guarantees no broken intermediate state. Callers are responsible for scope-checking link/target paths (out-of-scope). |
| T-03-03-05 (Stale checkpoint after code change) | mitigate | `InputHash` includes config_slice_json + wordlists.lock_content; any change to config or wordlist invalidates the hash and forces re-run on next startup. `TestInputHashChangeDetection` is the gate (one-byte diff in any of 4 fields produces a different hash). |
| T-03-03-06 (Checkpoint DB grows unboundedly) | accept | Phase 3 ships no retention policy. Phase 10 monitor mode handles rotation; expected DB size at 1000-task scale is <1MB. |
| T-03-03-07 (SQLite file corruption) | mitigate | WAL mode + busy_timeout(5000) per ADR §3.4 (DSN PRAGMAs validated by `TestCheckpointStoreWALMode`). modernc.org/sqlite is the same SQLite engine as mattn/go-sqlite3 but compiled to pure Go — no CGO race conditions. |
| T-03-03-SC (Go module supply chain — modernc/sqlite) | accept | 1 new direct Go module added via `go get` with `go.sum` checksum verification (built into Go toolchain). Per RESEARCH.md library blacklist, modernc/sqlite is sanctioned (Caddy / etcd / many other production users); the CGO-based driver remains forbidden. Phase 11 owns broader supply-chain audit. |
| T-03-03-08 (Output line containing a secret reaches an artefact) | accept (defer to per-task validation) | Phase 4-7 modules MUST sanitize tool output before passing to Tree.Append; Phase 3's responsibility is the scope filter, not the secret filter (XCUT-07 covers logs; artefacts are operator-facing). |

## Open Items for Downstream Plans

### Plan 04 (scheduler + backend + tool registry + lint rule)

- **`checkpoint.Interface`** ready to type the Scheduler's Checkpoint field on. Compile-time assertion in `checkpoint/interface.go` line `var _ Interface = (*Store)(nil)` enforces the contract.
- **`output.Interface`** ready to type AppContext.Tree (the production wiring keeps the concrete `*OutputTree` for Plan 05 ergonomics; module tests can choose Interface for substitution).
- **InputHash usage**: Scheduler calls `checkpoint.InputHash(taskName, target, configSliceJSON, wordlistsLockContent)` before calling `Done` — the hash uniquely identifies the (task, target, full-input-context) tuple. Callers compute their own `configSliceJSON` (the subset of the resolved Config relevant to the task) — Plan 04 will likely add a `Task.InputSlice(cfg *config.Config) []byte` extension to the Task interface, or document the convention in the Task contract.
- **Begin / Complete / Done ordering** mandated by ADR §3.4 lines 1321-1327 (BEGIN IMMEDIATE → Check Done → Insert in-progress → Run task → Complete). Plan 04 Scheduler must honour this 6-step ordering verbatim.

### Plan 05 (cmd/reconftw/main.go + AppContext.Boot + 15 subcommands)

- **AppContext.Tree** = `output.NewTree(workspaceRoot, scopeFilter)` — the scopeFilter is constructed from `cfg.Scope.Patterns` (per Plan 02 config). Boot order per ADR §10.3: logger → config.Load → register secrets → WorkspaceInit → NewTree → AppContext.New.
- **AppContext.Checkpoint** = `checkpoint.NewStore(filepath.Join(workspaceRoot, "checkpoints.db"))`.
- **CompatWriter wiring as a LifecycleAware.OnEnd hook**: Plan 05 registers the CompatWriter via Task.LifecycleAware extension; Phase 12 cutover replaces the skeleton with the real symlink-farm generation per ADR §4.4.
- **Manifest lifecycle**: WorkspaceInit writes the initial manifest (without finished_at); a deferred WorkspaceFinalize(workspaceRoot, manifest) at end-of-run stamps finished_at.
- **W19 follow-up** — config snapshot writer (Plan 02) is now thin (≤141 lines, down from 189); cmd/reconftw/main.go calling `config.WriteSnapshot(cfg, workspaceRoot+"/inputs/config.snapshot.toml")` is the canonical use site.

### Plan 07 (test mocks)

- **`testutil.MockOutputTree`** must satisfy `output.Interface` via its own compile-time assertion (`var _ output.Interface = (*MockOutputTree)(nil)`). In-memory implementation holds the artefact → []line map; exposes `Lines(artefact string) []string` for assertions.
- **`testutil.MockCheckpoint`** must satisfy `checkpoint.Interface` via `var _ checkpoint.Interface = (*MockCheckpoint)(nil)`. In-memory map keyed by (taskName, target, inputHash); Begin/Complete update the map; Done returns the recorded status.
- Both Mocks live in `internal/core/testutil/` per ADR §9.3 "Foundation Wave 0 Requirements."

### Plan 12 (cutover + migration)

- **V1ToV2Mapping table** seeded with 3 representative entries per ADR §4.3 (`subdomains/all.txt`, `webs/webs.txt`, `vulns/findings.txt`). Phase 12 extends this map to the full 40+ v1 output file shapes per the ADR §4.3 Scope-of-full-mapping line. The extension is structurally a map-literal addition + per-key extraction-loop logic — Phase 12 plan-01 owns the work.
- **CompatWriter.WriteCompat body** is currently a no-op (just creates `_compat/{subdomains, webs, vulns, osint}/`). Phase 12 replaces the body with the per-key extraction loop driven by V1ToV2Mapping: read the JSONL artefact via `os.ReadFile`, extract the field via `encoding/json`, write the plain-text compat file via `output.WriteFile`.
- **Top-level Recon/<domain> symlink**: Phase 3 does NOT create this; Phase 12 plan-01 adds the AtomicSymlink call from WorkspaceInit (or equivalent) to point at `workspaces/<target-id>/_compat/`.

### `interfaces_check/main.go` status

- Still compiles after Plan 03 changes (verified by `bash .planning/decisions/verify-0002.sh` passing all four checks). No action needed; Phase 4 plan-01 deletes it per the Phase 3 D-default schedule.

### Phase 3 internal hand-offs already completed

- **Plan 02 → Plan 03 (W19 migration)**: snapshot.go's inline 4-step helper has been deleted; `config.WriteSnapshot` delegates to `output.WriteFile`. Plan 02's atomicity tests (`TestSnapshotAtomicNoTempLeak`, `TestSnapshotIdempotent`) continue to pass — the contract is preserved.
- **Plan 03's W20 follow-up** also seeded the per-file gate for Plan 01's redactor.go + redacting_handler.go (both at 100%; trivially pass the gate).

## Self-Check: PASSED

Verified via direct filesystem + git checks before SUMMARY commit:

- `[ -f internal/core/output/atomic.go ]` → FOUND
- `[ -f internal/core/output/scope.go ]` → FOUND
- `[ -f internal/core/output/tree.go ]` → FOUND
- `[ -f internal/core/output/manifest.go ]` → FOUND
- `[ -f internal/core/output/init.go ]` → FOUND
- `[ -f internal/core/output/compat.go ]` → FOUND
- `[ -f internal/core/output/interface.go ]` → FOUND
- `[ -f internal/core/output/atomic_smoke_test.go ]` → FOUND (build tag `smoke`)
- `[ -f internal/core/checkpoint/store.go ]` → FOUND
- `[ -f internal/core/checkpoint/migrations.go ]` → FOUND
- `[ -f internal/core/checkpoint/hash.go ]` → FOUND
- `[ -f internal/core/checkpoint/interface.go ]` → FOUND
- `[ -f scripts/coverage-critical.sh ]` → FOUND, executable
- All 10 commits exist in `git log`:
  - `91b7e70` test(03-03): add failing tests for AtomicWriter + FOUND-04 atomicity
  - `8365eb2` feat(03-03): implement AtomicWriter (WriteJSONL + WriteFile) per ADR §3.5
  - `799b884` test(03-03): add failing tests for OutputTree + ScopeFilter + Manifest
  - `f35d7b4` feat(03-03): implement OutputTree + ScopeFilter + Manifest + WorkspaceInit
  - `6a4dd85` test(03-03): add failing tests for checkpoint Store + InputHash
  - `b30b559` feat(03-03): implement SQLite checkpoint Store with WAL + InputHash
  - `e90802e` test(03-03): add failing tests for CompatWriter + AtomicSymlink
  - `e321364` feat(03-03): implement CompatWriter skeleton + AtomicSymlink
  - `258183e` test(03-03): add failing interface-shape gates (W15)
  - `90c628a` feat(03-03): W15 interfaces + W19 snapshot migration + W20 per-file gate

## TDD Gate Compliance

All 5 tasks followed the test-first cadence:
- Task 1: `test(03-03)` commit `91b7e70` → `feat(03-03)` commit `8365eb2`. Added Ring 3 smoke test + internal-package coverage tests in the GREEN commit to keep coverage gate-passing as a single mental unit.
- Task 2: `test(03-03)` commit `799b884` → `feat(03-03)` commit `f35d7b4` (RED → GREEN; one shadow-variable bug auto-fixed in the GREEN commit per deviation #2).
- Task 3: `test(03-03)` commit `6a4dd85` → `feat(03-03)` commit `b30b559` (RED → GREEN; classifyError coverage tests folded into the GREEN commit).
- Task 4: `test(03-03)` commit `e90802e` → `feat(03-03)` commit `e321364`.
- Task 5: `test(03-03)` commit `258183e` (interface assertions only — the minimal RED gate) → `feat(03-03)` commit `90c628a` (interfaces + W19 migration + W20 CI/Makefile gate + atomic.go coverage refactor).

## Threat Flags

No new security-relevant surface introduced beyond what's enumerated in the threat_model block in PLAN.md (T-03-03-01 through T-03-03-08 + T-03-03-SC). No new network endpoints, auth paths, or file access patterns at trust boundaries. The CompatWriter skeleton DOES touch the filesystem to create `_compat/<sub>/` directories under WorkspaceRoot, but that path is under the operator-controlled workspaces root — no privilege boundary crossed.
