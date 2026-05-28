---
phase: 03-foundation-kernel
plan: 07
subsystem: foundation-kernel
tags: [testutil, mocks, tools-lock, embed, toml, integration-smoke, ci, binary-size, interfaces-check, acceptance, xcut-02, xcut-04, found-15, found-16, blocker-5, blocker-7, w15, w16]

# Dependency graph
requires:
  - phase: 01-language-adr-spike
    provides: spike/go/cmd/spike/main.go (cobra + signal pattern reference)
  - phase: 02-architecture-v2-design
    provides: |
      ADR §5 BINDING interface signatures (Task/Backend/AppContext)
      ADR §9.3 Foundation Wave 0 Requirements (MockBackend/MockCheckpoint/MockOutputTree placement)
      ADR §11 Pre-Sign Verification Gate (verify-0002.sh Check 3)
  - phase: 03-foundation-kernel
    provides: |
      Plan 01 — internal/core/errors (7-class typed errors) + log/{Secret,Redactor,RedactingHandler}
      Plan 02 — internal/core/config (Config struct + 8-source Load + pelletier/go-toml/v2 dep)
      Plan 03 — checkpoint.Interface + output.Interface (W15 introductions for mock substitution)
      Plan 04 — Backend interface + Tool struct (with Critical bool per Blocker 5) + ToolRegistry + Default singleton
      Plan 05 — Task + Scheduler + AppContext + noop.demo (Phase 3 demo task)
      Plan 06 — cmd/reconftw/{main.go,root.go,kernel_demo.go,healthcheck.go,version.go} (D-01..D-05)
provides:
  - internal/core/testutil/MockBackend     (satisfies backend.Backend; reads fixtures; no subprocess)
  - internal/core/testutil/MockCheckpoint  (satisfies checkpoint.Interface; in-memory map)
  - internal/core/testutil/MockOutputTree  (satisfies output.Interface; in-memory append + Lines())
  - internal/core/testutil/fixtures/       (subfinder/example.com.txt + httpx/hosts.jsonl + README.md)
  - internal/core/backend/tools.lock       (10 Phase 4 tools, 3 critical + 7 required)
  - internal/core/backend/registry_seed.go (//go:embed tools.lock + init() populates Default)
  - cmd/reconftw/integration_smoke_test.go (TestKernelDemoEndToEnd Phase 3 acceptance)
  - cmd/interfaces_check/main.go upgraded  (real package imports + compile-time assertions)
  - .github/workflows/ci.yml extended      (binary-size always-on + integration-smoke job)
  - Makefile integration-smoke target      (chained into make check)
  - .planning/phases/03-foundation-kernel/03-ACCEPTANCE.md (Phase 3 ROADMAP success criteria certification)
affects:
  - 04-01 (Subdomains E2E) — inherits populated backend.Default + ready-to-import testutil mocks
  - 04-01 (Subdomains E2E) — deletes internal/modules/demo + cmd/reconftw/kernel_demo.go + this plan's integration_smoke_test.go
  - 10-XX (Notifications) — wires real HTTP dispatchers replacing Plan 05 stubs
  - 11-XX (Installer) — extends tools.lock from 10 → 70+ tools + SHA-256 verification
  - 12-XX (Cutover) — implements CompatWriter.WriteCompat body + V1ToV2Mapping full table
  - rewrite/v2 — CI integration-smoke job runs TestKernelDemoEndToEnd + interfaces_check + verify-0002.sh on every push

# Tech tracking
tech-stack:
  added:
    - // none — Plan 07 reuses pelletier/go-toml/v2 (Plan 02), modernc/sqlite (Plan 03),
    - //        errgroup (Plan 04), goleak (Plan 05). Zero new direct Go modules.
  patterns:
    - "//go:embed tools.lock at package init() time — preserves XCUT-02 single-binary promise; no runtime file read"
    - "Compile-time interface assertion gate per mock (`var _ Interface = (*Mock)(nil)`) — W15 introduction propagates to test code"
    - "TDD with one-shot setters on MockBackend (SetExitCode/SetError cleared after next Exec) — natural per-call failure injection"
    - "Whitespace-tolerant substring AST tests via collapseWhitespace helper — gofumpt re-padding does not break test gates"
    - "Integration smoke test as `go build` + `os/exec` — exercises the binary end-to-end without external tools (runs in CI integration-smoke job, not standard `go test ./...`)"
    - "BINDING delta detector imports real packages + compile-time assertions — ADR §5 signature drift fails `go build ./cmd/interfaces_check/...` before reaching trunk"
    - "Blocker 7 allowlist enforced by grep over stripped-comment test files (registry_seed_test.go is the ONLY *_test.go in internal/core/backend/ that references backend.Default)"

key-files:
  created:
    - internal/core/testutil/mock_backend.go
    - internal/core/testutil/mock_backend_test.go
    - internal/core/testutil/mock_checkpoint.go
    - internal/core/testutil/mock_checkpoint_test.go
    - internal/core/testutil/mock_output_tree.go
    - internal/core/testutil/mock_output_tree_test.go
    - internal/core/testutil/fixtures/subfinder/example.com.txt
    - internal/core/testutil/fixtures/httpx/hosts.jsonl
    - internal/core/testutil/fixtures/README.md
    - internal/core/backend/tools.lock
    - internal/core/backend/registry_seed.go
    - internal/core/backend/registry_seed_test.go
    - cmd/reconftw/integration_smoke_test.go
    - .planning/phases/03-foundation-kernel/03-ACCEPTANCE.md
    - .planning/phases/03-foundation-kernel/deferred-items.md
  modified:
    - cmd/interfaces_check/main.go        (upgraded from placeholders to real packages + assertions)
    - internal/core/task/task_test.go     (TestInterfacesCheckSignaturesMatch updated for real-package shape)
    - .github/workflows/ci.yml            (binary-size always-on + integration-smoke job added)
    - Makefile                            (integration-smoke target + check chains it)
  deleted:
    - internal/core/testutil/.gitkeep     (replaced by real package files)

key-decisions:
  - "Plan files_modified listed interfaces_check/main.go at the OLD path (Phase 2 location). Actual file is cmd/interfaces_check/main.go since Plan 03-01 relocated it to avoid the `go build ./...` directory-name collision (Plan 01 deviation #1). Plan 07 works with the actual location."
  - "MockBackend SetExitCode + SetError are one-shot — cleared after the NEXT Exec call. This matches per-call failure injection semantics (each test sets up exactly one tool invocation's failure mode) better than session-wide state."
  - "MockOutputTree implements REPLACE semantics per ADR §3.2 ('merged set written at end of Task') — Append() overwrites prior content for the same artefact. Tests assert via Lines(artefact) → []string."
  - "tools.lock entries: 3 critical (subfinder, httpx, dnsx — the minimal passive+probe+resolve trio needed for any meaningful Phase 4 run) per FOUND-08 + Blocker 5. The remaining 7 (crt, puredns, gotator, anew, asnmap, s3scanner, subzy) are required-but-not-critical — health-check WARN, exit 0."
  - "registry_seed.go uses //go:embed to byte-embed tools.lock at build time. Preserves XCUT-02 single-binary promise (no runtime file read); modification requires rebuild."
  - "Blocker 7 audit gate (no backend.Default references in Plan 04 tests) verified via `grep 'backend\\.Default' internal/core/backend/*_test.go` after stripping `//.*` comments. Only registry_seed_test.go has real code references; all other tests' references are documentation comments."
  - "interfaces_check upgrade imports real packages (internal/core/{task,backend,appctx,config}) + 4 compile-time assertions. Phase 2 D-14 placeholders are gone — any ADR §5 signature drift now fails `go build ./cmd/interfaces_check/...` at compile time before reaching trunk."
  - "TestInterfacesCheckSignaturesMatch updated to verify the upgraded shape (4 real imports + 4 assertions) instead of the Phase 2 placeholder shape. Uses a whitespace-tolerant collapseWhitespace helper because gofumpt v0.7.0 re-pads the `var (...)` block when widths change."
  - "Integration smoke test (`TestKernelDemoEndToEnd`) lives in cmd/reconftw/ with package main_test. Builds the binary via `go build -ldflags=-s -w -trimpath` then invokes `kernel-demo --target example.com` under t.TempDir; asserts artefacts/demo.jsonl + checkpoints.db exist with the expected fixture line."
  - "XCUT-02 binary-size CI gate is now unconditional — Plan 01 had gated it on `hashFiles('cmd/reconftw/main.go') != ''`; Plan 06 landed main.go; Plan 07 activates the gate. Stripped binary at 10.4 MB (80% under the 50 MB budget)."
  - "Auto-fixed: task_test.go's TestInterfacesCheckSignaturesMatch literally encoded the Phase 2 placeholder signature (`Run(ctx context.Context, app *AppContext) (Result, error)`). After the interfaces_check upgrade to real packages, that placeholder signature no longer appears. Updated the test to verify the real-package shape — pure test-update, no implementation drift."
  - "Auto-deferred: 24 pre-existing gofumpt v0.7.0 drift files (cmd/reconftw/root.go, internal/core/{appctx,backend,checkpoint,config,log,notifier,output,scheduler,task,ui}/..., spike/go/internal/...). Pre-Plan-07 condition; out of scope per SCOPE BOUNDARY rule. Logged to deferred-items.md for a Phase 4 plan-00 housekeeping commit."

patterns-established:
  - "Pattern 1: Mocks as separate package (internal/core/testutil/) with compile-time interface assertions in *_test.go — adding a method to checkpoint.Interface or output.Interface forces mocks to grow the method via the W15 enforcement gates."
  - "Pattern 2: Fixture directory <FixturesDir>/<tool-name>/<scenario>.{txt|jsonl} consumed by MockBackend.Exec/Stream — Phase 4-7 tests can add new fixtures without touching mock code."
  - "Pattern 3: //go:embed tools.lock for the seed registry — preserves single-binary XCUT-02 promise; init() runs at package import time; tools.lock is the source of truth for Phase 4 tool inventory."
  - "Pattern 4: Integration smoke test as a separate cobra subcommand path (kernel-demo) — Phase 3 acceptance integration test invokes a hidden command via real binary exec. Phase 4 plan-01 deletes the hidden command + the integration test that targets it."
  - "Pattern 5: BINDING delta detector via compile-time assertions on real packages — `var _ task.Task = (*placeholderTask)(nil)` catches ADR §5 drift before merge. Phase 2 placeholders were a stepping stone; Phase 3 closes the gate end-to-end."
  - "Pattern 6: Whitespace-tolerant AST-substring tests (collapseWhitespace helper) — make AST-based test gates resilient to gofumpt re-alignment when adding/renaming Go identifiers in the same var-block."
  - "Pattern 7: Blocker 7 audit via stripped-comment grep — verify `backend.Default` references in test files are only documentation comments, not real code. `sed 's|//.*||'` then grep is the canonical pattern."

requirements-completed: [FOUND-15, FOUND-16, XCUT-02, XCUT-04]

# Metrics
duration: ~95min
completed: 2026-05-28
---

# Phase 3 Plan 7: Test Mocks + tools.lock Seed + Phase 3 Acceptance Summary

**FOUND-15 mocks (MockBackend + MockCheckpoint + MockOutputTree in `internal/core/testutil/`) + tools.lock seed populating `backend.Default` at `init()` with 10 Phase 4 tools (3 critical) per FOUND-08 + Blocker 5 + integration smoke test (`TestKernelDemoEndToEnd` — kernel runs noop.demo end-to-end through Scheduler + LocalBackend + OutputTree + Checkpoint) + XCUT-02 binary-size CI gate activated (10.4 MB measured, 80% under budget) + `cmd/interfaces_check/main.go` upgraded to import real packages with compile-time assertions (BINDING signature drift now caught at compile time) + Phase 3 ACCEPTANCE.md certifying all 5 ROADMAP success criteria.**

## Performance

- **Duration:** ~95 min
- **Started:** 2026-05-28 (post-Plan-06 wave merge)
- **Completed:** 2026-05-28T17:56:03Z
- **Tasks:** 3 (all auto, all TDD-cycled where applicable)
- **Files created:** 15 (9 testutil + 3 backend + 2 cmd/reconftw + 1 planning + 1 deferred)
- **Files modified:** 4 (cmd/interfaces_check/main.go, task_test.go, ci.yml, Makefile)
- **Test count delta:** +24 (10 MockBackend + 7 MockCheckpoint + 4 MockOutputTree + 4 registry_seed_test + 1 TestKernelDemoEndToEnd + updates to TestInterfacesCheckSignaturesMatch)
- **Binary size:** stripped 10.35 MB (10,854,962 bytes) — XCUT-02 50 MB gate cleared by 80%

## Accomplishments

### FOUND-15 — Test mocks (Task 1)

- **MockBackend** (`mock_backend.go`, 187 LoC) satisfies `backend.Backend`. Reads fixture file `<FixturesDir>/<tool>/<scenario>.{txt|jsonl}` (resolved with `.txt` then `.jsonl` fallback). `SetExitCode(n)` and `SetError(err)` are one-shot setters cleared after the next `Exec` call — natural per-call failure injection. `Stream` uses `bufio.Scanner` with 1 MiB initial / 10 MiB max buffer (LocalBackend parity per RESEARCH.md §Pattern 3). Honors `ctx.Done()` for fast cancellation. Never spawns a subprocess — FOUND-10 lint rule compatible.
- **MockCheckpoint** (`mock_checkpoint.go`, 183 LoC) satisfies `checkpoint.Interface` (W15). In-memory map keyed by `(taskName \x00 target \x00 inputHash)` (null-byte separators per checkpoint.InputHash — closes prefix-collision attack). `Begin` is INSERT-OR-REPLACE (mirrors `*Store.Begin`). `Complete` populates `errorClass` via the same 7-class `classifyError` walk as `*Store.Complete`. `AllRecords()` returns sorted slice for assertions. `Reset()` for test isolation.
- **MockOutputTree** (`mock_output_tree.go`, 79 LoC) satisfies `output.Interface` (W15). `Append` deep-copies each line + REPLACE semantics per ADR §3.2 ("merged set written at end of Task"). `Lines(artefact) []string` for test assertions. `Reset()` for isolation.
- **Compile-time interface assertions** in `*_test.go` files: `var _ backend.Backend = (*testutil.MockBackend)(nil)`, `var _ checkpoint.Interface = (*testutil.MockCheckpoint)(nil)`, `var _ output.Interface = (*testutil.MockOutputTree)(nil)`. Adding a method to any of the three W15 interfaces forces a compile error here unless mocks grow the method — the canonical enforcement gate.
- **Fixtures**: `fixtures/subfinder/example.com.txt` (6 realistic subdomain lines) + `fixtures/httpx/hosts.jsonl` (3 JSONL host records mirroring real httpx schema with input/host/port/status_code/title/tech fields) + `fixtures/README.md` (documents layout for Phase 4-7 contributors).
- **Package coverage**: 81.1% on `internal/core/testutil/...` (XCUT-04 ≥75% gate cleared).

### FOUND-08 + Blocker 5 — tools.lock seed (Task 2)

- **`tools.lock`** (TOML, 92 LoC): 10 Phase 4 tools per CONTEXT default option (b). Each entry: `name`, `kind` (go|python|system|rust), `go_module` (Go tools), `description`, `default_args`, `timeout_seconds`, `critical` bool per Blocker 5.
  - **3 Critical** (`critical = true`): `subfinder` (passive enumeration), `httpx` (HTTP probe + tech detection), `dnsx` (DNS resolver toolkit). These are the smallest passive + probe + resolve trio needed for any meaningful Phase 4 run.
  - **7 Required-but-not-critical** (`critical = false`): `crt`, `puredns`, `gotator`, `anew`, `asnmap`, `s3scanner`, `subzy`.
- **`registry_seed.go`**: `//go:embed tools.lock` byte-embeds the file at build time (preserves XCUT-02 single-binary promise — no runtime file read). `init()` parses TOML via `pelletier/go-toml/v2` (Plan 02 dep) and calls `Default.Register(...)` for each entry, propagating the `Critical` bool per Blocker 5.
- **Blocker 7 audit gate**: `grep 'backend\.Default' internal/core/backend/*_test.go` (after `sed 's|//.*||'` stripping comments) returns matches ONLY in `registry_seed_test.go` (the allowlist). Plan 04 tests continue to use fresh `NewToolRegistry()` per Blocker 7.
- **`registry_seed_test.go`**: 4 tests — `TestRegistrySeed_PopulatesDefault` (>=10 tools registered), `TestRegistrySeed_CriticalTier` (only subfinder/httpx/dnsx have `Critical=true`), `TestRegistrySeed_MissingCriticalIsCriticalSubset` (MissingCritical filter is correct), `TestRegistrySeed_TOMLParseSucceeded`.

### Phase 3 acceptance + CI gate activation (Task 3)

- **`TestKernelDemoEndToEnd`** (`cmd/reconftw/integration_smoke_test.go`, 175 LoC): the Phase 3 acceptance gate. Builds the binary into `t.TempDir()` via `go build -ldflags="-s -w" -trimpath`, runs `./bin/reconftw kernel-demo --target example.com` with a 30 s ctx, then asserts: (a) exit code 0, (b) `workspaces/example.com-*/artefacts/demo.jsonl` exists with exactly one line containing `"demo":"phase-3-kernel"`, (c) `workspaces/example.com-*/checkpoints.db` exists, (d) XCUT-07 transitive — no Slack webhook host / Discord webhook host / Bearer token patterns in the binary's stdout/stderr. The test runs in CI's `integration-smoke` job; ~3 s total (build + run).
- **`cmd/interfaces_check/main.go` upgrade**: Phase 2 D-14 shipped this file with placeholder `interface{}` types (so it could compile before `internal/core/{task,backend,appctx}` existed). Plan 07 upgrades it to import the real packages + declare 4 compile-time assertions:
  - `var _ task.Task = (*placeholderTask)(nil)` (ADR §5.1 — 6 methods)
  - `var _ task.LifecycleAware = (*placeholderLifecycle)(nil)` (ADR §5.1 — 2 methods)
  - `var _ backend.Backend = (*placeholderBackend)(nil)` (ADR §5.2 — 4 methods)
  - `var _ appctx.SchedulerRunner = (*placeholderScheduler)(nil)` (Plan 05 cycle-break interface)

  Any ADR §5 BINDING signature drift now fails `go build ./cmd/interfaces_check/...` at compile time before reaching trunk. `bash .planning/decisions/verify-0002.sh` Check 3 still passes — the BINDING gate is end-to-end. Also references `AppContext` field names (Log, Cfg, Scheduler, Tools, Tree, Checkpoint, Notify, Target, UI) + Target subfields (Domain, IsCIDR, IsIP, Scope, WorkDir) + Result fields + Status enum values, so renaming any of those also fails the build.
- **CI yaml updates**:
  - **`binary-size` job** is now unconditional. Plan 01 had it gated on `hashFiles('cmd/reconftw/main.go') != ''`; Plan 06 created `main.go`; Plan 07 removes the gate. **Stripped binary measured at 10.4 MB** — 80% under the XCUT-02 50 MB budget.
  - **New `integration-smoke` job**: runs `TestKernelDemoEndToEnd`, then `go build ./cmd/interfaces_check/...` (BINDING gate), then `bash .planning/decisions/verify-0002.sh` (ADR pre-sign gate). Installs `tomljson` (`pelletier/go-toml/v2/cmd/tomljson`) so verify-0002.sh Check 2 (TOML block parsing) works in CI.
- **`Makefile` updates**: new `integration-smoke` target running `TestKernelDemoEndToEnd`; the existing `check` target now chains `integration-smoke` after `test` so `make check` is the full local equivalent of the CI pipeline.
- **Phase 3 ACCEPTANCE.md** (`.planning/phases/03-foundation-kernel/03-ACCEPTANCE.md`, 165 LoC): certifies all 5 ROADMAP §"Phase 3" success criteria with implementation references + test gates. Includes a 12-row measurements table (binary 10.4 MB / kill-tree 101 ms / coverage 86.9% / per-file critical paths ≥90% — all PASS), CONTEXT D-01..D-05 verification, REQ-ID traceability for all 20 IDs (FOUND-01..16 + XCUT-02/04/07/09), and an Open Items section listing Phase 4/10/11/12 hand-offs.

## Task Commits

| # | Hash | Type | Description |
|---|------|------|-------------|
| 1 | `6c98654f` | test | RED — failing tests for MockBackend + MockCheckpoint + MockOutputTree + fixtures |
| 1 | `67e1deae` | feat | GREEN — implement MockBackend + MockCheckpoint + MockOutputTree (FOUND-15) |
| 2 | `17305395` | test | RED — failing tests for tools.lock seed (FOUND-08 Phase 4 default) |
| 2 | `f9bf9d6b` | feat | GREEN — tools.lock seed populates backend.Default at init() (FOUND-08) |
| 3 | `40bb6640` | feat | Phase 3 acceptance — integration smoke + interfaces_check upgrade + CI gate activation + ACCEPTANCE.md |

**Plan metadata commit:** pending (this SUMMARY).

## Files Created/Modified

### Task 1 — 10 files (6 created + 3 fixtures + 1 deleted)

**Created:**

- `internal/core/testutil/mock_backend.go` — MockBackend (FOUND-15) implementing `backend.Backend`. NewMockBackend factory; SetScenario/SetExitCode/SetError/SetHealthCheckError/SetCapacity setters. Exec reads `<FixturesDir>/<tool>/<scenario>.{txt|jsonl}` and returns `*backend.Result` (or `*coreerrors.ToolError` per setter state); Stream uses `bufio.Scanner` 1 MiB initial / 10 MiB max + ctx.Done() select for fast cancel.
- `internal/core/testutil/mock_backend_test.go` — 10 tests (interface assertion + Exec fixture read + SetExitCode → ToolError + SetError + Stream → Event channel + HealthCheck + Capacity + race-clean + ctx cancel fast-close + fixture shape + missing fixture branch).
- `internal/core/testutil/mock_checkpoint.go` — MockCheckpoint (FOUND-15) implementing `checkpoint.Interface` (W15). In-memory map keyed by null-byte-separated triple; Begin INSERT-OR-REPLACE; Complete with `classifyError` for non-nil errors; AllRecords sorted; Reset for test isolation.
- `internal/core/testutil/mock_checkpoint_test.go` — 7 tests (interface assertion + Begin/Complete/Done + different-hash idempotency + AllRecords sorted + race-clean + Complete with errored status + Reset).
- `internal/core/testutil/mock_output_tree.go` — MockOutputTree (FOUND-15) implementing `output.Interface` (W15). Append deep-copies + REPLACE semantics; Lines(artefact) → []string; Reset.
- `internal/core/testutil/mock_output_tree_test.go` — 4 tests (interface assertion + Append/Lines round-trip + Reset + race-clean + deep-copy verification).
- `internal/core/testutil/fixtures/subfinder/example.com.txt` — 6 realistic subdomain lines (api, www, mail, admin, dev, staging).
- `internal/core/testutil/fixtures/httpx/hosts.jsonl` — 3 JSONL records mirroring real httpx schema.
- `internal/core/testutil/fixtures/README.md` — documents fixture layout + adding-new-fixtures guidance + secret-sanitization warning.

**Deleted:** `internal/core/testutil/.gitkeep` (replaced by real package files).

### Task 2 — 3 files created

- `internal/core/backend/tools.lock` — TOML manifest with 10 Phase 4 tools. Schema header (schema_version, generated_by, generated_at) + 10 `[[tools]]` tables.
- `internal/core/backend/registry_seed.go` — `//go:embed tools.lock` byte-embed + `init()` parses + registers each tool with `Default` (populating Critical bool per Blocker 5). slog.Info on success, slog.Error on parse failure.
- `internal/core/backend/registry_seed_test.go` — 4 tests verifying Default populated with the expected 10 tools, Critical-tier correct, MissingCritical filtered correctly, TOML parse succeeded. **Blocker 7 allowlist**: this is the ONE *_test.go in `internal/core/backend/` referencing `backend.Default` (other tests use `NewToolRegistry()`).

### Task 3 — 5 files (3 created + 4 modified)

**Created:**

- `cmd/reconftw/integration_smoke_test.go` — `TestKernelDemoEndToEnd` Phase 3 acceptance integration test. Builds binary via `go build -ldflags="-s -w" -trimpath` then runs `kernel-demo --target example.com` under t.TempDir. Asserts artefacts/demo.jsonl (exactly 1 line with phase-3-kernel fixture) + checkpoints.db + XCUT-07 transitive no-secret-leak.
- `.planning/phases/03-foundation-kernel/03-ACCEPTANCE.md` — Phase 3 ROADMAP success criteria certification + 12-row measurements table + CONTEXT D-01..D-05 verification + REQ-ID traceability (20 IDs) + Open Items for Phase 4/10/11/12.
- `.planning/phases/03-foundation-kernel/deferred-items.md` — documents 24-file pre-existing gofumpt drift (Phase 4 housekeeping commit) + 6 other carryover items.

**Modified:**

- `cmd/interfaces_check/main.go` — upgraded from `interface{}` placeholders to real `internal/core/{task,backend,appctx,config}` imports + 4 compile-time assertions on Task/LifecycleAware/Backend/SchedulerRunner + field-name spot-checks on AppContext + Target + Result + Status enum.
- `internal/core/task/task_test.go` — `TestInterfacesCheckSignaturesMatch` updated to verify the real-package shape (4 imports + 4 compile-time assertions) instead of the Phase 2 placeholder signature. Added `collapseWhitespace` helper for gofumpt-resilient substring matching.
- `.github/workflows/ci.yml` — binary-size job no longer gated on `hashFiles()` (Plan 06 landed main.go); new `integration-smoke` job runs TestKernelDemoEndToEnd + interfaces_check + verify-0002.sh.
- `Makefile` — new `integration-smoke` target; `check` chains it after `test`.
- `internal/core/testutil/mock_checkpoint.go` — minor gofumpt v0.7.0 field-comment-alignment touch-up (FinishedAt comment width).

## Decisions Made

- **Plan files_modified frontmatter listed `interfaces_check/main.go` at the OLD Phase 2 path**. The actual file path after Plan 03-01 deviation #1 is `cmd/interfaces_check/main.go` (relocated to avoid `go build ./...` directory-name collision). Plan 07 works with the actual location; verify-0002.sh Check 3 references `./cmd/interfaces_check/...` correctly.
- **MockBackend SetExitCode + SetError are one-shot, cleared after next Exec**. Tests typically configure exactly one tool invocation's failure mode then run it — one-shot semantics match this pattern better than session-wide state. Tests needing multiple failures call the setter again before each Exec.
- **MockOutputTree REPLACE semantics** mirror production `*OutputTree` per ADR §3.2 — Tasks dedup/merge in-memory and call `Append` once with the full batch.
- **tools.lock Critical tier = {subfinder, httpx, dnsx}**. Three is the minimal passive+probe+resolve trio needed for any meaningful Phase 4 run. Going broader risks failing health-check on tools that Phase 4 plan-01 may not actually need on day 1. The other 7 entries (crt, puredns, gotator, anew, asnmap, s3scanner, subzy) are required-but-not-critical — health-check WARN, exit 0.
- **`//go:embed tools.lock`** preserves XCUT-02 single-binary promise. No runtime file read; modification requires rebuild.
- **Blocker 7 audit** verified via `sed 's|//.*||' internal/core/backend/*_test.go | grep 'backend\.Default'` returning matches ONLY in `registry_seed_test.go`. Other test files have comment references (allowed) but no code references (the allowlist gate).
- **interfaces_check upgrade is the BINDING enforcement gate end-to-end**. Phase 2 placeholders bought time for Phase 3 implementations to land. Plan 07 closes the loop: any ADR §5 signature drift now fails the build at compile time before reaching trunk. Phase 4+ plans can rely on this gate to catch unintentional BINDING violations.
- **TestInterfacesCheckSignaturesMatch whitespace-tolerant rewrite**: gofumpt v0.7.0 re-pads `var (...)` blocks based on the widest identifier (here, `appctx.SchedulerRunner` triggers wider padding than `task.Task`). The substring check `"task.Task             = (*..."` (with literal column-aligned spaces) would break each time. The collapseWhitespace helper collapses all whitespace runs to single spaces before matching — resilient to future re-alignment.
- **CI binary-size gate now unconditional**: Plan 01 deferred activation to "when main.go lands"; Plan 06 landed main.go; Plan 07 activates the gate. **Stripped binary 10.4 MB = 80% under the 50 MB budget**. Plenty of headroom for Phase 4-12 module growth.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Plan files_modified frontmatter listed `interfaces_check/main.go` at the Phase 2 path**

- **Found during:** Task 3 setup
- **Issue:** Plan 07 `files_modified` lists `interfaces_check/main.go` but Plan 03-01's deviation #1 relocated the file to `cmd/interfaces_check/main.go` to avoid the `go build ./...` directory-name collision. The Phase 2 path no longer exists.
- **Fix:** Used the actual `cmd/interfaces_check/main.go` location. Updated the SUMMARY frontmatter `key-files.modified` to reference the correct path. verify-0002.sh Check 3 already references the correct location (Plan 01 updated it).
- **Files modified:** `cmd/interfaces_check/main.go`
- **Verification:** `bash .planning/decisions/verify-0002.sh` exits 0; `go build ./cmd/interfaces_check/...` exits 0.
- **Committed in:** `40bb6640`

**2. [Rule 1 - Bug] Stale TestInterfacesCheckSignaturesMatch test broke after interfaces_check upgrade**

- **Found during:** Task 3 (after `gofumpt -w .` re-aligned the var-block)
- **Issue:** The test hard-coded the Phase 2 placeholder signature `Run(ctx context.Context, app *AppContext) (Result, error)` — literally with the local-package `*AppContext` type. After upgrading to real packages, the signature uses `*appctx.AppContext` and `task.Result` — the substring no longer appears in the file.
- **Fix:** Rewrote the `want` list to verify the upgraded shape: 4 real-package import strings + 4 compile-time assertions + the real Run signature. Added a `collapseWhitespace` helper so substring matches survive gofumpt re-padding when identifier widths change.
- **Files modified:** `internal/core/task/task_test.go`
- **Verification:** `go test -race -run TestInterfacesCheckSignaturesMatch ./internal/core/task/...` PASS.
- **Committed in:** `40bb6640`

**3. [Rule 3 - Blocking] gofumpt v0.7.0 wanted to re-format 24 pre-existing files outside Plan 07 scope**

- **Found during:** Task 3 after `gofumpt -w .`
- **Issue:** `gofumpt -w .` touched 24 files predating Plan 07 (struct comment alignment, trailing blank lines in spike/). These are pre-existing drift the prior plans didn't fix; SCOPE BOUNDARY rule says auto-fixes must be limited to the current task's changes.
- **Fix:** `git checkout HEAD -- <each-out-of-scope-file>` to revert the format-only touches. Kept gofumpt changes only on files Plan 07 actually owns/modifies (cmd/interfaces_check/main.go, internal/core/testutil/mock_checkpoint.go). Documented the 24 pre-existing drifts in `.planning/phases/03-foundation-kernel/deferred-items.md` for a Phase 4 plan-00 housekeeping commit.
- **Files modified:** none in-scope reverted; deferred-items.md created.
- **Verification:** `gofumpt -d cmd/interfaces_check/ cmd/reconftw/integration_smoke_test.go internal/core/task/task_test.go internal/core/testutil/` returns empty (Plan 07 scope is gofumpt-clean). Wider drift remains pre-existing and is documented as deferred.
- **Committed in:** `40bb6640`

---

**Total deviations:** 3 auto-fixed (1 Rule 1 bug, 2 Rule 3 blocking).
**Impact on plan:** All auto-fixes essential. Deviations #1 + #2 follow from the upgrade itself (file location + test gate parity); deviation #3 is a SCOPE BOUNDARY enforcement (out-of-scope formatting moved to a future housekeeping plan). No scope creep.

## Issues Encountered

- **Workspace timestamp prevents binary-level re-run idempotency test**: `output.WorkspaceInit` creates a NEW timestamped dir per run, so two binary invocations produce two separate workspaces — there's no shared `checkpoints.db` to verify the second run skips. Test 5 from Plan 07 PLAN.md's `<behavior>` block (re-run skips task) is therefore verified at the unit level (`TestCheckpointSkipOnHit` in Plan 05) rather than the integration level. The integration test focuses on what it can prove deterministically: first-run produces all expected artefacts. Documented as a deferred item.
- **Plan W19 status**: Plan 03's W19 already migrated `config/snapshot.go` to `output.WriteFile`. Plan 07 confirmed (no action needed).
- **gofumpt CI lint policy**: pre-existing 24-file drift on HEAD predates Plan 07. CI's `lint` job runs `gofumpt -d .` and would exit non-zero on this drift. Either prior CI runs failed at this step (and the team accepted it), or local-only drift not yet pushed. Documented as `deferred-items.md` for a Phase 4 housekeeping commit (it's a single mechanical commit — no behavior change).

## User Setup Required

None — no external service configuration required. The new tools.lock points at upstream Go module paths; Phase 11 ships the installer that fetches them. Phase 4 plan-01 will surface health-check `[FAIL]` lines for any critical tool not on PATH (subfinder/httpx/dnsx) — operators install those manually OR via the Phase 11 installer.

## Next Phase Readiness

**Ready for Phase 4 plan-01 (Subdomains E2E):**

- `backend.Default` is populated with 10 Phase 4 tools (3 critical, 7 required) at init() time. Phase 4 plan-01 starts with a working registry; subfinder/httpx/dnsx critical-tier semantics flow through `reconftw health-check`.
- `internal/core/testutil` mocks ship: Phase 4 module tests can substitute MockBackend + MockCheckpoint + MockOutputTree without subprocess / disk / SQLite I/O. The fixture directory pattern is in place (`fixtures/<tool>/<scenario>.{txt|jsonl}`).
- BINDING signature gate is end-to-end: `cmd/interfaces_check/` upgraded to real packages; any ADR §5 drift fails `go build ./cmd/interfaces_check/...` at compile time. `verify-0002.sh` runs in CI's `integration-smoke` job.
- CI pipeline complete: 6 jobs (lint, unit, integration, integration-smoke, binary-size, smoke) run on every push.
- Phase 4 plan-01 ACCEPTANCE deletion list documented in 03-ACCEPTANCE.md:
  1. Delete `internal/modules/demo/noop.go` + `noop_test.go`.
  2. Delete `cmd/reconftw/kernel_demo.go` + `kernel_demo_test.go`.
  3. Delete `cmd/reconftw/integration_smoke_test.go` (this plan's integration smoke targets kernel-demo).
  4. Update `cmd/reconftw/modules.go` blank import from `internal/modules/demo` to `internal/modules/subdomains`.
  5. Replace stubbed `subs` RunE with real subdomains pipeline.

**Ready for Phase 10 (Notifications):**

- LogSink + 3 stubs (Slack/Telegram/Discord) ship from Plan 05. Phase 10 wires real `retryablehttp.Client` dispatch — `TODO(phase-10)` markers in each stub file are explicit hand-off points.

**Ready for Phase 11 (Installer):**

- tools.lock skeleton is in place with 10 entries. Phase 11 extends to 70+ tools + SHA-256 verification per INST-02..04.

**Ready for Phase 12 (Cutover):**

- CompatWriter skeleton + 3-entry V1ToV2Mapping seed from Plan 03. Phase 12 implements the per-key extraction loop body + extends V1ToV2Mapping to 40+ v1 output shapes + adds the top-level Recon/<domain> AtomicSymlink.

## Threat Flags

No new security surface beyond what's enumerated in Plan 07 PLAN.md's `<threat_model>` block (T-03-07-01..07 + T-03-07-SC). All 8 mitigations land:

- T-03-07-01 (testutil imported by production code) — mitigated by naming convention; future iteration may add a lint rule that flags `import .*testutil` outside `_test.go`.
- T-03-07-02 (tools.lock tampering) — mitigated via `//go:embed`; tampering requires rebuild.
- T-03-07-03 (Integration smoke runs `go build` inside `go test`) — accepted; ~3 s build + run; well within ADR §9.1 integration ring budget.
- T-03-07-04 (ACCEPTANCE.md claims not matching reality) — mitigated by per-criterion test-command citations + Plan 07's `integration-smoke` CI job re-running the canonical TestKernelDemoEndToEnd on every push.
- T-03-07-05 (tools.lock tool inventory leak) — accepted (public per ROADMAP).
- T-03-07-SC (npm/pip/cargo installs) — accepted; Plan 07 adds 0 new Go modules. Reuses pelletier/go-toml/v2 (Plan 02), modernc/sqlite (Plan 03), errgroup (Plan 04), goleak (Plan 05).
- T-03-07-06 (interfaces_check delta detector bypass) — mitigated by adding the `interfaces_check` build to the `integration-smoke` CI job; verify-0002.sh runs in CI on every push.
- T-03-07-07 (Critical tool false-positive) — accepted; the trio (subfinder, httpx, dnsx) is intentionally minimal; CI runners install via `go install` in a setup step (Phase 11 owns the installer).

## Self-Check: PASSED

**Files exist on disk:**

```
FOUND: internal/core/testutil/mock_backend.go
FOUND: internal/core/testutil/mock_backend_test.go
FOUND: internal/core/testutil/mock_checkpoint.go
FOUND: internal/core/testutil/mock_checkpoint_test.go
FOUND: internal/core/testutil/mock_output_tree.go
FOUND: internal/core/testutil/mock_output_tree_test.go
FOUND: internal/core/testutil/fixtures/subfinder/example.com.txt
FOUND: internal/core/testutil/fixtures/httpx/hosts.jsonl
FOUND: internal/core/testutil/fixtures/README.md
FOUND: internal/core/backend/tools.lock
FOUND: internal/core/backend/registry_seed.go
FOUND: internal/core/backend/registry_seed_test.go
FOUND: cmd/reconftw/integration_smoke_test.go
FOUND: cmd/interfaces_check/main.go              (modified — upgraded to real packages)
FOUND: internal/core/task/task_test.go           (modified — updated TestInterfacesCheckSignaturesMatch)
FOUND: .github/workflows/ci.yml                  (modified — binary-size always-on + integration-smoke job)
FOUND: Makefile                                  (modified — integration-smoke target)
FOUND: .planning/phases/03-foundation-kernel/03-ACCEPTANCE.md
FOUND: .planning/phases/03-foundation-kernel/deferred-items.md
```

**Commits exist in git log:**

```
FOUND: 6c98654f — test(03-07): RED — failing tests for MockBackend + MockCheckpoint + MockOutputTree + fixtures
FOUND: 67e1deae — feat(03-07): GREEN — implement MockBackend + MockCheckpoint + MockOutputTree (FOUND-15)
FOUND: 17305395 — test(03-07): RED — failing tests for tools.lock seed (FOUND-08 Phase 4 default)
FOUND: f9bf9d6b — feat(03-07): GREEN — tools.lock seed populates backend.Default at init() (FOUND-08)
FOUND: 40bb6640 — feat(03-07): Phase 3 acceptance — integration smoke + interfaces_check upgrade + CI gate activation + ACCEPTANCE.md
```

**Test gates:**

- `go build ./...` — exit 0
- `go vet ./...` — exit 0
- `go test -race -short ./...` — PASS (all 14 packages green)
- `go test -race -run TestKernelDemoEndToEnd ./cmd/reconftw/...` — PASS (~2 s build + run)
- `go test -race -tags smoke ./...` — PASS (FOUND-04 SIGKILL + FOUND-09 kill-tree all green)
- `bash .planning/decisions/verify-0002.sh` — ALL CHECKS PASSED
- Stripped binary 10.35 MB — XCUT-02 PASS (80% margin)
- Coverage on internal/core/... — 86.9% (XCUT-04 ≥75% PASS, +12 pp margin)
- W20 per-file critical paths (redactor / redacting_handler / atomic / scope / store) — all ≥90% PASS
- Blocker 7 grep audit — only registry_seed_test.go has code references to `backend.Default`
- `gofumpt -d <plan-07-files>` — empty (Plan 07 scope clean; pre-existing drift documented in deferred-items.md)

## TDD Gate Compliance

All 3 tasks followed test-first cadence:

- **Task 1**: `test(03-07)` `6c98654f` RED — mock tests fail because mock files don't exist → `feat(03-07)` `67e1deae` GREEN — 3 mock files implemented; all tests pass; interface assertions compile.
- **Task 2**: `test(03-07)` `17305395` RED — registry_seed_test fails because tools.lock + registry_seed.go don't exist → `feat(03-07)` `f9bf9d6b` GREEN — tools.lock TOML + registry_seed.go init() ship; tests pass; Blocker 7 audit clean.
- **Task 3**: single `feat(03-07)` `40bb6640` (integration test + interfaces_check upgrade + ACCEPTANCE.md + CI yaml + Makefile + deferred-items.md). Not test-first because Task 3 is mostly infrastructure (CI yaml, Makefile, ACCEPTANCE.md, BINDING-gate upgrade) where tests-first is not applicable, plus one end-to-end integration test that is the verification gate itself.

---
*Phase: 03-foundation-kernel*
*Completed: 2026-05-28*
