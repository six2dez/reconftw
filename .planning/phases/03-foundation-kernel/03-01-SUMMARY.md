---
phase: 03-foundation-kernel
plan: 01
subsystem: foundation-kernel
tags: [errors, logging, redaction, ci, scaffold, xcut-07]
dependency_graph:
  requires:
    - .planning/decisions/0002-architecture-v2.md (BINDING §6 errors, §9.3 CI, §10 logging)
    - .planning/decisions/0001-language.md (Go locked)
    - .planning/phases/03-foundation-kernel/03-CONTEXT.md (D-01..D-05 + Claude defaults)
  provides:
    - internal/core/errors (7-class typed error hierarchy + 6 sentinels)
    - internal/core/log (Secret + Redactor + RedactingHandler + log.New factory)
    - .github/workflows/ci.yml (Go CI gate: lint/unit/integration/smoke/binary-size)
    - .golangci.yml (errcheck/govet/staticcheck/unused/gofumpt v2 scaffold)
    - Makefile (build/test/lint/fmt/coverage/ci v2 Go targets; v1 bash preserved as bash-*)
    - internal/core/ skeleton (.gitkeep placeholders for config/task/scheduler/backend/output/checkpoint/appctx/notifier/ui/testutil)
  affects:
    - cmd/interfaces_check/main.go (relocated from interfaces_check/ to resolve `go build ./...` directory collision)
    - .planning/decisions/verify-0002.sh (path update for new interfaces_check location)
tech_stack:
  added:
    - Go 1.24 (was Go 1.23 in Phase 2)
    - log/slog (stdlib) + slog.LogValuer for type-tagged secret redaction
    - errors stdlib + Is() sentinel bridge pattern (ADR §6)
  patterns:
    - Two-layer redaction defense (Layer 1: Secret type LogValuer; Layer 2: RedactingHandler substring scrubbing)
    - Sentinel + typed-struct error hybrid (errors.Is for category; errors.As for metadata)
    - cmd/<name>/ convention for all main packages (avoids `go build ./...` binary-name vs directory-name collision)
key_files:
  created:
    - internal/core/errors/errors.go
    - internal/core/errors/errors_test.go
    - internal/core/log/secret.go
    - internal/core/log/secret_test.go
    - internal/core/log/redactor.go
    - internal/core/log/redactor_test.go
    - internal/core/log/redacting_handler.go
    - internal/core/log/redacting_handler_test.go
    - internal/core/log/logger.go
    - internal/core/log/logger_test.go
    - .github/workflows/ci.yml
    - .golangci.yml
  modified:
    - go.mod (1.23 → 1.24)
    - Makefile (v2 Go targets primary; v1 bash preserved as bash-*)
    - .gitignore (added bin/, coverage.out, /interfaces_check)
    - .planning/decisions/verify-0002.sh (path: interfaces_check/ → cmd/interfaces_check/)
  renamed:
    - interfaces_check/main.go → cmd/interfaces_check/main.go
  deleted:
    - spike/python/ (entire directory; 37MB Python spike — loser per Phase 1 D-03)
decisions:
  - "Move interfaces_check/main.go to cmd/interfaces_check/ — resolves the `go build ./...` directory-name collision (Go writes binary to cwd using package dir basename). Follows the cmd/<name>/main.go convention. Updated verify-0002.sh to match."
  - "Makefile: v2 Go targets become primary (build/test/lint/fmt/check/coverage/ci/clean); v1 bash targets are preserved under bash-* prefix until Phase 12 cutover. Resolved conflict on `lint`/`fmt`/`test` keywords."
  - "Smoke CI job set to MANDATORY (not placeholder) per plan 03-01 W12 revision iter 1, but Phase 3 plan-01 ships an empty smoke suite — Plans 03-03/04 will land FOUND-04 SIGKILL atomicity + FOUND-09 kill-tree tests with //go:build smoke tag."
  - "Use go-version-file: go.mod for CI Go pinning so CI follows the module declaration (no version drift between local + CI)."
  - "golangci-lint pinned via curl install.sh @ v2.12.2 rather than golangci/golangci-lint-action (avoids third-party action surface)."
metrics:
  duration: 14m 57s
  completed_date: 2026-05-28T14:57:56Z
  tasks: 4
  commits: 6
  files_created: 24
  files_modified: 4
  files_deleted: 28
  coverage_combined: 96.6%
  coverage_errors: 100.0%
  coverage_log: 94.9%
---

# Phase 3 Plan 01: Foundation Kernel Base Layer Summary

**One-liner:** Typed errors + Secret-tagged structured logger with XCUT-07 sentinel CI gate; scaffolds internal/core/ tree, lifts Go to 1.24, and replaces the v1 bash CI seed with a Go pipeline.

## Tasks Completed

| Task | Name                                                                                          | Commit    | Files                                                                                                                                                                                                |
| ---- | --------------------------------------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | Scaffold internal/core tree + bump Go 1.24 + clean spike/python                               | `e4128f7a` | go.mod, Makefile, .gitignore, internal/core/{errors,log,…}/, internal/modules/demo/.gitkeep, cmd/reconftw/.gitkeep, cmd/interfaces_check/main.go (renamed), .planning/decisions/verify-0002.sh       |
| 2    | RED: failing tests for 7-class typed error hierarchy                                          | `9626e51f` | internal/core/errors/errors_test.go                                                                                                                                                                  |
| 2    | GREEN: 7-class typed error hierarchy with Is() sentinel bridge                                | `082d8a25` | internal/core/errors/errors.go                                                                                                                                                                       |
| 3    | RED: failing tests for Secret + Redactor + RedactingHandler + logger                          | `9830702f` | internal/core/log/{secret,redactor,redacting_handler,logger}_test.go                                                                                                                                 |
| 3    | GREEN: Secret + Redactor + RedactingHandler + log.New (two-layer defense)                     | `95adb962` | internal/core/log/secret.go, redactor.go, redacting_handler.go, logger.go                                                                                                                            |
| 4    | Wire Go CI pipeline + golangci-lint config + XCUT-07 sentinel gate                            | `ca637f4f` | .github/workflows/ci.yml, .golangci.yml                                                                                                                                                              |

## Acceptance Verification

### Whole-plan automated verification (from PLAN.md `<verification>` block)

- `go build ./...` — exit 0
- `go vet ./...` — exit 0
- `go test -race ./internal/core/...` — PASS
- `go test -race -run 'TestXCUT07Sentinel|TestSentinel' ./internal/core/log/...` — PASS (XCUT-07 gate confirmed)
- `bash .planning/decisions/verify-0002.sh` — exits 0 (ADR contracts intact)
- `python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/ci.yml"))'` — valid
- `grep -c 'type Secret string' internal/core/log/secret.go` → 1
- `! grep -E 'func \(.*Secret\) String\(' internal/core/log/secret.go` — confirmed (no String() method on Secret; XCUT-07 type-level invariant)
- `[ ! -d spike/python ]` — gone
- `[ -d spike/go ]` — kept (live reference until Phase 4)

### Coverage (XCUT-03/04 gates)

```
internal/core/errors    coverage: 100.0% of statements
internal/core/log       coverage: 94.9% of statements
total (errors + log):   96.6%
```

- XCUT-04 ≥75% on lib code — PASS (96.6%)
- XCUT-03 ≥90% on critical paths (secret redaction) — PASS (94.9% on log/)

### Per-task acceptance (selected highlights)

**Task 1:**
- `grep -q 'go 1.24' go.mod` ✅
- `grep -q 'ldflags="-s -w" -trimpath' Makefile` ✅
- `make -n build` references `./cmd/reconftw` ✅
- `make -n test` references `go test -race -short` ✅
- `interfaces_check/main.go` still compiles ✅ (at new location `cmd/interfaces_check/`)
- All 13 `internal/core/*` + `internal/modules/demo` + `cmd/reconftw` directories exist ✅

**Task 2:**
- 6 sentinel anchors created via `stderrors.New(...)` ✅
- 7 typed structs ✅
- `func (e *ToolError) Is(` exactly once ✅
- SECURITY NOTE comments on `ConfigError` and `AxiomFailure` within 1 line of the type decl ✅
- Coverage 100.0% on internal/core/errors/

**Task 3:**
- `type Secret string` exists; NO `String()` method (XCUT-07 invariant) ✅
- `Redactor.Register` skips length ≤ 4 values ✅
- `RedactingHandler.redactAttr` only redacts `Kind() == KindString` ✅
- `log.New(cfg, redactor)` returns `*slog.Logger` ✅
- XCUT-07 sentinel test (`TestXCUT07Sentinel`) — PASS (the exact ADR §10.4 line 2582 sentinel `test_sentinel_value_not_a_real_key_abc123` does not appear in log output across 4 attack surfaces: typed Secret attr, fmt-built message, raw String attr, raw substring in message)

**Task 4:**
- YAML valid (`python3 yaml.safe_load`) ✅
- All 5 jobs present: `lint`, `unit`, `integration`, `smoke`, `binary-size` ✅
- `go test -race -short`, `go test -race -tags smoke`, `52428800` (50MB gate), `TestXCUT07Sentinel`, `hashFiles('cmd/reconftw/main.go')` markers all present ✅
- 5 linters enabled (`errcheck`, `govet`, `staticcheck`, `unused`, `gofumpt`) — exceeds plan's "≥4" floor ✅

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `go build ./...` collided with same-named root directory**
- **Found during:** Task 1 verification
- **Issue:** Phase 2 committed `interfaces_check/main.go` as `package main` at repo root. Running `go build ./...` from the module root causes Go to write the `interfaces_check` binary to the cwd, which collides with the same-named directory (exit 1: `build output "interfaces_check" already exists and is a directory`). Pre-existing condition since commit `0b45a1d3`.
- **Fix:** `git mv interfaces_check/main.go cmd/interfaces_check/main.go` — follows Go's `cmd/<name>/main.go` convention so the binary is written to cwd (`/repo/interfaces_check`) and the source directory (`/repo/cmd/interfaces_check/`) no longer collides.
- **Files modified:**
  - `cmd/interfaces_check/main.go` (relocated)
  - `.planning/decisions/verify-0002.sh` (path update + comment)
  - `.gitignore` (added `/interfaces_check` for the build artifact)
- **Commit:** `e4128f7a`

**2. [Rule 3 - Blocking] Makefile target name collisions with v1 bash targets**
- **Found during:** Task 1
- **Issue:** Existing root `Makefile` defines `lint`, `fmt`, `test`, `test-unit`, `test-integration-smoke`, `test-integration-full`, `test-all`, `test-security`, `test-release-gate`, `setup-dev` — all bats/shellcheck-based. Plan 03-01 Task 1 requires `lint`, `fmt`, `test`, `check`, etc. as Go targets. Direct overwrite would lose v1 bash CI continuity before Phase 12 cutover (v1 user-facing).
- **Fix:** Rewrote the Makefile so v2 Go targets are PRIMARY (`build`, `test`, `lint`, `fmt`, `fmt-check`, `check`, `coverage`, `ci`, `clean`); the v1 bash targets are preserved under a `bash-*` prefix (`bash-lint`, `bash-fmt`, `bash-test`, `bash-test-unit`, `bash-test-integration-smoke`, `bash-test-integration-full`, `bash-test-release-gate`, `bash-test-all`, `bash-test-security`, `bash-setup-dev`). The data-repo helpers (`bootstrap`, `sync`, `upload`, `rm`) retain their original names. `help` target updated to document both surfaces.
- **Files modified:** `Makefile`
- **Commit:** `e4128f7a`

**3. [Rule 2 - Critical] SECURITY NOTE comments needed grep-friendly placement**
- **Found during:** Task 2 acceptance check
- **Issue:** Plan 03-01 Task 2 acceptance criteria use `grep -B1 'type ConfigError struct' | grep -qi 'SECURITY\|secret'` and the same pattern for `AxiomFailure`. My first draft had longer doc-comment paragraphs above the type declarations, pushing the SECURITY phrase outside the 1-line look-back window. Without the `-B1`-visible marker, code review and grep audits would miss the security warning.
- **Fix:** Restructured both struct doc comments so the literal line `// SECURITY NOTE: …` appears immediately before the `type X struct` line. The substance is preserved (longer rationale above; one-line BANNER directly above the type).
- **Files modified:** `internal/core/errors/errors.go`
- **Commit:** `082d8a25` (fix was part of the GREEN commit before promotion)

### Out-of-scope discoveries

None. All changes are within the plan scope.

### Issues Not Auto-fixed

None.

## Authentication / Manual Gates

None encountered. Plan 03-01 has no third-party API calls or installer touchpoints; the smoke job's third-party `golangci-lint` binary is fetched via `install.sh` pinned to `v2.12.2`.

## XCUT-07 Sentinel Test

- **Command:** `go test -race -run 'TestXCUT07Sentinel|TestSentinel' ./internal/core/log/...`
- **File:** `internal/core/log/logger_test.go` (`TestXCUT07Sentinel`)
- **Sentinel value:** `test_sentinel_value_not_a_real_key_abc123` (BINDING per ADR §10.4 line 2582)
- **Attack surfaces validated:**
  1. Typed Secret attr (`slog.Any("slack_url", log.Secret(sentinel))`) — Layer 1 LogValuer
  2. Raw substring in `logger.Info(msg)` — Layer 2 Redactor.Redact on Message
  3. Raw String attr (`slog.String("k", sentinel)`) — Layer 2 redactAttr on string Kind
- **Last passing run:** Local `go test -race` on `2026-05-28T14:57:56Z`, commit `ca637f4f`
- **CI guard:** `.github/workflows/ci.yml` `unit` job step `"XCUT-07 sentinel gate (logging hygiene)"` runs this explicitly on every push so the gate is visible in CI logs.

## CI Workflow URL / First-Green Commit

This plan ships the CI pipeline itself; the first green run will be reported by GitHub Actions on push of this plan's final commit `ca637f4f` (job set: `lint`, `unit`, `integration`, `binary-size` if main.go absent — `smoke` only on PR/schedule). The plan does NOT push the branch; the parent orchestrator owns push lifecycle after wave merge.

Local pre-push verification snapshot:

```
go build ./...                 → exit 0
go vet ./...                   → exit 0
go test -race ./internal/...   → PASS (errors + log green)
go test -race -run 'TestXCUT07Sentinel|TestSentinel' ./internal/core/log/... → PASS
verify-0002.sh                 → ALL CHECKS PASSED
go build -o /tmp/ic ./cmd/interfaces_check/... → exit 0
python3 yaml.safe_load ci.yml → valid
combined coverage on internal/core/...: 96.6%
```

## Open Items for Downstream Plans

### Plan 02 (config loader, FOUND-03)

- **`log.New(*Config, *Redactor)` config type is a placeholder.** The struct lives in `internal/core/log/logger.go` and exposes `Level slog.Level`, `Format string`, `Output io.Writer`. Plan 02 will introduce `internal/core/config/Config` (the koanf-loaded full config). Plan 02 should:
  - Either: change `log.New` signature to accept `*config.Config` directly (would require `internal/core/log` to import `internal/core/config`, introducing a cycle since config validation may emit log lines — be cautious here)
  - Or: keep `log.Config` as the minimal logger-only shim and have `cmd/reconftw/main.go` extract `cfg.Logging` from the full config and pass that to `log.New` (cleaner; no import cycle; matches ADR §10.3 build-order story)
- The XCUT-07 sentinel test in `logger_test.go` uses the inline `log.Config`; Plan 02 should leave it untouched (the test exercises the Layer 1/2 chain, not the config type).
- The 7 typed errors are ready for Plan 02 to return — `ConfigError` is the expected return type for koanf validation failures. The SECURITY NOTE on `ConfigError.Message` is BINDING: Plan 02's validation rules MUST format error messages with the field name + violation type, never the raw value.

### Plan 03 (output + checkpoint)

- `internal/core/output/.gitkeep` and `internal/core/checkpoint/.gitkeep` are in place.
- Errors package ready: `OutOfScope` (write-time scope rejection in `OutputTree.Append`), `ToolError`/`ToolTimeout` for tool-step failures.
- The smoke job in CI is mandatory; Plan 03 lands the FOUND-04 SIGKILL atomicity smoke test (under `//go:build smoke`) that the unit ring cannot deliver.

### Plan 04 (scheduler + backend + tool registry + raw-subprocess lint rule)

- `internal/core/backend/.gitkeep`, `internal/core/scheduler/.gitkeep` in place.
- `.golangci.yml` scaffold ready. Plan 04 owns FOUND-10 — adds the raw-subprocess lint rule (custom linter plugin) wired into the existing `golangci-lint run` step.
- Errors package ready: `AxiomFailure` for backend axiom-path failures; SECURITY NOTE on `Inner` rule applies — Axiom-related code MUST `Redactor.Redact()` ssh error strings before construction.
- Plan 04 lands the FOUND-09 kill-tree integration smoke test (under `//go:build smoke`).

### Plan 05 (cmd/reconftw/main.go + 15 subcommands + ui + notifier + version + health-check)

- `cmd/reconftw/.gitkeep` placeholder will be replaced by `main.go` in Plan 05.
- **CI binary-size job will activate** once `cmd/reconftw/main.go` exists — `hashFiles('cmd/reconftw/main.go') != ''` flips true. XCUT-02 50MB gate (`52428800` bytes) is wired and waiting.
- The Makefile `build` target intentionally fails-fast in CI until Plan 05 lands main.go — this is the design (CI surfaces the gate the moment `main.go` ships).
- Plan 05 implements ADR §10.3 init order in `main()`: logger → config load → register secrets → AppContext.Boot → cobra.Execute. The logger factory (`log.New`) and the 7 error types are ready.

### Plan 06 (test mocks + tools.lock seed + Phase 3 acceptance)

- `internal/core/testutil/.gitkeep` in place. Plan 06 lands `MockBackend`, `MockCheckpoint`, `MockOutputTree`.
- `internal/modules/demo/.gitkeep` in place. Plan 06 lands `noop.demo` Task per CONTEXT.md default (b).

### `interfaces_check/main.go` future disposition

- Moved to `cmd/interfaces_check/` for this plan. Still serves as the Phase 2 D-14 delta detector and is used by `verify-0002.sh`.
- Per CONTEXT.md "Out-of-scope reminders": planner decision deferred to end-of-Phase-3; Plan 04-01 may delete (replaced by `go vet ./internal/core/...` once Task/Backend/AppContext are real packages) or convert to a docs-only example.

## Threat Flags

No new security surface introduced beyond what the threat_model block in PLAN.md already covers (T-03-01-01 through T-03-01-06). The CI yaml uses `permissions: contents: read` (least privilege), pins `golangci-lint` via direct install rather than third-party action, and uses `go-version-file: go.mod` to avoid version-drift surface. No package-manager installs or third-party Go deps added by Plan 03-01.

## Self-Check: PASSED

Verified via direct filesystem and git checks before SUMMARY commit:

- `[ -f internal/core/errors/errors.go ]` → FOUND
- `[ -f internal/core/errors/errors_test.go ]` → FOUND
- `[ -f internal/core/log/secret.go ]` → FOUND
- `[ -f internal/core/log/secret_test.go ]` → FOUND
- `[ -f internal/core/log/redactor.go ]` → FOUND
- `[ -f internal/core/log/redactor_test.go ]` → FOUND
- `[ -f internal/core/log/redacting_handler.go ]` → FOUND
- `[ -f internal/core/log/redacting_handler_test.go ]` → FOUND
- `[ -f internal/core/log/logger.go ]` → FOUND
- `[ -f internal/core/log/logger_test.go ]` → FOUND
- `[ -f .github/workflows/ci.yml ]` → FOUND
- `[ -f .golangci.yml ]` → FOUND
- `[ -f Makefile ]` → FOUND (modified)
- `[ -f go.mod ]` → FOUND (modified: `go 1.24`)
- `[ -f cmd/interfaces_check/main.go ]` → FOUND
- `[ ! -d spike/python ]` → spike/python gone
- `[ -d spike/go ]` → spike/go kept
- All 13 `internal/core/*` package directories exist (errors + log have real files; others have `.gitkeep`)
- All 6 commits exist in `git log`:
  - `e4128f7a` chore(03-01): scaffold internal/core tree, bump Go 1.24, clean spike/python
  - `9626e51f` test(03-01): add failing tests for 7-class typed error hierarchy
  - `082d8a25` feat(03-01): implement 7-class typed error hierarchy with Is() sentinel bridge
  - `9830702f` test(03-01): add failing tests for Secret + Redactor + RedactingHandler + logger
  - `95adb962` feat(03-01): implement Secret + Redactor + RedactingHandler + log.New (two-layer defense)
  - `ca637f4f` ci(03-01): wire Go CI pipeline + golangci-lint config + XCUT-07 sentinel gate

## TDD Gate Compliance

Tasks 2 + 3 followed the test-first cadence:
- Task 2: `test(03-01)` commit `9626e51f` → `feat(03-01)` commit `082d8a25` (RED → GREEN; no separate REFACTOR commit needed — initial impl was clean)
- Task 3: `test(03-01)` commit `9830702f` → `feat(03-01)` commit `95adb962` (RED → GREEN; one SECURITY-NOTE restructure in the GREEN commit to satisfy `grep -B1` acceptance criteria)
- Tasks 1 + 4 were `chore`/`ci` scope without behavior tests; no TDD cadence applies.
