# Phase 3 — Deferred Items

Items discovered during Phase 3 execution that are **out of scope** for the discovering plan and have been deferred to a future plan/phase.

## Deferred from Plan 03-07 (Phase 3 closeout)

### gofumpt v0.7.0 drift across pre-existing files (24 files)

**Discovered:** 2026-05-28 during Plan 07 Task 3 (when `gofumpt -w .` re-formatted touched files)

**Files affected:** 24 files predate Plan 07 with gofumpt v0.7.0 strictness drift:

- `cmd/reconftw/root.go`
- `internal/core/appctx/appctx_test.go`
- `internal/core/backend/{backend.go, lint/no_raw_subprocess_test.go, registry_test.go, runner.go}`
- `internal/core/checkpoint/{hash_test.go, store_test.go}`
- `internal/core/config/{config.go, legacy_aliases.go, loader.go, loader_test.go}`
- `internal/core/log/logger_test.go`
- `internal/core/notifier/notifier_test.go`
- `internal/core/output/{atomic.go, scope_test.go}`
- `internal/core/scheduler/scheduler_test.go`
- `internal/core/task/registry_test.go`
- `internal/core/ui/printer.go`
- `spike/go/internal/httpxprobe/httpx.go`
- `spike/go/internal/passive/{crt.go, github.go, gitlab.go, subfinder.go}`

**Nature of the drift:** mostly minor gofumpt re-padding of struct field comment alignment (e.g. `Path string        // …` → `Path string // …`) and removal of trailing blank lines inside function bodies.

**Why deferred:** Per SCOPE BOUNDARY rule, only Plan 07 task files should be modified. Auto-fixing these would touch files outside Plan 07's `files_modified` frontmatter — that's a scope-bound violation.

**Risk:** the CI `lint` job runs `gofumpt -d .` and exits non-zero on any drift. If this drift was present before Plan 07 landed, every previous CI run on `rewrite/v2` would have failed at the lint job. Either:
(a) the lint job was failing pre-Plan 07 and the team accepted it; or
(b) the team has not yet pushed enough Phase 3 commits to trigger a CI run on `rewrite/v2`; or
(c) some local-only gofumpt version skew is masking the drift in CI.

**Recommended resolution:** A dedicated Phase 4 plan-00 housekeeping commit running `gofumpt -w .` against the full tree. Single mechanical commit; no behavior change. Spike directory `spike/go/` may be excluded from formatting per Phase 1 D-03 hermetic-spike rule (it has its own go.mod).

**Plan 07 scope boundary preserved:** Plan 07 ONLY modifies the files listed in its `files_modified` frontmatter. The drift in other files is documented here for the housekeeping plan to pick up.

### `--force` flag on hidden kernel-demo subcommand

**Discovered:** 2026-05-28 during Plan 07 Task 3 (integration smoke test).

**Status:** Plan 07 PLAN.md Task 3 lists Test 6 (`--force` flag bypasses checkpoint). Currently kernel-demo has no `--force` flag; the integration smoke test (`TestKernelDemoEndToEnd`) validates the first run only — it does not exercise the re-run-skip-vs-force path because timestamped workspace directories prevent workspace-level idempotency at the binary boundary.

**Why deferred:** Implementing `--force` requires wiring a flag through `kernel_demo.go` → scheduler → checkpoint bypass. The Phase 3 acceptance integration test already verifies the FIRST run produces all expected artefacts (manifest path, demo.jsonl, checkpoints.db). Checkpoint idempotency itself is verified at the unit level in `TestCheckpointSkipOnHit` (Plan 05) — so the end-to-end re-run scenario is already covered indirectly.

**Recommended resolution:** When Phase 4 plan-01 deletes `kernel_demo.go` and `noop.demo`, the question is moot — the real subdomains pipeline will be the integration target instead. If a Phase 4 plan needs the `--force` semantic at the binary level, it should add the flag at that time on the real subcommand.

### golangci-lint v2 custom plugin for FOUND-10

**Discovered:** Plan 04 SUMMARY (carried into Plan 07).

**Status:** Plan 04 ships FOUND-10 as a test-based AST scan via `golang.org/x/tools/go/packages` + `ast.Inspect`. The upgrade path to a real golangci-lint v2 custom plugin is documented in `internal/core/backend/lint/no_raw_subprocess.go` package comments + `.golangci.yml`. No signal yet that the test-based approach is insufficient (the test runs in CI's `unit` ring on every push).

**Why deferred:** Phase 4+ deferred ticket — upgrade only if violations accumulate.

### Real Slack/Telegram/Discord HTTP dispatchers (FOUND-11)

**Discovered:** Plan 05 SUMMARY (carried into Plan 07).

**Status:** Phase 3 ships LogSink + 3 stubs returning nil (CONTEXT default option (a)). Each stub file has a `TODO(phase-10)` marker.

**Why deferred:** Phase 10 (Monitor Mode + Reporting + Notifications) ships the real dispatchers.

### `tools.lock` SHA-256 verification (INST-02..04)

**Discovered:** Plan 07.

**Status:** Phase 3 ships `tools.lock` with 10 Phase 4 tools (TOML manifest) but NO SHA-256 verification.

**Why deferred:** Phase 11 (Installer + Cross-Platform + Docker) owns the full 70+ tool inventory + SHA-256 chain per INST-02..04.

### `CompatWriter.WriteCompat` body + `V1ToV2Mapping` full table (ARCH-04)

**Discovered:** Plan 03 SUMMARY (carried into Plan 07).

**Status:** Phase 3 ships the `CompatWriter` skeleton + `AtomicSymlink` + 3-entry `V1ToV2Mapping` seed. The `WriteCompat` body is a no-op (just creates `_compat/<sub>/` directories).

**Why deferred:** Phase 12 (Cutover + Migration) owns the per-key extraction loop + full v1-output-shape table (40+ entries) + top-level `Recon/<domain> → workspaces/<target-id>/_compat/` symlink.

### `LoadOptions.SkipValidation` for snapshot diagnostics

**Discovered:** Plan 02 SUMMARY (carried into Plan 07).

**Status:** Phase 3 snapshots are auditable records, not re-loadable canonical config (Slack/Discord webhooks redacted to "***" fail URL validation).

**Why deferred:** Phase 4+ if `cmd/reconftw` needs to re-load snapshots for diagnostics.
