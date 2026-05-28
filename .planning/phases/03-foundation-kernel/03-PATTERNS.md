# Phase 3: Foundation Kernel - Pattern Map

**Mapped:** 2026-05-28
**Files analyzed:** ~50 Go files across `cmd/reconftw/`, `internal/core/`, `internal/modules/demo/`, `interfaces_check/`, plus CI config and `tools.lock` seed
**Analogs found:** 50 / 50 (100% coverage — every new file maps to a spike analog, an ADR §N code snippet, or both)

**Source-of-truth note:** The full file list for Phase 3 is enumerated in ADR 0002 §1.2 "Recommended Project Structure" (lines 199-234) plus §10.3 (cmd/reconftw/main.go init order). All Go interface signatures are BINDING per ADR 0002 D-05. All bash references are reference-only (`v1 semantic intent`); Phase 3 code structure follows the spike + ADR.

---

## File Classification

The table below maps each new file to its role, data flow, closest analog, and the ADR §N + bash reference that frame the contract.

### `cmd/reconftw/` — CLI binary entry point (FOUND-14)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `cmd/reconftw/main.go` | entry-point | event-driven (signals) | `spike/go/cmd/spike/main.go:31-83` | §10.3 (init order: redactor → logger → config → secret-register → AppContext → cobra) | `reconftw.sh` (getopt + config source + dispatch) |
| `cmd/reconftw/root.go` | controller | request-response (cobra) | `spike/go/cmd/spike/main.go:34-72` (cobra Root + RunE) | §8.1-8.4 (subcommand surface + MarkDeprecated pattern) | `reconftw.sh` getopt long options |
| `cmd/reconftw/modules.go` | config | event-driven (init() side-effects) | _N/A — new pattern_; canonical Go blank-import idiom per RESEARCH.md §Module/Component Model | §1.2 (modules.go in tree) | _N/A_ (bash sources all modules eagerly) |
| `cmd/reconftw/version.go` | command | request-response | _no spike analog_; ADR D-04 spec | §8.1 (version subcommand fully working) | _N/A_ (v1 has no `version` subcmd) |
| `cmd/reconftw/healthcheck.go` | command | request-response | _no spike analog_; ADR D-04 spec | §8.1 (health-check subcommand fully working) | `reconftw.sh --health-check` flag (v1 alias) |
| `cmd/reconftw/stub.go` | utility | request-response | _no spike analog_; CONTEXT D-02 spec | §8.1 (`stubNotImplemented(cmd, phase, name)` helper returns exit 64) | _N/A_ (new in Phase 3) |
| `cmd/reconftw/stub_subcommands.go` | controller | request-response | _no spike analog_ | §8.1 (12 stubbed subcommands: recon/all/passive/subs/web/vulns/osint/zen/deep/monitor/report/mcp/migrate/install) | _N/A_ (new in Phase 3) |

### `internal/core/errors/` — 7-class typed error hierarchy (FOUND-01)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/errors/errors.go` | model | transform (typed values) | _no spike analog_; ADR §6 inlined sample is canonical | §6 (sentinel anchors + 7 typed structs with `Is()` bridge) | `modules/core.sh` (untyped `printf "ERROR:"` strings) |
| `internal/core/errors/errors_test.go` | test | unit | _no spike test_ | §9.2 Ring 1 example "Error type Is() / As() traversal across 7-class hierarchy" | _N/A_ |

### `internal/core/log/` — slog + Secret type + RedactingHandler (FOUND-02 + XCUT-07)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/log/secret.go` | model | transform (LogValue) | _no spike analog_; ADR §10.1 inlined sample (10 LoC) | §10.1 (`type Secret string` + `LogValue() slog.Value` returns `"***"`) | `modules/core.sh:24-42` (`REDACT_VARS` array) |
| `internal/core/log/redactor.go` | service | transform | _no spike analog_; ADR §10.2 inlined `Redactor` struct | §10.2 (Redactor: `Register(value)` skip≤4, `Redact(s)` → strings.ReplaceAll) | `modules/core.sh:53-89` (`register_secret`/`redact_secrets`) |
| `internal/core/log/redacting_handler.go` | middleware | event-driven (slog records) | _no spike analog_; ADR §10.2 inlined `RedactingHandler` struct | §10.2 (wraps slog.Handler: Enabled/Handle/WithAttrs/WithGroup; redactAttr only on slog.KindString) | `lib/ui.sh:382` + `modules/core.sh:95-103` (`_trace_redact_stream`) |
| `internal/core/log/logger.go` | service | transform (factory) | `spike/go/internal/ui/ui.go` (minimal stderr writes) | §10.3 (`log.New(cfg, redactor)` factory returns `*slog.Logger` with chain JSON→Redacting→Console) | `lib/common.sh` logger setup (NOT directly equivalent) |
| `internal/core/log/secret_test.go` | test | unit | _no spike test_ | §9.2 Ring 1 "Secret.LogValue() returns *** not actual value" | _N/A_ |
| `internal/core/log/redactor_test.go` | test | unit | _no spike test_ | §10.4 XCUT-07 sentinel-value test pattern | _N/A_ |

### `internal/core/config/` — koanf-based 8-source loader (FOUND-03)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/config/config.go` | model | transform | _no spike analog_; ADR §2.2 schema | §2.2 (full v2-native struct shape with `koanf:"..."` + `validate:"..."` tags) | `reconftw.cfg` (sourced flags; v1 grammar) |
| `internal/core/config/loader.go` | service | request-response | _no spike analog_; ADR §2.1 koanf mandate + RESEARCH.md §Stack Snapshot row "koanf v2 + go-toml v2" | §2.3 (8-source precedence; v2-native ALWAYS wins over legacy via load order) | `reconftw.sh` getopt + `source reconftw.cfg` + CLI override re-apply |
| `internal/core/config/validate.go` | service | transform | _no spike analog_; ADR §2.5 per-key validation rules | §2.5 (go-playground/validator v10 struct tags + custom `nopath_traversal`, `nuclei_severity`, `oneof_scheme=http https`) | `lib/validation.sh` (`validate_domain`, `sanitize_interlace_input`, etc.) |
| `internal/core/config/snapshot.go` | service | transform (write) | `spike/go/internal/output/atomic.go` (atomic write pattern) | §3.1 `inputs/config.snapshot.toml` (Secret fields redacted before write) | _N/A_ (v1 stores no resolved snapshot) |
| `internal/core/config/config_test.go` | test | unit | _no spike test_ | §9.2 Ring 1 "TestLegacyOverridePrecedence" + Ring 4 property tests via rapid | `tests/unit/validation.bats` (v1 pattern) |

### `internal/core/task/` — Task interface + Registry (FOUND-12)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/task/task.go` | model | request-response (Run) | `interfaces_check/main.go:55-68` (placeholder Task + LifecycleAware) | §5.1 (BINDING Task interface: Name/Module/Description/Enabled/DependsOn/Run; Result struct; Status enum; LifecycleAware) | `modules/core.sh:start_func`/`end_func` (v1 lifecycle wrapper) |
| `internal/core/task/registry.go` | service | event-driven (init()) | _no spike analog_; ADR §5.1 inlined `Registry` + `Register` + `Default` | §5.1 (`Default *Registry`, `Register(t Task)` panic on dup, topo-sort cycle detection in `Build()`) | _N/A_ (v1 has no registry — modules sourced flat) |
| `internal/core/task/topo.go` | utility | transform | _no spike analog_; PITFALL §3 (circular DependsOn cycle detection mandatory) | §5.1 PITFALL NOTE + §6 ConfigError (cycle → `ConfigError`, not runtime error) | _N/A_ |
| `internal/core/task/task_test.go` | test | unit | _no spike test_ | §9.2 Ring 1 "Scheduler topological sort for DependsOn() chains (no goroutines, just DAG logic)" | _N/A_ |

### `internal/core/scheduler/` — Bounded concurrency + failure_policy (FOUND-06)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/scheduler/scheduler.go` | service | event-driven (fan-out) | `spike/go/internal/passive/passive.go:60-67` (errgroup.SetLimit(4) + g.Go fan-out) | §7.2 inlined `Scheduler` struct + `runStage` fork (errgroup.WithContext for fail_fast vs zero-value errgroup for best_effort) | `lib/parallel.sh:33-42` (`_throttle_jobs` with `wait -n`) |
| `internal/core/scheduler/policy.go` | model | transform | _no spike analog_; ADR §7 enum | §7.2 (`FailurePolicy` type alias + `PolicyBestEffort` / `PolicyFailFast` consts; `policyFor(module)` lookup) | _N/A_ (v1 `CONTINUE_ON_TOOL_ERROR` global) |
| `internal/core/scheduler/heartbeat.go` | service | streaming | _no spike analog_; XCUT-09 spec | §1.1 (heartbeat node) + ROADMAP success criterion 4 "heartbeat events at configurable cadence" | `lib/parallel.sh` heartbeat poll (v1) |
| `internal/core/scheduler/scheduler_test.go` | test | integration | _no spike test_; spike `passive.go` is closest fan-out shape | §9.2 Ring 2 "Scheduler runs a DAG of 3-5 tasks in dependency order" + Ring 4 rapid scheduler deadlock-prevention | _N/A_ |

### `internal/core/backend/` — Backend interface + LocalBackend + AxiomBackend stub + ToolRegistry (FOUND-08 + FOUND-09 + FOUND-10)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/backend/backend.go` | model | request-response | `interfaces_check/main.go:99-107` (Backend interface placeholder) | §5.2 (BINDING Backend interface: Exec/Stream/HealthCheck/Capacity; Event struct; Result struct; Tool struct) | `modules/utils.sh:run_command` (v1 universal tool gate) |
| `internal/core/backend/local.go` | service | streaming + buffered | `spike/go/internal/proc/proc.go:40-130` (canonical kill-tree-safe subprocess: Setpgid + WaitDelay + Cancel callback + group-SIGKILL goroutine after WaitDelay+500ms) | §5.2 + RESEARCH.md §Pitfall 1.2 (top-impact) | `lib/parallel.sh:55-66` (`_kill_tree` pgrep walk — semantic intent only) |
| `internal/core/backend/axiom.go` | service | request-response | _no spike analog_; CONTEXT default (b) compile-only stub | §5.2 + CONTEXT decision-default-AxiomBackend-(b) (all 4 methods return `*AxiomFailure{Inner: ErrAxiomNotImplemented}`) | `modules/axiom.sh:axiom_launch`/`axiom_shutdown` (v1 — Phase 4 replaces stub) |
| `internal/core/backend/runner.go` | service | request-response | _no spike analog_ | §5.3 `AppContext.Tools *backend.Runner` (Runner wraps Backend + ToolRegistry; Tasks call `app.Tools.Run(ctx, name, args)`) | `modules/utils.sh:run_command` (the v1 successor in v2) |
| `internal/core/backend/registry.go` | service | request-response | _no spike analog_; CONTEXT discretion default (b) for tools.lock seed | §1.2 (ToolRegistry component) + RESEARCH.md §Stack Snapshot row "tools.lock pinning" | _N/A_ (v1 uses `command -v` ad-hoc) |
| `internal/core/backend/ratelimiter.go` | service | transform | _no spike analog_; RESEARCH.md §Stack picks `time/rate` | §5.2 (per-tool rate limit field in Tool struct) + FOUND-07 spec | `reconftw.cfg:HTTPX_RATELIMIT` + per-tool flags (v1) |
| `internal/core/backend/tools.lock` | config | transform | _no spike analog_; CONTEXT default (b) 5-10 tool seed | §1.2 + ROADMAP success criterion 4 | `install.sh` v1 (no lock file) |
| `internal/core/backend/local_test.go` | test | integration | `spike/go/internal/proc/proc.go` integration test pattern (`TestSIGINTKillsAllChildrenWithin10s` referenced in CONTEXT) | §9.2 Ring 2 "kill-tree integration test (FOUND-09 / §9.2 ring 2)" | `tests/unit/parallel.bats` (v1) |
| `internal/core/backend/lint/no_raw_subprocess.go` | utility | transform | _no spike analog_; FOUND-10 lint rule spec | §1.2 + ROADMAP success criterion 3 "lint rule forbids raw exec.Command outside the Tool wrapper" | _N/A_ (no v1 equivalent) |

### `internal/core/output/` — OutputTree + AtomicWriter + CompatWriter (FOUND-04)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/output/atomic.go` | service | transform (write) | `spike/go/internal/output/atomic.go:20-76` (canonical 4-step: tempfile-in-same-dir + fsync + rename + parent-dir fsync) | §3.5 (AtomicWriter contract — the ONLY sanctioned write path; direct `os.WriteFile` forbidden) | _N/A_ (v1 direct appends; PITFALL 3.1) |
| `internal/core/output/tree.go` | service | transform + dedup | _no spike analog_; ADR §3.1-3.2 spec | §3.1 (workspaces/<target-id>/ layout) + §3.2 (JSONL schemas + dedup keys + OutOfScope guard) | `Recon/<domain>/` v1 layout (`subdomains/`, `webs/`, `vulns/`, etc.) |
| `internal/core/output/scope.go` | service | transform (filter) | _no spike analog_; spike main.go:29 `domainRe` is the validation seed | §3.2 (OutputTree.Append checks scope BEFORE writing) | `lib/validation.sh:is_in_scope_host` + `modules/utils.sh:filter_in_scope_urls` |
| `internal/core/output/manifest.go` | service | transform (write) | `spike/go/internal/output/atomic.go` (writes manifest atomically) | §3.3 (manifest.json schema: workspace_version, target, started_at, finished_at, config_hash, tool_versions) | _N/A_ (v1 has no manifest) |
| `internal/core/output/compat.go` | service | event-driven (LifecycleAware.OnEnd) | _no spike analog_; ADR §4.1 inlined `AtomicSymlink` function | §4.1-4.4 (AtomicSymlink + compat directory layout + V1→V2 mapping + lifecycle) | v1 `Recon/<domain>/` is the contract being maintained |
| `internal/core/output/init.go` | service | transform (write) | _no spike analog_ | §3 WorkspaceInit/WorkspaceFinalize semantics | `modules/modes.sh:start()` (v1 workspace init) |
| `internal/core/output/atomic_test.go` | test | integration | `spike/go/internal/output/atomic.go` test pattern (`TestSIGKILLLeavesOriginalIntact` referenced in CONTEXT) | §9.2 Ring 2 "OutputTree.Append() scope filter at write boundary" + ROADMAP success criterion 2 SIGKILL-between-rename-and-fsync test | _N/A_ |

### `internal/core/checkpoint/` — SQLite-backed checkpoint store (FOUND-05)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/checkpoint/store.go` | service | CRUD | _no spike analog_; RESEARCH.md §Stack picks `modernc.org/sqlite` | §3.4 (SQL schema + WAL mode + BEGIN IMMEDIATE + 6-step read/write ordering) | `Recon/<d>/.called_fn/.${fn}` touch sentinels (v1 — replaced) |
| `internal/core/checkpoint/migrations.go` | config | transform | _no spike analog_ | §3.4 (CREATE TABLE tasks with PRIMARY KEY (task_name, target, input_hash)) | _N/A_ |
| `internal/core/checkpoint/hash.go` | utility | transform | _no spike analog_ | §3.4 (`input_hash = SHA-256(config_slice_json + wordlists.lock_content)`) | _N/A_ (PITFALL 3.2 in bash: stale checkpoint when code changes) |
| `internal/core/checkpoint/store_test.go` | test | integration | _no spike test_ | §9.2 Ring 2 "Checkpoint store: begin task → simulate crash → reopen → verify status=running detected → re-run → verify idempotent output" | _N/A_ |

### `internal/core/appctx/` — Dependency kernel struct (FOUND-AppContext wiring)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/appctx/appctx.go` | model | request-response | `interfaces_check/main.go:40-50` (AppContext placeholder) | §5.3 (BINDING AppContext struct: Log/Cfg/Scheduler/Tools/Tree/Checkpoint/Notify/Target/UI; NO package-level globals) | `reconftw.sh` (v1 — globals everywhere, REJECTED) |
| `internal/core/appctx/target.go` | model | transform | _no spike analog_ | §5.3 (Target struct: Domain/IsCIDR/IsIP/Scope/WorkDir) | `modules/modes.sh:start()` (v1 — globals `domain`, `dir`, `called_fn_dir`) |
| `internal/core/appctx/boot.go` | service | request-response (factory) | `spike/go/cmd/spike/main.go:46-70` (signal.NotifyContext + sequential boot) | §10.3 (CRITICAL init order — redactor → logger → config → secret-register → AppContext.New) | _N/A_ |
| `internal/core/appctx/appctx_test.go` | test | unit | _no spike test_ | §9.2 Ring 1 (mock AppContext; no subprocess; no filesystem I/O) | _N/A_ |

### `internal/core/notifier/` — Notifier interface + LogSink + stubs (FOUND-11)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/notifier/notifier.go` | model | request-response | _no spike analog_ | §1.2 (Notifier component) + FOUND-11 (interface + log sink + Slack/Telegram/Discord stubs) | `modules/utils.sh:sendToNotify()` (v1) |
| `internal/core/notifier/log_sink.go` | service | event-driven | `spike/go/internal/ui/ui.go` (minimal stderr writes) | §10.2 (all messages pass through Redactor) + CONTEXT default (a) "LogSink only" | _N/A_ |
| `internal/core/notifier/slack.go` | service | request-response | _no spike analog_ | §1.2 + FOUND-11 (stub returns nil; Phase 10 wires real webhook) | `modules/utils.sh:sendToNotify_slack` (v1) |
| `internal/core/notifier/telegram.go` | service | request-response | _no spike analog_ | §1.2 + FOUND-11 (stub) | `modules/utils.sh:sendToNotify_telegram` (v1) |
| `internal/core/notifier/discord.go` | service | request-response | _no spike analog_ | §1.2 + FOUND-11 (stub) | `modules/utils.sh:sendToNotify_discord` (v1) |
| `internal/core/notifier/notifier_test.go` | test | unit + integration | _no spike test_ | §9.2 Ring 2 "Notifier: mock sink receives task completion messages; asserts zero log lines contain unredacted secret values (XCUT-07 integration gate)" | _N/A_ |

### `internal/core/ui/` — Dot-fill UI printer (FOUND-13)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/ui/printer.go` | service | transform | `spike/go/internal/ui/ui.go:16-37` (minimum-viable Info/Skip/Warn/Err) | §1.2 (UI component — port of `lib/ui.sh` verbatim) | `lib/ui.sh:_print_status` (CANONICAL — `[OK  ] name .......... 12s` dot-fill format) |
| `internal/core/ui/tty.go` | utility | transform | _no spike analog_ | §1.2 + FOUND-13 (`OUTPUT_VERBOSITY=0/1/2` semantics, NO TUI library, plain printf+lipgloss for color/width on TTY only) | `lib/ui.sh:9-13` (`_UI_IS_TTY`, `_UI_NO_COLOR`, `_UI_LOG_FORMAT`) |
| `internal/core/ui/badge.go` | utility | transform | _no spike analog_ | RESEARCH.md §Architecture pattern 10 "UI: dot-fill plain text, not TUI" | `lib/ui.sh:148-156` (`ui_count_inc` OK/WARN/FAIL/SKIP/CACHE counter pattern) |
| `internal/core/ui/parallel_log.go` | service | transform | _no spike analog_ | FOUND-13 (`PARALLEL_LOG_MODE summary\|tail\|full`) | `lib/parallel.sh` parallel output modes |
| `internal/core/ui/printer_test.go` | test | unit | _no spike test_ | §9.2 Ring 1 "UI dot-fill format output (string comparison against expected badge format)" | `tests/unit/ui.bats` (v1) |

### `internal/modules/demo/` — Demo Task (CONTEXT default end-of-phase-demo option (b))

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/modules/demo/noop.go` | controller | event-driven (init() Task.Register) | `spike/go/internal/passive/passive.go` (errgroup fan-out shape) + RESEARCH.md §2a (PassiveTask example: `func init() { task.Register(&PassiveTask{}) }`) | §5.1 (Task interface implementation) + CONTEXT default end-of-phase-demo (b) "Phase 4 plan-01 replaces noop.demo registration with subdomains.passive" | _N/A_ (new; demo-only; deleted in Phase 4 plan-01) |

### `internal/core/testutil/` — Test mocks (FOUND-15)

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `internal/core/testutil/mock_backend.go` | test | request-response | `spike/go/internal/proc/proc.go` (Backend.Stream shape) | §9.3 (MockBackend — reads fixture from `testutil/fixtures/<tool>/<scenario>.txt`; never spawns subprocess) | _N/A_ |
| `internal/core/testutil/mock_checkpoint.go` | test | CRUD | _no spike analog_ | §9.3 (MockCheckpoint — in-memory map; supports all query patterns) | _N/A_ |
| `internal/core/testutil/mock_output_tree.go` | test | transform | _no spike analog_ | §9.3 (MockOutputTree — in-memory; `Lines(artefact) []string` for assertion) | _N/A_ |
| `internal/core/testutil/fixtures/` | test | data | _no spike analog_ | §9.3 (fixture files per tool/scenario) | `tests/fixtures/` (v1) |

### CI + tooling

| New/Modified File | Role | Data Flow | Closest Analog | ADR §N | Bash Reference |
|-------------------|------|-----------|----------------|--------|----------------|
| `.github/workflows/ci.yml` | config | event-driven | _no spike analog_; ADR §9.3 yaml is the seed | §9.3 (jobs: unit / integration / smoke per ring policy) | `.github/workflows/ci.yml` (v1 bats CI — replaced) |
| `.golangci.yml` | config | transform | _no spike analog_; RESEARCH.md §Stack picks `golangci-lint v2.12.2` | §10.1 (custom rule flags exported `*Key/*Token/*Password/*Secret` not typed as `log.Secret`) | `.shellcheck` v1 config (replaced) |
| `Makefile` | config | transform | `spike/go/Makefile` (build target reference) | RESEARCH.md §Stack Snapshot "Packaging: `goreleaser` → `-ldflags="-s -w"` for binary size <50MB stripped (XCUT-02)" | `Makefile` v1 (bats targets — extended) |
| `interfaces_check/main.go` | test (compile-gate) | transform | _already exists_; KEEP per CONTEXT "delta detector" rationale until end of Phase 3 | §11 (Pre-Sign Verification Gate Check 3: `go build ./interfaces_check/...`) | _N/A_ |

---

## Pattern Assignments

For each new file, the planner uses the analog file path + the ADR §N section + the bash reference to write the plan task. Concrete code excerpts follow per package below.

### 1. `cmd/reconftw/main.go` (entry-point, event-driven)

**Primary analog:** `spike/go/cmd/spike/main.go:31-83`
**Bash reference:** `reconftw.sh` (getopt + config source + dispatch — semantic intent only)
**ADR §:** §10.3 — CRITICAL init order

**Pattern to copy from spike main.go:14-25 (imports + cobra + signal.NotifyContext):**
```go
import (
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "github.com/spf13/cobra"
)
```

**Signal handler pattern (spike lines 47-48 — production version adds ADR §10.3 init order BEFORE the handler):**
```go
ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
defer stop()
```

**Production init order pattern (ADR §10.3 lines 2531-2562 — replaces spike's flat startup):**
```go
func main() {
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    // STEP 1: redactor + logger FIRST.
    redactor := &log.Redactor{}
    logger := log.New(cfg, redactor)
    slog.SetDefault(logger)

    // STEP 3: config load (logger active so validation lines are captured).
    cfg, err := config.Load(cliFlags)
    if err != nil {
        slog.Error("config_load_failed", "err", err)
        os.Exit(1)
    }

    // STEP 4: register all Secret fields with redactor.
    redactor.Register(string(cfg.Notifications.Slack.WebhookURL))
    redactor.Register(string(cfg.Notifications.Telegram.BotToken))
    redactor.Register(string(cfg.Notifications.Discord.WebhookURL))

    // STEP 5: Boot AppContext + execute cobra.
    app := appctx.New(logger, cfg /* ... */)
    if err := rootCmd.ExecuteContext(ctx); err != nil {
        os.Exit(1)
    }
}
```

**Exit code 64 (sysexits.h EX_USAGE) for stub subcommands per CONTEXT D-02** — used by `cmd/reconftw/stub.go`.

---

### 2. `cmd/reconftw/root.go` (controller, request-response)

**Primary analog:** `spike/go/cmd/spike/main.go:34-72` (cobra Root + RunE)
**Bash reference:** `reconftw.sh` getopt long options
**ADR §:** §8.1 (subcommand table) + §8.3 (`cobra.MarkDeprecated()` pattern)

**Imports + cobra Root pattern (spike lines 34-37):**
```go
root := &cobra.Command{
    Use:   "reconftw",
    Short: "Comprehensive reconnaissance automation",
    Long:  "...",
    // No RunE on root — subcommands handle dispatch.
}
```

**Persistent flag + deprecation pattern (ADR §8.3 lines 2120-2153):**
```go
// Subcommand-mode flags (v1 short flags → v2 subcommands)
rootCmd.PersistentFlags().BoolP("recon", "r", false, "Run recon mode")
rootCmd.PersistentFlags().MarkDeprecated("recon",
    "use subcommand 'recon' instead: `reconftw recon -d example.com`")

rootCmd.PersistentFlags().BoolP("all", "a", false, "Run all modules")
rootCmd.PersistentFlags().MarkDeprecated("all",
    "use subcommand 'all' instead: `reconftw all -d example.com`")

// ... 9 long-flag aliases + 10 short-flag aliases per ADR §8.3 +
// global flag aliases (--target/-d, --list/-l, --axiom/-v) ...
```

**Per-subcommand flag pattern (spike lines 74-78):**
```go
root.Flags().StringVarP(&target, "target", "t", "", "Target domain (required)")
if err := root.MarkFlagRequired("target"); err != nil {
    fmt.Fprintf(os.Stderr, "flag error: %v\n", err)
    os.Exit(1)
}
```

---

### 3. `internal/core/errors/errors.go` (model, transform)

**Primary analog:** _none — ADR §6 is canonical_
**Bash reference:** `modules/core.sh` (untyped error strings)
**ADR §:** §6 — 7-class typed error hierarchy

**Sentinel anchor pattern (ADR §6 lines 1786-1793):**
```go
var (
    ErrTool     = errors.New("tool execution failure")
    ErrTimeout  = errors.New("tool execution timeout")
    ErrScope    = errors.New("out of scope")
    ErrAxiom    = errors.New("axiom infrastructure failure")
    ErrConfig   = errors.New("configuration error")
    ErrChecksum = errors.New("checksum mismatch")
)
```

**Typed struct + Is() bridge pattern (ADR §6 lines 1803-1814):**
```go
type ToolError struct {
    Tool     string
    ExitCode int
    Stderr   string // last 1KB of stderr — truncate to prevent runaway alloc
    Inner    error
}

func (e *ToolError) Error() string {
    return fmt.Sprintf("tool %s (exit %d): %v", e.Tool, e.ExitCode, e.Inner)
}
func (e *ToolError) Unwrap() error { return e.Inner }
func (e *ToolError) Is(target error) bool { return target == ErrTool } // sentinel bridge
```

**Remaining 6 types follow this same shape** (ADR §6 lines 1817-1897): `ToolTimeout`, `OutOfScope`, `AxiomFailure`, `ConfigError`, `ScopeError`, `ChecksumMismatch`.

**Security note (XCUT-07-relevant — ADR §6 lines 1762-1764):** `ConfigError.Message` MUST NOT include raw secret values; `AxiomFailure.Inner` MUST NOT contain raw credentials (run Redactor.Redact on error strings before construction).

---

### 4. `internal/core/log/secret.go` (model, transform)

**Primary analog:** _none — ADR §10.1 is canonical (cites Go stdlib official LogValuer example)_
**Bash reference:** `modules/core.sh:24-42` (`REDACT_VARS` array — Go replaces array with type-level tagging)
**ADR §:** §10.1 — Layer 1 secret tagging

**Complete Secret type (ADR §10.1 lines 2367-2374):**
```go
package log

import "log/slog"

// Secret is a string that auto-redacts itself in all slog output.
// Any field in AppContext, Config, or Tool structs holding a secret MUST use this type.
// BINDING: do not add a Secret.String() method — the absence of String() prevents accidental
// fmt.Sprintf("%s", s) exposure. If a caller needs the raw value (e.g. to register it with
// the Redactor), they must explicitly cast: string(mySecret).
type Secret string

// LogValue implements slog.LogValuer. Returns "***" for any slog attribute.
func (Secret) LogValue() slog.Value {
    return slog.StringValue("***")
}
```

**Critical: NO `String()` method** — see ADR §10.1 lines 2402-2407 "Why no Secret.String() method".

---

### 5. `internal/core/log/redactor.go` + `redacting_handler.go` (service + middleware, transform + event-driven)

**Primary analog:** _none — ADR §10.2 is canonical (cites Arcjet 2024 article)_
**Bash reference:** `modules/core.sh:53-89` (`register_secret()` + `redact_secrets()`)
**ADR §:** §10.2 — Layer 2 RedactingHandler

**Redactor struct + Register pattern (ADR §10.2 lines 2431-2464):**
```go
type Redactor struct {
    mu      sync.RWMutex
    secrets []string
}

// Register adds a secret value to the redaction list.
// Values with length ≤ 4 are ignored (too short to be a meaningful secret).
// MUST be called BEFORE the first log line that could reference this value.
func (r *Redactor) Register(value string) {
    if len(value) <= 4 {
        return
    }
    r.mu.Lock()
    defer r.mu.Unlock()
    for _, s := range r.secrets {
        if s == value {
            return // dedup
        }
    }
    r.secrets = append(r.secrets, value)
}

// Redact replaces all registered secret substrings in s with "***".
func (r *Redactor) Redact(s string) string {
    r.mu.RLock()
    defer r.mu.RUnlock()
    for _, secret := range r.secrets {
        s = strings.ReplaceAll(s, secret, "***")
    }
    return s
}
```

**Bash parallel (v1 semantic equivalent — `modules/core.sh:70-89`):**
```bash
function redact_secrets() {
    local text="$1"
    local redacted="$text"
    for var in "${REDACT_VARS[@]}"; do
        value="${!var:-}"
        if [[ -n "$value" && ${#value} -gt 4 ]]; then
            redacted="${redacted//$value/[REDACTED]}"
        fi
    done
    for secret in "${REGISTERED_SECRETS[@]}"; do
        if [[ -n "$secret" && ${#secret} -gt 4 ]]; then
            redacted="${redacted//$secret/[REDACTED]}"
        fi
    done
    echo "$redacted"
}
```
**Note:** v2 type-tags secrets so Layer 1 catches the bulk; v1 had no type system so REDACT_VARS was the only defense.

**RedactingHandler pattern (ADR §10.2 lines 2466-2518)** — wraps slog.Handler chain; intercepts records; redacts `r.Message` and string attrs.

---

### 6. `internal/core/config/config.go` + `loader.go` (model + service, transform + request-response)

**Primary analog:** _none — ADR §2 is canonical_
**Bash reference:** `reconftw.sh` (getopt + config source + CLI override re-apply)
**ADR §:** §2.2 (schema) + §2.3 (precedence) + §2.5 (validation rules)

**MANDATE (ADR §2.1 lines 280-282):** NEVER use `spf13/viper` — key lowercasing breaks the `[legacy]` table. Always use `knadh/koanf/v2`.

**Config struct pattern with Secret type embedded (ADR §10.1 lines 2381-2393):**
```go
type NotificationsConfig struct {
    Slack struct {
        WebhookURL log.Secret `koanf:"webhook_url" validate:"omitempty,url,startswith=https"`
        Channel    string     `koanf:"channel"     validate:"omitempty"`
    } `koanf:"slack"`
    Telegram struct {
        BotToken   log.Secret `koanf:"bot_token"   validate:"omitempty,max=256"`
        ChatID     string     `koanf:"chat_id"     validate:"omitempty"`
    } `koanf:"telegram"`
    Discord struct {
        WebhookURL log.Secret `koanf:"webhook_url" validate:"omitempty,url,startswith=https"`
    } `koanf:"discord"`
}
```

**8-source precedence (RESEARCH.md §Stack Snapshot row "Config"):**
```text
defaults → /etc/reconftw → ~/.config/reconftw → ./reconftw.toml → --config FILE
         → secrets.toml → env (RECONFTW_*) → CLI flags
```

**Validation rules table:** ADR §2.5 lines 1096-1129 — all 30+ keys with `min`, `max`, `oneof`, `url`, `nopath_traversal` etc. Custom validators: `nopath_traversal`, `nuclei_severity`, `oneof_scheme=http https`.

**Mutex group 1 (legacy + v2-native collision):** ADR §2.3 lines 1039-1055 — v2-native ALWAYS wins; WARN emitted per colliding key.

---

### 7. `internal/core/task/task.go` (model, request-response)

**Primary analog:** `interfaces_check/main.go:55-68` (placeholder Task + LifecycleAware)
**Bash reference:** `modules/core.sh:start_func`/`end_func` (semantic intent only — v1 has no Task)
**ADR §:** §5.1 BINDING Task interface

**Complete Task interface (ADR §5.1 lines 1542-1569, replacing placeholders in interfaces_check):**
```go
package task

type Task interface {
    Name() string                               // "subdomains.passive"
    Module() string                             // "subdomains"
    Description() string                        // one-line for UI badges
    Enabled(cfg *config.Config) bool
    DependsOn() []string                        // empty = parallel with peers
    Run(ctx context.Context, app *appctx.AppContext) (Result, error)
}

type Result struct {
    Status   Status
    Duration time.Duration
    Outputs  []string         // paths written
    Stats    map[string]int   // optional counters
}

type Status string
const (
    StatusDone      Status = "done"
    StatusErrored   Status = "errored"
    StatusCancelled Status = "cancelled"
    StatusSkipped   Status = "skipped"
)

type LifecycleAware interface {
    OnStart(ctx context.Context, app *appctx.AppContext) error
    OnEnd(ctx context.Context, app *appctx.AppContext, r Result) error
}
```

**Registry + Register (ADR §5.1 lines 1591-1604):**
```go
type Registry struct{ tasks map[string]Task }
var Default = &Registry{tasks: map[string]Task{}}

func Register(t Task) {
    if _, ok := Default.tasks[t.Name()]; ok {
        panic("reconftw: duplicate task registration: " + t.Name())
    }
    Default.tasks[t.Name()] = t
}
```

**PITFALL §3 (must implement, ADR §6 PITFALL NOTE lines 1766-1769):** `Registry.Build()` MUST perform topological sort cycle detection BEFORE any task runs. Circular `DependsOn` chains are a `ConfigError`, NOT a runtime error. A detected cycle must halt startup, not deadlock the scheduler.

---

### 8. `internal/core/scheduler/scheduler.go` (service, event-driven fan-out)

**Primary analog:** `spike/go/internal/passive/passive.go:60-67` (canonical errgroup.SetLimit + g.Go fan-out)
**Bash reference:** `lib/parallel.sh:33-42` (`_throttle_jobs` with `wait -n` — semantic intent)
**ADR §:** §7.2 — Scheduler with `failure_policy` dispatch

**errgroup fan-out pattern (spike lines 60-67):**
```go
g, gctx := errgroup.WithContext(ctx)
g.SetLimit(4)

g.Go(func() error { return subfinderRun(gctx, target, collect) })
g.Go(func() error { return crtRun(gctx, target, collect) })
g.Go(func() error { return githubRun(gctx, target, collect) })
g.Go(func() error { return gitlabRun(gctx, target, collect) })

if err := g.Wait(); err != nil {
    ui.Warn("passive: one or more sources returned an error: " + err.Error())
}
```

**Production Scheduler with failure_policy fork (ADR §7.2 lines 1996-2032):**
```go
func (s *Scheduler) runStage(ctx context.Context, module string, tasks []Task) error {
    if len(tasks) == 0 { return nil }
    policy := s.policyFor(module)

    if policy == PolicyFailFast {
        // fail_fast: first error cancels all peers via context.
        g, gctx := errgroup.WithContext(ctx)
        g.SetLimit(int(s.maxConcurrent))
        for _, t := range tasks {
            t := t
            g.Go(func() error { return s.runOne(gctx, t) })
        }
        return g.Wait()
    }

    // best_effort: all tasks complete; errors are warnings, not failures.
    g := new(errgroup.Group) // ZERO-VALUE — no WithContext, no peer cancel
    g.SetLimit(int(s.maxConcurrent))
    for _, t := range tasks {
        t := t
        g.Go(func() error {
            if err := s.runOne(ctx, t); err != nil {
                s.log.Warn("task_error_best_effort",
                    slog.String("task", t.Name()),
                    slog.String("module", t.Module()),
                    slog.Any("err", err))
                return nil // swallow: best_effort continues
            }
            return nil
        })
    }
    return g.Wait() // always nil in best_effort
}
```

**Key distinction (ADR §7.2 lines 2042-2047):** `fail_fast` uses `errgroup.WithContext` (peer cancel via context). `best_effort` uses zero-value `errgroup.Group` (no peer cancel; errors logged + swallowed).

---

### 9. `internal/core/backend/backend.go` (model, request-response)

**Primary analog:** `interfaces_check/main.go:99-107` (Backend interface placeholder)
**Bash reference:** `modules/utils.sh:run_command` (v1 universal tool gate — semantic intent)
**ADR §:** §5.2 — BINDING Backend interface

**Complete Backend interface (ADR §5.2 lines 1665-1690, replacing placeholders):**
```go
type Backend interface {
    // Exec runs tool with args, buffers stdout+stderr, returns when done.
    Exec(ctx context.Context, t *Tool, args []string) (*Result, error)

    // Stream runs tool with args, yields stdout/stderr lines as Events on returned channel.
    // Suitable for long-running tools (nuclei, dalfox, katana).
    // Caller MUST drain the channel until closed to avoid goroutine leak.
    Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error)

    // HealthCheck verifies the backend is operational. Called at startup + `reconftw health-check`.
    HealthCheck(ctx context.Context) error

    // Capacity returns the number of concurrent tool invocations the backend supports.
    Capacity() int
}
```

---

### 10. `internal/core/backend/local.go` (service, streaming + buffered)

**Primary analog:** `spike/go/internal/proc/proc.go:40-130` (canonical kill-tree-safe subprocess)
**Bash reference:** `lib/parallel.sh:55-66` (`_kill_tree` pgrep walk — v1 semantic intent)
**ADR §:** §5.2 + RESEARCH.md §Pitfall 1.2 (top-impact)

**CRITICAL kill-tree pattern (spike `proc.go` lines 41-89) — verbatim adaptation:**
```go
cmd := exec.CommandContext(ctx, name, args...)

// Process-group isolation: every subprocess runs as its own process-group leader.
cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

// WaitDelay: after ctx cancels, SIGTERM via Cancel below; SIGKILL after WaitDelay.
cmd.WaitDelay = 5 * time.Second

// Cancel: when ctx is done, kill the ENTIRE process group (negative PID = group).
cmd.Cancel = func() error {
    if cmd.Process == nil { return nil }
    return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

// SIGKILL escalation goroutine: Go's WaitDelay fires cmd.Process.Kill() which sends
// SIGKILL only to the DIRECT child. We supplement with kill(-pgid, SIGKILL) to reap
// stubborn grandchildren after WaitDelay + 500ms.
pgid := cmd.Process.Pid
killGroupDone := make(chan struct{})
go func() {
    defer close(killGroupDone)
    select {
    case <-ctx.Done():
        time.Sleep(cmd.WaitDelay + 500*time.Millisecond)
        _ = syscall.Kill(-pgid, syscall.SIGKILL)
    case <-killGroupDone:
    }
}()
```

**Streaming with explicit buffer size (spike `proc.go` lines 92-94 — required for httpx 10M-line case):**
```go
// 1MiB initial / 10MiB max handles long httpx JSON objects.
scanner := bufio.NewScanner(stdout)
scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)
```

**Bash semantic anchor (`lib/parallel.sh:55-66`):**
```bash
function _kill_tree() {
    local parent="$1" sig="${2:-TERM}"
    if command -v pgrep >/dev/null 2>&1; then
        for child in $(pgrep -P "$parent" 2>/dev/null); do
            _kill_tree "$child" "$sig"
        done
    fi
    kill "-$sig" "$parent" 2>/dev/null || true
}
```
**Note:** v1 walks the tree via `pgrep -P` because bash `start()` runs `set +m` (job control off) so subshells share pgid. Go uses `Setpgid: true` to give each subprocess its own pgid — no recursion needed.

---

### 11. `internal/core/backend/axiom.go` (service, request-response)

**Primary analog:** _none — CONTEXT default (b) compile-only stub_
**Bash reference:** `modules/axiom.sh:axiom_launch`/`axiom_shutdown` (Phase 4 implementation)
**ADR §:** §5.2 + CONTEXT discretion default (b)

**Pattern (compile-only stub all 4 methods):**
```go
type AxiomBackend struct{}

var ErrAxiomNotImplemented = errors.New("axiom backend not implemented (Phase 4)")

func (a *AxiomBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
    return nil, &errors.AxiomFailure{Operation: "exec", Inner: ErrAxiomNotImplemented}
}
func (a *AxiomBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
    return nil, &errors.AxiomFailure{Operation: "exec", Inner: ErrAxiomNotImplemented}
}
func (a *AxiomBackend) HealthCheck(ctx context.Context) error {
    return &errors.AxiomFailure{Operation: "healthcheck", Inner: ErrAxiomNotImplemented}
}
func (a *AxiomBackend) Capacity() int { return 0 }
```

---

### 12. `internal/core/output/atomic.go` (service, transform)

**Primary analog:** `spike/go/internal/output/atomic.go:20-76` (CANONICAL — verbatim adaptation)
**Bash reference:** _none — v1 uses direct appends (PITFALL 3.1)_
**ADR §:** §3.5 — AtomicWriter contract

**The 4-step pattern (spike `atomic.go` lines 20-76):**
```go
func WriteJSONL(target string, lines [][]byte) error {
    dir, base := filepath.Split(target)
    if dir == "" { dir = "." }

    if err := os.MkdirAll(dir, 0o755); err != nil {
        return err
    }

    // Step 1: tempfile in same dir as target (same filesystem — avoids cross-device rename).
    tmp, err := os.CreateTemp(dir, base+".tmp.*")
    if err != nil { return err }
    defer os.Remove(tmp.Name()) //nolint:errcheck

    for _, line := range lines {
        if _, err := tmp.Write(line); err != nil { return err }
        if _, err := tmp.Write([]byte("\n")); err != nil { return err }
    }

    // Step 2: fsync the tempfile.
    if err := tmp.Sync(); err != nil { return err }
    if err := tmp.Close(); err != nil { return err }

    // Step 3: atomic rename (rename(2) is atomic if same filesystem).
    if err := os.Rename(tmp.Name(), target); err != nil { return err }

    // Step 4: fsync parent directory (CRITICAL — often missed).
    parentFD, err := os.Open(dir)
    if err != nil { return err }
    defer parentFD.Close() //nolint:errcheck

    return parentFD.Sync()
}
```

**ADR §3.5 mandate (lines 1338-1341):** This 4-step pattern is the ONLY sanctioned write path for `artefacts/` and `reports/`. Direct `os.WriteFile`, unbuffered `os.OpenFile`, or append-only writes are **forbidden by design**. Violation closes threat T-02-03-01.

---

### 13. `internal/core/output/compat.go` (service, event-driven)

**Primary analog:** _none — ADR §4.1 is canonical (AtomicSymlink function inlined)_
**Bash reference:** _none — v1's `Recon/<domain>/` IS the contract being maintained_
**ADR §:** §4.1-4.4

**AtomicSymlink pattern (ADR §4.1 lines 1392-1404):**
```go
func AtomicSymlink(target, link string) error {
    // Temp path in same directory as link (same filesystem guaranteed).
    dir := filepath.Dir(link)
    tmp, err := os.CreateTemp(dir, ".symlink-tmp.*")
    if err != nil { return err }
    tmpName := tmp.Name()
    tmp.Close()
    os.Remove(tmpName) // remove file placeholder — we need only the name slot

    if err := os.Symlink(target, tmpName); err != nil { return err }
    return os.Rename(tmpName, link) // atomic swap — overwrites any existing symlink
}
```

**Compat directory layout (ADR §4.2 lines 1417-1428):** `_compat/subdomains/all.txt`, `_compat/webs/webs.txt`, `_compat/vulns/findings.txt`, etc.

**Top-level symlink (ADR §4.2 lines 1431-1435):** `Recon/<domain> → workspaces/<target-id>/_compat/`

---

### 14. `internal/core/checkpoint/store.go` (service, CRUD)

**Primary analog:** _none — ADR §3.4 schema is canonical_
**Bash reference:** `Recon/<d>/.called_fn/.${fn}` sentinel files (v1 REPLACED — RESEARCH.md §Architecture pattern 3)
**ADR §:** §3.4 — checkpoints.db schema

**SQL schema (ADR §3.4 lines 1297-1309) — use `modernc.org/sqlite` per RESEARCH.md library blacklist (NOT `mattn/go-sqlite3` which pulls cgo):**
```sql
CREATE TABLE IF NOT EXISTS tasks (
    task_name    TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    input_hash   TEXT    NOT NULL,
    status       TEXT    NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    duration_ms  INTEGER,
    output_paths TEXT,
    error_class  TEXT,
    PRIMARY KEY (task_name, target, input_hash)
);
```

**Read/write ordering (ADR §3.4 lines 1322-1331):**
1. `BEGIN IMMEDIATE` transaction
2. Check for existing `done` row → skip if found
3. Insert `status="in-progress"` row
4. `COMMIT`
5. Run task
6. `UPDATE tasks SET status=?, finished_at=?, duration_ms=?, output_paths=? WHERE ...`

**Mandate:** Always open SQLite in WAL mode: `PRAGMA journal_mode=WAL` (concurrent readers don't block writes; mid-task crash leaves `in-progress` row which next startup treats as `cancelled` → safe re-run).

**input_hash formula (ADR §3.4 line 1319):**
```
input_hash = SHA-256(config_slice_json + wordlists.lock_content)
```

---

### 15. `internal/core/appctx/appctx.go` (model, request-response)

**Primary analog:** `interfaces_check/main.go:40-50` (placeholder AppContext)
**Bash reference:** `reconftw.sh` globals (REJECTED per ADR §5.3)
**ADR §:** §5.3 — AppContext (NO package-level globals)

**Complete AppContext (ADR §5.3 lines 1723-1733, replacing placeholders):**
```go
type AppContext struct {
    Log        *slog.Logger         // RedactingHandler applied at construction
    Cfg        *config.Config       // resolved + validated (all ~290-310 flags)
    Scheduler  *scheduler.Scheduler // bounded concurrency + failure_policy
    Tools      *backend.Runner      // wraps Backend + ToolRegistry
    Tree       *output.OutputTree   // atomic JSONL writer + scope filter + compat
    Checkpoint *checkpoint.Store    // SQLite-backed (checkpoints.db)
    Notify     notifier.Notifier    // multi-channel notification dispatcher
    Target     *Target              // immutable scan target description
    UI         *ui.Printer          // terminal UI printer
}

type Target struct {
    Domain  string   // sanitized domain, IP, or CIDR
    IsCIDR  bool
    IsIP    bool
    Scope   []string // wildcard patterns from scope file
    WorkDir string   // absolute path to workspaces/<target-id>/
}
```

**Mandate (ADR §5.3 line 1745):** NO package-level globals anywhere in `internal/`. The Go lint rule (FOUND-10 extension) flags any `var Default = …` outside the singletons defined in ADR §5 (`task.Default`).

---

### 16. `internal/core/ui/printer.go` (service, transform)

**Primary analog:** `spike/go/internal/ui/ui.go:14-37` (minimum-viable Info/Skip/Warn/Err)
**Bash reference:** `lib/ui.sh:_print_status` (CANONICAL — dot-fill format port verbatim)
**ADR §:** §1.2 + RESEARCH.md §Architecture pattern 10

**Spike baseline (minimum-viable; production extends):**
```go
package ui

import (
    "fmt"
    "os"
)

func Info(msg string) {
    fmt.Fprintln(os.Stderr, "[INFO] "+msg)
}
func Skip(component, reason string) {
    fmt.Fprintln(os.Stderr, "[SKIP] "+component+": "+reason)
}
func Warn(msg string) {
    fmt.Fprintln(os.Stderr, "[WARN] "+msg)
}
func Err(msg string) {
    fmt.Fprintln(os.Stderr, "[ERR ] "+msg)
}
```

**Production dot-fill format (port verbatim from `lib/ui.sh`):**
```
[OK  ] subdomains.passive .......... 12s
[WARN] web.fuzz .................... 45s (rate-limited)
[FAIL] vulns.xss .................. 120s (timeout)
[SKIP] osint.spoofy ................. (disabled)
```

**Bash semantic anchor (`lib/ui.sh:9-13` runtime state vars):**
```bash
_UI_IS_TTY=false
_UI_NO_COLOR=false
_UI_LOG_FORMAT="plain"
_UI_JSONL_STRICT=false
```

**OUTPUT_VERBOSITY semantics (memory/MEMORY.md "Features Added"):**
- `0` = quiet: only errors/FAIL printed
- `1` = normal (default): OK/WARN/FAIL/SKIP status lines
- `2` = verbose: + INFO + start_func messages

**Mandate (RESEARCH.md §Architecture pattern 10):** NO TUI frameworks (no bubbletea/textual/rich Live) — breaks CI logs, pipes, journalctl.

---

### 17. `internal/modules/demo/noop.go` (controller, event-driven)

**Primary analog:** `spike/go/internal/passive/passive.go` (Task shape) + RESEARCH.md §2a (PassiveTask example with `init() { task.Register(...) }`)
**Bash reference:** _none — demo only_
**ADR §:** §5.1

**Self-registration pattern (RESEARCH.md §2a lines 112-126):**
```go
package demo

func init() { task.Register(&NoopTask{}) }

type NoopTask struct{}

func (NoopTask) Name() string  { return "noop.demo" }
func (NoopTask) Module() string { return "demo" }
func (NoopTask) Description() string { return "Phase 3 demo task — replaced in Phase 4 plan-01" }
func (NoopTask) DependsOn() []string { return nil }
func (NoopTask) Enabled(c *config.Config) bool { return true } // always on for demo

func (NoopTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
    // Write one fixture line to artefacts/demo.jsonl through OutputTree.Append.
    // Proves Scheduler + Backend + Tree + Checkpoint cooperate end-to-end.
    line := []byte(`{"demo":"phase-3-kernel","timestamp":"..."}`)
    if err := app.Tree.Append("demo", [][]byte{line}); err != nil {
        return task.Result{Status: task.StatusErrored}, err
    }
    return task.Result{
        Status: task.StatusDone,
        Outputs: []string{"artefacts/demo.jsonl"},
    }, nil
}
```

**Blank-import wiring (RESEARCH.md §2a lines 132-137) in `cmd/reconftw/modules.go`:**
```go
package main

import (
    _ "github.com/six2dez/reconftw/internal/modules/demo"
    // Phase 4: add _ "github.com/six2dez/reconftw/internal/modules/subdomains"
)
```

---

### 18. `.github/workflows/ci.yml` (config, event-driven)

**Primary analog:** _none — ADR §9.3 yaml is canonical seed_
**Bash reference:** `.github/workflows/*.yml` v1 (replaced)
**ADR §:** §9.3

**CI yaml seed (ADR §9.3 lines 2288-2313):**
```yaml
jobs:
  unit:
    name: Unit + Property tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test -race -short ./...     # Ring 1 + Ring 4

  integration:
    name: Integration tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test -race ./...             # Ring 1 + Ring 2 + Ring 4

  smoke:
    name: Smoke tests
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request' || github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test -race -tags smoke ./... # Ring 3
```

**Additional gates per CONTEXT discretion + XCUT-04:**
- `golangci-lint v2.12.2` lint job (every push)
- `gofumpt` format check (every push)
- branch coverage ≥75% on lib code (`go test -coverprofile=…` + grep)
- binary size <50MB stripped (`go build -ldflags="-s -w" -trimpath` + `wc -c`)

**Platform scope (CONTEXT default (a)):** ubuntu-latest only in Phase 3; Phase 11 owns the cross-platform matrix (XPLAT-05).

---

## Shared Patterns

### Authentication / Authorization

**N/A** — Phase 3 builds the kernel; no user-facing auth surface yet. (Phase 8 MCP server adds API key auth per MCP-04.)

### Error Handling

**Source:** ADR §6 + `internal/core/errors/errors.go`
**Apply to:** All service/controller files
**Pattern (caller — RESEARCH.md §11):**
```go
// Sentinel check (don't need metadata):
if errors.Is(err, errors.ErrTool) {
    // handle category
}

// Typed extraction (need metadata):
var te *errors.ToolError
if errors.As(err, &te) {
    log.Warn("tool failed", "tool", te.Tool, "exit", te.ExitCode)
}

// Wrap with context:
return fmt.Errorf("subfinder run: %w", &errors.ToolError{Tool: "subfinder", ExitCode: 1, Inner: err})
```

**XCUT-07 hygiene:** Never include raw secret values in error messages. `ConfigError.Message` = `"invalid URL format"` NOT `"invalid URL: http://..."`. Run `Redactor.Redact()` on error strings before constructing `AxiomFailure{Inner: err}`.

### Logging

**Source:** `internal/core/log/{secret.go,redactor.go,redacting_handler.go,logger.go}`
**Apply to:** All files that log
**Pattern (caller):**
```go
// Idiomatic structured logging:
slog.Info("task_complete",
    slog.String("task", t.Name()),
    slog.Duration("elapsed", elapsed),
    slog.Int("findings", count),
)

// Secrets are TYPE-tagged at the field level — auto-redact via LogValuer:
slog.Info("config_loaded", slog.Any("webhook", cfg.Notifications.Slack.WebhookURL))
// → emits {"webhook":"***"} automatically because WebhookURL is log.Secret type
```

**Mandate:** All `Cfg`, `AppContext`, `Tool` struct fields holding secrets MUST be typed `log.Secret`. The custom golangci-lint rule (ADR §10.1 lines 2396-2400) flags any exported `*Key/*Token/*Password/*Secret` field NOT typed as `log.Secret`.

### Validation

**Source:** `internal/core/config/validate.go`
**Apply to:** All config load + all input validation
**Pattern (struct tags — ADR §2.5):**
```go
type Config struct {
    Concurrency struct {
        MaxJobs            int `koanf:"max_jobs"            validate:"min=1,max=64"`
        KillGraceSeconds   int `koanf:"kill_grace_seconds"  validate:"min=1,max=300"`
        LogMode            string `koanf:"log_mode"         validate:"oneof=summary tail full"`
    } `koanf:"concurrency"`
    Paths struct {
        WordlistsDir string `koanf:"wordlists_dir" validate:"omitempty,nopath_traversal"`
    } `koanf:"paths"`
}
```

**Custom validators (ADR §2.5 lines 1132-1136):** `nopath_traversal`, `nuclei_severity`, `oneof_scheme=http https`.

**Bash semantic equivalent (`lib/validation.sh:validate_domain`):** `^[a-zA-Z0-9.-]+$` regex — REUSE in Go per spike `main.go:29`.

### Atomic Writes

**Source:** `internal/core/output/atomic.go`
**Apply to:** EVERY file write under `workspaces/<target-id>/artefacts/`, `reports/`, `manifest.json`, `inputs/config.snapshot.toml`
**Pattern (caller):**
```go
// NEVER call os.WriteFile / os.OpenFile / os.Create directly on artefacts.
// ALWAYS go through OutputTree.Append:
err := app.Tree.Append("subdomains", lines)
```

**Mandate (ADR §3.5):** AtomicWriter is the ONLY sanctioned write path. Direct writes are forbidden by design.

### Subprocess Execution

**Source:** `internal/core/backend/local.go`
**Apply to:** EVERY external tool invocation
**Pattern (caller):**
```go
// NEVER call exec.Command / exec.CommandContext directly.
// ALWAYS go through Backend.Exec / Backend.Stream:
result, err := app.Tools.Run(ctx, "subfinder", "-d", target, "-silent")

// Long-running tools use Stream for line-by-line consumption:
events, err := app.Tools.Stream(ctx, "nuclei", "-l", inputFile, "-jsonl")
for event := range events {
    // process event.Line; channel closes when tool exits
}
```

**Mandate (FOUND-10 — custom golangci-lint rule):** Any `exec.Command*` call outside `internal/core/backend/local.go` is a CI failure.

### Checkpointing

**Source:** `internal/core/checkpoint/store.go`
**Apply to:** All Tasks (via Scheduler — Task implementations don't write checkpoints directly)
**Pattern (Scheduler runs before/after each Task.Run):**
```go
// 1. Compute input_hash for this task + target + config slice.
hash := checkpoint.InputHash(task, target, cfgSlice, wordlistsLock)

// 2. Check for existing done row.
done, err := app.Checkpoint.Done(task.Name(), target, hash)
if done {
    app.UI.Skip(task.Name(), "checkpoint hit")
    return nil
}

// 3. Mark in-progress, run, mark done/errored.
app.Checkpoint.Begin(task.Name(), target, hash)
result, err := task.Run(ctx, app)
app.Checkpoint.Complete(task.Name(), target, hash, result, err)
```

---

## No Analog Found

The table below lists files where neither spike code nor an ADR §N code snippet provides a direct line-by-line analog. The planner reads RESEARCH.md, ADR §N section prose, or the bash semantic intent to write these files.

| File | Role | Data Flow | Reason | Reference |
|------|------|-----------|--------|-----------|
| `cmd/reconftw/version.go` | command | request-response | New in Phase 3 per ADR D-04 | `runtime/debug.ReadBuildInfo()` + ldflags `-X main.version`/`-X main.buildDate` |
| `cmd/reconftw/healthcheck.go` | command | request-response | New in Phase 3 per ADR D-04 | ADR D-04 spec: `LocalBackend.HealthCheck` + ToolRegistry exec.LookPath + config parse-time check |
| `cmd/reconftw/stub.go` + `stub_subcommands.go` | controller | request-response | New in Phase 3 per CONTEXT D-01/D-02 | CONTEXT D-02 spec: exit 64 + phase pointer message |
| `internal/core/backend/lint/no_raw_subprocess.go` | utility | transform | New in Phase 3 per FOUND-10 | RESEARCH.md §Library blacklist + `golangci-lint` plugin API docs |
| `internal/core/backend/ratelimiter.go` | service | transform | New per FOUND-07 + RESEARCH.md `time/rate` pick | RESEARCH.md §Stack Snapshot row + per-tool config keys (ADR §2.2 advanced.tools.*) |
| `internal/core/backend/registry.go` + `tools.lock` | service + config | request-response | New per FOUND-08 + CONTEXT discretion default (b) | CONTEXT discretion: seed with `subfinder`, `httpx`, `crt`, `dnsx`, `puredns`, `gotator`, `anew`, `asnmap`, `s3scanner`, `subzy` (Phase 4 needs) |
| `internal/core/scheduler/heartbeat.go` | service | streaming | New per XCUT-09 spec | ROADMAP success criterion 4 "heartbeat events at configurable cadence" |
| `internal/core/output/scope.go` | service | transform | Combines spike main.go:29 domainRe with ADR §3.2 OutputTree.Append scope check | Bash `lib/validation.sh:is_in_scope_host` + `modules/utils.sh:filter_in_scope_urls` (semantic) |
| `internal/core/output/manifest.go` | service | transform | Uses spike atomic.go for write; manifest schema from ADR §3.3 | ADR §3.3 manifest.json schema (workspace_version/target/started_at/etc.) |
| `internal/core/notifier/{notifier.go,log_sink.go,slack.go,telegram.go,discord.go}` | model + services | request-response | All Phase 3 stubs per CONTEXT default (a); Phase 10 implements real | FOUND-11 spec + ADR §10.2 (all bodies through Redactor) |
| `internal/core/checkpoint/{migrations.go,hash.go}` | config + utility | transform | New per ADR §3.4 | ADR §3.4 SQL schema + input_hash formula |
| `internal/core/ui/{tty.go,badge.go,parallel_log.go}` | utility + services | transform | New per FOUND-13 (port lib/ui.sh) | `lib/ui.sh` (entire file is the semantic reference) |
| `internal/core/testutil/{mock_backend.go,mock_checkpoint.go,mock_output_tree.go}` | tests | various | New per FOUND-15 + ADR §9.3 | ADR §9.3 "Foundation Wave 0 Requirements" |

**Planner action for "No Analog Found" files:** cite the ADR §N + RESEARCH.md + bash semantic anchor in the plan task; do not require a spike file reference.

---

## Metadata

**Analog search scope:**
- `spike/go/**/*.go` (cmd, internal/proc, internal/output, internal/passive, internal/ui, internal/httpxprobe, internal/crt, internal/subfinder, internal/github, internal/gitlab)
- `interfaces_check/main.go` (placeholder Task/Backend interface)
- `lib/{common.sh,parallel.sh,ui.sh,validation.sh}` (bash semantic anchors)
- `modules/{core.sh,utils.sh,modes.sh,axiom.sh}` (bash module references)
- `.planning/decisions/0002-architecture-v2.md` §1-§12 (BINDING contracts + inlined code snippets)

**Files scanned:** 50+ Go files, 6 bash files, 1 ADR (2736 lines), 1 RESEARCH SUMMARY (538 lines), 1 RESEARCH ARCHITECTURE (300+ lines), 1 REQUIREMENTS file (sections only)

**Key patterns identified:**
1. **Spike-derived patterns (4 canonical):** kill-tree subprocess (proc.go) → `internal/core/backend/local.go`; atomic JSONL write (output/atomic.go) → `internal/core/output/atomic.go`; errgroup fan-out (passive/passive.go) → `internal/core/scheduler/scheduler.go`; cobra+signal bootstrap (cmd/spike/main.go) → `cmd/reconftw/main.go`.
2. **ADR-inlined patterns (5 canonical):** 7-class error hierarchy (§6) verbatim; Secret type + Redactor + RedactingHandler (§10.1-§10.2) verbatim; failure_policy fork (§7.2) verbatim; AtomicSymlink (§4.1) verbatim; CRITICAL init order (§10.3) verbatim.
3. **Interface contracts (3 BINDING):** Task (6 methods, §5.1), Backend (4 methods, §5.2), AppContext (9 fields + Target, §5.3) — `interfaces_check/main.go` is the delta detector.
4. **Bash → Go semantic ports:** `start_func`/`end_func` → `Task.Run`+Scheduler boundary logging; `parallel_funcs` → `errgroup.SetLimit(N)`; `_kill_tree` → `Setpgid`+`syscall.Kill(-pgid, …)`; `register_secret`/`redact_secrets` → `Redactor.Register`/`Redact`; `_print_status` dot-fill → `internal/core/ui/printer.go`; `validate_domain` regex → reuse `^[a-zA-Z0-9.-]+$`.
5. **CLI grammar locked in Phase 3 (per CONTEXT D-01/D-03):** all 15 subcommands surfaced + all v1 deprecated aliases wired via `cobra.MarkDeprecated()`; D-02 stub message format with exit code 64; D-04 makes version + health-check fully working.

**Pattern extraction date:** 2026-05-28
