# Phase 9: Composite Modes — Research

**Researched:** 2026-06-11
**Domain:** Go CLI orchestration — cobra subcommand wiring, config transform functions, v1 alias dispatch, passive-mode hard-guard, stateful utility subcommands
**Confidence:** HIGH — all claims verified against actual source files in the repo

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Boot-once composite handler. Refactor each existing `RunXAsync` into a Boot step + reusable "run-stages-on-an-already-booted-app" seam. New composite handler boots ONCE and runs stage groups (subs → web → osint, +vulns for `all`) under a single AppContext, single scheduler, single workspace, single checkpoint timeline, and a unified end-of-run summary.
- **D-02:** In-memory override functions applied after config load and before Boot: `applyZenProfile(cfg)` and `applyDeepProfile(cfg)`. No new TOML preset surface.
- **D-03:** Mode overrides win over file config. zen/deep transforms layer above resolved file config.
- **D-04:** `gen-resolvers` — full. Runs dnsvalidator to regenerate DNS resolver list, mirroring v1 `resolvers_update`.
- **D-05:** `refresh-cache` — full. Invalidate + rebuild DNS/ASN/geo cached data for a target.
- **D-06:** `quick-rescan` — thin. Re-runs `recon` with checkpoint-skip / force-refresh semantics. Diff reporting defers to Phase 10.
- **D-07:** `--list` batch = sequential, isolated workspace per target, continue-on-error. Exits non-zero if any target failed.
- **D-08:** V1 alias dispatch = pre-cobra arg translation. Extend `parseEarlyFlags` to rewrite deprecated forms into v2 invocations BEFORE cobra parses. Cobra's `MarkDeprecated` still emits the one-time stderr warning.
- **D-09:** Passive = backend-level hard-guard, not composition alone. Guard hard-blocks any active/network exec against the target while `mode=passive`.
- **D-10:** Guarantee secret redaction on `--dry-run` / `--quiet` / piped paths. Build the redacting handler unconditionally in Boot, wrap whatever sink is chosen.

### Claude's Discretion

- Exact name/signature of the extracted stage-runner seam and composite handler.
- Exact set of cfg fields each of `applyZenProfile`/`applyDeepProfile` touches.
- Composite unified-summary format and how per-stage progress UI composes across pipelines.
- `refresh-cache` cache-key/storage mechanism and which cache entries it covers.
- Per-target batch summary table format and exit-code aggregation details.

### Deferred Ideas (OUT OF SCOPE)

- Findings-diff engine / "new artefacts only" reporting → Phase 10 (MON-*/REPORT-*).
- Monitor loop / incremental re-run engine → Phase 10.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| MODE-01 | `reconftw recon` — passive subs → web probe → web analysis → OSINT, skipping vulns | Stage-extraction seam (Q1) + composite handler shape |
| MODE-02 | `reconftw all` — recon + vulns | Same seam; adds vulns stage group after OSINT |
| MODE-03 | `reconftw passive` — passive-only, no active probing | Backend-level hard-guard (Q4) |
| MODE-04 | `reconftw zen` — stealth/minimal-noise profile | `applyZenProfile` field list (Q2) |
| MODE-05 | `reconftw deep` — extended brute + permutations | `applyDeepProfile` field list (Q2) |
| MODE-06 | `reconftw quick-rescan` — force-refresh against last workspace | Store baseline (Q5) |
| MODE-07 | `reconftw refresh-cache` — rebuild DNS/ASN/geo cache | Cache anatomy (Q5) |
| MODE-08 | `reconftw gen-resolvers` — regenerate DNS resolver list via dnsvalidator | V1 command (Q5) |
| MODE-09 | V1 long-flag aliases with deprecation warning | Alias dispatch (Q3) |
| MODE-10 | `--target X` and `--list FILE` work across all modes | Batch implementation (Q6) |
| MODE-11 | `--config FILE` overrides default reconftw.toml | Loader chain already handles; only CLI plumbing needed |
| MODE-12 | `--dry-run` across composites | Dry-run composition + XCUT-07 fold (Q7) |
</phase_requirements>

---

## Summary

Phase 9 completes the CLI surface by replacing the five stub subcommands (`recon`, `all`, `passive`, `zen`, `deep`) with real orchestration, adding three stateful utility subcommands (`quick-rescan`, `refresh-cache`, `gen-resolvers`), finishing v1 alias dispatch, and guaranteeing secret redaction on all output paths. It introduces NO new recon capabilities — it only composes Phases 4-7 pipelines.

The core work divides into three areas. First, a **stage-runner seam extraction**: the identical `afterBoot` + stage loop pattern duplicated across `runSubsCmd`/`runWebCmd`/`runVulnsCmd`/`runOSINTCmd` (≈80 lines each, four copies) is extracted into a shared `RunStagesOnBootedApp` function that accepts an `AppBoot` and a pipeline descriptor. Second, **config transform functions** (`applyZenProfile`/`applyDeepProfile`) that manipulate an already-loaded `*config.Config` in memory before `BootReconApp` is called. Third, **pre-cobra arg translation** extending `parseEarlyFlags` to rewrite v1 flag forms into v2 subcommand invocations.

The primary technical risk is the axiom kill-switch hazard described in the CONTEXT.md: within a composite that includes OSINT with `--axiom`, a gato auth failure can trip the axiom failover counter for the rest of the composite run (subs/web stages may lose axiom). The planner must ensure the composite axiom lifecycle (launch-once, shutdown-once) scopes the kill-switch to the composite, not per-pipeline.

**Primary recommendation:** Extract the `afterBoot` body into a `commonAfterBoot(boot, sched, dryRun, ...)` helper first, then build `RunStagesOnBootedApp(ctx, app, sched, cfg, workdir, stageGroups)`. The composite `recon` handler calls `BootReconApp` once, fires the afterBoot helpers once, then runs stage groups sequentially via the extracted seam.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Composite orchestration (recon/all/passive/zen/deep) | CLI cmd layer (`cmd/reconftw/`) | `internal/mcp/handlers/` | CLI owns per-subcommand RunE; handlers own stage loop execution |
| Config transforms (zen/deep profiles) | Config layer (`internal/core/config/`) | CLI cmd layer | Pure functions on *Config; called from cmd layer before BootReconApp |
| V1 alias dispatch / pre-cobra translation | CLI cmd layer (`cmd/reconftw/main.go`) | — | parseEarlyFlags is already the pre-cobra scan point |
| Passive hard-guard | Backend / AppContext layer | CLI mode flag threading | Hard-block must live below the CLI so it cannot be bypassed |
| Batch --list iteration | CLI cmd layer | — | Sequential per-target loop; each target boots independently |
| gen-resolvers | New `internal/core/resolvers/` or inline in cmd | — | Standalone; no target required |
| refresh-cache | CLI cmd layer + Cache layer | — | Invalidates in-process cache state for a target |
| quick-rescan | CLI cmd layer | `internal/store/` | Force-refresh checkpoint; Phase 10 owns diff computation |
| Secret redaction on all paths (D-10) | `internal/core/log/` (logger.go) | main.go Boot sequence | Redacting handler must wrap every sink unconditionally |

---

## Standard Stack

### Core (already in go.mod — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/spf13/cobra` | existing | CLI subcommand wiring | Already used; all subcommands share it |
| `github.com/six2dez/reconftw/internal/mcp/handlers` | internal | BootReconApp + RunXAsync stage loops | The seam to split |
| `github.com/six2dez/reconftw/internal/core/config` | internal | Config struct + Load + Defaults | transform functions live here |
| `github.com/six2dez/reconftw/internal/core/scheduler` | internal | Per-scan scheduler; Limiter | One scheduler per composite run |
| `github.com/six2dez/reconftw/internal/core/log` | internal | Redactor + RedactingHandler | D-10 unconditional wrapping |
| `github.com/six2dez/reconftw/internal/store` | internal | scan_observation / scans tables for quick-rescan |  |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `os/exec` (stdlib) | stdlib | gen-resolvers: invoke `dnsvalidator` | gen-resolvers only; use backend.LocalBackend path |
| `net/http` (stdlib) | stdlib | refresh-cache: re-fetch resolver/geo seed files | refresh-cache fallback download |

**No new external dependencies are required for Phase 9.**

---

## Architecture Patterns

### System Architecture Diagram

```
CLI invocation
    │
    ├─ parseEarlyFlags (pre-cobra)  ← EXTENDED in Phase 9 to rewrite v1 aliases
    │      rewrites: -r → ["recon","--target",...], -d X → --target X, etc.
    │
    ├─ config.Load (8-source chain) ← --config FILE hooks here (MODE-11)
    │
    ├─ applyZenProfile(cfg) / applyDeepProfile(cfg)  ← NEW, applied before Boot
    │      (only if zen/deep subcommand or --zen/--deep flag)
    │
    └─ cobra.ExecuteContext
           │
           ├─ recon / all / passive / zen / deep   ← Phase 9 replaces stub
           │       │
           │       └─ RunCompositeAsync(ctx, CompositeOptions)
           │               │
           │               ├─ BootReconApp(ctx, opts)  ← single Boot
           │               ├─ commonAfterBoot(...)     ← extracted helper
           │               ├─ RunStagesOnBootedApp(app, sched, cfg, stageGroups)
           │               │       subs stages → web stages → osint stages
           │               │       (→ vulns stages for all/deep)
           │               └─ printCompositeSummary(...)
           │
           ├─ quick-rescan   ← thin: force Advanced.Diff=true + recon pipeline
           ├─ refresh-cache  ← invalidate + rebuild per-target caches
           ├─ gen-resolvers  ← standalone dnsvalidator invocation
           │
           └─ (subs/web/vulns/osint — Phase 4-7, unchanged RunE bodies)
```

### Recommended Project Structure (new files only)

```
cmd/reconftw/
├── composite_subcommands.go   # newReconCmd/newAllCmd/newPassiveCmd/newZenCmd/newDeepCmd RunE bodies
├── composite_test.go          # ordering, passive guard, dry-run composition tests
├── batch.go                   # runBatch(cmd, subcommandFn, targets) sequential loop
├── stateful_subcommands.go    # newQuickRescanCmd/newRefreshCacheCmd/newGenResolversCmd
├── stateful_test.go           # gen-resolvers dry-run, refresh-cache smoke
internal/core/config/
├── profiles.go                # applyZenProfile / applyDeepProfile
├── profiles_test.go           # unit tests: each field set to expected value
internal/core/resolvers/
├── gen.go                     # RunGenResolvers(ctx, cfg) — dnsvalidator wrapper
├── gen_test.go
```

### Pattern 1: Stage-Runner Seam Extraction

**What:** Extract the duplicated `afterBoot` + scheduler wiring + stage loop from each `runXCmd` into two shared helpers.

**When to use:** All composite handlers; also simplifies the four existing single-pipeline handlers.

The duplicated block in each `runSubsCmd` / `runWebCmd` / `runVulnsCmd` / `runOSINTCmd` (`stub_subcommands.go` lines ~159-237, ~404-466, ~666-728, ~862-924) is structurally identical:

```
1. sched.MaxConcurrent = cfg.Concurrency.MaxJobs
2. sched.HeartbeatSeconds = cfg.Concurrency.HeartbeatSeconds
3. if dryRun: capture task list; return
4. liveUI check → route slog to run.log (redactor re-registration)
5. axiomBE launch / defer shutdown
6. wire sched.RunTask = progress closure
```

**Proposed seam signatures (Claude's discretion names — adjust as appropriate):**

```go
// commonAfterBoot wires the scheduler limits, log routing, axiom launch,
// and per-task progress UI. Extracted from the four duplicated afterBoot
// closures in stub_subcommands.go. Called inside AfterBoot in each RunE.
func commonAfterBoot(ctx context.Context, boot handlers.AppBoot, sched *scheduler.Scheduler,
    dryRun bool, capturedDryRun *dryRunCapture) {
    // ... extracted body from any of the four runXCmd afterBoot blocks
}

// RunStagesOnBootedApp executes pipeline stage groups sequentially against
// an already-booted AppContext. Each group is a []stageGroup; within a group
// stages run in order. Used by composite handlers only.
func RunStagesOnBootedApp(ctx context.Context, app *appctx.AppContext,
    sched *scheduler.Scheduler, cfg *config.Config,
    groups [][]handlers.StageGroupSpec) error {
    // calls handlers.RunSubsStages / RunWebStages / RunVulnsStages / RunOSINTStages
    // (the extracted inner stage loops from RunXAsync)
}
```

**What breaks if the same scheduler/AppContext is reused across pipelines:**
- `sched.Checkpoint` is set once in `RunSubsAsync` (`subs.go:65`): `sched.Checkpoint = app.Checkpoint`. Since each `RunXAsync` sets it from the same app, this is idempotent when using ONE boot with ONE app — safe.
- The axiom `Launch` / `Shutdown` lifecycle is per-run, not per-pipeline. In a composite, `Launch` must be called ONCE before stages start and `Shutdown` deferred once after all stages complete. Each current `runXCmd` calls `Launch` inside `afterBoot` — the composite must move this to the composite-level afterBoot only.
- `app.Checkpoint` is closed via `defer` in each `RunXAsync`. In the composite, this defer belongs to the composite handler, not the individual stage runners. The extracted `RunStagesOnBootedApp` must NOT close the checkpoint; the composite `RunCompositeAsync` owns the defer.
- Findings single-writer: each pipeline calls its own `MergeAllXArtefacts` at the end. In a composite these are called sequentially — subs merges first, then web, then OSINT, then vulns. No concurrent-write race because the composite runs pipelines sequentially (D-01: single scheduler, sequential stage groups).
- Checkpoint keys are namespaced by `(taskName, target, hash)`. Since all pipelines use the same target and same checkpoint store, checkpoint keys from subs/web/osint/vulns tasks remain distinct by their `taskName` prefix (`subdomains.`, `web.`, `osint.`, `vulns.`). No collision risk.

**Axiom kill-switch hazard (from CONTEXT.md integration points):** When OSINT runs gato with `--axiom` and gato fails due to missing `GH_TOKEN`, the axiom failover counter increments. If it crosses `cfg.Axiom.FailoverThreshold`, `axiom_disable_runtime` fires and all subsequent module calls use local backend. In a composite, this affects subs/web stages that run AFTER OSINT in `all` mode. Mitigation: run subs → web BEFORE osint → vulns in `all` (which the ordering already does for `recon` = subs→web→osint; `all` adds vulns last). Document this; no code change needed beyond the sequencing the context already specifies.

### Pattern 2: Config Profile Transform Functions

**What:** Pure functions that mutate a `*config.Config` in memory, applied after `config.Load` and before `BootReconApp`.

**When to use:** `zen` and `deep` subcommands; stackable (deep+zen stacks cleanly because both are applied in sequence).

**Exact layering point:** In the composite `RunE`, the sequence is:
1. `efs := parseEarlyFlags(os.Args[1:])`
2. `cfg, err := config.Load(config.LoadOptions{ConfigPath: efs.configPath, ...})` — user file wins over defaults
3. `applyZenProfile(cfg)` OR `applyDeepProfile(cfg)` OR both — mode wins over user file (D-03)
4. `handlers.BootReconApp(ctx, handlers.RunOptions{...})` — receives the already-mutated cfg

The key insight is that `BootReconApp` takes `RunOptions.ConfigPath` which it passes to `config.Load`. So the profile transform cannot be applied inside `BootReconApp` — it must be applied by the caller to the returned `*config.Config` **before** passing it back. However, `BootReconApp` calls `config.Load` internally (`handlers/common.go:107`). This means the profile transform must be applied AFTER the internal `config.Load` inside `BootReconApp` returns — which requires the `AfterBoot` hook or a refactor that separates `BootReconApp` into a Load step + a Boot step.

**Concrete resolution:** The cleanest approach consistent with D-01 is to add a `ConfigTransform func(*config.Config)` field to `RunOptions`. `BootReconApp` applies it after loading config and before `appctx.Boot`:

```go
// In RunOptions (handlers/common.go):
ConfigTransform func(*config.Config) // applied after Load, before Boot; nil = no-op

// In BootReconApp (handlers/common.go, after line 113):
if opts.ConfigTransform != nil {
    opts.ConfigTransform(cfg)
}
```

This keeps the transform inside the boot seam so the booted `app.Cfg` already reflects zen/deep settings, rather than having a divergence between the config passed to Boot and the config the tasks read.

### Pattern 3: Pre-Cobra Arg Translation (D-08)

**What:** Extend `parseEarlyFlags` (`cmd/reconftw/main.go:194`) to rewrite deprecated flag forms into their v2 subcommand equivalents **before** cobra's `Execute` sees them.

**Current state:** `parseEarlyFlags` only extracts `--config`, `--secrets`, `--target` (`main.go:199-215`). The cobra `addV1DeprecatedAliases` registers the deprecated flags and emits warnings via `MarkDeprecated` but the root `RunE` does nothing — `reconftw --recon -d X` currently emits the warning and then cobra finds no action.

**D-08 translation map (complete):**

| V1 form | Rewritten os.Args before cobra |
|---------|-------------------------------|
| `--recon` or `-r` | prepend `recon` subcommand to remaining non-flag args |
| `--all` or `-a` | prepend `all` |
| `--passive` or `-p` | prepend `passive` |
| `--subdomains` or `-s` | prepend `subs` |
| `--web` or `-w` | prepend `web` |
| `--vulns` | prepend `vulns` |
| `--osint` or `-n` | prepend `osint` |
| `--zen` or `-z` | prepend `zen` |
| `--deep` or `-y` | prepend `deep` |
| `-d X` | translate to `--target X` (populate the v2 global flag) |
| `-l X` | translate to `--list X` |
| `-v` | translate to `--axiom` |

**Implementation approach:** A `translateV1Args(args []string) []string` function that returns a new slice. It scans for the subcommand-mode flags (boolean) and global flags (`-d`, `-l`, `-v`). If a boolean mode flag is found and no subcommand is already at `args[0]`, it inserts the v2 subcommand name at position 0. The cobra `MarkDeprecated` entries still fire because the rewritten args still contain the original flag (they just also have the subcommand now). If a subcommand IS already present (user invokes `reconftw recon --recon`), the translation is a no-op.

**Warning emission:** Cobra's `MarkDeprecated` emits to the command's `OutOrStdout()` when the deprecated flag is parsed. Since the translated args still include the original flag (e.g., `["recon", "--recon", "--target", "X"]`), cobra will still parse `--recon` and emit the warning. This satisfies the MODE-09 criterion of "exactly once per invocation."

**Test approach:** A table-driven test in `main_test.go` asserting `translateV1Args(input) == expected`. The warning test already exists in `root_test.go` `TestDeprecationWarningLongAliases` — verify it still passes after the translation is applied.

### Pattern 4: Passive Hard-Guard (D-09)

**What:** A backend-level flag that hard-blocks any task whose module would perform active network probing against the target.

**Where to implement:** Two complementary layers:
1. **Composition layer:** `passive` subcommand only registers the passive subs stage group (prefix `subdomains.passive.`). Active subs (brute, permut, TLS pivot, zone transfer), web, and vulns stages are not included at all. This is the first guard.
2. **Backend layer (D-09 requirement):** A `PassiveMode bool` flag threaded from the `AppContext` into the `LocalBackend`. When `PassiveMode=true`, `LocalBackend.Exec` and `LocalBackend.Stream` check whether the target IP/host is the configured target domain — if the task's network operation reaches the actual target, it is hard-blocked with an `ErrPassiveViolation` sentinel.

**Practical implementation for Phase 9:** The composition layer alone satisfies the network-test success criterion because the passive composite only schedules tasks classified as passive. The backend hard-guard is the defense-in-depth against a future misclassified task. The minimal viable approach for Phase 9 is:
- Add `PassiveMode bool` to `AppContext` (or `appctx.BootOptions`).
- Have `BootReconApp` set it when called from `runPassiveCmd`.
- Have `LocalBackend.Exec` check: if `PassiveMode` and the tool is in a hard-blocked set (the active tools: puredns, naabu, nmap, dalfox, sqlmap, etc.), return `ErrPassiveViolation` immediately without executing.
- The network test: `go test -run TestPassiveModeBlocksActiveTool` with a mock backend that asserts the exec is never called.

**Exact hard-blocked tool list for passive mode** (sourced from v1 `passive()` saves/restores):
Tasks with module prefixes `subdomains.active`, `subdomains.brute`, `subdomains.permut`, `web.httpx` (probe — active HTTP), `web.ffuf`, `web.nuclei`, `web.wafw00f` (active), `vulns.*` — all should be absent from the passive stage list, and the guard should additionally block them if somehow reached.

### Anti-Patterns to Avoid

- **Re-calling `RunXAsync` sequentially from the composite:** This calls `BootReconApp` N times (N config loads, N schedulers, N axiom launches, N checkpoints opened). Breaks D-01 single-boot model and creates N separate summaries.
- **Sharing `*scheduler.Scheduler` across concurrent batch targets (D-07):** Each target's boot gets its own scheduler. The shared `Limiter` is the global cap. Per the project memory: "NEVER share one [Scheduler] across concurrent sessions."
- **Applying `applyZenProfile` after `BootReconApp` returns:** The booted `app.Cfg` will not reflect the overrides, so tasks that read `app.Cfg` see the wrong values. Apply before Boot via `ConfigTransform` in `RunOptions`.
- **Calling axiom `Launch` inside the extracted stage loop:** The composite must call Launch once before all stage groups and shutdown once after. If the sub-pipeline extracted helpers call Launch/Shutdown, the fleet will be launched/torn down between subs and web.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Resolver list download | Custom HTTP client | `config.Paths.ResolversDownload.URL` + existing `cached_download_typed` pattern / `net/http` with retry | Config already has URL, retry, timeout fields |
| Checkpoint force-invalidation | Custom checkpoint key wipe | Set `cfg.Advanced.Diff = true` | `Diff=true` forces all tasks to re-run (existing logic in `Scheduler.runOne`) |
| Secret redaction on non-TTY paths | New redaction mechanism | Add `ConfigTransform` that ensures redactor wraps the sink; use existing `log.New(cfg, redactor)` | Redactor + RedactingHandler already exist; the gap is only that `BootReconApp` uses `slog.Default()` when logger is nil — wrap unconditionally |
| Stage ordering duplication | New stage registry | Reuse the `stageSpec` / `osintStageSpec` types and the exported `osintStages()` / `osintHandlerStages()` | Already exported; composite just concatenates stage group slices |
| Per-target workspace isolation | Custom directory naming | `output.WorkspaceInit(cfg.Paths.DataDir, tgt.Domain)` | Already creates per-domain timestamped dirs |

---

## Q1: Stage-Extraction Seam — Detailed Analysis

**Exact duplicated code across the four `runXCmd` afterBoot closures** (verified against `stub_subcommands.go`):

Every afterBoot body (`runSubsCmd:159-237`, `runWebCmd:404-466`, `runVulnsCmd:666-728`, `runOSINTCmd:862-924`) does the following in the same order:
1. `sched.MaxConcurrent = cfg.Concurrency.MaxJobs` (line ~167)
2. `sched.HeartbeatSeconds = cfg.Concurrency.HeartbeatSeconds` (line ~168)
3. `if dryRun { capture task list; return }` (lines ~171-179)
4. `liveUI check` + `os.Create(run.log)` + `rdct := &log.Redactor{}` + `registerSecrets` + `slog.SetDefault(subLogger)` (lines ~182-198)
5. `axiomBE` extraction from `FailoverBackend` + `Launch` + `defer Shutdown` (lines ~204-220)
6. `progress := ui.NewStageProgress(...)` + `sched.RunTask = closure` (lines ~225-236)

The **only** differences are:
- The log warn message prefix (`"subs:"`, `"web:"`, `"osint:"`, `"vulns:"`)
- Nothing else — the entire structure is identical.

**Minimal extracted seam:**

```go
// cmd/reconftw/composite_subcommands.go

type dryRunCapture struct {
    Tasks []task.Task
    Cfg   *config.Config
}

// commonAfterBoot wires scheduler limits, log routing, axiom lifecycle,
// and per-task progress UI. Extracted from the four duplicate afterBoot
// closures. module is the log prefix ("recon", "all", etc.).
func commonAfterBoot(
    ctx context.Context,
    boot handlers.AppBoot,
    sched *scheduler.Scheduler,
    dryRun bool,
    module string,
    capture *dryRunCapture,
) {
    app := boot.App
    workdir := boot.WorkDir
    cfg := boot.Cfg

    sched.MaxConcurrent = cfg.Concurrency.MaxJobs
    sched.HeartbeatSeconds = cfg.Concurrency.HeartbeatSeconds

    if dryRun {
        cfg.Advanced.Diff = false
        if ts, err := task.Default.Build(); err == nil {
            capture.Tasks = ts
            capture.Cfg = cfg
        }
        return
    }

    liveUI := ui.Verbosity(cfg.Output.Verbosity) != ui.VerbosityQuiet && ui.IsTTY(os.Stderr)
    if liveUI {
        p := filepath.Join(workdir, "run.log")
        if f, ferr := os.Create(p); ferr == nil {
            rdct := &log.Redactor{}
            registerSecrets(cfg, rdct)
            lc := cfg.AsLoggerConfig()
            lc.Output = f
            subLogger := log.New(lc, rdct)
            slog.SetDefault(subLogger)
            _ = f
        }
    }

    var axiomBE *backend.AxiomBackend
    if fb, ok := boot.ChosenBackend.(*backend.FailoverBackend); ok {
        if abe, ok := fb.Primary.(*backend.AxiomBackend); ok {
            axiomBE = abe
        }
    }
    if axiomBE != nil {
        if launchErr := axiomBE.Launch(ctx); launchErr != nil {
            if app.Log != nil {
                app.Log.Warn(module+": axiom launch failed — continuing locally", "err", launchErr)
            }
        } else {
            // Caller defers shutdown at composite scope, not here.
            // (For single-pipeline handlers, they still own their own defer.)
        }
    }

    progress := ui.NewStageProgress(app.UI.W, app.UI.NoColor, app.UI.Verbosity)
    sched.RunTask = func(rctx context.Context, t task.Task) (task.Result, error) {
        progress.TaskStart(t.Name())
        started := time.Now()
        result, runErr := t.Run(rctx, app)
        dur := result.Duration
        if dur <= 0 { dur = time.Since(started) }
        progress.TaskDone(t.Name(), badgeForStatus(result.Status), dur)
        return result, runErr
    }
}
```

**`RunCompositeAsync` shape** (lives in `internal/mcp/handlers/composite.go`):

```go
// CompositeMode defines which pipelines to run.
type CompositeMode int
const (
    ModeRecon   CompositeMode = iota // subs(passive) + web + osint
    ModeAll                          // subs(full) + web + osint + vulns
    ModePassive                      // subs(passive only)
)

func RunCompositeAsync(ctx context.Context, opts RunOptions, mode CompositeMode) error {
    boot, err := BootReconApp(ctx, opts)
    // ... AfterBoot, checkpoint defer, stage loops per mode
}
```

The stage groups for each composite are:
- `recon`: subs.passive + subs.resolve + subs.discovery (NO brute/permut) → web all stages → osint all stages
- `all`: subs ALL stages → web ALL stages → osint ALL stages → vulns ALL stages
- `passive`: subs.passive stage ONLY (prefixes: `subdomains.passive.`)
- `zen`: same pipeline as `recon` after `applyZenProfile` lowers rate limits
- `deep`: same pipeline as `all` after `applyDeepProfile` enables brute/permut extensions

---

## Q2: Zen/Deep Config Fields — Exact Field List

**Verified against `internal/core/config/config.go` and `internal/core/config/defaults.go`.**

### `applyZenProfile(cfg *config.Config)`

Zen = passive + safe probes + stealth. V1 `reconftw.cfg` stealth equivalents mapped to v2 fields:

| Field path | Default | Zen value | V1 source / rationale |
|-----------|---------|-----------|----------------------|
| `cfg.Advanced.PerfProfile` | `"balanced"` | `"low"` | Lower concurrency multipliers |
| `cfg.Concurrency.MaxJobs` | `4` | `2` | Reduce parallelism for stealth |
| `cfg.Web.Probe.RateLimit` | `150` | `30` | httpx rate limit lowered (v1 HTTPX_RATELIMIT=150 → stealth ~30) |
| `cfg.Web.Nuclei.RateLimit` | `150` | `15` | nuclei rate limit lowered |
| `cfg.Web.Fuzz.RateLimit` | `0` | `10` | ffuf rate limit |
| `cfg.Web.Fuzz.Threads` | `0` | `5` | ffuf thread cap |
| `cfg.Subdomains.Brute.Enabled` | `true` | `false` | No active brute-force in zen/recon (zen ≈ passive+safe) |
| `cfg.Subdomains.Permut.Enabled` | `true` | `false` | No permutations in zen |
| `cfg.Subdomains.TLSPivot.Enabled` | `false` | `false` | Already false; leave |
| `cfg.Web.Portscan.ActiveEnabled` | `true` | `false` | No active nmap/naabu in zen |
| `cfg.Web.VirtualHosts.Enabled` | `false` | `false` | Already false |
| `cfg.Vulns.Enabled` | `false` | `false` | Zen never runs vulns (zen = recon-level) |
| `cfg.Web.Katana.HeadlessProfile` | `"off"` | `"off"` | No headless browser in stealth |
| `cfg.Output.Verbosity` | (from config) | `0` | Quiet output in zen ("be quiet, period" per CONTEXT.md) |

**Note:** zen does NOT need to disable OSINT — OSINT is passive by design. It should disable `cfg.OSINT.GitHub.ActionsAudit.Enabled` (gato is active/credentialed) and potentially `cfg.OSINT.GoogleDorks.Enabled` (search-engine noise).

Additional fields from v1 stealth semantics (ASSUMED for exact values — planner should confirm with operator):

| Field path | Zen value | Rationale |
|-----------|-----------|-----------|
| `cfg.OSINT.GitHub.ActionsAudit.Enabled` | `false` | gato makes active GitHub API calls |
| `cfg.Web.Wordlist.PasswordDict` | `false` | cewler crawls pages — active |

### `applyDeepProfile(cfg *config.Config)`

Deep = extended brute + permutations. V1 `DEEP=true` + `DEEP_LIMIT=500` + `DEEP_LIMIT2=1500`:

| Field path | Default | Deep value | V1 source |
|-----------|---------|-----------|-----------|
| `cfg.Advanced.Deep` | `false` | `true` | `DEEP=true` in v1 |
| `cfg.Advanced.DeepLimit` | `500` | `500` | Already the default (tasks check `cfg.Advanced.Deep` to decide whether to honor the limit) |
| `cfg.Advanced.DeepLimit2` | `1500` | `1500` | Already default |
| `cfg.Subdomains.Recursive.BruteEnabled` | `false` | `true` | `DEEP_RECURSIVE_PASSIVE=10` + v1 deep brute |
| `cfg.Subdomains.Recursive.PassiveEnabled` | `false` | `true` | v1 `SUB_RECURSIVE_PASSIVE` enabled in deep |
| `cfg.Subdomains.Permut.WordlistMode` | `"auto"` | `"full"` | v1 full permutations in DEEP |
| `cfg.Web.Fuzz.RecursionDepth` | `2` | `4` | v1 `FUZZ_RECURSION_DEPTH=2` → deep increases |
| `cfg.Vulns.Spray.DeepOnly` | (already gated) | — | `VulnSpray.DeepOnly=true` is already default; setting `Advanced.Deep=true` enables it |
| `cfg.Web.Portscan.Naabu.Ports` | `"--top-ports 1000"` | `"--top-ports 10000"` | Deeper port scan in DEEP mode |

**Layering point (D-03):** `applyZenProfile` / `applyDeepProfile` are applied to the config struct AFTER `config.Load` resolves the user's file. Because Go struct mutation happens in memory after the koanf merge chain completes, these transforms always win. The correct injection point is via `RunOptions.ConfigTransform` added to `handlers.RunOptions` (see Pattern 2 above), called inside `BootReconApp` after `config.Load` returns but before `appctx.Boot`.

---

## Q3: V1 Alias Dispatch — Complete Map

**Current state** (verified `cmd/reconftw/root.go:123-177`):
- 11 long-flag deprecated entries: `--recon`, `--all`, `--passive`, `--subdomains`, `--web`, `--vulns`, `--osint`, `--zen`, `--deep`, `--monitor`, `--health-check`
- 8 short-flag shorthands on BoolP flags: `-r`, `-a`, `-p`, `-s`, `-w`, `-n`, `-z`, `-y`
- 3 global short aliases: `-d` → `target-deprecated`, `-l` → `list-deprecated`, `-v` → `vps`

**Phase 3's limitation** (`root.go:106-111`): cobra parses the flag, `MarkDeprecated` emits the warning, and the root `RunE` does nothing — the operator still has to invoke the subcommand explicitly. Phase 9 wires the dispatch.

**`translateV1Args` function** (to be added in `cmd/reconftw/main.go` or a new `alias.go`):

```go
// translateV1Args rewrites deprecated v1 flag forms into v2 subcommand
// invocations before cobra parses os.Args. Called from run() between
// parseEarlyFlags and cobra.ExecuteContext.
//
// Leaves the original flag in the rewritten slice so MarkDeprecated still
// emits its one-time warning to stderr.
func translateV1Args(args []string) []string {
    // subcommandFor maps a v1 boolean flag name (long or short) → v2 subcommand.
    subcommandFor := map[string]string{
        "--recon": "recon", "-r": "recon",
        "--all": "all", "-a": "all",
        "--passive": "passive", "-p": "passive",
        "--subdomains": "subs", "-s": "subs",
        "--web": "web", "-w": "web",
        "--vulns": "vulns",
        "--osint": "osint", "-n": "osint",
        "--zen": "zen", "-z": "zen",
        "--deep": "deep", "-y": "deep",
    }
    // Global flag rewrites: -d → --target, -l → --list, -v → --axiom
    // ...
}
```

**How `MarkDeprecated` satisfies MODE-09 criterion 5:** Cobra emits the deprecation message exactly once per flag parse (per invocation). Since `translateV1Args` leaves the original flag in the rewritten args (e.g., `["recon", "--recon", "--target", "X"]`), cobra will still parse `--recon` and emit the warning. No custom emission needed.

**Edge case:** `reconftw --recon --all -d example.com` — both `--recon` and `--all` are present. The translation should pick the first mode flag found and ignore subsequent conflicting modes (last-wins or first-wins — document the behavior; first-wins is simpler).

**parseEarlyFlags integration:** `parseEarlyFlags` is called BEFORE cobra in `run()` (`main.go:102`). `translateV1Args` should be called on `os.Args[1:]` between `parseEarlyFlags` and `rootCmd.ExecuteContext`. The translated slice becomes the args cobra parses via `rootCmd.SetArgs(translated)` before `Execute`.

---

## Q4: Passive Hard-Guard — Implementation

**Network-test proof:** A unit test in `composite_test.go`:
1. Create a `MockBackend` that records every `Exec` call.
2. Boot with `PassiveMode=true`.
3. Run the `passive` composite.
4. Assert `MockBackend.ExecCalls` contains no entries whose tool is in the active-tool set.

The test proves "no active probe touched the target" without needing a real network.

**Backend-level guard implementation:**
- Add `PassiveMode bool` to `appctx.BootOptions`.
- `appctx.Boot` passes it to `LocalBackend` configuration or stores it in `AppContext`.
- `LocalBackend.Exec`: if `PassiveMode && isActiveTool(tool.Name)` → return `coreerrors.ErrPassiveViolation` immediately.
- `isActiveTool` checks a hardcoded set: puredns, massdns, dnsx (active brute), naabu, nmap, dalfox, sqlmap, commix, ffuf, nuclei, httpx (for active scan modes), etc.

The composition guard (only passive stage tasks are scheduled) is the primary protection. The backend guard is defense-in-depth.

---

## Q5: Stateful Modes — Implementation Details

### gen-resolvers (MODE-08, D-04)

**V1 source** (`modules/axiom.sh:16-65`, verified):

```bash
# Two dnsvalidator invocations:
dnsvalidator -tL https://public-dns.info/nameservers.txt \
    -threads "$DNSVALIDATOR_THREADS" -o "$resolvers"

dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt \
    -threads "$DNSVALIDATOR_THREADS" -o tmp_resolvers
# merges tmp_resolvers into $resolvers via anew

# Fallback: download from trickest/resolvers if dnsvalidator produces nothing:
wget -O - https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt > $resolvers
wget -O - https://gist.githubusercontent.com/six2dez/.../trusted_resolvers.txt > $resolvers_trusted
```

**V2 implementation:**
- Source URLs already live in `config.go:PathsResolversDownload` struct:
  - `cfg.Paths.ResolversDownload.URL` (defaults to the trickest URL via `reconftw.cfg` `resolvers_url`)
  - `cfg.Paths.ResolversDownload.TrustedURL`
- Output paths: `cfg.Paths.Resolvers` + `cfg.Paths.ResolversTrusted`
- `gen-resolvers` subcommand: no `--target` required (standalone per D-04)
- Implementation: `internal/core/resolvers/gen.go` — calls `dnsvalidator` via `LocalBackend.Exec`, falls back to HTTP download if dnsvalidator fails or is missing
- Thread count: `cfg.Advanced.Tools.DNSValidator.Threads`

**Note:** `SubDNSResolve.GenerateResolvers` bool field (`config.go:208`) already exists — gen-resolvers subcommand sets this to true and calls the existing resolver generation logic if it exists, or implements it inline.

### refresh-cache (MODE-07, D-05)

**What cache exists in v2 today (verified):**
- `internal/store/sqlc/` — SQLite tables: `scans`, `scan_observation`, `targets`, `hosts`, `findings`, `urls`, `ports`, `js` — these are NOT a cache, they are the findings store. `refresh-cache` does NOT wipe these.
- `cfg.Cache` — `CacheConfig{MaxAgeDays, MaxAgeDaysResolvers, MaxAgeDaysWordlists, MaxAgeDaysTools, Refresh bool}` — the config describes a cache refresh policy but the actual in-flight cache is DNS/ASN/geo data fetched per-scan.
- Per-scan cache: `workspaces/<target>/inputs/*.txt` staging files, `artefacts/*.jsonl` — these are the "cache" for a target's previously-run results.
- Resolver cache: `cfg.Paths.Resolvers` (static file on disk, updated by gen-resolvers).
- `cfg.Cache.Refresh bool` — when true, forces re-fetch of cached resources.

**`refresh-cache` implementation for Phase 9:**
1. Requires `--target` (to know which workspace to refresh).
2. Sets `cfg.Cache.Refresh = true` and `cfg.Advanced.Diff = true`.
3. Deletes or truncates per-target staging files in `workspaces/<target>/inputs/` that represent cached DNS/geo data (the specific files that geo_info, asnmap, etc. produce).
4. Optionally re-fetches the resolver list if stale.
5. Does NOT wipe the `findings.jsonl` or `subdomains.jsonl` — those are results, not caches.

The exact cache entries to invalidate (Claude's discretion): files matching `inputs/geo.*.txt`, `inputs/asn*.jsonl`, `inputs/resolvers*.txt` in the workspace, plus `cfg.Paths.Resolvers` if older than `cfg.Cache.MaxAgeDaysResolvers`.

### quick-rescan (MODE-06, D-06)

**Store baseline today** (verified `internal/store/sqlc/scan_observation.sql.go`):
- `DiffBetweenScans` query exists: `SELECT asset_kind, asset_id FROM scan_observation WHERE target_id=? AND scan_id=? EXCEPT ...` — the diff infrastructure is present in the DB schema.
- `scans` table has `mode` column (`CreateScanParams.Mode`) — the composite can record the scan mode.

**Phase 9 quick-rescan (thin):**
1. Sets `cfg.Advanced.QuickRescan = true` and `cfg.Advanced.Diff = true` (forces checkpoint bypass).
2. Reads the latest completed scan row from `scans` table for the target (Phase 10 will diff against it; Phase 9 only sets the baseline).
3. Runs the `recon` pipeline (same as `recon` subcommand) with checkpoint bypass.
4. The diff between the new scan and the previous one is computable by Phase 10 via `DiffBetweenScans(ctx, targetID, newScanID, targetID, previousScanID)`.

**Phase 10 boundary:** Phase 9 does NOT call `DiffBetweenScans` or build a diff report. It ensures the new scan is stored in `scan_observation` so Phase 10 can compute the diff. The `quick-rescan` subcommand in Phase 9 is essentially `recon --force` with a stored scan record.

---

## Q6: Batch (--list) Implementation

**D-07 constraints:** sequential, isolated workspace per target, continue-on-error, aggregate non-zero exit.

**Implementation shape:**

```go
// cmd/reconftw/batch.go
func runBatch(cmd *cobra.Command, targets []string,
    subcommandFn func(ctx context.Context, target string) error,
) error {
    type result struct {
        target string
        err    error
    }
    var results []result
    for _, tgt := range targets {
        err := subcommandFn(cmd.Context(), tgt)
        results = append(results, result{tgt, err})
        // continue-on-error: log failure, do not abort loop
        if err != nil {
            slog.Warn("batch_target_failed", "target", tgt, "err", err)
        }
    }
    // Print per-target summary table
    printBatchSummary(os.Stderr, results)
    // Aggregate non-zero exit
    for _, r := range results {
        if r.err != nil {
            return fmt.Errorf("batch: %d target(s) failed", countFailed(results))
        }
    }
    return nil
}
```

**Per-target isolation:** Each `subcommandFn` call is a full `RunCompositeAsync` (or `RunSubsAsync` etc.) with its own `BootReconApp` call. `output.WorkspaceInit` creates `workspaces/<target>-<timestamp>/` per target. Schedulers are per-invocation. No shared state between targets.

**`--list` flag parsing:** `--list FILE` is already wired as a persistent global flag (`root.go:89`). The composite `RunE` checks if `--list` is set; if so, reads the file line by line and calls `runBatch`. If `--target` is also set, prefer `--target` (single-target mode). If both absent, return error.

**Exit code aggregation:** The batch function returns a non-nil error (causing `main()` to exit 1) if ANY target failed. The batch summary table printed to stderr before exit shows per-target status. The exact table format is Claude's discretion.

---

## Q7: --dry-run Composition and D-10 (XCUT-07 Fold)

### Composite dry-run composition

Each pipeline already has a `printXDryRun` function:
- `printDryRun` (subs, `stub_subcommands.go:311`)
- `printWebDryRun` (web, `stub_subcommands.go:496`)
- `printVulnsDryRun` (vulns, `stub_subcommands.go:752`)
- `printOSINTDryRun` (osint, `stub_subcommands.go:1011`)

A composite dry-run calls them in pipeline order with a header for each:

```
[dry-run] recon pipeline:
--- SUBS ---
  Stage 1 (passive): 6 task(s)
    - subdomains.passive.subfinder: ...
  ...
--- WEB ---
  Stage 1 (probe): 1 task(s)
  ...
--- OSINT ---
  Stage (github-repos): 1 task(s)
  ...
```

The `stageSpec` / `osintStageSpec` types in `stub_subcommands.go` are local to the function. To reuse them for composite dry-run, either: (a) extract them to package-level types, or (b) call the existing `printXDryRun` functions directly from the composite dry-run handler. Option (b) is simpler and requires no refactor.

### D-10: Unconditional redacting handler

**The bug (CONTEXT.md folded todo):** `BootReconApp` calls `appctx.Boot(ctx, nil, cfg, ...)` with `logger=nil` (`handlers/common.go:149`). When `logger` is nil, `appctx.Boot` falls back to `slog.Default()`. On non-TTY (piped/`--quiet`/`--dry-run`) paths, `slog.Default()` may be the plain bootstrap logger (set in `run()` step 3 before config is fully loaded) which uses a bare `slog.JSONHandler` NOT wrapped in `RedactingHandler`.

**Verified path:** In `main.go:97-98`, the bootstrap logger IS wrapped: `bootstrapLogger := log.New(&log.Config{}, redactor)` — `log.New` wraps the inner handler with `NewRedactingHandler`. So `slog.Default()` after step 3 IS a redacting logger.

**The real gap:** In the `runXCmd` afterBoot closures, when `liveUI` is false (non-TTY / quiet mode), the code skips the `run.log` routing block entirely. No new `slog.SetDefault` is called. The default logger from STEP 3 (which IS redacting) remains in place. **However**, the `run.log` routing block (when `liveUI=true`) creates a NEW `log.Redactor{}` and calls `registerSecrets(cfg, rdct)` to register config secrets on the file logger — but does NOT re-register on the default stderr logger. If a secret value escapes through a code path that uses `slog.Default()` on the stderr path, the bootstrap logger's redactor (created in STEP 2) already has the secrets registered (via STEP 7 `registerSecrets(cfg, redactor)`).

**The actual gap for D-10:** On `--dry-run`, `BootReconApp` returns early without executing stages. The `printXDryRun` helpers call `cmd.OutOrStdout()` directly (not via slog), formatting tool invocation strings. If tool args contain secrets (e.g., `--header "Authorization: Bearer <token>"`), the `Fprintf` output is NOT redacted because `fmt.Fprintf` bypasses the slog handler.

**D-10 fix:** The `printXDryRun` helpers must pass their strings through the redactor before printing. The redactor is accessible via the `cfg`-level secret registration. Add `redact func(string) string` parameter to the dry-run printers, or make the composite dry-run handler apply `redactor.Redact(line)` to each tool invocation string before printing.

**Concretely:** In `commonAfterBoot`, after `registerSecrets(cfg, rdct)`, the dry-run case should use the same `rdct` to scrub any printed strings. The `dryRunCapture` struct can carry the `rdct` reference.

---

## Common Pitfalls

### Pitfall 1: Axiom fleet launched per-pipeline in composite

**What goes wrong:** Current `runSubsCmd`, `runWebCmd`, etc. each call `axiomBE.Launch(ctx)` inside their `afterBoot`. If the composite naively calls all four `RunXAsync` functions, the axiom fleet is launched 4 times and shut down 4 times (or each shutdown kills the fleet mid-composite).

**Why it happens:** Phase 4-7 each owned the full lifecycle.

**How to avoid:** The composite's single `commonAfterBoot` call handles Launch once. The extracted `RunStagesOnBootedApp` helper does NOT call Launch/Shutdown. The composite defers one `axiomBE.Shutdown` at the composite-RunE scope.

**Warning signs:** Axiom fleet missing for web/osint stages when `--axiom` is used with `recon`.

### Pitfall 2: Checkpoint closed multiple times

**What goes wrong:** Each `RunXAsync` has `defer app.Checkpoint.Close()`. In a composite, if the stage groups are run by calling individual `RunXAsync` functions (incorrect approach), each deferred Close fires. Second Close may panic or error.

**How to avoid:** The composite owns exactly ONE `defer app.Checkpoint.Close()`. The extracted stage runners do NOT call Close.

**Warning signs:** `sql: database is closed` or `checkpoint: use after close` errors during the web stage of a `recon` run.

### Pitfall 3: Zero-value scheduler in dry-run

**What goes wrong:** `scheduler.NewScheduler(0, 0, nil, nil)` in `runXCmd` normalizes `maxJobs=0` to `4` (`scheduler.go:122`). But `commonAfterBoot` then sets `sched.MaxConcurrent = cfg.Concurrency.MaxJobs`. If this is called in the dry-run path before AfterBoot captures the task list, the scheduler is inconsistent.

**How to avoid:** The dry-run path returns early from `commonAfterBoot` after capturing the task list. The scheduler limits only matter for live execution.

### Pitfall 4: `translateV1Args` breaks subcommand-first invocation

**What goes wrong:** `reconftw recon --recon --target X` — `args[0]` is already `"recon"` (a subcommand), and `--recon` is also present. The translation inserts a second `"recon"` before `--recon`, producing `["recon", "recon", "--recon", "--target", "X"]` — cobra sees an unknown subcommand `"recon"` for the `recon` subcommand.

**How to avoid:** `translateV1Args` checks whether `args[0]` (after stripping leading flags) is already a known subcommand name. If so, skip the subcommand-insertion step but still translate `-d`/`-l`/`-v`.

### Pitfall 5: `applyZenProfile` after Boot

**What goes wrong:** The profile transform is applied to `cfg` after `BootReconApp` returns. The `app` has already been booted with the pre-transform `cfg`. Tasks read `app.Cfg` which is a pointer to the same `*Config`, so they would see the zen overrides — but `appctx.Boot` may have wired concurrency limits (MaxJobs, etc.) at boot time from the pre-transform values.

**How to avoid:** Use `RunOptions.ConfigTransform` so the transform is applied inside `BootReconApp` after `config.Load` and before `appctx.Boot`. Verified: the appctx Boot wires `sched.MaxConcurrent` from `cfg.Concurrency.MaxJobs` at boot time (`appctx.Boot` sets this). If zen lowers MaxJobs to 2, it must be done before Boot.

### Pitfall 6: osint gato kill-switch trips axiom for subs

**What goes wrong:** In `all` mode with `--axiom`, the pipeline is subs→web→osint→vulns. OSINT runs gato (`osint.github_actions` task). If gato fails (no `GH_TOKEN`), the axiom failover counter increments. If it hits `cfg.Axiom.FailoverThreshold` (default probably 3-5), axiom is disabled for ALL subsequent tasks. Since subs and web run BEFORE osint, they complete with axiom. Vulns after osint may lose axiom.

**How to avoid:** The current pipeline ordering (subs→web→osint→vulns) already minimizes the blast radius. In `recon` mode, vulns never runs. Document that gato failures may silently degrade `all` mode to local-only for vulns. Consider decrementing or resetting the axiom kill-switch counter between pipeline groups (Claude's discretion).

---

## Code Examples

### Example 1: RunOptions with ConfigTransform

```go
// Source: analysis of handlers/common.go:100-159 + D-02/D-03 decisions

// In cmd/reconftw/composite_subcommands.go:
opts := handlers.RunOptions{
    Target:       targetFlag,
    DryRun:       dryRun,
    ConfigPath:   efs.configPath,
    SecretsPath:  efs.secretsPath,
    AxiomEnabled: axiomEnabled,
    Scheduler:    sched,
    AfterBoot:    func(boot handlers.AppBoot) { commonAfterBoot(...) },
    ConfigTransform: applyZenProfile, // nil for non-zen subcommands
}
```

### Example 2: applyDeepProfile skeleton

```go
// Source: config.go AdvancedConfig fields + reconftw.cfg DEEP semantics

// internal/core/config/profiles.go
func applyDeepProfile(cfg *Config) {
    cfg.Advanced.Deep = true
    // DeepLimit and DeepLimit2 stay at defaults (500, 1500) — tasks use them
    // as thresholds to decide whether to skip (if count > DeepLimit && !Deep)
    cfg.Subdomains.Recursive.BruteEnabled = true
    cfg.Subdomains.Recursive.PassiveEnabled = true
    cfg.Subdomains.Permut.WordlistMode = "full"
    cfg.Web.Fuzz.RecursionDepth = 4
    cfg.Web.Portscan.Naabu.Ports = "--top-ports 10000"
    // VulnSpray.DeepOnly=true already default; setting Advanced.Deep=true enables it
}

func applyZenProfile(cfg *Config) {
    cfg.Advanced.PerfProfile = "low"
    cfg.Concurrency.MaxJobs = 2
    cfg.Web.Probe.RateLimit = 30
    cfg.Web.Nuclei.RateLimit = 15
    cfg.Web.Fuzz.RateLimit = 10
    cfg.Web.Fuzz.Threads = 5
    cfg.Subdomains.Brute.Enabled = false
    cfg.Subdomains.Permut.Enabled = false
    cfg.Web.Portscan.ActiveEnabled = false
    cfg.Vulns.Enabled = false
    cfg.Output.Verbosity = 0
    cfg.OSINT.GitHub.ActionsAudit.Enabled = false // gato is active/credentialed
}
```

### Example 3: translateV1Args skeleton

```go
// Source: root.go addV1DeprecatedAliases + main.go parseEarlyFlags pattern

// cmd/reconftw/alias.go (new file)
var v1SubcommandFlags = map[string]string{
    "--recon": "recon", "-r": "recon",
    "--all": "all", "-a": "all",
    "--passive": "passive", "-p": "passive",
    "--subdomains": "subs", "-s": "subs",
    "--web": "web", "-w": "web",
    "--vulns": "vulns",
    "--osint": "osint", "-n": "osint",
    "--zen": "zen", "-z": "zen",
    "--deep": "deep", "-y": "deep",
}

func translateV1Args(args []string) []string {
    if len(args) == 0 { return args }
    // If first non-flag token is already a v2 subcommand, skip mode injection.
    knownSubcmds := map[string]bool{
        "recon":true,"all":true,"passive":true,"subs":true,"web":true,
        "vulns":true,"osint":true,"zen":true,"deep":true,
        "monitor":true,"report":true,"mcp":true,"migrate":true,"install":true,
        "health-check":true,"version":true,
    }
    // ... scan and rewrite
}
```

### Example 4: Batch loop

```go
// Source: D-07 decision + output.WorkspaceInit pattern

func runBatch(ctx context.Context, listFile string,
    run func(ctx context.Context, target string) error,
) (int, error) {
    targets, err := readTargetList(listFile)
    if err != nil { return 0, err }
    failed := 0
    for _, t := range targets {
        if err := run(ctx, t); err != nil {
            slog.Warn("batch_target_failed", "target", t, "err", err)
            failed++
        }
    }
    return failed, nil
}
```

---

## Runtime State Inventory

Not applicable — Phase 9 is a code-and-config phase (no rename/refactor/migration). Omitting per spec.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `dnsvalidator` (Python tool) | gen-resolvers (D-04) | Unknown — not checked | — | HTTP download of pre-validated resolver list from `cfg.Paths.ResolversDownload.URL` |
| `anew` (Go binary) | gen-resolvers merge step | Likely installed (core tool) | — | Use `sort -u` or Go dedup |
| SQLite / `internal/store` | quick-rescan scan record | Available (store.db exists in working tree) | sqlc v1.31.1 generated | — |

**gen-resolvers fallback:** if `dnsvalidator` is not on PATH, fall back to downloading from `cfg.Paths.ResolversDownload.URL` directly. Log a warning. This mirrors the v1 fallback in `modules/axiom.sh:42-43`.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go testing (`go test ./...`) + table-driven |
| Config file | none — standard Go test tooling |
| Quick run command | `go test ./cmd/reconftw/... -run TestComposite -count=1` |
| Full suite command | `go test ./... -race -count=1` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| MODE-01 | `recon` pipeline = subs(passive+resolve+discovery) → web → osint | unit (MockBackend) | `go test ./cmd/reconftw/... -run TestReconPipelineOrder` | ❌ Wave 0 |
| MODE-02 | `all` pipeline includes vulns after osint | unit | `go test ./cmd/reconftw/... -run TestAllPipelineIncludesVulns` | ❌ Wave 0 |
| MODE-03 | `passive` hard-blocks active tools | unit | `go test ./cmd/reconftw/... -run TestPassiveModeBlocksActiveTool` | ❌ Wave 0 |
| MODE-04 | zen lowers rate limits + disables active sources | unit | `go test ./internal/core/config/... -run TestApplyZenProfile` | ❌ Wave 0 |
| MODE-05 | deep sets Advanced.Deep + enables brute/permut | unit | `go test ./internal/core/config/... -run TestApplyDeepProfile` | ❌ Wave 0 |
| MODE-06 | quick-rescan sets Diff=true + runs recon | unit | `go test ./cmd/reconftw/... -run TestQuickRescanForcesDiff` | ❌ Wave 0 |
| MODE-07 | refresh-cache invalidates per-target cache files | unit | `go test ./cmd/reconftw/... -run TestRefreshCache` | ❌ Wave 0 |
| MODE-08 | gen-resolvers calls dnsvalidator or falls back to download | unit | `go test ./internal/core/resolvers/... -run TestGenResolvers` | ❌ Wave 0 |
| MODE-09 | V1 alias dispatch rewrites args before cobra | unit | `go test ./cmd/reconftw/... -run TestTranslateV1Args` | ❌ Wave 0 |
| MODE-09 (warn) | Deprecation warning emitted exactly once | existing | `go test ./cmd/reconftw/... -run TestDeprecationWarning` | ✅ root_test.go |
| MODE-10 | `--list` batch iterates targets sequentially, continues on error | unit | `go test ./cmd/reconftw/... -run TestBatchContinuesOnError` | ❌ Wave 0 |
| MODE-11 | `--config FILE` threads through all composite subcommands | existing | `go test ./cmd/reconftw/... -run TestParseEarlyFlags` | ✅ main_test.go (partial) |
| MODE-12 | composite `--dry-run` prints all pipeline stages; no tool exec | unit | `go test ./cmd/reconftw/... -run TestCompositeDryRun` | ❌ Wave 0 |
| D-10 | registered secrets scrubbed on dry-run/quiet paths | unit | `go test ./cmd/reconftw/... -run TestDryRunRedactsSecrets` | ❌ Wave 0 |
| composite ordering | stage order guards (mirror osint_stage_order_test.go pattern) | unit | `go test ./cmd/reconftw/... -run TestCompositeStageOrderHonorsDependsOn` | ❌ Wave 0 |
| dag acyclic | full task DAG builds without cycle | existing | `go test ./cmd/reconftw/... -run TestRegisteredTaskDAGBuilds` | ✅ dag_build_test.go |

### Sampling Rate
- **Per task commit:** `go test ./cmd/reconftw/... -run TestRegisteredTaskDAGBuilds -count=1` (< 5s)
- **Per wave merge:** `go test ./... -race -count=1`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `cmd/reconftw/composite_test.go` — covers MODE-01, MODE-02, MODE-03, MODE-12, D-10
- [ ] `cmd/reconftw/stateful_test.go` — covers MODE-06, MODE-07, MODE-08
- [ ] `cmd/reconftw/batch_test.go` — covers MODE-10 (can be in composite_test.go instead)
- [ ] `internal/core/config/profiles_test.go` — covers MODE-04, MODE-05
- [ ] `internal/core/resolvers/gen_test.go` — covers MODE-08 (with mock exec)
- [ ] `cmd/reconftw/alias_test.go` (or in main_test.go) — covers MODE-09 translation

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes — passive mode hard-guard | `ErrPassiveViolation` sentinel in LocalBackend; scope enforcement |
| V5 Input Validation | yes — `--list FILE` target list | `validate_domain` equivalent for each line read from list file |
| V6 Cryptography | no | — |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Path traversal via `--list FILE` path | Tampering | `validate_file_readable` check on list path |
| Command injection via v1 alias translation | Tampering | `translateV1Args` must not shell-eval any translated value; pure string substitution only |
| Secret leak in dry-run output | Information Disclosure | D-10: pass all tool arg strings through `redactor.Redact()` before `fmt.Fprintf` in `printXDryRun` helpers |
| Passive-mode bypass via misclassified task | Spoofing | Backend hard-guard (`ErrPassiveViolation`) as defense-in-depth beyond composition guard |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Zen profile should disable `cfg.OSINT.GitHub.ActionsAudit.Enabled` (gato is active) | Q2 zen field list | Gato runs in zen mode making credentialed GitHub API calls — operator may not want this |
| A2 | Zen sets `cfg.Concurrency.MaxJobs = 2` | Q2 zen field list | Actual stealth may require a different concurrency cap |
| A3 | Deep sets `cfg.Web.Fuzz.RecursionDepth = 4` | Q2 deep field list | V1 had `FUZZ_RECURSION_DEPTH=2` as the DEEP value; exact target depth needs operator confirmation |
| A4 | `refresh-cache` should NOT wipe findings/subdomains artefacts | Q5 | If operator expects a clean re-scan, they may want artefacts wiped too |
| A5 | gen-resolvers output path = `cfg.Paths.Resolvers` | Q5 | Confirmed from config.go PathsConfig field; actual default value at runtime may be empty (needs fallback to `~/.config/reconftw/resolvers.txt`) |
| A6 | Deep profile should NOT imply zen profile by default | Q2 | deep+zen can stack explicitly; deep alone should not enforce stealth |

**If this table is empty:** n/a — assumptions are listed above.

---

## Open Questions (RESOLVED)

> All four questions below carry inline recommendations actioned by the Phase 9 plans:
> Q1 zen rate-limit values are set in plan 09-01; Q2 ConfigTransform is CLI-only (nil for MCP);
> Q3 composite/batch summary format is Claude's discretion per CONTEXT.md; Q4 `-d`→`--target`
> rewrite is handled in plan 09-03's translateV1Args. No blocking unknowns remain.

1. **`applyZenProfile` exact rate limit values**
   - What we know: v1 `HTTPX_RATELIMIT=150`, no explicit zen override in v1 config
   - What's unclear: v1's zen mode did not explicitly lower rate limits; it relied on `PerfProfile=low`; whether `PerfProfile=low` auto-scales rates or is purely a label
   - Recommendation: Check if `PerfProfile` is consumed by any task to scale rates. If not, the explicit rate limit overrides in `applyZenProfile` are the only mechanism.

2. **`ConfigTransform` addition to `RunOptions`**
   - What we know: `RunOptions` is defined in `internal/mcp/handlers/common.go:58`; adding a field is additive (nil is backward-compatible)
   - What's unclear: whether the MCP layer (`internal/mcp/handlers/`) should also accept config transforms (MCP callers currently pass nil for AfterBoot)
   - Recommendation: Add the field to `RunOptions`; MCP callers leave it nil; document that zen/deep profiles are CLI-surface-only and not exposed via MCP for Phase 9.

3. **Composite summary format**
   - What we know: four `printXSummary` functions exist with a shared pattern
   - What's unclear: whether the composite summary should be a single merged table or four sequential tables
   - Recommendation: Single merged table grouped by pipeline (subs/web/osint/vulns artefacts) is cleaner; Claude's discretion per CONTEXT.md.

4. **`translateV1Args` scope for `-d` collision**
   - What we know: `-d` is `target-deprecated` in cobra, NOT the same as `--target`. Cobra does not auto-populate `--target` from `-d X` today.
   - What's unclear: the exact rewrite needed — does `translateV1Args` need to replace `-d X` with `--target X` in the args slice, or can it populate `efs.target` and have `BootReconApp` use that?
   - Recommendation: Replace `-d X` with `--target X` in the translated args slice so cobra sees and validates the standard `--target` flag. This is simpler than adding a second code path.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Stub exit 64 for recon/all/passive/zen/deep | Real orchestration (Phase 9) | Phase 9 | These subcommands become functional |
| Per-pipeline afterBoot duplication | `commonAfterBoot` extracted helper | Phase 9 | ~320 lines of duplication eliminated |
| Pre-cobra flag extraction only for --config/--secrets/--target | Extended to v1 alias translation | Phase 9 | `reconftw --recon -d X` becomes equivalent to `reconftw recon --target X` |

**Deprecated / outdated in Phase 9:**
- `phasePointers` entries for `recon`, `all`, `passive`, `zen`, `deep` in `stub_subcommands.go:50-62` — replaced with real implementations, entries removed
- `newStubCmd` usage for the five composite subcommands — replaced with real RunE constructors

---

## Sources

### Primary (HIGH confidence — verified against actual source files)

- `cmd/reconftw/stub_subcommands.go` — complete afterBoot duplication analysis (lines 159-237, 404-466, 666-728, 862-924); stage specs; dry-run printers; printSummary helpers
- `cmd/reconftw/root.go` — complete v1 alias inventory (lines 123-177); parseEarlyFlags location (main.go:194)
- `cmd/reconftw/main.go` — 10-STEP init order; redactor bootstrap; parseEarlyFlags body
- `internal/mcp/handlers/common.go` — BootReconApp body; RunOptions fields; AppBoot struct
- `internal/mcp/handlers/subs.go` — RunSubsAsync with stage loop and checkpoint lifecycle
- `internal/mcp/handlers/osint.go` — RunOSINTAsync; osintHandlerStages()
- `internal/mcp/handlers/web.go` — RunWebAsync stage loop (lines 1-80)
- `internal/mcp/handlers/vulns.go` — RunVulnsAsync stage loop (lines 1-100)
- `internal/core/config/config.go` — complete AdvancedConfig, ConcurrencyConfig, SubdomainsConfig, WebConfig, VulnsConfig field inventory
- `internal/core/config/defaults.go` — exact default values: Deep=false, DeepLimit=500, DeepLimit2=1500, PerfProfile="balanced", MaxJobs=4, HTTPX RateLimit=150, Nuclei RateLimit=150
- `internal/core/config/loader.go` — 8-source load chain; CLIOverrides layer 8
- `internal/core/scheduler/scheduler.go` — RunStage, Limiter, per-scan Scheduler contract
- `internal/core/log/logger.go` — log.New wraps inner handler with RedactingHandler unconditionally
- `internal/store/sqlc/scan_observation.sql.go` — DiffBetweenScans query; scan_observation schema
- `internal/store/sqlc/scans.sql.go` — CreateScan; Mode column
- `cmd/reconftw/osint_stage_order_test.go` — osintStageIndex test pattern; GAP-01 guard
- `cmd/reconftw/dag_build_test.go` — TestRegisteredTaskDAGBuilds; TestWebURLDedupOrderingInFullDAG
- `cmd/reconftw/root_test.go` — TestDeprecationWarning tests; TestEveryStubReturnsExit64
- `modules/axiom.sh:16-65` — v1 dnsvalidator invocation; source URLs; fallback download
- `modules/modes.sh:1418-1450` — v1 zen_menu() function body; what modules it runs
- `reconftw.cfg:26-27,340-342,377-381` — v1 resolver URLs; DEEP defaults; rate limits

### Secondary (MEDIUM confidence)

- `reconftw.cfg` v1 stealth/zen semantics inferred from `DEEP`, `HTTPX_RATELIMIT`, `NUCLEI_RATELIMIT` values and absence of explicit zen rate-limit overrides

### Tertiary (LOW confidence — needs validation)

- Exact rate limit values for `applyZenProfile` (A2 in assumptions log) — derived from v1 conventions but no explicit zen rate config found

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all existing packages verified in source
- Architecture (stage seam): HIGH — complete code read of all four runXCmd bodies confirms exact duplication
- zen/deep field lists: MEDIUM — core fields (Advanced.Deep, DeepLimit, PerfProfile) are HIGH; exact rate limits for zen are MEDIUM (no v1 explicit zen-rate override found)
- Passive hard-guard: HIGH — mechanism and test approach clear from existing patterns
- v1 alias dispatch: HIGH — root.go addV1DeprecatedAliases complete; gap in dispatch is documented
- Stateful modes: HIGH (gen-resolvers v1 source confirmed); MEDIUM (refresh-cache cache inventory)
- Pitfalls: HIGH — all grounded in specific code locations

**Research date:** 2026-06-11
**Valid until:** 2026-07-11 (stable codebase, no fast-moving dependencies)
