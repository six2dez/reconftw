# Phase 9: Composite Modes — Pattern Map

**Mapped:** 2026-06-11
**Files analyzed:** 12 new/modified files
**Analogs found:** 11 / 12

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `cmd/reconftw/composite_subcommands.go` | controller | request-response (sequential pipeline) | `cmd/reconftw/stub_subcommands.go` (`runSubsCmd`/`runWebCmd`/`runOSINTCmd`/`runVulnsCmd`) | exact |
| `cmd/reconftw/composite_test.go` | test | request-response | `cmd/reconftw/osint_stage_order_test.go`, `cmd/reconftw/root_test.go` | exact |
| `cmd/reconftw/batch.go` | utility | batch | `cmd/reconftw/stub_subcommands.go` (single-target runXCmd loop) | role-match |
| `cmd/reconftw/stateful_subcommands.go` | controller | request-response | `cmd/reconftw/stub_subcommands.go` (`newSubsCmd` shape) | role-match |
| `cmd/reconftw/stateful_test.go` | test | request-response | `cmd/reconftw/stub_test.go` | role-match |
| `cmd/reconftw/alias.go` | utility | transform | `cmd/reconftw/main.go` (`parseEarlyFlags`) | role-match |
| `internal/mcp/handlers/composite.go` | service | sequential pipeline | `internal/mcp/handlers/subs.go` (`RunSubsAsync`) | exact |
| `internal/core/config/profiles.go` | utility | transform | `internal/core/config/loader.go` + `defaults.go` | role-match |
| `internal/core/config/profiles_test.go` | test | transform | `internal/core/config/coverage_test.go` | role-match |
| `internal/core/resolvers/gen.go` | service | batch / I-O | `internal/core/backend/local.go` (`Exec`) | partial-match |
| `internal/core/resolvers/gen_test.go` | test | batch / I-O | `cmd/reconftw/dag_build_test.go` | partial-match |
| `internal/mcp/handlers/common.go` (modified) | service | request-response | itself (additive: `ConfigTransform` field to `RunOptions`) | exact |

---

## Pattern Assignments

### `cmd/reconftw/composite_subcommands.go` (controller, sequential pipeline)

**Analogs:** `cmd/reconftw/stub_subcommands.go` lines 129-258 (`runSubsCmd`) + lines 379-487 (`runWebCmd`) + lines 641-944 (`runOSINTCmd`)

**Imports pattern** (copy from `stub_subcommands.go` lines 19-37):
```go
import (
    "bufio"
    "context"
    "fmt"
    "log/slog"
    "os"
    "path/filepath"
    "time"

    "github.com/spf13/cobra"

    "github.com/six2dez/reconftw/internal/core/backend"
    "github.com/six2dez/reconftw/internal/core/config"
    "github.com/six2dez/reconftw/internal/core/log"
    "github.com/six2dez/reconftw/internal/core/scheduler"
    "github.com/six2dez/reconftw/internal/core/task"
    "github.com/six2dez/reconftw/internal/core/ui"
    "github.com/six2dez/reconftw/internal/mcp/handlers"
)
```

**Subcommand constructor pattern** (copy from `stub_subcommands.go` lines 109-127; used for `newReconCmd`/`newAllCmd`/etc.):
```go
func newSubsCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "subs",
        Short: "Run subdomain enumeration (passive + active + permut + takeover)",
        Long: `...`,
        RunE: func(cmd *cobra.Command, args []string) error {
            return runSubsCmd(cmd)
        },
    }
    cmd.Flags().String("target", "", "Target domain")
    cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
    return cmd
}
```

**Target resolution pattern** (copy from `stub_subcommands.go` lines 132-148 — applies to ALL composite RunE bodies):
```go
func runSubsCmd(cmd *cobra.Command) error {
    ctx := cmd.Context()
    targetFlag, _ := cmd.Flags().GetString("target")
    dryRun, _ := cmd.Flags().GetBool("dry-run")

    if targetFlag == "" {
        if pf := cmd.InheritedFlags().Lookup("target"); pf != nil {
            targetFlag = pf.Value.String()
        }
    }
    if targetFlag == "" {
        return fmt.Errorf("--target is required for subs subcommand")
    }

    axiomEnabled, _ := cmd.Flags().GetBool("axiom")
    efs := parseEarlyFlags(os.Args[1:])
    sched := scheduler.NewScheduler(0, 0, nil, nil)
    // ...
```

**Core afterBoot pattern** — this is the IDENTICAL block in all four `runXCmd` functions; composite extracts it into `commonAfterBoot`. Source: `stub_subcommands.go` lines 159-237 (subs), 404-466 (web), 666-728 (vulns), 862-924 (osint). Exact body from subs afterBoot (lines 159-237):
```go
afterBoot := func(boot handlers.AppBoot) {
    app := boot.App
    workdir := boot.WorkDir
    cfg := boot.Cfg
    summaryWorkdir = workdir
    summaryVerbosity = ui.Verbosity(cfg.Output.Verbosity)

    sched.MaxConcurrent = cfg.Concurrency.MaxJobs
    sched.HeartbeatSeconds = cfg.Concurrency.HeartbeatSeconds

    if dryRun {
        cfg.Advanced.Diff = false
        if ts, err := task.Default.Build(); err == nil {
            dryRunTaskList = ts
            dryRunCfg = cfg
        }
        return
    }

    liveUI := summaryVerbosity != ui.VerbosityQuiet && ui.IsTTY(os.Stderr)
    if liveUI {
        p := filepath.Join(workdir, "run.log")
        if f, ferr := os.Create(p); ferr == nil { //nolint:gosec
            summaryRunLog = p
            rdct := &log.Redactor{}
            registerSecrets(cfg, rdct)
            lc := cfg.AsLoggerConfig()
            lc.Output = f
            subLogger := log.New(lc, rdct)
            slog.SetDefault(subLogger)
            fmt.Fprintf(os.Stderr, "  logs → %s\n", summaryRunLog)
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
                app.Log.Warn("subs: axiom launch failed — continuing locally", "err", launchErr)
            }
        } else {
            defer func() { _ = axiomBE.Shutdown(context.Background()) }() //nolint:staticcheck
        }
    }

    progress := ui.NewStageProgress(app.UI.W, app.UI.NoColor, app.UI.Verbosity)
    sched.RunTask = func(rctx context.Context, t task.Task) (task.Result, error) {
        progress.TaskStart(t.Name())
        started := time.Now()
        result, runErr := t.Run(rctx, app)
        dur := result.Duration
        if dur <= 0 {
            dur = time.Since(started)
        }
        progress.TaskDone(t.Name(), badgeForStatus(result.Status), dur)
        return result, runErr
    }
}
```

**COMPOSITE DIFFERENCE vs single-pipeline:** For the composite, axiom `Launch` must be called ONCE before all stage groups and `Shutdown` deferred once after all stage groups. The extracted `commonAfterBoot` omits the `defer axiomBE.Shutdown` — the composite RunE owns that defer. The single-pipeline `runXCmd` functions retain their own `defer Shutdown` in `afterBoot` (no change needed to them).

**RunOptions wiring pattern** (`stub_subcommands.go` lines 239-248; composite adds `ConfigTransform`):
```go
if err := handlers.RunSubsAsync(ctx, handlers.RunOptions{
    Target:       targetFlag,
    DryRun:       dryRun,
    ConfigPath:   efs.configPath,
    SecretsPath:  efs.secretsPath,
    AxiomEnabled: axiomEnabled,
    Scheduler:    sched,
    AfterBoot:    afterBoot,
    // Phase 9 addition for zen/deep:
    // ConfigTransform: applyZenProfile,
}); err != nil {
    return fmt.Errorf("subs: %w", err)
}
```

**Post-run dry-run gate + summary pattern** (`stub_subcommands.go` lines 252-257):
```go
if dryRun && dryRunTaskList != nil {
    return printDryRun(cmd, dryRunTaskList, dryRunCfg)
}
printSubsSummary(os.Stderr, summaryWorkdir, summaryRunLog, summaryVerbosity)
return nil
```

**Dry-run printer pattern** (`stub_subcommands.go` lines 311-335 `printDryRun`; mirrors `printWebDryRun` lines 489-561, `printVulnsDryRun` lines 752-773, `printOSINTDryRun` lines 1011-1022):
```go
func printDryRun(cmd *cobra.Command, allTasks []task.Task, cfg *config.Config) error {
    type stageSpec struct {
        name     string
        module   string
        prefixes []string
    }
    stages := []stageSpec{
        {"passive", "subdomains.passive", []string{"subdomains.passive."}},
        // ...
    }
    fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] subs pipeline stages:")
    for i, stage := range stages {
        filtered := filterByModuleAndEnabled(allTasks, "subdomains", cfg, stage.prefixes)
        fmt.Fprintf(cmd.OutOrStdout(), "  Stage %d (%s): %d task(s)\n", i+1, stage.name, len(filtered))
        for _, t := range filtered {
            fmt.Fprintf(cmd.OutOrStdout(), "    - %s: %s\n", t.Name(), t.Description())
        }
    }
    return nil
}
```

**Composite dry-run** calls the per-pipeline printers in pipeline order with a header:
```go
// Composite dry-run: call per-pipeline printers in order, no new types needed.
fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] recon pipeline:")
fmt.Fprintln(cmd.OutOrStdout(), "--- SUBS ---")
_ = printDryRun(cmd, allTasks, dryRunCfg)
fmt.Fprintln(cmd.OutOrStdout(), "--- WEB ---")
_ = printWebDryRun(cmd, allTasks, dryRunCfg)
fmt.Fprintln(cmd.OutOrStdout(), "--- OSINT ---")
_ = printOSINTDryRun(cmd, allTasks, dryRunCfg)
```

**Summary pattern** (`stub_subcommands.go` lines 283-308 `printSubsSummary`; same shape for printWebSummary/printVulnsSummary):
```go
func printSubsSummary(w *os.File, workdir, runLogPath string, verbosity ui.Verbosity) {
    if verbosity == ui.VerbosityQuiet {
        return
    }
    artefacts := []struct{ label, file string }{
        {"subdomains", "subdomains.jsonl"},
        // ...
    }
    fmt.Fprintf(w, "\n  ── results ──────────────────────────────\n")
    for _, a := range artefacts {
        p := filepath.Join(workdir, "artefacts", a.file)
        n := countFileLines(p)
        if n == 0 {
            continue
        }
        fmt.Fprintf(w, "  %-11s %6d   %s\n", a.label, n, p)
    }
    fmt.Fprintf(w, "  workspace   %s\n", workdir)
    if runLogPath != "" {
        fmt.Fprintf(w, "  logs        %s\n", runLogPath)
    }
    fmt.Fprintf(w, "  ─────────────────────────────────────────\n")
}
```

**phasePointers removal:** Remove entries for `"recon"`, `"all"`, `"passive"`, `"zen"`, `"deep"` from `phasePointers` map (`stub_subcommands.go` lines 50-62) and from `newStubCmd` callers (`newReconCmd`/`newAllCmd`/etc.) — these five become real implementations.

---

### `internal/mcp/handlers/composite.go` (service, sequential pipeline)

**Analogs:** `internal/mcp/handlers/subs.go` lines 26-130 (`RunSubsAsync`), `internal/mcp/handlers/osint.go` lines 64-127 (`RunOSINTAsync`)

**Package header + imports pattern** (copy from `internal/mcp/handlers/subs.go` lines 1-11):
```go
// Package handlers — composite pipeline handler.
package handlers

import (
    "context"
    "fmt"
    "path/filepath"

    "github.com/six2dez/reconftw/internal/core/task"
    "github.com/six2dez/reconftw/internal/modules/subdomains"
    // + osint, web, vulns
)
```

**RunXAsync structure to replicate** (`internal/mcp/handlers/subs.go` lines 26-130):
```go
func RunSubsAsync(ctx context.Context, opts RunOptions) error {
    if opts.Scheduler == nil {
        return fmt.Errorf("mcp/subs: RunOptions.Scheduler must not be nil")
    }

    boot, err := BootReconApp(ctx, opts)
    if err != nil {
        return fmt.Errorf("mcp/subs: %w", err)
    }
    app := boot.App
    workdir := boot.WorkDir
    cfg := boot.Cfg
    sched := opts.Scheduler

    // Checkpoint lifecycle owned here — NOT via shared scheduler.
    defer func() {
        if closer, ok := app.Checkpoint.(interface{ Close() error }); ok {
            _ = closer.Close()
        }
    }()

    if opts.AfterBoot != nil {
        opts.AfterBoot(boot)
    }
    if opts.DryRun {
        return nil
    }

    sched.Checkpoint = app.Checkpoint

    allTasks, err := task.Default.Build()
    if err != nil {
        return fmt.Errorf("mcp/subs: task DAG: %w", err)
    }
    // ... stage loop
```

**CRITICAL COMPOSITE DIFFERENCE:** `RunCompositeAsync` owns the single `defer app.Checkpoint.Close()`. The extracted `RunStagesOnBootedApp` (or inlined stage groups) must NOT call `Close()`. Stage groups called by the composite must not call `BootReconApp` — they receive the already-booted `AppBoot` + `sched`.

**Stage loop pattern** (copy from `internal/mcp/handlers/osint.go` lines 99-127):
```go
for _, stage := range osintHandlerStages() {
    stageSlice := task.FilterByModuleAndEnabled(allTasks, "osint", cfg, stage.prefixes)

    if opts.ProgressSink != nil {
        opts.ProgressSink <- StageEvent{Stage: stage.name, Done: false}
    }

    if runErr := sched.RunStage(ctx, "osint", stageSlice); runErr != nil {
        if app.Log != nil {
            app.Log.Warn("mcp/osint: stage failed (best_effort — continuing)",
                "stage", stage.name, "err", runErr)
        }
    }

    count := countJSONLLines(filepath.Join(workdir, "artefacts", "findings.jsonl"))
    if opts.ProgressSink != nil {
        opts.ProgressSink <- StageEvent{Stage: stage.name, Done: true, Count: count}
    }
}
```

**osintStageSpec / osintHandlerStages pattern** (copy from `internal/mcp/handlers/osint.go` lines 14-57):
```go
type osintStageSpec struct {
    name     string
    prefixes []string
}

func osintHandlerStages() []osintStageSpec {
    return []osintStageSpec{
        {
            name:     "github-repos",
            prefixes: []string{"osint.github_repos"},
        },
        {
            name: "osint",
            prefixes: []string{
                "osint.domain_info",
                "osint.ip_info",
                // ... (see osint.go lines 34-55 for full list)
            },
        },
    }
}
```

---

### `internal/mcp/handlers/common.go` (modified — additive `ConfigTransform` field)

**Analog:** itself — `internal/mcp/handlers/common.go` lines 58-78 (`RunOptions` struct)

**Current `RunOptions` struct** (lines 58-78):
```go
type RunOptions struct {
    Target       string
    DryRun       bool
    ExtraFile    string
    ConfigPath   string
    SecretsPath  string
    AxiomEnabled bool
    Scheduler    *scheduler.Scheduler
    ProgressSink chan<- StageEvent
    AfterBoot    func(boot AppBoot)
}
```

**Phase 9 addition** — add ONE new field (nil is backward-compatible with all existing callers):
```go
// ConfigTransform is applied after config.Load inside BootReconApp and before
// appctx.Boot. Used by zen/deep subcommands to override rate limits and feature
// flags. nil = no-op. Must be applied before Boot so appctx.Boot wires the
// correct concurrency limits (e.g., zen's MaxJobs=2).
ConfigTransform func(*config.Config)
```

**BootReconApp injection point** (`internal/mcp/handlers/common.go` lines 106-113 — add after config.Load):
```go
cfg, err := config.Load(config.LoadOptions{
    ExplicitConfigPath: opts.ConfigPath,
    SecretsPath:        opts.SecretsPath,
})
if err != nil {
    return AppBoot{}, fmt.Errorf("handlers: config load: %w", err)
}

// Apply mode transform (zen/deep) AFTER Load and BEFORE Boot.
// This ensures appctx.Boot wires the transformed concurrency limits.
if opts.ConfigTransform != nil {
    opts.ConfigTransform(cfg)
}
```

---

### `internal/core/config/profiles.go` (utility, transform)

**Analog:** `internal/core/config/loader.go` (`Load` function shape) + `defaults.go` (field names/defaults)

**File pattern** (copy from `internal/core/config/coverage_test.go` lines 1-14 for the package declaration style):
```go
// profiles.go — in-memory config transforms for zen and deep modes.
// Applied after config.Load, before BootReconApp (D-02/D-03).
// Pure functions; no side effects; stackable (deep+zen = apply both).
package config
```

**applyZenProfile exact fields** (verified against `internal/core/config/defaults.go` default values):
```go
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

**applyDeepProfile exact fields** (verified against `internal/core/config/defaults.go`):
```go
func applyDeepProfile(cfg *Config) {
    cfg.Advanced.Deep = true
    // DeepLimit (500) and DeepLimit2 (1500) stay at defaults — tasks gate on
    // cfg.Advanced.Deep to decide whether to honor the limit.
    cfg.Subdomains.Recursive.BruteEnabled = true
    cfg.Subdomains.Recursive.PassiveEnabled = true
    cfg.Subdomains.Permut.WordlistMode = "full"
    cfg.Web.Fuzz.RecursionDepth = 4
    cfg.Web.Portscan.Naabu.Ports = "--top-ports 10000"
    // VulnSpray.DeepOnly=true is already default; setting Advanced.Deep=true enables it.
}
```

**Usage pattern** (from `cmd/reconftw/composite_subcommands.go` RunE, called before `handlers.RunXAsync`):
```go
// Example: zen subcommand wiring
opts := handlers.RunOptions{
    Target:          targetFlag,
    DryRun:          dryRun,
    ConfigPath:      efs.configPath,
    SecretsPath:     efs.secretsPath,
    AxiomEnabled:    axiomEnabled,
    Scheduler:       sched,
    AfterBoot:       afterBoot,
    ConfigTransform: config.ApplyZenProfile, // exported from profiles.go
}
```

---

### `internal/core/config/profiles_test.go` (test, transform)

**Analog:** `internal/core/config/coverage_test.go` lines 1-60

**Pattern** (external test package, table-driven, copy structure from `coverage_test.go`):
```go
// profiles_test.go — unit tests for applyZenProfile / applyDeepProfile.
package config_test

import (
    "testing"
    "github.com/six2dez/reconftw/internal/core/config"
)

func TestApplyZenProfile(t *testing.T) {
    cfg := config.Defaults()
    config.ApplyZenProfile(cfg)
    // Assert each override field by field — same exhaustive style as coverage_test.go
    if cfg.Concurrency.MaxJobs != 2 {
        t.Errorf("zen MaxJobs = %d, want 2", cfg.Concurrency.MaxJobs)
    }
    if cfg.Vulns.Enabled {
        t.Error("zen must disable Vulns.Enabled")
    }
    // ...
}

func TestApplyDeepProfile(t *testing.T) {
    cfg := config.Defaults()
    config.ApplyDeepProfile(cfg)
    if !cfg.Advanced.Deep {
        t.Error("deep must set Advanced.Deep = true")
    }
    // ...
}

func TestZenDeepStackable(t *testing.T) {
    cfg := config.Defaults()
    config.ApplyDeepProfile(cfg)
    config.ApplyZenProfile(cfg) // zen over deep — zen wins (D-03)
    if cfg.Vulns.Enabled {
        t.Error("stacked zen+deep: zen should override deep for Vulns.Enabled")
    }
}
```

---

### `cmd/reconftw/alias.go` (utility, transform)

**Analog:** `cmd/reconftw/main.go` lines 187-217 (`parseEarlyFlags`)

**Pattern to copy from** (`main.go` lines 194-217):
```go
func parseEarlyFlags(args []string) earlyFlagSet {
    var efs earlyFlagSet
    for i := 0; i < len(args); i++ {
        a := args[i]
        switch {
        case a == "--config" && i+1 < len(args):
            efs.configPath = args[i+1]
            i++
        case strings.HasPrefix(a, "--config="):
            efs.configPath = strings.TrimPrefix(a, "--config=")
        // ...
        }
    }
    return efs
}
```

**`translateV1Args` — exact pattern** (new function, follows same linear scan pattern):
```go
// translateV1Args rewrites deprecated v1 flag forms into v2 subcommand
// invocations before cobra parses os.Args. Called from run() between
// parseEarlyFlags and rootCmd.ExecuteContext. Leaves the original flag
// in the rewritten slice so MarkDeprecated still emits its one-time warning.
func translateV1Args(args []string) []string {
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
    var knownSubcmds = map[string]bool{
        "recon": true, "all": true, "passive": true, "subs": true, "web": true,
        "vulns": true, "osint": true, "zen": true, "deep": true,
        "monitor": true, "report": true, "mcp": true, "migrate": true,
        "install": true, "health-check": true, "version": true,
    }
    // ... linear scan; if args[0] already a known subcommand, skip mode injection
    // Rewrite -d X → --target X, -l X → --list X, -v → --axiom
}
```

**Integration point in `main.go`** (`run()` lines 100-177 — insert after `parseEarlyFlags`, before `rootCmd.ExecuteContext`):
```go
efs := parseEarlyFlags(os.Args[1:])
// Phase 9: rewrite v1 aliases before cobra parses.
translated := translateV1Args(os.Args[1:])
rootCmd := newRootCmd(app, cfg)
rootCmd.SetArgs(translated) // cobra uses translated args instead of os.Args[1:]
return rootCmd.ExecuteContext(ctx)
```

---

### `cmd/reconftw/batch.go` (utility, batch)

**Analog:** `cmd/reconftw/stub_subcommands.go` (`runSubsCmd` target resolution + result handling pattern)

**Pattern** (new function, no direct line analog — shape derived from D-07 spec + `runXCmd` per-target flow):
```go
// runBatch iterates targets from listFile sequentially, calling run for each.
// On any failure: logs the error, continues to next target (D-07 continue-on-error).
// Returns non-nil error summarizing total failures (for non-zero exit).
func runBatch(ctx context.Context, listFile string,
    run func(ctx context.Context, target string) error,
) (int, error) {
    targets, err := readTargetList(listFile)
    if err != nil {
        return 0, err
    }
    failed := 0
    for _, tgt := range targets {
        if runErr := run(ctx, tgt); runErr != nil {
            slog.Warn("batch_target_failed", "target", tgt, "err", runErr)
            failed++
        }
    }
    return failed, nil
}
```

**printBatchSummary pattern** (copy from `printSubsSummary` in `stub_subcommands.go` lines 283-308 — same `fmt.Fprintf` table pattern with `──` rule separator):
```go
func printBatchSummary(w *os.File, results []batchResult) {
    fmt.Fprintf(w, "\n  ── batch summary ─────────────────────────\n")
    for _, r := range results {
        status := "OK"
        if r.err != nil {
            status = "FAIL"
        }
        fmt.Fprintf(w, "  %-40s  %s\n", r.target, status)
    }
    fmt.Fprintf(w, "  ─────────────────────────────────────────\n")
}
```

---

### `cmd/reconftw/stateful_subcommands.go` (controller, request-response)

**Analog:** `cmd/reconftw/stub_subcommands.go` `newSubsCmd` / `runSubsCmd` constructor pattern + `cmd/reconftw/main.go` `parseEarlyFlags` for gen-resolvers flag parsing

**Constructor pattern** (copy `newSubsCmd` pattern from `stub_subcommands.go` lines 109-127):
```go
func newGenResolversCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "gen-resolvers",
        Short: "Regenerate the DNS resolver list via dnsvalidator",
        RunE: func(cmd *cobra.Command, args []string) error {
            return runGenResolversCmd(cmd)
        },
    }
    // No --target required (standalone per D-04)
    return cmd
}
```

**gen-resolvers RunE pattern** — no `afterBoot` (no AppContext needed); invokes `dnsvalidator` via `LocalBackend.Exec` or falls back to HTTP download. Pattern for backend invocation from `internal/core/backend/local.go` lines 77-79:
```go
func (b *LocalBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
    return b.ExecEnv(ctx, t, args, nil)
}
```

**quick-rescan and refresh-cache** set config flags then delegate to the composite `recon` pipeline:
```go
func runQuickRescanCmd(cmd *cobra.Command) error {
    // D-06: force checkpoint bypass + rerun recon pipeline
    // cfg.Advanced.Diff = true is set via ConfigTransform before BootReconApp
    return runCompositeWithTransform(cmd, func(cfg *config.Config) {
        cfg.Advanced.Diff = true
        cfg.Advanced.QuickRescan = true
    })
}
```

---

### `cmd/reconftw/composite_test.go` (test)

**Analogs:** `cmd/reconftw/osint_stage_order_test.go` (full file — stage-order guard pattern) + `cmd/reconftw/root_test.go` lines 72-92 (cobra execution test pattern) + `cmd/reconftw/dag_build_test.go` lines 28-38

**Package declaration + blank imports pattern** (copy from `osint_stage_order_test.go` lines 18-29):
```go
package main

import (
    "testing"

    "github.com/six2dez/reconftw/internal/core/config"
    "github.com/six2dez/reconftw/internal/core/task"

    _ "github.com/six2dez/reconftw/internal/modules/subdomains"
    _ "github.com/six2dez/reconftw/internal/modules/web"
    _ "github.com/six2dez/reconftw/internal/modules/osint"
    _ "github.com/six2dez/reconftw/internal/modules/vulns"
)
```

**Stage-order assertion pattern** (copy from `osint_stage_order_test.go` lines 72-119):
```go
// TestReconPipelineOrder asserts subs stages precede web stages precede osint stages.
func TestReconPipelineOrder(t *testing.T) {
    // Build stageIndex from composite stage groups (same pattern as osintStageIndex())
    // Assert that for each cross-pipeline DependsOn edge, the dep is in a strictly
    // earlier pipeline group.
}
```

**Stub exit-64 gate pattern** (copy from `root_test.go` lines 72-92 — use to assert stubs `recon`/`all`/etc. NO LONGER return exit 64 after Phase 9):
```go
root := newRootCmd(nil, &config.Config{})
root.SetArgs([]string{name})
root.SetErr(&bytes.Buffer{})
err := root.Execute()
var ec *exitCodeError
// Phase 9: assert errors.As(err, &ec) is FALSE for composite subcommands
```

**Passive guard test pattern** (new; mock backend pattern from `dag_build_test.go` spirit):
```go
// TestPassiveModeBlocksActiveTool: boot with PassiveMode=true, run passive
// composite, assert MockBackend.ExecCalls contains no active tool names.
func TestPassiveModeBlocksActiveTool(t *testing.T) {
    // Construct a MockBackend recording Exec calls
    // BootReconApp with PassiveMode=true via AppContext BootOptions
    // Assert no active tool (puredns, naabu, nmap, dalfox, etc.) was exec'd
}
```

**Dry-run redaction test pattern** (D-10, new):
```go
// TestDryRunRedactsSecrets: register a secret with cfg, run --dry-run on
// composite, capture cmd.OutOrStdout(), assert secret not present in output.
func TestDryRunRedactsSecrets(t *testing.T) {
    // Matches the spirit of TestDeprecationWarningLongAliases (root_test.go lines 99-119)
    // in capturing output and asserting string presence/absence.
}
```

---

### `cmd/reconftw/stateful_test.go` (test)

**Analog:** `cmd/reconftw/stub_test.go` lines 1-85 (package-main test structure + `cobra.Command` construction pattern)

**Pattern** (copy `stub_test.go` structure):
```go
package main

import (
    "testing"
)

func TestGenResolversDryRun(t *testing.T) {
    // Use same cmd construction pattern as TestStubNotImplementedFormat
    // (stub_test.go lines 15-19): cobra.Command + SetErr + Execute + assert
}

func TestRefreshCacheSetsForceRefreshFlag(t *testing.T) {
    // Assert cfg.Cache.Refresh and cfg.Advanced.Diff are true after runRefreshCacheCmd
}
```

---

### `cmd/reconftw/alias_test.go` (test — or in `main_test.go`)

**Analog:** `cmd/reconftw/root_test.go` lines 99-151 (`TestDeprecationWarningLongAliases` / `TestDeprecationWarningShortAliases` — table-driven CLI flag tests)

**Pattern** (copy table-driven structure from `root_test.go` lines 99-119):
```go
// TestTranslateV1Args: table-driven — each row is an input []string and
// expected translated []string. No cobra needed — pure function test.
func TestTranslateV1Args(t *testing.T) {
    cases := []struct {
        input    []string
        wantHead string // expected args[0] after translation
    }{
        {[]string{"--recon", "-d", "example.com"}, "recon"},
        {[]string{"-a", "--target", "example.com"}, "all"},
        {[]string{"recon", "--recon", "--target", "x"}, "recon"}, // no double-insertion
        {[]string{"-d", "example.com", "-r"}, "recon"},
    }
    for _, tc := range cases {
        got := translateV1Args(tc.input)
        if len(got) == 0 || got[0] != tc.wantHead {
            t.Errorf("translateV1Args(%v)[0] = %v, want %v", tc.input, got[0], tc.wantHead)
        }
    }
}
```

---

### `internal/core/resolvers/gen.go` (service, batch/I-O)

**Analog (partial):** `internal/core/backend/local.go` lines 77-79 (`Exec` pattern) + `cmd/reconftw/main.go` lines 187-217 (`parseEarlyFlags` linear scan for the fallback download pattern)

**No close analog exists** — this is the closest role-match in the codebase. The `LocalBackend.Exec` pattern provides the subprocess invocation shape:
```go
// RunGenResolvers invokes dnsvalidator with two source URLs and writes
// combined output to cfg.Paths.Resolvers. Falls back to HTTP download
// if dnsvalidator is not on PATH (mirroring v1 modules/axiom.sh:42-43).
func RunGenResolvers(ctx context.Context, cfg *config.Config) error {
    be := backend.NewLocalBackend(0)
    // Invoke dnsvalidator via be.Exec (Tool{Name:"dnsvalidator", ...})
    // On ToolError or PathError → fall back to net/http GET cfg.Paths.ResolversDownload.URL
    // Write output to cfg.Paths.Resolvers
}
```

---

## Shared Patterns

### BootReconApp / AfterBoot Lifecycle
**Source:** `internal/mcp/handlers/common.go` lines 100-160 + `internal/mcp/handlers/subs.go` lines 26-65
**Apply to:** All composite handler functions in `composite.go` and `stateful_subcommands.go`
```go
boot, err := BootReconApp(ctx, opts)
if err != nil {
    return fmt.Errorf("mcp/composite: %w", err)
}
defer func() {
    if closer, ok := boot.App.Checkpoint.(interface{ Close() error }); ok {
        _ = closer.Close()
    }
}()
if opts.AfterBoot != nil {
    opts.AfterBoot(boot)
}
if opts.DryRun {
    return nil
}
sched.Checkpoint = boot.App.Checkpoint
```

### Secret Registration / Log Routing (XCUT-07)
**Source:** `cmd/reconftw/stub_subcommands.go` lines 182-201 (liveUI log routing block in every afterBoot)
**Apply to:** `commonAfterBoot` extracted helper; `printXDryRun` must pass output through `rdct.Redact()` (D-10)
```go
// Register secrets on every sink — not just liveUI path.
rdct := &log.Redactor{}
registerSecrets(cfg, rdct)
// For dry-run: use rdct.Redact(line) before fmt.Fprintf on tool invocations.
```

### filterByModuleAndEnabled
**Source:** `cmd/reconftw/appctx_init.go` lines 40-54 + `internal/core/task.FilterByModuleAndEnabled`
**Apply to:** All composite stage groups in `composite.go` and `composite_subcommands.go`
```go
stageSlice := task.FilterByModuleAndEnabled(allTasks, "subdomains", cfg, stage.prefixes)
// OR via the package-private shim:
stageSlice := filterByModuleAndEnabled(allTasks, "subdomains", cfg, stage.prefixes)
```

### Axiom FailoverBackend extraction (one-shot per composite)
**Source:** `cmd/reconftw/stub_subcommands.go` lines 204-221 (in every afterBoot)
**Apply to:** `commonAfterBoot` — extracted once; composite defers one `axiomBE.Shutdown`
```go
var axiomBE *backend.AxiomBackend
if fb, ok := boot.ChosenBackend.(*backend.FailoverBackend); ok {
    if abe, ok := fb.Primary.(*backend.AxiomBackend); ok {
        axiomBE = abe
    }
}
if axiomBE != nil {
    if launchErr := axiomBE.Launch(ctx); launchErr != nil {
        if app.Log != nil {
            app.Log.Warn("composite: axiom launch failed — continuing locally", "err", launchErr)
        }
    }
    // COMPOSITE: defer Shutdown at composite scope, NOT inside commonAfterBoot.
    // Single-pipeline runXCmd: defer inside afterBoot (no change).
}
```

### Scheduler construction (per-invocation, never shared)
**Source:** `cmd/reconftw/stub_subcommands.go` line 151 (every runXCmd)
**Apply to:** Every composite and stateful subcommand RunE
```go
sched := scheduler.NewScheduler(0, 0, nil, nil)
// MaxConcurrent/HeartbeatSeconds set in afterBoot from cfg values.
// NEVER share a Scheduler across concurrent sessions (memory: scheduler per-scan landmine).
```

### earlyFlagSet extraction
**Source:** `cmd/reconftw/main.go` lines 194-217 (`parseEarlyFlags`) — used in every `runXCmd`
**Apply to:** Every composite and stateful RunE
```go
efs := parseEarlyFlags(os.Args[1:])
// efs.configPath → RunOptions.ConfigPath
// efs.secretsPath → RunOptions.SecretsPath
```

### badgeForStatus
**Source:** `cmd/reconftw/appctx_init.go` lines 23-38
**Apply to:** `commonAfterBoot` extracted helper (the `sched.RunTask` closure)
```go
progress.TaskDone(t.Name(), badgeForStatus(result.Status), dur)
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `internal/core/resolvers/gen.go` | service | batch/I-O | No external-tool invocation + fallback HTTP download pattern exists in Go layer yet (v1 analog is `modules/axiom.sh:16-65` bash); `LocalBackend.Exec` provides the subprocess shape but not the HTTP fallback half |

---

## Key Structural Constraints (Planner Must Enforce)

1. **Axiom lifecycle:** Composite owns ONE `axiomBE.Launch` before stage groups and ONE `defer axiomBE.Shutdown` after all groups. The extracted `commonAfterBoot` must NOT contain the `defer Shutdown` call (unlike the existing per-pipeline afterBoot closures). Single-pipeline `runXCmd` bodies are unchanged.

2. **Checkpoint lifecycle:** Composite owns ONE `defer app.Checkpoint.Close()`. Extracted stage runners do NOT call `Close()`. Source: `subs.go` lines 41-46 comment "B3 fix".

3. **ConfigTransform before Boot:** `applyZenProfile`/`applyDeepProfile` must be passed via `RunOptions.ConfigTransform` and applied inside `BootReconApp` after `config.Load` and before `appctx.Boot`. Applying them after Boot means appctx.Boot already wired stale concurrency limits. Source: RESEARCH.md Pattern 2 / Pitfall 5.

4. **Per-scan scheduler:** `scheduler.NewScheduler(0, 0, nil, nil)` is called fresh per composite invocation. Never reuse across batch targets. Source: memory note "scheduler per-scan landmine".

5. **phasePointers cleanup:** Remove the 5 composite entries (`recon`, `all`, `passive`, `zen`, `deep`) from `phasePointers` map and from `TestEveryStubReturnsExit64`'s `stubs` slice. Source: `stub_subcommands.go` lines 50-62, `root_test.go` lines 72-92.

6. **translateV1Args guard:** When `args[0]` (after stripping leading non-flag tokens) is already a known subcommand, skip mode-flag injection but still translate `-d`/`-l`/`-v`. Source: RESEARCH.md Pitfall 4.

7. **D-10 redaction scope:** `printXDryRun` helpers currently call `fmt.Fprintf(cmd.OutOrStdout(), ...)` directly — tool invocation strings bypass the slog redactor. The composite dry-run must apply `rdct.Redact(line)` to each tool arg string before printing. Source: RESEARCH.md Q7.

---

## Metadata

**Analog search scope:** `cmd/reconftw/`, `internal/mcp/handlers/`, `internal/core/config/`, `internal/core/log/`, `internal/core/backend/`, `internal/core/appctx/`, `internal/core/scheduler/`
**Files scanned:** 22
**Pattern extraction date:** 2026-06-11
