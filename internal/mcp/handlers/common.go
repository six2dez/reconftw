// Package handlers provides shared run-option types and the BootReconApp
// helper that is used by both the cobra CLI subcommands and the MCP tool
// handlers. Extracting the wiring here satisfies MCP-02: the CLI and MCP
// server invoke identical pipeline logic.
//
// Concurrency model (D-03 concurrent sessions): each scan session gets its
// OWN *scheduler.Scheduler (the MCP tool handler calls a per-scan factory; the
// CLI passes a per-invocation scheduler). Because every scan owns its scheduler,
// appctx.Boot wiring the per-scan RunTask / Checkpoint / Hash onto it is safe —
// concurrent sessions never share those mutable fields. The global
// PARALLEL_MAX_JOBS ceiling (MCP-05) is enforced separately by a shared
// scheduler.Limiter (a process-wide semaphore injected by the factory), NOT by
// sharing a Scheduler struct. Each RunXxxAsync closes app.Checkpoint via defer.
package handlers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/scheduler"
)

// StageEvent is sent on ProgressSink at stage boundaries. Done=false means
// the stage is about to start; Done=true means it has completed. Count is
// the running artefact count after the stage (meaningful only when Done=true).
type StageEvent struct {
	Stage string
	Done  bool
	Count int
}

// RunOptions carries all parameters for a RunXxxAsync call. Both the cobra
// CLI RunE bodies and the MCP tool handlers construct a RunOptions and call
// the corresponding RunXxxAsync function — a single code path satisfies MCP-02.
//
// Scheduler must not be nil; BootReconApp returns an error if it is. The
// Scheduler should be the shared process-level instance when called from
// the MCP server (D-03 / Pitfall 3 avoidance), or a per-invocation scheduler
// when called from the CLI.
//
// ProgressSink is optional (nil = stderr UI). When non-nil, RunXxxAsync sends
// StageEvent values at each stage boundary so the MCP layer can emit
// server.ResourceUpdated notifications.
//
// AfterBoot is an optional callback invoked after BootReconApp succeeds but
// before the stage loop starts. The CLI uses this to wire sched.RunTask with
// the per-task progress UI (badgeForStatus + StageProgress). MCP callers
// leave it nil.
//
// ConfigTransform is applied after config.Load inside BootReconApp and before
// appctx.Boot. Used by zen/deep subcommands to override rate limits and feature
// flags in memory (D-02/D-03). nil = no-op. Must be applied before Boot so
// appctx.Boot wires the correct concurrency limits (e.g., zen lowers MaxJobs
// to 2).
type RunOptions struct {
	// Target is the domain or IP being scanned.
	Target string
	// DryRun previews tasks without executing tools.
	DryRun bool
	// ExtraFile carries --hosts (web) or --urls (vulns); unused by subs/osint.
	ExtraFile string
	// ConfigPath is the explicit --config path (may be empty).
	ConfigPath string
	// SecretsPath is the explicit --secrets path (may be empty).
	SecretsPath string
	// AxiomEnabled enables the FailoverBackend wrapping axiom + local.
	AxiomEnabled bool
	// Scheduler is the bounded task dispatcher. Must not be nil.
	Scheduler *scheduler.Scheduler
	// ProgressSink receives stage completion events. nil = no MCP notifications.
	ProgressSink chan<- StageEvent
	// AfterBoot is called after BootReconApp succeeds, before the stage loop.
	// The CLI uses this to inject per-task UI into sched.RunTask. May be nil.
	AfterBoot func(boot AppBoot)
	// ConfigTransform is applied after config.Load inside BootReconApp and before
	// appctx.Boot. Used by zen/deep subcommands to override rate limits and feature
	// flags. nil = no-op. Must be applied before Boot so appctx.Boot wires the
	// correct concurrency limits (e.g., zen's MaxJobs=2).
	ConfigTransform func(*config.Config)
	// PassiveMode enables the backend-level hard-guard (D-09): wraps the chosen
	// backend with PassiveBackend so active tools return ErrPassiveViolation.
	// Set by the passive composite subcommand.
	PassiveMode bool
	// TargetListPath carries a path to a file of target FQDNs, one per line.
	// When set, the run operates in list mode — cfgSliceJSON includes this path,
	// so checkpoint.InputHash differs from a full-target run, triggering genuine
	// re-execution for the listed assets only. Used by the monitor incremental
	// re-feed path (D-04/D-05 fix — checkpoint hash alone does not change between
	// monitor cycles with identical opts).
	TargetListPath string
}

// AppBoot is the return bundle from BootReconApp.
type AppBoot struct {
	App           *appctx.AppContext
	WorkDir       string
	Cfg           *config.Config
	ChosenBackend backend.Backend // nil when Axiom is not enabled
}

// BootReconApp wires config → target → workspace → backend → appctx.Boot.
// It mirrors steps 1-5a of runSubsCmd in cmd/reconftw/stub_subcommands.go
// exactly.
//
// opts.Scheduler is a per-scan instance (CLI: per-invocation; MCP: produced by
// the per-scan factory). appctx.Boot wires this scan's RunTask/Checkpoint onto
// it; because the scheduler is not shared across sessions, that is race-free.
// The global concurrency ceiling is enforced by the scheduler's shared Limiter
// (MCP-05), not by sharing the Scheduler struct.
//
// The caller must pass a non-nil opts.Scheduler; returning an error on nil
// prevents silent DoS bypass of the concurrency ceiling (T-08-03-02).
func BootReconApp(ctx context.Context, opts RunOptions) (AppBoot, error) {
	if opts.Scheduler == nil {
		return AppBoot{}, fmt.Errorf("handlers: RunOptions.Scheduler must not be nil")
	}

	// Step 1: Load config.
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: opts.ConfigPath,
		SecretsPath:        opts.SecretsPath,
	})
	if err != nil {
		return AppBoot{}, fmt.Errorf("handlers: config load: %w", err)
	}

	// Apply mode transform (zen/deep) AFTER Load and BEFORE Boot.
	// This ensures appctx.Boot wires the transformed concurrency limits (D-02/D-03).
	// Pitfall 5: applying after Boot means Boot already wired stale values.
	if opts.ConfigTransform != nil {
		opts.ConfigTransform(cfg)
	}

	// Step 2: Build target.
	tgt, err := appctx.NewTarget(opts.Target, nil, "")
	if err != nil {
		return AppBoot{}, fmt.Errorf("handlers: invalid target: %w", err)
	}

	// Step 3: Workspace init with fallback.
	workdir, err := output.WorkspaceInit(cfg.Paths.DataDir, tgt.Domain)
	if err != nil {
		workdir, err = output.WorkspaceInit("workspaces", tgt.Domain)
		if err != nil {
			return AppBoot{}, fmt.Errorf("handlers: workspace init: %w", err)
		}
	}
	tgt.WorkDir = workdir

	// Step 4: Use opts.Scheduler as-is (DO NOT call scheduler.NewScheduler —
	// Pitfall 3). The shared process-level scheduler owns the MaxJobs ceiling.

	// Step 5: Choose backend.
	var chosenBackend backend.Backend
	if opts.AxiomEnabled {
		axiomBE := backend.NewAxiomBackend(cfg, backend.Default, nil)
		localBE := backend.NewLocalBackend(time.Duration(cfg.Concurrency.KillGraceSeconds) * time.Second)
		chosenBackend = &backend.FailoverBackend{
			Primary:   axiomBE,
			Fallback:  localBE,
			Threshold: cfg.Axiom.FailoverThreshold,
		}
	}
	// nil chosenBackend → Boot.pickBackend selects LocalBackend.

	// Step 5a: Boot the AppContext.
	// Logger nil → uses slog.Default(). The MCP server sets slog.Default to a
	// redacted logger before starting scans, so this is safe.
	app, err := appctx.Boot(ctx, nil, cfg, tgt, opts.Scheduler, appctx.BootOptions{
		Backend:     chosenBackend,
		PassiveMode: opts.PassiveMode,
	})
	if err != nil {
		return AppBoot{}, fmt.Errorf("handlers: appctx boot: %w", err)
	}

	// Checkpoint wiring happens in each RunXxxAsync (sched.Checkpoint =
	// app.Checkpoint) and is race-free because opts.Scheduler is this scan's
	// own instance, not a shared one. RunXxxAsync also owns the app.Checkpoint
	// lifecycle (closed via defer).

	return AppBoot{App: app, WorkDir: workdir, Cfg: cfg, ChosenBackend: chosenBackend}, nil
}

// countJSONLLines returns the number of non-empty lines in a JSONL file.
// Returns 0 if the file does not exist or cannot be read.
func countJSONLLines(path string) int {
	f, err := os.Open(path) //nolint:gosec // path derived from validated workdir
	if err != nil {
		return 0
	}
	defer f.Close() //nolint:errcheck
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	return n
}

// mergeTakeoverFindings reads both takeover staging files and calls
// app.Tree.Append("findings", merged) exactly once (B2 fix — single-writer).
//
// TakeoverSubzyTask and TakeoverDNSTakeTask each write their own staging file
// to avoid concurrent-write data loss (OutputTree.Append uses REPLACE semantics).
// This function serializes the merge after the enrichment RunStage completes.
func mergeTakeoverFindings(ctx context.Context, app *appctx.AppContext) error {
	_ = ctx

	subzyPath := filepath.Join(app.Target.WorkDir, "inputs", "takeover.subzy.jsonl")
	dnstakePath := filepath.Join(app.Target.WorkDir, "inputs", "takeover.dnstake.jsonl")

	var merged [][]byte
	for _, p := range []string{subzyPath, dnstakePath} {
		lines, lerr := readJSONLLines(p)
		if lerr != nil {
			if app.Log != nil {
				app.Log.Debug("mergeTakeoverFindings: skipping staging file", "path", p, "err", lerr)
			}
			continue
		}
		merged = append(merged, lines...)
	}

	if len(merged) == 0 {
		return nil
	}
	return app.Tree.Append("findings", merged)
}

// readJSONLLines reads a JSONL file and returns each non-empty line as []byte.
func readJSONLLines(path string) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var lines [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		b := sc.Bytes()
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
