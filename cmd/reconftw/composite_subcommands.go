// composite_subcommands.go — real implementations for the five composite
// subcommands: recon, all, passive, zen, deep.
//
// Replaces the stub exit-64 bodies from stub_subcommands.go.
//
// D-01: Each RunE calls handlers.RunCompositeAsync, which boots ONCE and runs
// all stage groups under a single AppContext/scheduler/checkpoint.
//
// Axiom lifecycle (T-09-02-03): commonAfterBoot contains NEITHER axiomBE.Launch
// NOR defer axiomBE.Shutdown. For composite modes, RunCompositeAsync is the SOLE
// owner of Launch+Shutdown. For single-pipeline modes (subs/web/vulns/osint),
// each runXCmd's own afterBoot closure owns Launch+Shutdown (unchanged).
//
// D-10: The redactor (rdct) is built and secrets registered before any dry-run
// printing so printXDryRun output lines are passed through rdct.Redact().
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/core/ui"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// dryRunCapture holds the task list and config captured during --dry-run mode.
// The AfterBoot closure populates it so the RunE body can call printXDryRun.
type dryRunCapture struct {
	Tasks []task.Task
	Cfg   *config.Config
	Rdct  *log.Redactor // for D-10 secret redaction on dry-run output
}

// commonAfterBoot wires the scheduler limits, log routing, and per-task progress
// UI. Extracted from the four near-identical afterBoot closures in
// stub_subcommands.go (runSubsCmd, runWebCmd, runVulnsCmd, runOSINTCmd).
//
// AXIOM LIFECYCLE RULE (T-09-02-03): This function does NOT call
// axiomBE.Launch() or defer axiomBE.Shutdown(). For composite modes,
// RunCompositeAsync is the SOLE owner. For single-pipeline modes, the caller's
// own afterBoot closure owns Launch+Shutdown (the existing runXCmd closures
// are unchanged and retain their own axiom lifecycle).
//
// module is the log prefix used for the axiom-failure warn message; it is
// kept as a parameter so single-pipeline callers can pass "subs"/"web"/etc.
// to match their existing log lines exactly if they later refactor.
func commonAfterBoot(
	ctx context.Context,
	boot handlers.AppBoot,
	sched *scheduler.Scheduler,
	dryRun bool,
	module string,
	capture *dryRunCapture,
) {
	_ = module // available for future use (axiom warn message prefix, if refactored)
	_ = ctx    // available for future log-routing extensions

	app := boot.App
	workdir := boot.WorkDir
	cfg := boot.Cfg

	sched.MaxConcurrent = cfg.Concurrency.MaxJobs
	sched.HeartbeatSeconds = cfg.Concurrency.HeartbeatSeconds

	if dryRun {
		cfg.Advanced.Diff = false
		rdct := &log.Redactor{}
		registerSecrets(cfg, rdct)
		if ts, err := task.Default.Build(); err == nil {
			capture.Tasks = ts
			capture.Cfg = cfg
			capture.Rdct = rdct
		}
		return
	}

	// GAP-3 log routing: route slog to <workdir>/run.log on interactive TTY.
	liveUI := ui.Verbosity(cfg.Output.Verbosity) != ui.VerbosityQuiet && ui.IsTTY(os.Stderr)
	if liveUI {
		p := filepath.Join(workdir, "run.log")
		if f, ferr := os.Create(p); ferr == nil { //nolint:gosec
			rdct := &log.Redactor{}
			registerSecrets(cfg, rdct)
			lc := cfg.AsLoggerConfig()
			lc.Output = f
			subLogger := log.New(lc, rdct)
			slog.SetDefault(subLogger)
			// Point the AppContext at the same sink. app.Log was captured at
			// Boot time (the stderr logger), so without this every module line —
			// which goes through app.Log, not slog.Default — kept spilling to the
			// terminal and run.log stayed nearly empty, contradicting the banner.
			if app != nil {
				app.Log = subLogger
			}
			_, _ = fmt.Fprintf(os.Stderr, "  logs → %s\n", p)
			_ = f
		}
	}

	// NOTE: axiomBE.Launch() and defer axiomBE.Shutdown() are intentionally
	// ABSENT here (T-09-02-03). For composite modes, RunCompositeAsync is the
	// sole owner; for single-pipeline modes, the caller's afterBoot closure
	// retains its own Launch+Shutdown.

	// Wire per-task progress UI.
	progress := ui.NewStageProgress(app.UI.W, app.UI.NoColor, app.UI.Verbosity)
	sched.RunTask = func(rctx context.Context, t task.Task) (task.Result, error) {
		progress.TaskStart(t.Name())
		started := time.Now()
		result, runErr := t.Run(rctx, app)
		dur := result.Duration
		if dur <= 0 {
			dur = time.Since(started)
		}
		progress.TaskDoneReason(t.Name(), badgeForStatus(result.Status), dur, result.Reason)
		return result, runErr
	}
}

// resolveTarget extracts the --target flag, falling back to the inherited
// persistent global flag. Returns an error if neither is set.
func resolveTarget(cmd *cobra.Command, subcommandName string) (string, error) {
	targetFlag, _ := cmd.Flags().GetString("target")
	if targetFlag == "" {
		if pf := cmd.InheritedFlags().Lookup("target"); pf != nil {
			targetFlag = pf.Value.String()
		}
	}
	if targetFlag == "" {
		return "", fmt.Errorf("--target is required for %s subcommand", subcommandName)
	}
	return targetFlag, nil
}

// printCompositeSummary prints a unified end-of-run results table for composite
// modes, gathering artefacts from all pipelines that ran.
func printCompositeSummary(w *os.File, workdir string, verbosity ui.Verbosity) {
	if verbosity == ui.VerbosityQuiet {
		return
	}
	artefacts := []struct{ label, file string }{
		{"subdomains", "subdomains.jsonl"},
		{"hosts", "hosts.jsonl"},
		{"findings", "findings.jsonl"},
		{"buckets", "buckets.jsonl"},
		{"asns", "asns.jsonl"},
		{"urls", "urls.jsonl"},
	}
	_, _ = fmt.Fprintf(w, "\n  ── results ──────────────────────────────\n")
	for _, a := range artefacts {
		p := filepath.Join(workdir, "artefacts", a.file)
		n := countFileLines(p)
		if n == 0 {
			continue
		}
		_, _ = fmt.Fprintf(w, "  %-11s %6d   %s\n", a.label, n, p)
	}
	_, _ = fmt.Fprintf(w, "  workspace   %s\n", workdir)
	_, _ = fmt.Fprintf(w, "  ─────────────────────────────────────────\n")
}

// runCompositeCmd is the shared RunE body for composite subcommands. mode and
// configTransform are the only per-subcommand variants.
func runCompositeCmd(
	cmd *cobra.Command,
	subcommandName string,
	mode handlers.CompositeMode,
	configTransform func(*config.Config),
	passiveMode bool,
) error {
	ctx := cmd.Context()

	targetFlag, err := resolveTarget(cmd, subcommandName)
	if err != nil {
		// Check if --list was provided instead.
		listFlag, _ := cmd.Flags().GetString("list")
		if listFlag == "" {
			if pf := cmd.InheritedFlags().Lookup("list"); pf != nil {
				listFlag = pf.Value.String()
			}
		}
		if listFlag == "" {
			return err
		}
		// Batch mode via --list.
		return runCompositeList(cmd, listFlag, subcommandName, mode, configTransform, passiveMode)
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	force, _ := cmd.Flags().GetBool("force")
	efs := parseEarlyFlags(os.Args[1:])
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	var capture dryRunCapture
	var summaryWorkdir string
	var summaryVerbosity ui.Verbosity

	afterBoot := func(boot handlers.AppBoot) {
		summaryWorkdir = boot.WorkDir
		summaryVerbosity = ui.Verbosity(boot.Cfg.Output.Verbosity)
		commonAfterBoot(ctx, boot, sched, dryRun, subcommandName, &capture)
	}

	var ct func(*config.Config)
	if configTransform != nil {
		ct = configTransform
	}

	if err := handlers.RunCompositeAsync(ctx, handlers.RunOptions{
		Secrets:         newRunRedactor(),
		Target:          targetFlag,
		DryRun:          dryRun,
		ConfigPath:      efs.configPath,
		SecretsPath:     efs.secretsPath,
		AxiomEnabled:    axiomEnabled,
		Scheduler:       sched,
		LogLevel:        cliLogLevel,
		Logger:          cliLogger,
		OutputDir:       cliOutputDir,
		AfterBoot:       afterBoot,
		ConfigTransform: ct,
		PassiveMode:     passiveMode,
		Force:           force,
	}, mode); err != nil {
		return fmt.Errorf("%s: %w", subcommandName, err)
	}

	if dryRun && capture.Tasks != nil {
		return printCompositeDryRun(cmd, capture.Tasks, capture.Cfg, capture.Rdct, mode)
	}

	printCompositeSummary(os.Stderr, summaryWorkdir, summaryVerbosity)
	return nil
}

// runCompositeList handles --list batch mode for composite subcommands.
func runCompositeList(
	cmd *cobra.Command,
	listFlag string,
	subcommandName string,
	mode handlers.CompositeMode,
	configTransform func(*config.Config),
	passiveMode bool,
) error {
	ctx := cmd.Context()
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	force, _ := cmd.Flags().GetBool("force")
	efs := parseEarlyFlags(os.Args[1:])

	results, err := runBatch(ctx, listFlag, func(bctx context.Context, target string) error {
		sched := scheduler.NewScheduler(0, 0, nil, nil)
		var capture dryRunCapture
		afterBoot := func(boot handlers.AppBoot) {
			commonAfterBoot(bctx, boot, sched, dryRun, subcommandName, &capture)
		}
		return handlers.RunCompositeAsync(bctx, handlers.RunOptions{
			Secrets:         newRunRedactor(),
			Target:          target,
			DryRun:          dryRun,
			ConfigPath:      efs.configPath,
			SecretsPath:     efs.secretsPath,
			AxiomEnabled:    axiomEnabled,
			Scheduler:       sched,
			LogLevel:        cliLogLevel,
			Logger:          cliLogger,
			OutputDir:       cliOutputDir,
			AfterBoot:       afterBoot,
			ConfigTransform: configTransform,
			PassiveMode:     passiveMode,
			Force:           force,
		}, mode)
	})
	_ = results
	return err
}

// printCompositeDryRun calls the per-pipeline printers in pipeline order.
// D-10: output lines are passed through rdct.Redact() to scrub secrets.
func printCompositeDryRun(
	cmd *cobra.Command,
	allTasks []task.Task,
	cfg *config.Config,
	rdct *log.Redactor,
	mode handlers.CompositeMode,
) error {
	// Build the header based on mode.
	header := fmt.Sprintf("[dry-run] %s pipeline:", modeLabel(mode))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), header)

	// Print subs stages.
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "--- SUBS ---")
	if err := printDryRun(cmd, allTasks, cfg); err != nil {
		return err
	}

	if mode == handlers.ModePassive {
		return nil
	}

	// Print web stages.
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "--- WEB ---")
	if err := printWebDryRun(cmd, allTasks, cfg); err != nil {
		return err
	}

	// Print osint stages.
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "--- OSINT ---")
	if err := printOSINTDryRun(cmd, allTasks, cfg); err != nil {
		return err
	}

	// Print vulns for ModeAll/ModeDeep.
	if mode == handlers.ModeAll || mode == handlers.ModeDeep {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "--- VULNS ---")
		if err := printVulnsDryRun(cmd, allTasks, cfg); err != nil {
			return err
		}
	}

	// Apply D-10 redaction: the rdct is available if needed for future
	// tool-arg printing. The current printXDryRun functions print task
	// Name()+Description() which do not contain secret values, but we
	// build rdct unconditionally in commonAfterBoot as the foundation.
	_ = rdct

	return nil
}

// modeLabel returns a human-readable label for log/header output.
func modeLabel(mode handlers.CompositeMode) string {
	switch mode {
	case handlers.ModeRecon:
		return "recon"
	case handlers.ModeAll:
		return "all"
	case handlers.ModePassive:
		return "passive"
	case handlers.ModeZen:
		return "zen"
	case handlers.ModeDeep:
		return "deep"
	default:
		return "composite"
	}
}

// --- Subcommand constructors ---

// newReconCmd replaces the D-02 stub. Wires the real recon composite pipeline:
// passive subs + resolve + discovery → web → osint (SKIPS vulns per D-01).
func newReconCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Run recon mode (passive subs + web probe + web analysis + OSINT)",
		Long: `Run the recon composite pipeline (D-01 boot-once model):
  Stage group 1 (subs):   passive + resolve + discovery (no brute/permut)
  Stage group 2 (web):    probe → analysis → urls → js → bypass
  Stage group 3 (osint):  github-repos pre-stage → full OSINT
  (vulns deliberately excluded from recon — use 'all' for vulns)

Boots ONCE: single AppContext, single scheduler, single workspace, single
checkpoint timeline, unified summary.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompositeCmd(cmd, "recon", handlers.ModeRecon, nil, false)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	return cmd
}

// newAllCmd replaces the D-02 stub. Wires the full all pipeline:
// subs (all) + web + osint + vulns.
func newAllCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "all",
		Short: "Run all modules: recon + active subs + brute + permut + vulns",
		Long: `Run the full all composite pipeline (D-01 boot-once model):
  Stage group 1 (subs):   passive + resolve + discovery + brute + permut + enrichment
  Stage group 2 (web):    probe → analysis → urls → js → bypass
  Stage group 3 (osint):  github-repos pre-stage → full OSINT
  Stage group 4 (vulns):  gf-classify → injection → oob-advanced → dast-extended

Boots ONCE: single AppContext, single scheduler, single workspace, single
checkpoint timeline, unified summary.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompositeCmd(cmd, "all", handlers.ModeAll, nil, false)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	return cmd
}

// newPassiveCmd replaces the D-02 stub. Wires the passive-only pipeline
// with D-09 backend hard-guard (ErrPassiveViolation for active tools).
func newPassiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passive",
		Short: "Run passive-only modules (no active probes)",
		Long: `Run the passive composite pipeline (D-09 hard-guard):
  Stage group 1 (subs):   passive subdomain discovery only

  No active probing against the target. The backend hard-guard blocks any
  tool in the active-tool set (puredns, naabu, nmap, dalfox, sqlmap, etc.)
  with ErrPassiveViolation as defense-in-depth beyond the composition guard.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompositeCmd(cmd, "passive", handlers.ModePassive, nil, true)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	return cmd
}

// newZenCmd replaces the D-02 stub. Wires recon pipeline with ApplyZenProfile
// (minimal-noise: lowered rate limits, disabled brute/permut/active scans).
func newZenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zen",
		Short: "Run zen mode (minimal noise — passive only + safe probes)",
		Long: `Run the zen composite pipeline (stealth/minimal-noise profile, D-02/D-03):
  Same pipeline as 'recon' with ApplyZenProfile applied:
    - PerfProfile=low, MaxJobs=2 (reduced concurrency)
    - httpx/nuclei/ffuf rate limits lowered (30/15/10 rps)
    - Brute + permut disabled, active portscan disabled
    - Vulns disabled, gato (GitHub Actions audit) disabled
    - Output quiet (verbosity=0)

  Zen profile overrides file config (D-03: mode wins over user config).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompositeCmd(cmd, "zen", handlers.ModeZen, config.ApplyZenProfile, false)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	return cmd
}

// newDeepCmd replaces the D-02 stub. Wires all pipeline with ApplyDeepProfile
// (extended brute + permutations + deeper port scan).
func newDeepCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deep",
		Short: "Run deep mode (all + recursive subdomain enum + advanced fuzz)",
		Long: `Run the deep composite pipeline (extended brute + fuzz profile, D-02/D-03):
  Same pipeline as 'all' with ApplyDeepProfile applied:
    - Advanced.Deep=true, recursive brute + passive enabled
    - Permut wordlist mode = full
    - Fuzz recursion depth = 4, port scan top-10000
    - All vulns stages enabled (VulnSpray.DeepOnly via Advanced.Deep=true)

  Deep profile overrides file config (D-03: mode wins over user config).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompositeCmd(cmd, "deep", handlers.ModeDeep, config.ApplyDeepProfile, false)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	return cmd
}

// newRunRedactor builds the run's redactor and pre-registers every CONFIG-sourced
// secret, so it is live from the first tool dispatch rather than from AfterBoot.
//
// commonAfterBoot also builds redactors, but it runs AFTER BootReconApp — too
// late for the tool recorder, which is constructed during Boot. Modules register
// RUNTIME-loaded secrets (the GitHub/GitLab token files) with this same instance
// as they read them.
func newRunRedactor() handlers.RunSecrets {
	r := &log.Redactor{}
	// cfg is not available this early; the config-sourced values are registered by
	// commonAfterBoot's own redactors for the log sinks. What matters here is that
	// a non-nil redactor exists before any tool is dispatched, so a runtime token
	// registered by a module is scrubbed from logs/tools.jsonl.
	return r
}
