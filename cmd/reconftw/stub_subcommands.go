// stub_subcommands.go — 12 stubbed v2 subcommand constructors per D-01 + D-02.
//
// Source: ADR 0002 §8.1 (subcommand inventory) + 03-CONTEXT.md D-01 / D-02.
//
// All 12 stubbed subcommands share the same shape — Use/Short/Long populate
// from the constants table below; RunE returns stubNotImplemented(cmd, phase, name).
// Phase 4-12 implementers replace the RunE body without touching the CLI plumbing.
//
// Subcommand inventory (12 stubbed + 3 working + 1 hidden = 16 subcommands total):
//
//	stubbed  (12):  recon, all, passive, subs, web, vulns, osint, zen, deep,
//	                monitor, report, mcp, migrate, install     — D-02 exit 64
//	working  (3):   version, health-check                       — D-04 fully working
//	hidden   (1):   kernel-demo                                 — W16 / ADR §0 D-07

package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/core/ui"
	"github.com/six2dez/reconftw/internal/modules/subdomains"
)

// stubPhase carries the (Phase N, Phase Name) tuple used by the phase-pointer message.
type stubPhase struct {
	Phase int
	Name  string
}

// phasePointers maps a stubbed subcommand name → (Phase number, Phase name).
// Each entry sources from .planning/ROADMAP.md phase plan inventory.
//
// All 12 entries match the 12 stubbed subcommand names; lookup by `cmd.Name()`.
var phasePointers = map[string]stubPhase{
	"recon":   {4, "Subdomains E2E + Axiom Integration (recon composite)"},
	"all":     {9, "Composite Modes (all)"},
	"passive": {9, "Composite Modes (passive)"},
	"subs":    {4, "Subdomains E2E + Axiom Integration"},
	"web":     {5, "Web Pipeline E2E"},
	"vulns":   {6, "Vulnerability Scanning E2E"},
	"osint":   {7, "OSINT E2E"},
	"zen":     {9, "Composite Modes (zen)"},
	"deep":    {9, "Composite Modes (deep)"},
	"monitor": {10, "Monitor Mode + Reporting + Notifications"},
	"report":  {10, "Monitor Mode + Reporting + Notifications"},
	"mcp":     {8, "MCP Server"},
	"migrate": {11, "Installer + Cross-Platform + Docker"},
	"install": {11, "Installer + Cross-Platform + Docker"},
}

// newStubCmd is the shared constructor for all stubbed v2 subcommands.
// Use/Short are populated from the caller; the RunE looks up phase pointer
// from phasePointers and returns the D-02 phase-pointer error.
func newStubCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := phasePointers[cmd.Name()]
			return stubNotImplemented(cmd, p.Phase, p.Name)
		},
	}
}

// newReconCmd — Phase 4 (Subdomains E2E + Axiom Integration). Stubbed per D-02.
// V2 entry point for the `recon` composite mode (passive subs + web probe + OSINT).
func newReconCmd() *cobra.Command {
	return newStubCmd("recon", "Run recon mode (passive subs + web probe + web analysis + OSINT)")
}

// newAllCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newAllCmd() *cobra.Command {
	return newStubCmd("all", "Run all modules: recon + active subs + brute + permut + vulns")
}

// newPassiveCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newPassiveCmd() *cobra.Command {
	return newStubCmd("passive", "Run passive-only modules (no active probes)")
}

// newSubsCmd — Phase 4 (Subdomains E2E). Real implementation replacing D-02 stub.
//
// Wires the full subdomain enumeration pipeline:
//  1. Config load + target construction
//  2. Scheduler construction BEFORE Boot (cycle-break — checkpoint wired post-Boot)
//  3. FailoverBackend when --axiom flag is set; otherwise Boot selects LocalBackend
//  4. appctx.Boot with BootOptions{Backend: chosenBackend}
//  5. sched.Checkpoint = app.Checkpoint (B3 fix — per-tool resume operational)
//  6. sched.RunTask closure (cycle-break #2 — wired after Boot)
//  7. Optional Axiom fleet launch / shutdown
//  8. 5 sequential RunStage calls (passive → resolve → permut → enrichment);
//     each stage slice filtered by filterByModuleAndEnabled (REVIEWS finding #4 fix)
//  9. mergeTakeoverFindings after enrichment stage (B2 fix — single findings writer)
// 10. MergeStage after each stage (produces merged.txt for next stage)
func newSubsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subs",
		Short: "Run subdomain enumeration (passive + active + permut + takeover)",
		Long: `Run the full subdomain enumeration pipeline:
  Stage 1 (passive):    subfinder, crt.sh, GitHub, GitLab, urlfinder, hackertarget
  Stage 2 (resolve):    DNS resolution, brute-force, TLS cert harvest, scraping, analytics
  Stage 3 (permut):     gotator permutations, regex permutations, DNS cewl, recursive
  Stage 4 (enrichment): subdomain takeover, S3/GCS buckets, ASN mapping, geo, zone transfer

Output: workspaces/<target>/artefacts/subdomains.jsonl`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSubsCmd(cmd)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	return cmd
}

// runSubsCmd is the extracted RunE body for newSubsCmd. Returns an error on any
// hard failure; soft failures (single-stage errors in best_effort mode) are logged.
func runSubsCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	// Step 1: Load config with CLI overrides.
	targetFlag, _ := cmd.Flags().GetString("target")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Inherit --target from parent (persistent flag) if not set locally.
	if targetFlag == "" {
		if pf := cmd.InheritedFlags().Lookup("target"); pf != nil {
			targetFlag = pf.Value.String()
		}
	}
	if targetFlag == "" {
		return fmt.Errorf("--target is required for subs subcommand")
	}

	// Honor --config / --secrets for the subs reload (was config.Load(LoadOptions{}),
	// which silently ignored both — the user's reconftw.toml + secrets.cfg never
	// applied to a `subs` run). Mirror main.go's early-flag extraction so the same
	// explicit TOML config + secrets file drive the subs pipeline (resolvers paths,
	// API keys, wordlists, per-task toggles). Env vars (RECONFTW_*) still layer on top.
	efs := parseEarlyFlags(os.Args[1:])
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		return fmt.Errorf("subs: config load: %w", err)
	}

	// Step 2: Build target.
	tgt, err := appctx.NewTarget(targetFlag, nil, "")
	if err != nil {
		return fmt.Errorf("subs: invalid target: %w", err)
	}
	workdir, err := output.WorkspaceInit(cfg.Paths.DataDir, tgt.Domain)
	if err != nil {
		workdir, err = output.WorkspaceInit("workspaces", tgt.Domain)
		if err != nil {
			return fmt.Errorf("subs: workspace init: %w", err)
		}
	}
	tgt.WorkDir = workdir

	// Step 3: Construct logger and Scheduler BEFORE Boot (cycle-break).
	// checkpoint is passed as nil — it will be set to app.Checkpoint after Boot returns.
	sched := scheduler.NewScheduler(cfg.Concurrency.MaxJobs, cfg.Concurrency.HeartbeatSeconds, nil, nil)

	// Step 4: Choose backend (FailoverBackend when axiom flag is set).
	var chosenBackend backend.Backend
	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	if axiomEnabled || cfg.Axiom.Enabled {
		axiomBE := backend.NewAxiomBackend(cfg, backend.Default, nil)
		localBE := backend.NewLocalBackend(time.Duration(cfg.Concurrency.KillGraceSeconds) * time.Second)
		chosenBackend = &backend.FailoverBackend{
			Primary:   axiomBE,
			Fallback:  localBE,
			Threshold: cfg.Axiom.FailoverThreshold,
		}
	}
	// nil chosenBackend → Boot.pickBackend selects LocalBackend.

	// Step 5: Boot the AppContext.
	// Dry-run mode: disable tool execution (will be handled via config override).
	if dryRun {
		cfg.Advanced.Diff = false // ensure checkpoint bypass doesn't activate
	}

	// GAP-3 log routing: the UI Printer and the default slog logger BOTH write
	// to stderr, so structured JSON log lines clobber the in-place progress UI
	// ("anticuado y estático" + JSON soup). When the live UI is active
	// (interactive TTY, not quiet, not dry-run) route slog to <workdir>/run.log
	// so stderr carries ONLY the human UI; otherwise (piped / quiet / dry-run)
	// keep the default stderr logger. Redaction (XCUT-07) is preserved by
	// re-registering secrets on the file logger's redactor.
	verbosity := ui.Verbosity(cfg.Output.Verbosity)
	liveUI := !dryRun && verbosity != ui.VerbosityQuiet && ui.IsTTY(os.Stderr)
	var subLogger *slog.Logger
	var runLogPath string
	if liveUI {
		p := filepath.Join(workdir, "run.log")
		if f, ferr := os.Create(p); ferr == nil { //nolint:gosec // path derived from validated workdir
			defer f.Close() //nolint:errcheck // best-effort close of the run log
			runLogPath = p
			rdct := &log.Redactor{}
			registerSecrets(cfg, rdct)
			lc := cfg.AsLoggerConfig()
			lc.Output = f
			subLogger = log.New(lc, rdct)
			// Route ALL slog output (not just app.Log) to the file: the Scheduler
			// was constructed with a nil logger and falls back to slog.Default(),
			// so heartbeats / task_error_best_effort warnings would otherwise
			// still hit stderr and clobber the UI. SetDefault redirects them too.
			slog.SetDefault(subLogger)
			fmt.Fprintf(os.Stderr, "  logs → %s\n", runLogPath)
		}
	}

	app, err := appctx.Boot(ctx, subLogger, cfg, tgt, sched, appctx.BootOptions{Backend: chosenBackend})
	if err != nil {
		return fmt.Errorf("subs: appctx boot: %w", err)
	}
	defer func() {
		if closer, ok := app.Checkpoint.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()

	// Step 5b: Wire sched.Checkpoint AFTER Boot returns (B3 fix — per-tool resume).
	// Without this, sched.Checkpoint remains nil and all checkpoint integration is
	// silently disabled (D-07 per-tool resume semantics broken).
	sched.Checkpoint = app.Checkpoint

	// Step 6: Wire RunTask closure (cycle-break #2 — can only close after Boot).
	// GAP-3: construct StageProgress before the RunTask closure so the closure
	// can reference it. progress.StageStart is called inside the stages loop
	// (step 10) before each RunStage; progress.TaskStart/TaskDone are called
	// inside this closure around t.Run so every task completion is reflected.
	//
	// XCUT-07: the closure passes only t.Name() and badge/duration to progress —
	// never result.Stdout, result.Stderr, or any other tool output.
	progress := ui.NewStageProgress(app.UI.W, app.UI.NoColor, app.UI.Verbosity)
	sched.RunTask = func(rctx context.Context, t task.Task) (task.Result, error) {
		progress.TaskStart(t.Name())
		started := time.Now()
		result, err := t.Run(rctx, app)
		// GAP-3 duration fix: Tasks do not all populate Result.Duration, so the
		// UI showed "0s". Fall back to the measured wall-clock when unset.
		dur := result.Duration
		if dur <= 0 {
			dur = time.Since(started)
		}
		badge := badgeForStatus(result.Status)
		progress.TaskDone(t.Name(), badge, dur)
		return result, err
	}

	// Step 7: Launch Axiom fleet if applicable.
	var axiomBE *backend.AxiomBackend
	if fb, ok := chosenBackend.(*backend.FailoverBackend); ok {
		if abe, ok := fb.Primary.(*backend.AxiomBackend); ok {
			axiomBE = abe
		}
	}
	if axiomBE != nil {
		if err := axiomBE.Launch(ctx); err != nil {
			return fmt.Errorf("subs: axiom launch: %w", err)
		}
		defer func() { _ = axiomBE.Shutdown(context.Background()) }()
	}

	// Step 8: Build the task DAG.
	allTasks, err := task.Default.Build()
	if err != nil {
		return fmt.Errorf("subs: task DAG: %w", err)
	}

	// Step 9: Dry-run mode — list tasks and exit.
	if dryRun {
		return printDryRun(cmd, allTasks, cfg)
	}

	// Step 10: Sequential 5-stage RunStage execution.
	// Fixes REVIEWS Scheduler-ordering finding: RunStage fires ALL tasks in a slice
	// concurrently under the MaxConcurrent semaphore. DependsOn ordering is NOT
	// enforced within a single RunStage call. Sequential stage calls provide ordering.
	//
	// GAP-2: stageSpec.module carries the scheduler module name. The passive stage
	// uses "subdomains.passive" → PolicyBestEffort (independent sources; single-source
	// flakiness is non-fatal). All other stages use "subdomains" → PolicyFailFast
	// (the spine — empty resolved list breaks every downstream stage).
	// stageSpec.module → scheduler FailurePolicy (policyFor). stageSpec.merge →
	// the staging-file PREFIX that MergeStage globs (inputs/<merge>.*.txt); this
	// is intentionally distinct from the display name because resolve-stage Tasks
	// write inputs/resolved.*.txt (with a 'd'), not resolve.*.txt — passing the
	// display name "resolve" to MergeStage globbed nothing and silently dropped
	// the entire resolved set (live-run bug). merge="" means "no subdomains
	// artefact merge for this stage" (enrichment writes its own artefacts).
	//
	// FAILURE POLICY (live-run follow-up to GAP-2): only the resolve SPINE
	// (active/brute/resolvers.health/dns/tls/srv) is fail_fast — an empty
	// resolved set breaks every downstream stage. Everything else is best_effort
	// (module "subdomains.passive"/"subdomains.aux") so a flaky source, an
	// uninstalled tool, or a panicking aux tool degrades instead of aborting —
	// matching bash v1. ScopeError/OutOfScope still re-propagate even in
	// best_effort (scheduler errors.Is(ErrScope) guard is policy-keyed).
	type stageSpec struct {
		name     string
		module   string // scheduler module name → determines FailurePolicy via policyFor
		merge    string // staging-file prefix for MergeStage glob ("" = skip merge)
		prefixes []string
	}

	stages := []stageSpec{
		{
			name:   "passive",
			module: "subdomains.passive", // best_effort — independent sources
			merge:  "passive",
			prefixes: []string{
				"subdomains.passive.",
			},
		},
		{
			name:   "resolve",
			module: "subdomains", // fail_fast — TRUE SPINE
			merge:  "resolved",   // Tasks write inputs/resolved.*.txt
			prefixes: []string{
				"subdomains.active",
				"subdomains.tls",
				"subdomains.noerror",
				"subdomains.dns",
				"subdomains.srv",
				"subdomains.ptr",
				"subdomains.brute",
				"subdomains.resolvers.",
			},
		},
		{
			name:   "discovery",
			module: "subdomains.aux", // best_effort — aux independent discovery
			merge:  "resolved",       // scraping/analytics/ns_delegation write resolved.*.txt
			prefixes: []string{
				"subdomains.scraping",
				"subdomains.analytics",
				"subdomains.ns_delegation",
			},
		},
		{
			name:   "permut",
			module: "subdomains.aux", // best_effort — permutations augment, never gate
			merge:  "permut",
			prefixes: []string{
				"subdomains.permut",
				"subdomains.recursive.",
			},
		},
		{
			name:   "enrichment",
			module: "subdomains.aux", // best_effort — post-processing; own artefacts
			merge:  "",               // takeover/buckets/asn/geo write their own *.jsonl
			prefixes: []string{
				"subdomains.takeover.",
				"subdomains.buckets",
				"subdomains.asn",
				"subdomains.geo",
				"subdomains.zonetransfer",
			},
		},
	}

	for _, stage := range stages {
		stageSlice := filterByModuleAndEnabled(allTasks, "subdomains", cfg, stage.prefixes)

		// GAP-3: signal stage beginning to the progress UI.
		progress.StageStart(stage.name, len(stageSlice))

		if err := sched.RunStage(ctx, stage.module, stageSlice); err != nil {
			return fmt.Errorf("subs: stage %s: %w", stage.name, err)
		}

		// B2 fix: after enrichment stage, merge takeover staging files into findings.jsonl.
		if stage.name == "enrichment" {
			if mergeErr := mergeTakeoverFindings(ctx, app); mergeErr != nil {
				app.Log.Warn("subs: takeover_merge_failed", "err", mergeErr)
				// Non-fatal: continue with best-effort findings.
			}
		}

		// MergeStage: consolidate stage outputs into subdomains.jsonl + <merge>.merged.txt.
		// Non-fatal: log and continue — subsequent stages use best-effort input set.
		if stage.merge != "" {
			if mergeErr := subdomains.MergeStage(ctx, app, stage.merge); mergeErr != nil {
				app.Log.Warn("subs: merge_stage_failed", "stage", stage.name, "merge", stage.merge, "err", mergeErr)
			}
		}

		// GAP-3: signal stage completion with the running subdomain count so the
		// user sees live cumulative results per stage (not a static "0 found").
		progress.StageDone(stage.name, countFileLines(filepath.Join(workdir, "artefacts", "subdomains.jsonl")))
	}

	// Final consolidation: per-stage MergeStage calls only REPLACE subdomains.jsonl
	// (Tree.Append truncates), so write the cumulative UNION of every stage's
	// staging files once at the end. Non-fatal.
	if mergeErr := subdomains.MergeAllSubdomains(ctx, app); mergeErr != nil {
		app.Log.Warn("subs: final_union_merge_failed", "err", mergeErr)
	}

	// GAP-3 results summary: per-artefact counts + output paths + a pointer to
	// run.log when logs were routed there. Replaces the old "no results shown".
	printSubsSummary(os.Stderr, workdir, runLogPath, verbosity)

	return nil
}

// countFileLines returns the number of non-empty lines in path, or 0 if the
// file does not exist / cannot be read. Used for live subdomain counts.
func countFileLines(path string) int {
	f, err := os.Open(path) //nolint:gosec // path derived from validated workdir
	if err != nil {
		return 0
	}
	defer f.Close() //nolint:errcheck
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	return n
}

// printSubsSummary writes an end-of-run results table to w: one row per
// produced artefact (subdomains/findings/buckets/asns/hosts) with its count
// and path, plus a pointer to run.log when logs were routed off the terminal.
// Suppressed entirely in quiet mode.
func printSubsSummary(w *os.File, workdir, runLogPath string, verbosity ui.Verbosity) {
	if verbosity == ui.VerbosityQuiet {
		return
	}
	artefacts := []struct{ label, file string }{
		{"subdomains", "subdomains.jsonl"},
		{"findings", "findings.jsonl"},
		{"buckets", "buckets.jsonl"},
		{"asns", "asns.jsonl"},
		{"hosts", "hosts.jsonl"},
	}
	fmt.Fprintf(w, "\n  ── results ──────────────────────────────\n")
	for _, a := range artefacts {
		p := filepath.Join(workdir, "artefacts", a.file)
		n := countFileLines(p)
		if n == 0 {
			continue // skip empty/absent artefacts to keep the summary tight
		}
		fmt.Fprintf(w, "  %-11s %6d   %s\n", a.label, n, p)
	}
	fmt.Fprintf(w, "  workspace   %s\n", workdir)
	if runLogPath != "" {
		fmt.Fprintf(w, "  logs        %s\n", runLogPath)
	}
	fmt.Fprintf(w, "  ─────────────────────────────────────────\n")
}

// printDryRun lists the tasks that would run per stage and returns nil.
func printDryRun(cmd *cobra.Command, allTasks []task.Task, cfg *config.Config) error {
	// stageSpec mirrors the struct in runSubsCmd (same module field for consistency).
	// Policy is unused in dry-run but the field keeps struct shapes aligned.
	type stageSpec struct {
		name     string
		module   string
		prefixes []string
	}
	stages := []stageSpec{
		{"passive", "subdomains.passive", []string{"subdomains.passive."}},
		{"resolve", "subdomains", []string{"subdomains.active", "subdomains.tls", "subdomains.noerror", "subdomains.dns", "subdomains.srv", "subdomains.ptr", "subdomains.brute", "subdomains.resolvers."}},
		{"discovery", "subdomains.aux", []string{"subdomains.scraping", "subdomains.analytics", "subdomains.ns_delegation"}},
		{"permut", "subdomains.aux", []string{"subdomains.permut", "subdomains.recursive."}},
		{"enrichment", "subdomains.aux", []string{"subdomains.takeover.", "subdomains.buckets", "subdomains.asn", "subdomains.geo", "subdomains.zonetransfer"}},
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

// newWebCmd — Phase 5 (Web Pipeline E2E). Stubbed per D-02.
func newWebCmd() *cobra.Command {
	return newStubCmd("web", "Run web probing + analysis (httpx + screenshots + nuclei + fuzz + JS)")
}

// newVulnsCmd — Phase 6 (Vulnerability Scanning E2E). Stubbed per D-02.
func newVulnsCmd() *cobra.Command {
	return newStubCmd("vulns", "Run vulnerability scanning (XSS, SQLi, SSRF, LFI, SSTI, etc.)")
}

// newOSINTCmd — Phase 7 (OSINT E2E). Stubbed per D-02.
func newOSINTCmd() *cobra.Command {
	return newStubCmd("osint", "Run OSINT collection (dorks, GitHub leaks, emails, cloud, etc.)")
}

// newZenCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newZenCmd() *cobra.Command {
	return newStubCmd("zen", "Run zen mode (minimal noise — passive only + safe probes)")
}

// newDeepCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newDeepCmd() *cobra.Command {
	return newStubCmd("deep", "Run deep mode (all + recursive subdomain enum + advanced fuzz)")
}

// newMonitorCmd — Phase 10 (Monitor + Reporting). Stubbed per D-02.
func newMonitorCmd() *cobra.Command {
	return newStubCmd("monitor", "Run monitor loop (periodic re-scan with diff notifications)")
}

// newReportCmd — Phase 10 (Monitor + Reporting). Stubbed per D-02.
func newReportCmd() *cobra.Command {
	return newStubCmd("report", "Generate report from prior scan workspace")
}

// newMCPCmd — Phase 8 (MCP Server). Stubbed per D-02.
func newMCPCmd() *cobra.Command {
	return newStubCmd("mcp", "Run MCP server (Model Context Protocol — SSE multiplexing)")
}

// newMigrateCmd — Phase 11 (Installer + Cross-Platform). Stubbed per D-02.
func newMigrateCmd() *cobra.Command {
	return newStubCmd("migrate", "Migrate v1 reconftw.cfg to v2 reconftw.toml")
}

// newInstallCmd — Phase 11 (Installer + Cross-Platform). Stubbed per D-02.
func newInstallCmd() *cobra.Command {
	return newStubCmd("install", "Install or update reconFTW tool dependencies (per tools.lock)")
}
