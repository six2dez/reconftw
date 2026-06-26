// stub_subcommands.go — stubbed v2 subcommand constructors per D-01 + D-02.
//
// Source: ADR 0002 §8.1 (subcommand inventory) + 03-CONTEXT.md D-01 / D-02.
//
// All stubbed subcommands share the same shape — Use/Short/Long populate
// from the constants table below; RunE returns stubNotImplemented(cmd, phase, name).
// Phase 4-12 implementers replace the RunE body without touching the CLI plumbing.
//
// Subcommand inventory (as of Phase 8 Wave 3):
//
//	stubbed  (11):  recon, all, passive, zen, deep,
//	                monitor, report, migrate, install    — D-02 exit 64
//	                subs, web, vulns, osint              — Phase 4-7 real implementations
//	working  (4):   version, health-check, mcp          — D-04 / Phase 8 real implementations
//	hidden   (1):   kernel-demo                         — W16 / ADR §0 D-07 (deleted Phase 4)

package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/report"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/core/ui"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
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
	// recon, all, passive, zen, deep — implemented in composite_subcommands.go (Phase 9).
	"subs":    {4, "Subdomains E2E + Axiom Integration"},
	"web":     {5, "Web Pipeline E2E"},
	"vulns":   {6, "Vulnerability Scanning E2E"},
	"osint":   {7, "OSINT E2E"},
	"monitor": {10, "Monitor Mode + Reporting + Notifications"},
	"report":  {10, "Monitor Mode + Reporting + Notifications"},
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

// newReconCmd, newAllCmd, newPassiveCmd, newZenCmd, newDeepCmd — Phase 9.
// Real implementations live in composite_subcommands.go. Stubs removed.

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

// runSubsCmd is the extracted RunE body for newSubsCmd. Thin wrapper over
// handlers.RunSubsAsync — extracts CLI flags and delegates the full pipeline.
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

	// CLI creates its own per-invocation scheduler (the shared process-level
	// scheduler is reserved for MCP server mode — D-03 / Pitfall 3).
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	// dryRunTasks holds the task list when --dry-run is set; populated in AfterBoot.
	var dryRunTaskList []task.Task
	var dryRunCfg *config.Config
	var summaryWorkdir, summaryRunLog string
	var summaryVerbosity ui.Verbosity

	afterBoot := func(boot handlers.AppBoot) {
		app := boot.App
		workdir := boot.WorkDir
		cfg := boot.Cfg
		summaryWorkdir = workdir
		summaryVerbosity = ui.Verbosity(cfg.Output.Verbosity)

		// Update scheduler limits from the loaded config.
		sched.MaxConcurrent = cfg.Concurrency.MaxJobs
		sched.HeartbeatSeconds = cfg.Concurrency.HeartbeatSeconds

		// Dry-run mode: disable checkpoint bypass.
		if dryRun {
			cfg.Advanced.Diff = false
			// Capture task list + cfg for dry-run printing after AfterBoot.
			if ts, err := task.Default.Build(); err == nil {
				dryRunTaskList = ts
				dryRunCfg = cfg
			}
			return
		}

		// GAP-3 log routing: route slog to <workdir>/run.log on interactive TTY
		// so stderr carries only the human UI. Redaction (XCUT-07) preserved by
		// re-registering secrets on the file logger's redactor.
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
				// f is intentionally not closed here — it lives for the scan duration.
				// The file handle is leaked after the subcommand returns, which is
				// acceptable for a single-invocation CLI process (OS reclaims on exit).
				_ = f
			}
		}

		// Launch Axiom fleet if applicable.
		var axiomBE *backend.AxiomBackend
		if fb, ok := boot.ChosenBackend.(*backend.FailoverBackend); ok {
			if abe, ok := fb.Primary.(*backend.AxiomBackend); ok {
				axiomBE = abe
			}
		}
		if axiomBE != nil {
			if launchErr := axiomBE.Launch(ctx); launchErr != nil {
				// Non-fatal launch failure; log and continue without Axiom.
				if app.Log != nil {
					app.Log.Warn("subs: axiom launch failed — continuing locally", "err", launchErr)
				}
			} else {
				// Register shutdown so the fleet is torn down after the scan.
				// This runs after RunSubsAsync returns (deferred in the closure scope).
				defer func() { _ = axiomBE.Shutdown(context.Background()) }() //nolint:staticcheck
			}
		}

		// Wire per-task progress UI (GAP-3). XCUT-07: only name/badge/duration passed
		// to progress — never result.Stdout, result.Stderr, or tool output.
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

	if err := handlers.RunSubsAsync(ctx, handlers.RunOptions{
		Target:       targetFlag,
		DryRun:       dryRun,
		ConfigPath:   efs.configPath,
		SecretsPath:  efs.secretsPath,
		AxiomEnabled: axiomEnabled,
		Scheduler:    sched,
		AfterBoot:    afterBoot,
	}); err != nil {
		return fmt.Errorf("subs: %w", err)
	}

	// Dry-run: print task list and return (AfterBoot populated dryRunTaskList).
	if dryRun && dryRunTaskList != nil {
		return printDryRun(cmd, dryRunTaskList, dryRunCfg)
	}

	printSubsSummary(os.Stderr, summaryWorkdir, summaryRunLog, summaryVerbosity)
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

// newWebCmd — Phase 5 (Web Pipeline E2E). Real implementation replacing D-02 stub.
//
// Wires the full web analysis pipeline:
//  1. Config load + target construction
//  2. Scheduler construction BEFORE Boot (cycle-break — checkpoint wired post-Boot)
//  3. FailoverBackend when --axiom flag is set; otherwise Boot selects LocalBackend
//  4. appctx.Boot with BootOptions{Backend: chosenBackend}
//  5. sched.Checkpoint = app.Checkpoint (B3 fix — per-tool resume operational)
//  6. sched.RunTask closure (cycle-break #2 — wired after Boot)
//  7. Optional Axiom fleet launch / shutdown
//  8. 4 sequential best_effort RunStage calls (wave1: httpx → wave2a: analysis →
//     wave2b: url-discovery → wave3: bypass/param)
//  9. MergeAllWebArtefacts after all stages (consolidates parallel staging writes)
//
// ALL stages are best_effort per D-W12 — no fail_fast anywhere in the web pipeline.
func newWebCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Run web probing + analysis (httpx + screenshots + nuclei + fuzz + JS + WAF + URLs)",
		Long: `Run the full web analysis pipeline:
  Stage 1 (probe):     httpx HTTP probe + tech detection → hosts.jsonl
  Stage 2a (analysis): nuclei, screenshot, ffuf, wafw00f, cdncheck, favirecon, VhostFinder,
                       hakoriginfinder, csprecon
  Stage 2b (urls):     katana, urlfinder, waymore, urldedup, subjs, jsluice, mantra, jsa,
                       sourcemapper
  Stage 3 (bypass):    nomore403, shortscan, Gxss, arjun

All stages are best_effort (D-W12) — pipeline completes even if individual tools fail.

Output: workspaces/<target>/artefacts/hosts.jsonl (+ findings, fuzz, waf, origins, urls)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebCmd(cmd)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	cmd.Flags().String("hosts", "", "Seed host list file (overrides prior subs artefacts)")
	return cmd
}

// runWebCmd is the extracted RunE body for newWebCmd. Thin wrapper over
// handlers.RunWebAsync — extracts CLI flags and delegates the full pipeline.
func runWebCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	targetFlag, _ := cmd.Flags().GetString("target")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	hostsFlag, _ := cmd.Flags().GetString("hosts")

	if targetFlag == "" {
		if pf := cmd.InheritedFlags().Lookup("target"); pf != nil {
			targetFlag = pf.Value.String()
		}
	}
	if targetFlag == "" {
		return fmt.Errorf("--target is required for web subcommand")
	}

	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	efs := parseEarlyFlags(os.Args[1:])
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	var dryRunTaskList []task.Task
	var dryRunCfg *config.Config
	var summaryWorkdir, summaryRunLog string
	var summaryVerbosity ui.Verbosity

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
					app.Log.Warn("web: axiom launch failed — continuing locally", "err", launchErr)
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

	if err := handlers.RunWebAsync(ctx, handlers.RunOptions{
		Target:       targetFlag,
		DryRun:       dryRun,
		ExtraFile:    hostsFlag,
		ConfigPath:   efs.configPath,
		SecretsPath:  efs.secretsPath,
		AxiomEnabled: axiomEnabled,
		Scheduler:    sched,
		AfterBoot:    afterBoot,
	}); err != nil {
		return fmt.Errorf("web: %w", err)
	}

	if dryRun && dryRunTaskList != nil {
		return printWebDryRun(cmd, dryRunTaskList, dryRunCfg)
	}

	printWebSummary(os.Stderr, summaryWorkdir, summaryRunLog, summaryVerbosity)
	return nil
}

// printWebDryRun lists the tasks that would run per stage and returns nil.
// Stage ordering mirrors the live RunE stages (CR-04 fix, plan 05-10; CR-02
// reorder so urls-dedup precedes bypass):
//
//	probe → analysis-waf [+merge waf] → analysis [+merge findings]
//	→ urls-fetch [+intermediate merge urls] → js-extract → js-analyze
//	→ urls-dedup → bypass [+merge findings]
func printWebDryRun(cmd *cobra.Command, allTasks []task.Task, cfg *config.Config) error {
	type stageSpec struct {
		name        string
		prefixes    []string
		mergeAfter  string // artefact name merged after this stage, or ""
		mergeNote   string // human-readable note about the merge call
	}
	stages := []stageSpec{
		{
			name:     "probe",
			prefixes: []string{"web.httpx"},
		},
		{
			name:       "analysis-waf",
			prefixes:   []string{"web.wafw00f", "web.cdncheck"},
			mergeAfter: "waf",
			mergeNote:  "MergeStage(\"waf\") — merges wafw00f+cdncheck staging",
		},
		{
			name:       "analysis",
			prefixes:   []string{"web.nuclei", "web.screenshot", "web.ffuf", "web.favirecon", "web.vhostfinder", "web.hakoriginfinder", "web.csprecon"},
			mergeAfter: "findings",
			mergeNote:  "MergeStage(\"findings\") — merges nuclei staging",
		},
		{
			name:       "urls-fetch",
			prefixes:   []string{"web.katana", "web.urlfinder", "web.waymore"},
			mergeAfter: "urls",
			mergeNote:  "intermediate MergeStage(\"urls\") — populates artefacts/urls.jsonl for js-extract input",
		},
		{
			name:     "js-extract",
			prefixes: []string{"web.subjs", "web.sourcemapper"},
		},
		{
			name:     "js-analyze",
			prefixes: []string{"web.jsluice", "web.jsa", "web.mantra"},
			// No intermediate urls merge here: urldedup (urls-dedup stage) IS the merge step.
		},
		{
			name:     "urls-dedup",
			prefixes: []string{"web.urldedup"},
			// urldedup calls Tree.Append("urls") once after semantic dedup — no MergeStage needed.
			// CR-02: runs BEFORE bypass so gxss/arjun read the final deduped urls.jsonl.
		},
		{
			name:       "bypass",
			prefixes:   []string{"web.nomore403", "web.shortscan", "web.gxss", "web.arjun"},
			mergeAfter: "findings",
			mergeNote:  "MergeStage(\"findings\") — merges nomore403/shortscan/gxss/arjun staging",
		},
	}
	fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] web pipeline stages:")
	for i, stage := range stages {
		filtered := filterByModuleAndEnabled(allTasks, "web", cfg, stage.prefixes)
		fmt.Fprintf(cmd.OutOrStdout(), "  Stage %d (%s): %d task(s)\n", i+1, stage.name, len(filtered))
		for _, t := range filtered {
			fmt.Fprintf(cmd.OutOrStdout(), "    - %s: %s\n", t.Name(), t.Description())
		}
		if stage.mergeAfter != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "    [after stage] %s\n", stage.mergeNote)
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "  [final sweep] MergeStage(\"waf\"), MergeStage(\"findings\") — safety backstop (urls excluded: urldedup is sole urls writer)")
	return nil
}

// printWebSummary writes an end-of-run results table to w: one row per
// produced artefact with its count and path.
func printWebSummary(w *os.File, workdir, runLogPath string, verbosity ui.Verbosity) {
	if verbosity == ui.VerbosityQuiet {
		return
	}
	artefacts := []struct{ label, file string }{
		{"hosts", "hosts.jsonl"},
		{"findings", "findings.jsonl"},
		{"fuzz", "fuzz.jsonl"},
		{"waf", "waf.jsonl"},
		{"origins", "origins.jsonl"},
		{"urls", "urls.jsonl"},
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

// newVulnsCmd — Phase 6 (Vulnerability Scanning E2E). Real implementation replacing D-02 stub.
//
// Wires the full vulnerability scanning pipeline:
//  1. Config load + target construction
//  2. Scheduler construction BEFORE Boot (cycle-break — checkpoint wired post-Boot)
//  3. FailoverBackend when --axiom flag is set; otherwise Boot selects LocalBackend
//  4. appctx.Boot with BootOptions{Backend: chosenBackend}
//  5. sched.Checkpoint = app.Checkpoint (B3 fix — per-tool resume operational)
//  6. sched.RunTask closure (cycle-break #2 — wired after Boot)
//  7. Optional Axiom fleet launch / shutdown
//  8. 4 sequential best_effort RunStage calls:
//     gf-classify → injection → oob-advanced → dast-extended
//  9. MergeAllVulnsArtefacts after all stages
//
// ALL stages are best_effort per D-V7 — no fail_fast anywhere in the vulns pipeline.
// GFTask is the DAG root; empty gf bucket → downstream runs with empty input → completes.
func newVulnsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vulns",
		Short: "Run vulnerability scanning (XSS, SQLi, SSRF, LFI, SSTI, CRLF, smuggling, etc.)",
		Long: `Run the full vulnerability scanning pipeline:
  Stage 1 (gf-classify):  URL gf-pattern classification -> per-class bucket files
  Stage 2 (injection):    dalfox (XSS), sqlmap/ghauri (SQLi), crlfuzz (CRLF),
                          commix (CMDi), TInjA/SSTImap (SSTI), LFI param-fuzz
  Stage 3 (oob-advanced): SSRF+interactsh OOB, smugglex (HTTP smuggling),
                          WCVS+toxicache (web cache), second-order injection
  Stage 4 (dast-extended): nuclei DAST, fuzzparams, 4xx-bypass, testssl,
                            fray, GraphQL, gRPC, LLM probe, WebSocket checks

All stages are best_effort (D-V7) — pipeline completes even if individual tools fail.
Run "reconftw web" first, or pass --urls to seed the URL corpus (D-V5).

Master gate: vulns.enabled defaults false in config (D-V7). Running this subcommand
is the explicit opt-in and bypasses the master gate.

Output: workspaces/<target>/artefacts/findings.jsonl`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVulnsCmd(cmd)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	cmd.Flags().String("urls", "", "Seed URL list file (overrides prior web artefacts; D-V5)")
	return cmd
}

// runVulnsCmd is the extracted RunE body for newVulnsCmd. Thin wrapper over
// handlers.RunVulnsAsync — extracts CLI flags and delegates the full pipeline.
func runVulnsCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	targetFlag, _ := cmd.Flags().GetString("target")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	urlsFlag, _ := cmd.Flags().GetString("urls")

	if targetFlag == "" {
		if pf := cmd.InheritedFlags().Lookup("target"); pf != nil {
			targetFlag = pf.Value.String()
		}
	}
	if targetFlag == "" {
		return fmt.Errorf("--target is required for vulns subcommand")
	}

	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	efs := parseEarlyFlags(os.Args[1:])
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	var dryRunTaskList []task.Task
	var dryRunCfg *config.Config
	var summaryWorkdir, summaryRunLog string
	var summaryVerbosity ui.Verbosity

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
					app.Log.Warn("vulns: axiom launch failed — continuing locally", "err", launchErr)
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

	if err := handlers.RunVulnsAsync(ctx, handlers.RunOptions{
		Target:       targetFlag,
		DryRun:       dryRun,
		ExtraFile:    urlsFlag,
		ConfigPath:   efs.configPath,
		SecretsPath:  efs.secretsPath,
		AxiomEnabled: axiomEnabled,
		Scheduler:    sched,
		AfterBoot:    afterBoot,
	}); err != nil {
		return fmt.Errorf("vulns: %w", err)
	}

	if dryRun && dryRunTaskList != nil {
		return printVulnsDryRun(cmd, dryRunTaskList, dryRunCfg)
	}

	printVulnsSummary(os.Stderr, summaryWorkdir, summaryRunLog, summaryVerbosity)
	return nil
}

// printVulnsDryRun lists the tasks that would run per stage and returns nil.
func printVulnsDryRun(cmd *cobra.Command, allTasks []task.Task, cfg *config.Config) error {
	type stageSpec struct {
		name     string
		prefixes []string
	}
	stages := []stageSpec{
		{"gf-classify", []string{"vulns.gf"}},
		{"injection", []string{"vulns.xss", "vulns.sqli", "vulns.lfi", "vulns.ssti", "vulns.crlf", "vulns.cmdi"}},
		{"oob-advanced", []string{"vulns.ssrf", "vulns.smuggling", "vulns.webcache_wcvs", "vulns.webcache_toxicache", "vulns.second_order"}},
		{"dast-extended", []string{"vulns.nuclei_dast", "vulns.fuzzparams", "vulns.bypass4xx", "vulns.testssl", "vulns.fray", "vulns.graphql", "vulns.grpc", "vulns.llm", "vulns.websocket"}},
	}
	fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] vulns pipeline stages:")
	for i, stage := range stages {
		filtered := filterByModuleAndEnabled(allTasks, "vulns", cfg, stage.prefixes)
		fmt.Fprintf(cmd.OutOrStdout(), "  Stage %d (%s): %d task(s)\n", i+1, stage.name, len(filtered))
		for _, t := range filtered {
			fmt.Fprintf(cmd.OutOrStdout(), "    - %s: %s\n", t.Name(), t.Description())
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "  [final] MergeAllVulnsArtefacts(\"findings\")")
	return nil
}

// printVulnsSummary writes an end-of-run results table to w: one row per
// produced artefact with its count and path.
func printVulnsSummary(w *os.File, workdir, runLogPath string, verbosity ui.Verbosity) {
	if verbosity == ui.VerbosityQuiet {
		return
	}
	artefacts := []struct{ label, file string }{
		{"findings", "findings.jsonl"},
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

// newOSINTCmd — Phase 7 (OSINT E2E). Wires the real RunE: Build → best_effort
// RunStage → MergeAllOSINTArtefacts. Root-domain/company-seeded (D-O1) — needs
// NO --urls corpus. Master gate osint.enabled defaults TRUE (D-O9), but running
// this subcommand is the explicit opt-in.
func newOSINTCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "osint",
		Short: "Run OSINT collection (dorks, GitHub leaks, emails, cloud, etc.)",
		Long: `Run the OSINT collection pipeline (OSINT-01..16):
  domain_info (whois + DNS records), ip_info (CIDR/ASN/geo), emails,
  GitHub dorks/repos/leaks/actions, cloud bucket enum, Postman/Swagger leaks,
  email-spoofing posture, Microsoft tenant recon, CMS fingerprint, GraphQL
  introspection, custom wordlists, Google dorking, third-party misconfig.

OSINT is root-domain / company-seeded (D-O1) — it needs NO --urls corpus and
NEVER triggers a subs/web run. metadata/apileaks opportunistically read
workspace artefacts IF present (D-O2).

All sources are best_effort (D-O8/ARCH-09) — a tool failing or a missing API
key logs a warning and the run COMPLETES. Heavy/noisy sources (GitHub dorking,
cloud enum, Google dorking) ship with v1 conservative caps.

Master gate: osint.enabled defaults TRUE in config (D-O9 — the deliberate
inversion of vulns' default-off, matching v1 OSINT=true). Running this
subcommand is the explicit opt-in.

Output: workspaces/<target>/artefacts/findings.jsonl (osint-class, XCUT-07 redacted)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOSINTCmd(cmd)
		},
	}
	cmd.Flags().String("target", "", "Target domain")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	return cmd
}

// runOSINTCmd is the RunE body for newOSINTCmd. Thin wrapper over
// handlers.RunOSINTAsync — extracts CLI flags and delegates the full pipeline.
func runOSINTCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	targetFlag, _ := cmd.Flags().GetString("target")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	if targetFlag == "" {
		if pf := cmd.InheritedFlags().Lookup("target"); pf != nil {
			targetFlag = pf.Value.String()
		}
	}
	if targetFlag == "" {
		return fmt.Errorf("--target is required for osint subcommand")
	}

	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	efs := parseEarlyFlags(os.Args[1:])
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	var dryRunTaskList []task.Task
	var dryRunCfg *config.Config
	var summaryWorkdir, summaryRunLog string
	var summaryVerbosity ui.Verbosity

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
					app.Log.Warn("osint: axiom launch failed — continuing locally", "err", launchErr)
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

	if err := handlers.RunOSINTAsync(ctx, handlers.RunOptions{
		Target:       targetFlag,
		DryRun:       dryRun,
		ConfigPath:   efs.configPath,
		SecretsPath:  efs.secretsPath,
		AxiomEnabled: axiomEnabled,
		Scheduler:    sched,
		AfterBoot:    afterBoot,
	}); err != nil {
		return fmt.Errorf("osint: %w", err)
	}

	if dryRun && dryRunTaskList != nil {
		return printOSINTDryRun(cmd, dryRunTaskList, dryRunCfg)
	}

	printVulnsSummary(os.Stderr, summaryWorkdir, summaryRunLog, summaryVerbosity)
	return nil
}

// osintStageSpec describes one sequential osint execution stage: tasks whose
// name matches any prefix run CONCURRENTLY within the stage; stages run in slice
// order. It mirrors the local stageSpec used by the web/vulns pipelines but is
// package-level so the TestOSINTStageOrderHonorsDependsOn guard can read the
// SAME ordering the production runOSINTCmd executes (single source of truth — no
// duplicated ordering literal).
type osintStageSpec struct {
	name     string
	prefixes []string
}

// osintStages is the authoritative ordered osint pipeline (GAP-01/CR-01 fix).
//
// D-O1/D-O8/ARCH-09: most osint tasks have no DependsOn and run in parallel
// within the single "osint" stage. Only the github_repos→github_leaks fold
// (D-O10) needs sequencing: github_repos runs in a pre-stage that completes
// before the "osint" stage containing github_leaks, so github_leaks' trufflehog
// scan reads the FULLY-written inputs/github_repos.txt instead of a partial list.
//
// github_repos appears in EXACTLY ONE stage. The "osint" stage uses an explicit
// prefix list (NOT a catch-all "osint." prefix) so github_repos is not matched
// twice — matching the readable explicit-prefix approach the web/vulns stages use.
func osintStages() []osintStageSpec {
	return []osintStageSpec{
		{
			// Pre-stage: produce inputs/github_repos.txt before any reader runs.
			// github_leaks DependsOn ["osint.github_repos"] — this stage MUST
			// complete (RunStage returns) before the "osint" stage below.
			name:     "github-repos",
			prefixes: []string{"osint.github_repos"},
		},
		{
			// Main stage: every OTHER osint task, run in parallel under the
			// scheduler semaphore (D-O1). Includes github_leaks, which now reads
			// the fully-written repo list. Explicit prefixes (NOT "osint.")
			// deliberately EXCLUDE osint.github_repos so it runs exactly once.
			name: "osint",
			prefixes: []string{
				"osint.domain_info",
				"osint.ip_info",
				"osint.emails",
				"osint.spoofy",
				"osint.github_dorks",
				"osint.gitdorks",
				"osint.github_leaks",
				"osint.github_actions",
				"osint.cloud_enum",
				"osint.postman",
				"osint.swagger",
				"osint.misconfig",
				"osint.msftrecon",
				"osint.cmseek",
				"osint.favirecon",
				"osint.gqlspection",
				"osint.cewler",
				"osint.xnldorker",
				"osint.metadata",
			},
		},
	}
}

// printOSINTDryRun lists the osint tasks that would run, in sequential stage
// order, and returns nil. Mirrors the ordered web dry-run so --dry-run reflects
// the REAL execution order (github-repos pre-stage before the github_leaks stage).
func printOSINTDryRun(cmd *cobra.Command, allTasks []task.Task, cfg *config.Config) error {
	fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] osint pipeline (sequential best_effort stages):")
	for _, stage := range osintStages() {
		filtered := filterByModuleAndEnabled(allTasks, "osint", cfg, stage.prefixes)
		fmt.Fprintf(cmd.OutOrStdout(), "  Stage (%s): %d task(s)\n", stage.name, len(filtered))
		for _, t := range filtered {
			fmt.Fprintf(cmd.OutOrStdout(), "    - %s: %s\n", t.Name(), t.Description())
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "  [final] MergeAllOSINTArtefacts(\"findings\")")
	return nil
}

// newMonitorCmd — Phase 10 real implementation replacing the D-02 stub.
//
// Runs a periodic re-scan loop against a target, diffing each cycle against
// the previous scan via DiffBetweenScans/DiffScansFindings/DiffScansHosts/
// DiffScansURLs sqlc queries. New findings are dispatched via EventFilter
// (honoring notifications.events TOML rules), coalesced into digests, and
// flushed at cycle-end via the Flusher interface.
//
// SIGINT (Pitfall 7): signal.NotifyContext is wired here in the CLI layer,
// NOT inside RunMonitorAsync. The context passed down is already signal-aware.
func newMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Run monitor loop (periodic re-scan with diff notifications)",
		Long: `Run a periodic re-scan loop that diffs each cycle against the previous scan.

After each scan completes, new subdomains, hosts, URLs and findings are
compared against the prior scan baseline. New critical findings are dispatched
via EventFilter (honoring the notifications.events TOML rules) and coalesced
into a per-channel digest before sending.

SIGINT (Ctrl-C): the current task completes, checkpoints are written, and the
monitor loop exits cleanly. No partial scan state is lost.

Examples:
  reconftw monitor --target example.com --interval 6h
  reconftw monitor --target example.com --interval 30m --monitor-cycles 3
  reconftw monitor --target example.com --incremental --interval 12h`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMonitorCmd(cmd)
		},
	}
	cmd.Flags().String("target", "", "Target domain (required)")
	cmd.Flags().String("interval", "6h", "Scan interval between cycles (e.g. 6h, 30m, 1h30m)")
	cmd.Flags().Int("monitor-cycles", 0, "Number of cycles to run (0 = infinite)")
	cmd.Flags().Bool("incremental", false, "Re-run only on new assets from diff (D-04/D-05)")
	cmd.Flags().Bool("dry-run", false, "Preview tasks without executing tools")
	cmd.Flags().String("recon-mode", "recon", "Pipeline mode: recon or all")
	return cmd
}

// runMonitorCmd is the RunE body for newMonitorCmd.
//
// SIGINT handling (Pitfall 7): signal.NotifyContext is called HERE in the
// CLI layer. RunMonitorAsync receives a context that is already signal-aware
// and must NOT call signal.NotifyContext internally.
func runMonitorCmd(cmd *cobra.Command) error {
	// Wire SIGINT/SIGTERM at the CLI layer (Pitfall 7 fix).
	// The context passed to RunMonitorAsync is already signal-aware.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	targetFlag, _ := cmd.Flags().GetString("target")
	if targetFlag == "" {
		return fmt.Errorf("--target is required for monitor subcommand")
	}

	intervalStr, _ := cmd.Flags().GetString("interval")
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return fmt.Errorf("monitor: invalid --interval %q: %w", intervalStr, err)
	}

	maxCycles, _ := cmd.Flags().GetInt("monitor-cycles")
	incremental, _ := cmd.Flags().GetBool("incremental")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	reconModeStr, _ := cmd.Flags().GetString("recon-mode")

	reconMode := handlers.ModeRecon
	if reconModeStr == "all" {
		reconMode = handlers.ModeAll
	}

	efs := parseEarlyFlags(os.Args[1:])
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	// commonAfterBoot wires scheduler limits, log routing, and per-task
	// progress UI — same pattern as composite subcommands.
	capture := &dryRunCapture{}
	afterBoot := func(boot handlers.AppBoot) {
		commonAfterBoot(ctx, boot, sched, dryRun, "monitor", capture)
	}

	monOpts := handlers.MonitorOptions{
		Mode:        reconMode,
		Interval:    interval,
		MaxCycles:   maxCycles,
		Incremental: incremental,
	}

	// FlushNow is wired inside RunMonitorAsync via the notifier.Flusher interface
	// assertion on boot.App.Notify (*notifier.Multi implements Flusher via Plan 02).
	// The CLI layer does NOT need to wire or inject a coalescer reference.
	return handlers.RunMonitorAsync(ctx, handlers.RunOptions{
		Target:      targetFlag,
		DryRun:      dryRun,
		ConfigPath:  efs.configPath,
		SecretsPath: efs.secretsPath,
		Scheduler:   sched,
		AfterBoot:   afterBoot,
	}, monOpts)
}

// newReportCmd — Phase 10 (Monitor + Reporting). Real implementation replacing D-02 stub.
//
// Opens store.db read-only for the given target, resolves the latest completed scan
// (or a specific scan via --scan-id), and writes all report formats to reports/
// without re-running scans (D-03, REPORT-08).
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate report from prior scan workspace without re-running scans",
		Long: `Generate all report formats from a prior scan stored in store.db.

Opens store.db in the configured data directory read-only, resolves the latest
completed scan for the target (or a specific scan via --scan-id), and writes:
  reports/report.html    — self-contained offline HTML dashboard
  reports/findings.sarif — SARIF 2.1.0 findings export
  reports/hotlist.json   — top N findings by risk score (D-08)
  reports/faraday.json   — Faraday fplugin-compatible JSON (when enabled)
  reports/notes.jsonl    — canonical empty JSONL artefact (REPORT-01)
  reports/findings.csv   — CSV findings export
  reports/hosts.csv      — CSV hosts/subdomains export
  reports/urls.csv       — CSV URLs export

No scan execution occurs. Use reconftw recon --target <domain> to run a scan first.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReportCmd(cmd)
		},
	}
	cmd.Flags().String("target", "", "Target domain (required)")
	cmd.Flags().String("scan-id", "", "Specific scan ID to render (default: latest completed)")
	cmd.Flags().Bool("allow-partial", false, "Also accept incomplete scans (use with --scan-id)")
	return cmd
}

func runReportCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	targetFlag, _ := cmd.Flags().GetString("target")
	if targetFlag == "" {
		return fmt.Errorf("--target is required for the report subcommand")
	}
	scanIDFlag, _ := cmd.Flags().GetString("scan-id")

	efs := parseEarlyFlags(os.Args[1:])
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		return fmt.Errorf("report: config load: %w", err)
	}

	// Resolve the data directory where store.db lives.
	dataDir := cfg.Paths.DataDir
	if dataDir == "" {
		dataDir = "data"
	}

	rdct := &log.Redactor{}
	registerSecrets(cfg, rdct)

	renderer, err := report.NewReportRenderer(dataDir, cfg, slog.Default(), rdct)
	if err != nil {
		return fmt.Errorf("report: open renderer: %w", err)
	}
	defer renderer.Close() //nolint:errcheck

	if err := renderer.RenderAll(ctx, targetFlag, scanIDFlag); err != nil {
		return fmt.Errorf("report: render: %w", err)
	}

	reportsDir := filepath.Join(dataDir, "reports")
	fmt.Fprintf(cmd.OutOrStdout(), "reports written to: %s\n", reportsDir)
	return nil
}

// newMigrateCmd — Phase 11 (Installer + Cross-Platform). Stubbed per D-02.
func newMigrateCmd() *cobra.Command {
	return newStubCmd("migrate", "Migrate v1 reconftw.cfg to v2 reconftw.toml")
}

// The `install` subcommand is now a real implementation in
// cmd/reconftw/install.go — its exit-64 stub was removed in Phase 11 plan 03.
