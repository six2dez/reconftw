// stateful_subcommands.go — the three stateful utility subcommands:
//   - gen-resolvers (MODE-08, D-04): regenerate DNS resolver list via dnsvalidator
//   - refresh-cache (MODE-07, D-05): invalidate + rebuild DNS/ASN/geo cached data
//   - quick-rescan  (MODE-06, D-06): checkpoint-bypass + scan baseline record
//
// Registration: all three are added in root.go alongside the composite subcommands.
//
// D-06 THIN: quick-rescan sets ONLY cfg.Advanced.Diff=true via ConfigTransform.
// It does NOT set cfg.Advanced.QuickRescan and does NOT call DiffBetweenScans
// (that is Phase 10).
//
// T-15-12-03 (Phase 15): quick-rescan no longer writes a "baseline" scan row of
// its own. See the note on newQuickRescanCmd for why that row was both orphaned
// and useless.
//
// T-09-04-02 mitigation: refresh-cache file deletion is scoped to workdir/inputs/
// only (derived from cfg.Paths.DataDir + domain workspace) — no absolute path
// deletion possible outside the workspace.
//
// T-09-04-03 mitigation: target string passes through resolveTarget (same
// validation as all other subcommands) before being stored.
//
// F14 / T-15-12-02 (Phase 15): all three commands read --dry-run BEFORE any
// mutation. Previously refresh-cache deleted cache files at the top of its RunE
// and only consulted the flag afterwards, and quick-rescan inserted a scan row
// before the same check — so `--dry-run`, the flag an operator uses to inspect a
// destructive command's blast radius, performed the destruction first.
//
// T-15-12-04: the refresh-cache preview and the refresh-cache deletion are both
// driven by planCacheInvalidation, so a preview cannot drift from the action.
//
// T-15-12-01 / T-15-12-06: refresh-cache selects its workspace by EQUALITY
// against the canonical identity slug (plan 15-01's output.CanonicalTargetID),
// never by name prefix, and never through a fallback to the pre-Phase-15 slug
// helper in internal/core/output (whose name is deliberately not repeated here,
// so a grep for it over this file stays a meaningful guard).
package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/resolvers"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// --- gen-resolvers ---

// newGenResolversCmd returns the "gen-resolvers" subcommand (MODE-08, D-04).
// Standalone — no --target required.
func newGenResolversCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-resolvers",
		Short: "Regenerate the DNS resolver list via dnsvalidator (D-04)",
		Long: `Regenerate the DNS resolver list by invoking dnsvalidator with two source
URLs (public-dns.info + massdns resolver list), then merging the results.

Falls back to HTTP download of the configured resolver URL if dnsvalidator is
absent or produces zero output — mirroring v1 modules/axiom.sh:resolvers_update.

Standalone: does not require --target.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenResolversCmd(cmd)
		},
	}
}

func runGenResolversCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()
	efs := parseEarlyFlags(os.Args[1:])

	// F14: read --dry-run FIRST. resolvers.RunGenResolvers MkdirAlls the resolver
	// directory and writes (or HTTP-downloads into) the resolver file in its very
	// first statements, so a check placed below it is not a check at all.
	dryRun := resolveDryRun(cmd)

	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		return fmt.Errorf("gen-resolvers: config load: %w", err)
	}

	// -o/--output is deliberately NOT consumed here. gen-resolvers writes to
	// cfg.Paths.Resolvers and cfg.Paths.ResolversTrusted; neither is derived from
	// cfg.Paths.DataDir, so the workspace root has no bearing on where this
	// command writes. Applying it would be dead code that implies otherwise.

	resolversPath := genResolversOutputPath(cfg)

	if dryRun {
		printGenResolversDryRun(cmd, cfg, resolversPath)
		return nil
	}

	if err := resolvers.RunGenResolvers(ctx, cfg); err != nil {
		return fmt.Errorf("gen-resolvers: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "gen-resolvers: resolver list written to %s\n", resolversPath)
	return nil
}

// genResolversOutputPath resolves the resolver file path exactly as
// resolvers.RunGenResolvers does, so the dry-run preview and the real run name
// the same file.
func genResolversOutputPath(cfg *config.Config) string {
	if cfg.Paths.Resolvers != "" {
		return cfg.Paths.Resolvers
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", "reconftw", "resolvers.txt")
}

// printGenResolversDryRun reports every path gen-resolvers would write and the
// source it would draw from, writing nothing itself. exec.LookPath is a pure
// read of PATH — it is what decides dnsvalidator vs. the HTTP fallback inside
// RunGenResolvers, so consulting it here keeps the preview truthful.
func printGenResolversDryRun(cmd *cobra.Command, cfg *config.Config, resolversPath string) {
	w := cmd.OutOrStdout()

	source := "HTTP download " + resolversDownloadURL(cfg.Paths.ResolversDownload.URL)
	if _, lookErr := exec.LookPath("dnsvalidator"); lookErr == nil {
		source = "dnsvalidator (found on PATH)"
	}

	_, _ = fmt.Fprintln(w, "[dry-run] gen-resolvers: nothing written")
	_, _ = fmt.Fprintf(w, "[dry-run]   would write %s\n", resolversPath)
	_, _ = fmt.Fprintf(w, "[dry-run]   source: %s\n", source)

	if cfg.Paths.ResolversTrusted != "" {
		_, _ = fmt.Fprintf(w, "[dry-run]   would write %s\n", cfg.Paths.ResolversTrusted)
		_, _ = fmt.Fprintf(w, "[dry-run]   trusted source: HTTP download %s\n",
			resolversDownloadURL(cfg.Paths.ResolversDownload.TrustedURL))
	}
}

// resolversDownloadURL renders a configured download URL for the preview.
// The resolvers package substitutes its own built-in constant when the config
// leaves the URL empty; naming that state beats printing a bare empty string.
func resolversDownloadURL(configured string) string {
	if configured == "" {
		return "<built-in default>"
	}
	return configured
}

// resolveDryRun reads --dry-run for a subcommand that declares no local copy of
// the flag. Under the root command cobra has already merged the root's
// persistent flags into cmd.Flags(); InheritedFlags is the fallback for a
// subcommand constructed and executed standalone (as unit tests do).
func resolveDryRun(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	if v, err := cmd.Flags().GetBool("dry-run"); err == nil {
		return v
	}
	if f := cmd.InheritedFlags().Lookup("dry-run"); f != nil {
		return f.Value.String() == "true"
	}
	return false
}

// resolveOutputDir returns the operator-supplied -o/--output workspace root, or
// "" when the operator did not supply one.
//
// T-15-12-05: the value is only honoured when the flag was actually Changed —
// reading it unconditionally would push the flag's "workspaces" default over a
// configured paths.data_dir on every run (the same rule applyCLIOutputDir
// applies for the composite commands). cliOutputDir is the fallback for the
// real CLI, where PersistentPreRunE has already recorded it.
func resolveOutputDir(cmd *cobra.Command) string {
	if cmd != nil {
		if f := cmd.Flags().Lookup("output"); f != nil && f.Changed {
			return f.Value.String()
		}
		if f := cmd.InheritedFlags().Lookup("output"); f != nil && f.Changed {
			return f.Value.String()
		}
	}
	return cliOutputDir
}

// --- refresh-cache ---

// newRefreshCacheCmd returns the "refresh-cache" subcommand (MODE-07, D-05).
// Requires --target (to locate the workspace to refresh).
func newRefreshCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "refresh-cache",
		Short: "Rebuild DNS/ASN/geo cached data for a target (D-05)",
		Long: `Invalidate and rebuild DNS/ASN/geo cached data for the given target.

Sets cfg.Cache.Refresh=true and cfg.Advanced.Diff=true so the next pipeline
run re-fetches all cached resources. Also deletes per-target staging files
under workdir/inputs/ matching geo/ASN/resolver cache patterns BEFORE running
the recon pipeline — ensuring the re-fetch starts clean.

Does NOT wipe findings.jsonl, subdomains.jsonl, or any artefact files (those
are results, not caches).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRefreshCacheCmd(cmd)
		},
	}
	return cmd
}

// refreshCacheConfigTransform builds the ConfigTransform for refresh-cache.
// Exported as a function so stateful_test.go can test it in isolation.
func refreshCacheConfigTransform(cfg *config.Config) {
	cfg.Cache.Refresh = true
	cfg.Advanced.Diff = true
}

func runRefreshCacheCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	targetFlag, err := resolveTarget(cmd, "refresh-cache")
	if err != nil {
		return err
	}

	// F14 / T-15-12-02: read --dry-run BEFORE invalidateCacheFiles. This read used
	// to sit below the deletion, so `refresh-cache --dry-run` wiped the very cache
	// it was asked to preview.
	dryRun := resolveDryRun(cmd)
	outputDir := resolveOutputDir(cmd)

	efs := parseEarlyFlags(os.Args[1:])
	cfg, loadErr := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if loadErr != nil {
		return fmt.Errorf("refresh-cache: config load: %w", loadErr)
	}

	// T-15-12-05: -o/--output beats the config file, applied BEFORE any path is
	// computed — otherwise the invalidation below services a different data dir
	// than the pipeline run it is supposed to be preparing.
	if outputDir != "" {
		cfg.Paths.DataDir = outputDir
	}

	// Apply transform upfront for cache deletion logic.
	refreshCacheConfigTransform(cfg)

	if dryRun {
		// T-15-12-04: the preview comes from the SAME function that supplies the
		// deletion list, so the two cannot drift apart.
		planned, planErr := planCacheInvalidation(cfg, targetFlag)
		if planErr != nil {
			slog.WarnContext(ctx, "refresh-cache: cache invalidation planning had errors (non-fatal)", "err", planErr)
		}
		printCacheInvalidationPlan(cmd, planned)
	} else {
		// T-09-04-02: delete per-target cache staging files scoped to workdir/inputs/.
		// The workdir is derived from cfg.Paths.DataDir (config-controlled, not user input).
		if err := invalidateCacheFiles(cfg, targetFlag); err != nil {
			// Non-fatal — log and continue.
			slog.WarnContext(ctx, "refresh-cache: cache invalidation had errors (non-fatal)", "err", err)
		}
	}

	// Re-run the recon pipeline with Diff=true + Cache.Refresh=true.
	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	var capture dryRunCapture
	var summaryWorkdir string
	var summaryVerbosity interface {
		// Only ui.Verbosity
	}
	_ = summaryVerbosity

	afterBoot := func(boot handlers.AppBoot) {
		summaryWorkdir = boot.WorkDir
		commonAfterBoot(ctx, boot, sched, dryRun, "refresh-cache", &capture)
	}

	if err := handlers.RunCompositeAsync(ctx, handlers.RunOptions{
		Target:          targetFlag,
		DryRun:          dryRun,
		ConfigPath:      efs.configPath,
		SecretsPath:     efs.secretsPath,
		AxiomEnabled:    axiomEnabled,
		Scheduler:       sched,
		OutputDir:       outputDir,
		AfterBoot:       afterBoot,
		ConfigTransform: refreshCacheConfigTransform,
	}, handlers.ModeRecon); err != nil {
		return fmt.Errorf("refresh-cache: %w", err)
	}

	if dryRun && capture.Tasks != nil {
		return printCompositeDryRun(cmd, capture.Tasks, capture.Cfg, capture.Rdct, handlers.ModeRecon)
	}

	if summaryWorkdir != "" {
		printCompositeSummary(os.Stderr, summaryWorkdir, 1)
	}
	return nil
}

// cacheInvalidationPatterns are the inputs/ glob patterns refresh-cache treats
// as regenerable cache. Findings artefacts (findings.jsonl, subdomains.jsonl,
// ...) are deliberately absent — those are results, not caches.
//
// The list overlaps on purpose ("geo.*.txt" is a subset of "geo*.txt"); the
// planner deduplicates, which is what makes the previewed set equal the deleted
// set rather than a multiset with repeats.
var cacheInvalidationPatterns = []string{
	"geo.*.txt", "geo*.txt",
	"asn*.jsonl", "asn*.txt",
	"resolvers*.txt",
}

// targetWorkspaceDir returns the ONE workspace directory that belongs to target,
// or "" when no such directory exists yet.
//
// T-15-12-01: selection is EQUALITY against the canonical identity slug that
// output.WorkspaceInit uses to name the directory. The previous implementation
// compared name PREFIXES, so `--target example.com` also selected the workspace
// of example.com.evil — an operator who can be steered into scanning one target
// could thereby cause deletions inside an unrelated engagement's workspace.
//
// Prefix matching is not merely imprecise now, it is wrong: since plan 15-01 the
// directory name is "<readable>-<sha256:8>", so example.com's slug is not a
// prefix of example.com.evil's slug and a raw-name comparison would match
// nothing at all. The slug is a pure function of the target, so the path is
// computed directly and os.ReadDir is gone.
//
// T-15-12-06: that also makes the legacy question structural rather than
// incidental. Plan 15-01 adopts a pre-upgrade workspace by renaming it onto the
// new slug, but REFUSES when the new-slug directory already exists or when the
// legacy directory carries a different canonical identity — in both cases a
// directory under the old sanitised name survives beside the new one. It is
// never enumerated here, so it can never be deleted here. Do NOT add a fallback
// that also tries the pre-Phase-15 slug: a refused adoption means the ownership
// of that directory is UNRESOLVED, and a delete loop must not be what resolves
// it. TestRefreshCacheHasNoLegacyFallback greps this file for that helper's
// name, which is why it is spelled out nowhere above.
func targetWorkspaceDir(dataDir, target string) (string, error) {
	id, err := output.CanonicalTargetID(target)
	if err != nil {
		return "", fmt.Errorf("resolve target identity: %w", err)
	}

	workspace := filepath.Join(dataDir, id.Slug)
	info, statErr := os.Stat(workspace)
	if statErr != nil || !info.IsDir() {
		// No workspace for this target yet — nothing to invalidate.
		return "", nil
	}
	return workspace, nil
}

// planCacheInvalidation returns the per-target DNS/ASN/geo cache staging files
// refresh-cache WOULD delete, in deterministic order, WITHOUT deleting anything.
//
// T-15-12-04: this is the single source of the path list for both the --dry-run
// preview and invalidateCacheFiles' delete loop. A separately maintained preview
// eventually lies about what the real run does.
func planCacheInvalidation(cfg *config.Config, target string) ([]string, error) {
	dataDir := cfg.Paths.DataDir
	if dataDir == "" {
		dataDir = "workspaces"
	}

	workspace, err := targetWorkspaceDir(dataDir, target)
	if err != nil {
		return nil, err
	}
	if workspace == "" {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var planned []string
	var cacheErrors []error

	inputsDir := filepath.Join(workspace, "inputs")
	for _, pattern := range cacheInvalidationPatterns {
		matches, globErr := filepath.Glob(filepath.Join(inputsDir, pattern))
		if globErr != nil {
			cacheErrors = append(cacheErrors, globErr)
			continue
		}
		for _, match := range matches {
			// Safety: verify the match is inside the workspace. This is a
			// SECOND, independent guard (the first being the exact-slug
			// selection above) against a glob escaping the workspace.
			if !isInsideDir(match, workspace) {
				slog.Warn("refresh-cache: skipping deletion outside workspace", "path", match)
				continue
			}
			if _, dup := seen[match]; dup {
				continue
			}
			seen[match] = struct{}{}
			planned = append(planned, match)
		}
	}
	sort.Strings(planned)

	if len(cacheErrors) > 0 {
		return planned, fmt.Errorf("%d cache glob error(s)", len(cacheErrors))
	}
	return planned, nil
}

// invalidateCacheFiles deletes per-target DNS/ASN/geo cache staging files
// under workdir/inputs/ — scoped to the workspace directory (T-09-04-02).
// The set deleted is exactly planCacheInvalidation's output.
func invalidateCacheFiles(cfg *config.Config, target string) error {
	planned, planErr := planCacheInvalidation(cfg, target)

	var cacheErrors []error
	if planErr != nil {
		cacheErrors = append(cacheErrors, planErr)
	}
	for _, match := range planned {
		if rmErr := os.Remove(match); rmErr != nil && !os.IsNotExist(rmErr) {
			cacheErrors = append(cacheErrors, rmErr)
		}
	}

	if len(cacheErrors) > 0 {
		return fmt.Errorf("%d cache file deletion error(s)", len(cacheErrors))
	}
	return nil
}

// printCacheInvalidationPlan renders the --dry-run preview. Each path is printed
// on its own line under a stable "[dry-run]   " prefix so the set is machine
// comparable against what a real run removes.
func printCacheInvalidationPlan(cmd *cobra.Command, planned []string) {
	w := cmd.OutOrStdout()
	if len(planned) == 0 {
		_, _ = fmt.Fprintln(w, "[dry-run] refresh-cache: no cache files to invalidate")
		return
	}
	_, _ = fmt.Fprintf(w, "[dry-run] refresh-cache: would delete %d cache file(s):\n", len(planned))
	for _, match := range planned {
		_, _ = fmt.Fprintf(w, "[dry-run]   %s\n", match)
	}
}

// isInsideDir reports whether path is inside (or equal to) dir.
// T-09-04-02: prevents accidental deletion outside the workspace.
func isInsideDir(path, dir string) bool {
	absPath, err1 := filepath.Abs(path)
	absDir, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	return absPath == absDir || len(absPath) > len(absDir) && absPath[:len(absDir)+1] == absDir+string(filepath.Separator)
}

// --- quick-rescan ---

// newQuickRescanCmd returns the "quick-rescan" subcommand (MODE-06, D-06).
// THIN: sets cfg.Advanced.Diff=true so every task re-runs. Does NOT implement
// diff reporting.
//
// Key constraint (D-06): ConfigTransform sets ONLY cfg.Advanced.Diff=true.
// No cfg.Advanced.QuickRescan mutation.
//
// T-15-12-03 — the removed baseline row. This command used to insert a scan row
// with mode="quick-rescan" and status="running" BEFORE the pipeline ran, and
// nothing ever closed it. Two independent findings retired it rather than
// patching a terminal-state update onto it:
//
//  1. It had no reader. `grep -rn 'quick-rescan' --include=*.go` outside this
//     file matches only the alias table in alias.go and test/doc strings; no
//     query filters on mode = "quick-rescan".
//  2. It could not have served its stated purpose. The Phase 10 baseline lookup
//     is GetLatestCompletedScanForTarget, whose SQL is
//     `WHERE target_id = ? AND status = 'completed'` — a "running" row is never
//     selectable by it, so the row was never a diff baseline in the first place.
//
// Meanwhile it WAS visible to the generic listings (ListScansForTarget,
// ListScansCursor, CountScansForTarget) and to any "is a scan in progress"
// check, so every quick-rescan permanently added a phantom in-flight scan.
//
// The real run is still recorded: RunCompositeAsync's end-of-scan
// persistScanToStore → ingest.ScanIntoStore writes a row with true counts and a
// terminal status. The one thing lost is the mode LABEL — that row is written as
// "recon" (compositeModeLabel(ModeRecon)), because RunOptions carries no mode
// override. Restoring a distinct label belongs in handlers, not here.
func newQuickRescanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "quick-rescan",
		Short: "Re-run recon with checkpoint bypass against the last workspace (D-06)",
		Long: `Re-run the recon pipeline with checkpoint bypass (cfg.Advanced.Diff=true).

All tasks re-run regardless of prior completion state. The run is recorded in
store.db by the normal end-of-scan ingest, so Phase 10 can compute the findings
diff via DiffBetweenScans.

Diff reporting defers to Phase 10.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuickRescanCmd(cmd)
		},
	}
}

// quickRescanConfigTransform is the ConfigTransform for quick-rescan.
// D-06 THIN: sets ONLY cfg.Advanced.Diff=true. No QuickRescan field mutation.
// Exported as a function so stateful_test.go can test it in isolation.
func quickRescanConfigTransform(cfg *config.Config) {
	cfg.Advanced.Diff = true
	// D-06 THIN: do NOT set cfg.Advanced.QuickRescan here.
	// Phase 9 relies solely on Advanced.Diff for checkpoint bypass.
}

func runQuickRescanCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	targetFlag, err := resolveTarget(cmd, "quick-rescan")
	if err != nil {
		return err
	}

	// F14 / T-15-12-02: the dry-run read stays at the top of the function even
	// though quick-rescan no longer has a pre-pipeline mutation of its own — it
	// is what gates RunCompositeAsync below, and the position is the invariant
	// TestStatefulDryRunReadPrecedesMutation enforces against regression.
	//
	// T-15-12-05: -o/--output is forwarded to RunOptions, where BootReconApp
	// applies it to cfg.Paths.DataDir before the workspace is resolved. This
	// command no longer loads its own config: with the baseline insert gone it
	// had no path of its own left to compute.
	dryRun := resolveDryRun(cmd)
	outputDir := resolveOutputDir(cmd)

	efs := parseEarlyFlags(os.Args[1:])
	axiomEnabled, _ := cmd.Flags().GetBool("axiom")
	sched := scheduler.NewScheduler(0, 0, nil, nil)

	var capture dryRunCapture
	var summaryWorkdir string

	afterBoot := func(boot handlers.AppBoot) {
		summaryWorkdir = boot.WorkDir
		commonAfterBoot(ctx, boot, sched, dryRun, "quick-rescan", &capture)
	}

	if err := handlers.RunCompositeAsync(ctx, handlers.RunOptions{
		Target:          targetFlag,
		DryRun:          dryRun,
		ConfigPath:      efs.configPath,
		SecretsPath:     efs.secretsPath,
		AxiomEnabled:    axiomEnabled,
		Scheduler:       sched,
		OutputDir:       outputDir,
		AfterBoot:       afterBoot,
		ConfigTransform: quickRescanConfigTransform,
	}, handlers.ModeRecon); err != nil {
		return fmt.Errorf("quick-rescan: %w", err)
	}

	if dryRun && capture.Tasks != nil {
		return printCompositeDryRun(cmd, capture.Tasks, capture.Cfg, capture.Rdct, handlers.ModeRecon)
	}

	if summaryWorkdir != "" {
		printCompositeSummary(os.Stderr, summaryWorkdir, 1)
	}
	return nil
}
