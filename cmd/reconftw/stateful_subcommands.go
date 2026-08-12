// stateful_subcommands.go — the three stateful utility subcommands:
//   - gen-resolvers (MODE-08, D-04): regenerate DNS resolver list via dnsvalidator
//   - refresh-cache (MODE-07, D-05): invalidate + rebuild DNS/ASN/geo cached data
//   - quick-rescan  (MODE-06, D-06): checkpoint-bypass + scan baseline record
//
// Registration: all three are added in root.go alongside the composite subcommands.
//
// D-06 THIN: quick-rescan sets ONLY cfg.Advanced.Diff=true via ConfigTransform.
// It does NOT set cfg.Advanced.QuickRescan and does NOT call DiffBetweenScans
// (that is Phase 10). It records a new scan row in store.db (best-effort) so
// Phase 10 can compute the diff.
//
// T-09-04-02 mitigation: refresh-cache file deletion is scoped to workdir/inputs/
// only (derived from cfg.Paths.DataDir + domain workspace) — no absolute path
// deletion possible outside the workspace.
//
// T-09-04-03 mitigation: target string passes through resolveTarget (same
// validation as all other subcommands) before being stored.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	// modernc.org/sqlite registers the "sqlite" driver name (XCUT-02 pure-Go).
	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/resolvers"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
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

	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		return fmt.Errorf("gen-resolvers: config load: %w", err)
	}

	if err := resolvers.RunGenResolvers(ctx, cfg); err != nil {
		return fmt.Errorf("gen-resolvers: %w", err)
	}

	resolversPath := cfg.Paths.Resolvers
	if resolversPath == "" {
		home, _ := os.UserHomeDir()
		resolversPath = filepath.Join(home, ".config", "reconftw", "resolvers.txt")
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "gen-resolvers: resolver list written to %s\n", resolversPath)
	return nil
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

	efs := parseEarlyFlags(os.Args[1:])
	cfg, loadErr := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if loadErr != nil {
		return fmt.Errorf("refresh-cache: config load: %w", loadErr)
	}

	// Apply transform upfront for cache deletion logic.
	refreshCacheConfigTransform(cfg)

	// T-09-04-02: delete per-target cache staging files scoped to workdir/inputs/.
	// The workdir is derived from cfg.Paths.DataDir (config-controlled, not user input).
	if err := invalidateCacheFiles(cfg, targetFlag); err != nil {
		// Non-fatal — log and continue.
		slog.WarnContext(ctx, "refresh-cache: cache invalidation had errors (non-fatal)", "err", err)
	}

	// Re-run the recon pipeline with Diff=true + Cache.Refresh=true.
	dryRun, _ := cmd.Flags().GetBool("dry-run")
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

// invalidateCacheFiles deletes per-target DNS/ASN/geo cache staging files
// under workdir/inputs/ — scoped to the workspace directory (T-09-04-02).
func invalidateCacheFiles(cfg *config.Config, target string) error {
	dataDir := cfg.Paths.DataDir
	if dataDir == "" {
		dataDir = "workspaces"
	}

	// Find the workspace directory for the target.
	// WorkspaceInit uses dataDir/<target>-<timestamp> naming; we find the
	// most recent matching entry.
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil // workspace directory does not exist yet — nothing to invalidate
	}

	var cacheErrors []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Match directories starting with the target name.
		if len(entry.Name()) < len(target) || entry.Name()[:len(target)] != target {
			continue
		}

		inputsDir := filepath.Join(dataDir, entry.Name(), "inputs")
		patterns := []string{
			"geo.*.txt", "geo*.txt",
			"asn*.jsonl", "asn*.txt",
			"resolvers*.txt",
		}
		for _, pattern := range patterns {
			matches, globErr := filepath.Glob(filepath.Join(inputsDir, pattern))
			if globErr != nil {
				cacheErrors = append(cacheErrors, globErr)
				continue
			}
			for _, match := range matches {
				// Safety: verify the match is inside the workspace.
				if !isInsideDir(match, filepath.Join(dataDir, entry.Name())) {
					slog.Warn("refresh-cache: skipping deletion outside workspace", "path", match)
					continue
				}
				if rmErr := os.Remove(match); rmErr != nil && !os.IsNotExist(rmErr) {
					cacheErrors = append(cacheErrors, rmErr)
				}
			}
		}
	}

	if len(cacheErrors) > 0 {
		return fmt.Errorf("%d cache file deletion error(s)", len(cacheErrors))
	}
	return nil
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
// THIN: sets cfg.Advanced.Diff=true + records a scan row (mode="quick-rescan")
// in store.db so Phase 10 can diff against it. Does NOT implement diff reporting.
//
// Key constraint (D-06): ConfigTransform sets ONLY cfg.Advanced.Diff=true.
// No cfg.Advanced.QuickRescan mutation.
func newQuickRescanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "quick-rescan",
		Short: "Re-run recon with checkpoint bypass against the last workspace (D-06)",
		Long: `Re-run the recon pipeline with checkpoint bypass (cfg.Advanced.Diff=true).

All tasks re-run regardless of prior completion state. A new scan row is
recorded in store.db with mode="quick-rescan" so Phase 10 can compute the
findings diff via DiffBetweenScans.

Diff reporting defers to Phase 10. Phase 9 provides the scan baseline only.`,
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

	efs := parseEarlyFlags(os.Args[1:])
	cfg, loadErr := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if loadErr != nil {
		return fmt.Errorf("quick-rescan: config load: %w", loadErr)
	}

	// Record a scan baseline in store.db BEFORE running (best-effort).
	// T-09-04-03: targetFlag is validated by resolveTarget (same path as all subcommands).
	recordQuickRescanBaseline(ctx, cfg, targetFlag)

	dryRun, _ := cmd.Flags().GetBool("dry-run")
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

// recordQuickRescanBaseline inserts a scan row with mode="quick-rescan" into
// store.db so Phase 10 can later compute a findings diff via DiffBetweenScans.
//
// This is best-effort: if the store is unavailable (no store.db, schema mismatch,
// etc.), a warning is logged and the function returns without error — the recon
// pipeline proceeds regardless.
func recordQuickRescanBaseline(ctx context.Context, cfg *config.Config, target string) {
	dataDir := cfg.Paths.DataDir
	if dataDir == "" {
		dataDir = "data"
	}
	storePath := filepath.Join(dataDir, "store.db")

	dsn := storePath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		slog.WarnContext(ctx, "quick-rescan: store.db unavailable (non-fatal)", "err", err)
		return
	}
	defer db.Close() //nolint:errcheck // read-only query path

	q := sqlcgen.New(db)
	scanID := uuid.New().String()
	targetID := target // T-09-04-03: same validated domain string as the run uses

	_, insertErr := q.CreateScan(ctx, sqlcgen.CreateScanParams{
		ID:                  scanID,
		TargetID:            targetID,
		Mode:                "quick-rescan",
		Status:              "running",
		StartedAt:           time.Now().Unix(),
		ReconftwVersion:     nil,
		ToolVersionsJson:    nil,
		RawArgsJson:         "{}",
		ConfigOverridesJson: "{}",
		OutputDir:           "",
	})
	if insertErr != nil {
		slog.WarnContext(ctx, "quick-rescan: store CreateScan failed (non-fatal)", "err", insertErr)
	}
}
