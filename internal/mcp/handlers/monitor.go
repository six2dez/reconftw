// Package handlers — monitor loop handler (MON-01..08, D-01..06).
//
// RunMonitorAsync runs the monitor loop: one RunCompositeAsync call per cycle
// with after-completion delay between cycles. SIGINT cancels ctx after the
// current cycle's tasks finish (MON-08).
//
// Design choice — single-boot per cycle, NOT once-for-all:
// RunCompositeAsync owns BootReconApp internally and also owns the checkpoint
// lifecycle (defer app.Checkpoint.Close()). Calling it directly per cycle is
// the correct pattern — each cycle gets a fresh AppContext / checkpoint so the
// per-task checkpoint store reflects the cycle's scan record correctly.
// The incremental re-feed path calls RunCompositeAsync a second time in the
// same cycle with a modified RunOptions (TargetListPath set to the seed file)
// so that cfgSliceJSON changes and checkpoint.InputHash differs from the first
// call — triggering genuine re-execution for the new-asset partition.
//
// SIGINT wiring (Pitfall 7): signal.NotifyContext MUST be called in the CLI
// layer (cmd/reconftw/stub_subcommands.go runMonitorCmd), NOT here. This
// function receives a context that is already signal-aware.
package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver registration

	"github.com/six2dez/reconftw/internal/core/notifier"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// MonitorOptions configures the monitor loop.
type MonitorOptions struct {
	// Mode is which composite pipeline to run each cycle (ModeRecon or ModeAll).
	Mode CompositeMode
	// Interval is the wait between cycles (after the previous cycle completes).
	// From --interval flag or cfg.Monitor.IntervalMinutes.
	Interval time.Duration
	// MaxCycles is the number of cycles to run before exiting. 0 = indefinite.
	// From --monitor-cycles flag or cfg.Monitor.MaxCycles.
	MaxCycles int
	// Incremental: when true, writes a new-asset seed file from the diff result
	// and invokes a scoped downstream re-run seeded from that file. This
	// produces a different cfgSliceJSON (TargetListPath differs), yielding a new
	// checkpoint.InputHash and triggering genuine re-execution for new-asset
	// partitions only (D-04/D-05 fix — checkpoint hash alone does NOT change
	// between cycles with identical opts).
	Incremental bool
	// NewAssetSeedPath is populated by the monitor loop after writing the seed
	// file for the current cycle. Reset at the start of each cycle.
	NewAssetSeedPath string
}

// findingContentHash returns a stable 32-hex-char hash for a finding tuple.
// Using templateSig + severity + matchedAt as the identity key (D-02 dedup).
// Takes plain string arguments so the function is testable without a sqlcgen
// import at the test site.
func findingContentHash(templateSig, severity, matchedAt string) string {
	h := sha256.Sum256([]byte(templateSig + "|" + severity + "|" + matchedAt))
	return hex.EncodeToString(h[:16]) // 32 hex chars
}

// writeNewAssetSeedFile writes newFQDNs (one per line) to
// <workDir>/monitor/newassets-cycle-N.txt and returns the path.
func writeNewAssetSeedFile(workDir string, cycleNum int, newFQDNs []string) (string, error) {
	dir := filepath.Join(workDir, "monitor")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("monitor: mkdir %s: %w", dir, err)
	}
	seedPath := filepath.Join(dir, fmt.Sprintf("newassets-cycle-%d.txt", cycleNum))
	content := strings.Join(newFQDNs, "\n") + "\n"
	if err := os.WriteFile(seedPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("monitor: write seed file: %w", err)
	}
	return seedPath, nil
}

// formatFindingNotification formats a per-cycle finding notification line.
func formatFindingNotification(cycleNum int, templateSig, severity, matchedAt string) string {
	return fmt.Sprintf("[cycle %d] new finding: %s (%s) at %s",
		cycleNum, templateSig, severity, matchedAt)
}

// runMonitorLoop runs runCycle in a loop with after-completion delay.
// maxCycles == 0 means indefinite. Context cancellation (e.g. SIGINT)
// causes a clean exit after the current runCycle returns (MON-08).
//
// Pattern: after-completion delay (not time.Ticker) so that a slow cycle does
// not cause interval drift or concurrent overlapping cycles.
func runMonitorLoop(
	ctx context.Context,
	interval time.Duration,
	maxCycles int,
	runCycle func(context.Context, int) error,
) error {
	for cycle := 0; maxCycles == 0 || cycle < maxCycles; cycle++ {
		if err := runCycle(ctx, cycle); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil // clean SIGINT exit (MON-08)
			}
			// Best-effort: log the error and continue (mirrors isBestEffortModule pattern).
			slog.Warn("monitor: cycle error (continuing)", "cycle", cycle, "err", err)
		}

		if maxCycles > 0 && cycle+1 >= maxCycles {
			break
		}

		// After-completion delay: wait interval then run the next cycle.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
	return nil
}

// RunMonitorAsync executes the monitor loop: per-cycle RunCompositeAsync,
// post-cycle diff, dedup, EventFilter dispatch, and Flusher flush.
//
// SIGINT handling (Pitfall 7): the caller (runMonitorCmd in CLI layer) wraps
// ctx with signal.NotifyContext before calling this function. RunMonitorAsync
// does NOT call signal.NotifyContext — it must not own signal wiring.
func RunMonitorAsync(ctx context.Context, opts RunOptions, monCfg MonitorOptions) error {
	if opts.Scheduler == nil {
		return fmt.Errorf("mcp/monitor: RunOptions.Scheduler must not be nil")
	}

	// D-02 dedup: in-memory content-hash set — lives for the process lifetime
	// of the monitor run. Prevents re-alerting on findings already notified in
	// a prior cycle even if they re-appear in later diff results.
	notifiedHashes := make(map[string]struct{})

	// prevScanID tracks the baseline scan for cross-cycle diff (D-01).
	// Empty on the first cycle — no diff is performed until cycle 1+.
	prevScanID := ""

	// Single Boot to obtain workDir and config for the DB path + EventFilter.
	// Per-cycle pipeline calls go to RunCompositeAsync which boots internally.
	// This pre-boot is read-only (for workDir, cfg, notifier wiring) and its
	// checkpoint is closed immediately after.
	boot, err := BootReconApp(ctx, opts)
	if err != nil {
		return fmt.Errorf("mcp/monitor: initial boot: %w", err)
	}
	// Close the pre-boot checkpoint — cycle boots own their own checkpoints.
	if closer, ok := boot.App.Checkpoint.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	// EventFilter for WARNING-4 fix: all finding notifications go through ef
	// so that notifications.events TOML rules gate dispatch (NOTIF-04).
	ef := notifier.NewEventFilter(boot.App.Notify, boot.App.Cfg.Notifications.Events)

	// Open store.db read-only for diff queries.
	dbPath := filepath.Join(boot.WorkDir, "store.db")
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("mcp/monitor: open store.db: %w", err)
	}
	defer db.Close() //nolint:errcheck

	q := sqlcgen.New(db)

	runCycle := func(cycleCtx context.Context, cycleNum int) error {
		cycleStart := time.Now()
		monCfg.NewAssetSeedPath = "" // reset per-cycle

		// Step 1: Run the composite pipeline.
		// RunCompositeAsync boots internally (D-01 single-boot-per-call) and
		// owns its own checkpoint lifecycle. Each cycle records a new scan row.
		if err := RunCompositeAsync(cycleCtx, opts, monCfg.Mode); err != nil {
			return fmt.Errorf("monitor: cycle %d: pipeline: %w", cycleNum, err)
		}

		// Step 2: Resolve current scan from the store.
		currScan, scanErr := q.GetLatestCompletedScanForTarget(cycleCtx, opts.Target)
		if errors.Is(scanErr, sql.ErrNoRows) {
			slog.Warn("monitor: no completed scan found after cycle — skipping diff",
				"cycle", cycleNum, "target", opts.Target)
			return nil
		}
		if scanErr != nil {
			slog.Warn("monitor: GetLatestCompletedScanForTarget failed — skipping diff",
				"cycle", cycleNum, "err", scanErr)
			return nil
		}

		var newFQDNs []string
		newFindingCount := 0

		// Step 3: Diff against previous scan when we have a baseline (D-01).
		if prevScanID != "" && currScan.ID != prevScanID {
			// Findings diff — new findings in currScan not present in prevScan.
			findingRows, ferr := q.DiffScansFindings(cycleCtx, sqlcgen.DiffScansFindingsParams{
				ScanA: currScan.ID,
				ScanB: prevScanID,
			})
			if ferr != nil {
				slog.Warn("monitor: DiffScansFindings failed", "cycle", cycleNum, "err", ferr)
			}

			// Hosts diff — new FQDNs for incremental seed file.
			hostRows, herr := q.DiffScansHosts(cycleCtx, sqlcgen.DiffScansHostsParams{
				ScanA: currScan.ID,
				ScanB: prevScanID,
			})
			if herr != nil {
				slog.Warn("monitor: DiffScansHosts failed", "cycle", cycleNum, "err", herr)
			}

			// URLs diff (informational — logged but not used for re-feed).
			_, uerr := q.DiffScansURLs(cycleCtx, sqlcgen.DiffScansURLsParams{
				ScanA: currScan.ID,
				ScanB: prevScanID,
			})
			if uerr != nil {
				slog.Warn("monitor: DiffScansURLs failed", "cycle", cycleNum, "err", uerr)
			}

			// Step 4: Collect new FQDNs for incremental seed file.
			for _, h := range hostRows {
				newFQDNs = append(newFQDNs, h.FQDN)
			}

			// Step 5: Dispatch new findings via EventFilter (D-04, WARNING-4 fix).
			for _, f := range findingRows {
				hash := findingContentHash(f.TemplateSignature, f.Severity, f.Title)
				if _, seen := notifiedHashes[hash]; seen {
					// D-02 dedup: already notified in a prior cycle — skip.
					continue
				}
				notifiedHashes[hash] = struct{}{}
				msg := formatFindingNotification(cycleNum, f.TemplateSignature, f.Severity, f.Title)
				if err := ef.NotifyEvent(cycleCtx, notifier.EventCriticalFinding, notifier.LevelWarn, msg); err != nil {
					slog.Warn("monitor: NotifyEvent(CriticalFinding) failed", "err", err)
				}
				newFindingCount++
			}
		}

		// Step 6: Incremental re-feed (BLOCKER-1 fix, D-04/D-05).
		// Checkpoint InputHash = SHA-256(taskName+target+cfgSliceJSON+wordlistsLockContent).
		// Between cycles with identical opts, every task gets the IDENTICAL inputHash,
		// so checkpoint.Done() returns true and all tasks skip.
		// Fix: write a seed file containing new FQDNs and re-run with TargetListPath
		// pointing to it. Because TargetListPath changes cfgSliceJSON, the inputHash
		// differs — triggering genuine re-execution for new-asset partitions only.
		if monCfg.Incremental && len(newFQDNs) > 0 {
			seedPath, seedErr := writeNewAssetSeedFile(boot.WorkDir, cycleNum, newFQDNs)
			if seedErr != nil {
				slog.Warn("monitor: writeNewAssetSeedFile failed — skipping incremental re-run",
					"cycle", cycleNum, "err", seedErr)
			} else {
				monCfg.NewAssetSeedPath = seedPath
				incrementalOpts := opts
				incrementalOpts.TargetListPath = seedPath
				if rerunErr := RunCompositeAsync(cycleCtx, incrementalOpts, monCfg.Mode); rerunErr != nil {
					slog.Warn("monitor: incremental re-run failed",
						"cycle", cycleNum, "err", rerunErr)
				} else {
					slog.Info("monitor: incremental re-run complete",
						"cycle", cycleNum, "new_assets", len(newFQDNs), "seed", seedPath)
				}
			}
		}

		// Step 7: Dispatch cycle-end notification via EventFilter (WARNING-4 fix).
		elapsed := time.Since(cycleStart)
		summaryMsg := fmt.Sprintf("[cycle %d] complete — new_findings=%d new_subs=%d elapsed=%s",
			cycleNum, newFindingCount, len(newFQDNs), elapsed.Round(time.Second))
		if err := ef.NotifyEvent(cycleCtx, notifier.EventScanComplete, notifier.LevelInfo, summaryMsg); err != nil {
			slog.Warn("monitor: NotifyEvent(ScanComplete) failed", "err", err)
		}

		// Step 8: Print cycle summary per OUTPUT_VERBOSITY (MON-07).
		verbosity := boot.App.Cfg.Output.Verbosity
		switch {
		case verbosity == 0:
			// VerbosityQuiet — suppress cycle summary.
		case verbosity == 1:
			// VerbosityNormal — one summary line.
			fmt.Fprintf(os.Stderr, "[OK  ] monitor cycle %d  new_findings=%d  new_subs=%d  elapsed=%s\n",
				cycleNum, newFindingCount, len(newFQDNs), elapsed.Round(time.Second))
		default:
			// VerbosityVerbose — summary + per-category breakdown.
			fmt.Fprintf(os.Stderr, "[OK  ] monitor cycle %d  new_findings=%d  new_subs=%d  elapsed=%s\n",
				cycleNum, newFindingCount, len(newFQDNs), elapsed.Round(time.Second))
			fmt.Fprintf(os.Stderr, "         findings_delta=%d  hosts_delta=%d\n",
				newFindingCount, len(newFQDNs))
		}

		// Step 9: FlushNow via Flusher interface (BLOCKER-2 fix).
		// app.Notify is *notifier.Multi (Boot always wraps sinks in NewMulti).
		// *Multi implements Flusher by delegating to any Flusher sink (DigestCoalescer).
		// The ok-check is a safety guard; this assertion WILL succeed when wired
		// correctly per Plan 02.
		// NEVER type-assert to *notifier.DigestCoalescer — the outer type is *Multi.
		if f, ok := boot.App.Notify.(notifier.Flusher); ok {
			if err := f.FlushNow(cycleCtx); err != nil {
				slog.Warn("monitor: FlushNow failed", "cycle", cycleNum, "err", err)
			}
		}

		// Step 10: Advance baseline.
		prevScanID = currScan.ID

		return nil
	}

	return runMonitorLoop(ctx, monCfg.Interval, monCfg.MaxCycles, runCycle)
}

// Compile-time proof: *notifier.Multi implements notifier.Flusher.
// This verifies the BLOCKER-2 fix — the type assertion in RunMonitorAsync
// will succeed at runtime.
var _ notifier.Flusher = (*notifier.Multi)(nil)
