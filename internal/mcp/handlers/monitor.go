// Package handlers — monitor loop handler (MON-01..08, D-01..06, F13).
//
// RunMonitorAsync runs the monitor loop: one RunCompositeAsync call per cycle
// with after-completion delay between cycles. SIGINT cancels ctx after the
// current cycle's tasks finish (MON-08).
//
// Dry-run (F1): when opts.DryRun is set, RunMonitorAsync resolves the plan,
// reports it through AfterBoot and returns. It boots nothing, opens no
// store.db, opens no monitor state.db, constructs no notifier and never enters
// the loop — an operator previewing a monitor must not have a workspace, a
// checkpoint database and a state database created underneath them.
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
// SIGINT wiring (Pitfall 7): the OS interrupt handler MUST be installed in the
// CLI layer (cmd/reconftw/stub_subcommands.go runMonitorCmd), NOT here. This
// function receives a context that is already signal-aware.
//
// F13 — what this file used to get wrong, and what now guarantees otherwise:
//
//	interval        A zero/empty interval reached `case <-time.After(0)`, i.e. a
//	                continuous scan loop with no pause against third-party
//	                infrastructure. Now resolved (flag → cfg.Monitor →
//	                defaultMonitorInterval) and FLOORED at minMonitorInterval.
//	generation      RunGeneration was fmt.Sprintf("cycle-%d", loopIndex), which
//	                restarts at cycle-0. RunGeneration feeds checkpoint.InputHash,
//	                so a replayed value makes Done() true for every task and the
//	                cycle scans NOTHING while logging success. Now a persistent
//	                monotonic counter (MonitorState.NextGeneration).
//	baseline        prevScanID lived in a local variable. Now MonitorState, and
//	                written only AFTER the cycle's diff and notifications, so a
//	                crash mid-cycle re-diffs rather than skipping a delta.
//	suppression     notifiedHashes lived in a map. Now MonitorState.
//	fingerprint     Three inputs (template, severity, title) collapsed distinct
//	                findings on distinct hosts into one identity. Now includes
//	                host and normalised path (see findingFingerprint).
//	notify ordering The hash was marked BEFORE checking the notifier's error, so
//	                a transient outage suppressed a critical finding forever. Now
//	                marked only after a successful dispatch, with bounded retry.
//	severity        Every finding was emitted as EventCriticalFinding and
//	                cfg.Monitor.MinSeverity / AlertSuppression were never read.
//	                Both are applied now; the event kind follows the severity.
//	incremental     The re-feed produced a new scan but the baseline stayed on
//	                the previous one. The baseline now advances to the scan the
//	                cycle actually produced.
package handlers

import (
	"context"
	"database/sql"
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

const (
	// defaultMonitorInterval is the single home of the monitor's default
	// cadence. It replaces the literal "6h" that used to live in the CLI flag
	// default while cfg.Monitor.IntervalMinutes was ignored entirely.
	defaultMonitorInterval = 6 * time.Hour

	// minMonitorInterval is a hard floor. It is a SAFETY limit, not a
	// preference: a monitor with no pause issues continuous active scans
	// against third-party infrastructure, which is the most damaging failure
	// mode a recon tool has. Every path that produces an interval passes
	// through ResolveMonitorInterval, and runMonitorLoop re-applies the floor
	// defensively in case a future caller bypasses it.
	minMonitorInterval = 1 * time.Minute

	// monitorNotifyAttempts / monitorNotifyBaseDelay bound the notification
	// retry: attempt, wait 2s, attempt, wait 4s, attempt. Worst-case sleep is
	// 6 seconds — an order of magnitude below minMonitorInterval, so a failing
	// notifier can never stall the loop past its own cadence.
	monitorNotifyAttempts  = 3
	monitorNotifyBaseDelay = 2 * time.Second

	// monitorNotifiedTTL is how long a suppressed fingerprint stays suppressed.
	// Without a TTL the table grows for the life of the monitor; with one, a
	// finding that is still present after the TTL is re-surfaced, which is the
	// behaviour an operator expects from a long-running watch.
	monitorNotifiedTTL = 90 * 24 * time.Hour
)

// monitorWaitFunc waits for d, or until ctx is done. It reports whether the
// wait completed (false = the context was cancelled).
type monitorWaitFunc func(ctx context.Context, d time.Duration) bool

// realMonitorWait is the production wait.
func realMonitorWait(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		// Defensive: a non-positive duration must never become a busy loop.
		d = minMonitorInterval
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// MonitorOptions configures the monitor loop.
type MonitorOptions struct {
	// Mode is which composite pipeline to run each cycle (ModeRecon or ModeAll).
	Mode CompositeMode
	// Interval is the wait between cycles (after the previous cycle completes).
	// Zero means "resolve from cfg.Monitor.IntervalMinutes, then the package
	// default" — see ResolveMonitorInterval. The resolved value is always at
	// least minMonitorInterval.
	Interval time.Duration
	// MaxCycles is the number of cycles to run before exiting. 0 = "resolve
	// from cfg.Monitor.MaxCycles", and 0 there means indefinite.
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
	// MinSeverity is the lowest finding severity that may be dispatched.
	// Empty = "resolve from cfg.Monitor.MinSeverity" (default "high").
	MinSeverity string
	// AlertSuppression enables the persistent already-notified set. nil =
	// "resolve from cfg.Monitor.AlertSuppression" (default true). It is a
	// pointer because false is a meaningful explicit value that must be
	// distinguishable from "not set".
	AlertSuppression *bool

	// waitFn replaces the inter-cycle wait and the notification retry backoff.
	// Unexported ON PURPOSE: the interval floor is a safety limit, and an
	// exported override would be a supported way around it. Tests reach this
	// through export_test.go's WithMonitorWaiter.
	waitFn monitorWaitFunc
}

// ResolveMonitorInterval turns an explicitly requested interval and the
// configured interval_minutes into the duration the loop will actually use.
//
// Precedence: explicit > cfg.Monitor.IntervalMinutes > defaultMonitorInterval,
// and the result is floored at minMonitorInterval.
//
// Exported because the CLI must be able to show and test the same resolution the
// handler performs; the CLI itself cannot read cfg.Monitor (BootReconApp owns
// the only config.Load on this path, and reintroducing a second one is exactly
// the divergence plan 15-11 recorded as a deferred defect).
func ResolveMonitorInterval(explicit time.Duration, cfgIntervalMinutes int) time.Duration {
	d := explicit
	if d <= 0 && cfgIntervalMinutes > 0 {
		d = time.Duration(cfgIntervalMinutes) * time.Minute
	}
	if d <= 0 {
		d = defaultMonitorInterval
	}
	if d < minMonitorInterval {
		d = minMonitorInterval
	}
	return d
}

// resolveMonitorMaxCycles applies the same precedence to the cycle budget.
// 0 from both sources means "run indefinitely".
func resolveMonitorMaxCycles(explicit, cfgMaxCycles int) int {
	if explicit > 0 {
		return explicit
	}
	if cfgMaxCycles > 0 {
		return cfgMaxCycles
	}
	return 0
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

// monitorSeverityRank mirrors internal/core/report/hotlist.go's severityWeights
// table, which that file documents as "the canonical source". It is duplicated
// rather than imported because the table there is unexported and the report
// package is a heavier dependency than the monitor needs; the VALUES must stay
// in step, and any change to one is a change to both.
var monitorSeverityRank = map[string]int{
	"critical": 10,
	"high":     7,
	"medium":   4,
	"low":      2,
	"info":     1,
}

// severityMeetsMin reports whether severity is at least minSeverity.
//
// FAIL-OPEN on an unrecognised severity. A finding whose severity label the
// table does not know is dispatched rather than dropped: silently discarding an
// unclassified finding is the failure mode a security tool can least afford,
// and the cost of being wrong in the other direction is one extra alert.
// An empty or unrecognised minSeverity disables the filter entirely.
func severityMeetsMin(severity, minSeverity string) bool {
	minRank, ok := monitorSeverityRank[strings.ToLower(strings.TrimSpace(minSeverity))]
	if !ok {
		return true
	}
	rank, ok := monitorSeverityRank[strings.ToLower(strings.TrimSpace(severity))]
	if !ok {
		return true // unknown severity — fail open
	}
	return rank >= minRank
}

// monitorEventForSeverity maps a finding's severity to the notifier event kind
// and level it is dispatched under.
//
// The previous code emitted EVERY finding as EventCriticalFinding at LevelWarn,
// which trains an operator to ignore the channel and thereby defeats monitoring.
// notifier.EventKind has exactly four members (event_filter.go), constrained by
// the `oneof` tag on cfg.Notifications.Events, so the mapping uses the two that
// can carry finding traffic:
//
//	critical → EventCriticalFinding / LevelError
//	high     → EventCriticalFinding / LevelWarn
//	medium   → EventScanComplete    / LevelWarn
//	low      → EventScanComplete    / LevelInfo
//	info,?   → EventScanComplete    / LevelInfo
//
// Sub-"high" findings ride the cycle channel so an operator subscribed only to
// on-critical-finding is not spammed with informational deltas. With the default
// cfg.Monitor.MinSeverity of "high" they are filtered out before this is
// consulted at all.
func monitorEventForSeverity(severity string) (notifier.EventKind, notifier.Level) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return notifier.EventCriticalFinding, notifier.LevelError
	case "high":
		return notifier.EventCriticalFinding, notifier.LevelWarn
	case "medium":
		return notifier.EventScanComplete, notifier.LevelWarn
	default:
		return notifier.EventScanComplete, notifier.LevelInfo
	}
}

// ---------------------------------------------------------------------------
// Notification dispatch
// ---------------------------------------------------------------------------

// notifyWithRetry dispatches through ef, retrying with exponential backoff.
//
// Shape borrowed from internal/installer/bootstrap.go's retry (attempts + base
// delay + context awareness); the body is not reused because that one is
// HTTP-download-specific. The budget is deliberately small: see
// monitorNotifyAttempts.
func notifyWithRetry(
	ctx context.Context,
	ef *notifier.EventFilter,
	kind notifier.EventKind,
	lvl notifier.Level,
	msg string,
	wait monitorWaitFunc,
) error {
	if ef == nil {
		return fmt.Errorf("monitor: notify: nil EventFilter")
	}
	if wait == nil {
		wait = realMonitorWait
	}
	var lastErr error
	delay := monitorNotifyBaseDelay
	for attempt := 1; attempt <= monitorNotifyAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := ef.NotifyEvent(ctx, kind, lvl, msg); err == nil {
			return nil
		} else { //nolint:revive // the else keeps lastErr assignment next to its cause
			lastErr = err
		}
		if attempt == monitorNotifyAttempts {
			break
		}
		if !wait(ctx, delay) {
			return errors.Join(lastErr, ctx.Err())
		}
		delay *= 2
	}
	return fmt.Errorf("monitor: notify failed after %d attempts: %w", monitorNotifyAttempts, lastErr)
}

// FindingAlert is one finding the monitor may alert on.
type FindingAlert struct {
	// Fingerprint is the suppression key (findingFingerprint).
	Fingerprint string
	// Severity drives both the MinSeverity gate and the event kind.
	Severity string
	// Message is the rendered notification body.
	Message string
}

// dispatchFindingAlert notifies about one finding and, ONLY on success, records
// it as notified. It reports whether a notification was dispatched.
//
// The ordering is the whole point. The previous code inserted the hash into the
// dedup set and then called Notify, discarding its error — so a Slack outage
// during one cycle suppressed that finding permanently. Here the mark is a
// consequence of a successful send, and a final failure leaves the fingerprint
// unrecorded so the next cycle retries it.
//
// When suppression is false the store is not consulted or written at all: every
// diff finding is dispatched, which is what cfg.Monitor.Alert_suppression=false
// asks for.
func dispatchFindingAlert(
	ctx context.Context,
	ef *notifier.EventFilter,
	st *MonitorState,
	target string,
	alert FindingAlert,
	suppression bool,
	wait monitorWaitFunc,
) (bool, error) {
	if suppression && st != nil {
		seen, err := st.WasNotified(ctx, target, alert.Fingerprint)
		if err != nil {
			// A suppression-store read failure must not silence an alert; fall
			// through and dispatch. A duplicate alert is recoverable, a dropped
			// critical finding is not.
			slog.Warn("monitor: WasNotified failed — dispatching anyway", "err", err)
		} else if seen {
			return false, nil
		}
	}

	kind, lvl := monitorEventForSeverity(alert.Severity)
	if err := notifyWithRetry(ctx, ef, kind, lvl, alert.Message, wait); err != nil {
		return false, err
	}
	if suppression && st != nil {
		if err := st.MarkNotified(ctx, target, alert.Fingerprint); err != nil {
			// The alert DID go out; failing to record it only risks a duplicate.
			slog.Warn("monitor: MarkNotified failed — the finding may re-alert", "err", err)
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Seed files and message formatting
// ---------------------------------------------------------------------------

// writeNewAssetSeedFile writes newFQDNs (one per line) to
// <workDir>/monitor/newassets-gen-N.txt and returns the path.
//
// The name is keyed on the persistent GENERATION rather than the loop index:
// the loop index restarts at 0 on every process start, so a restarted monitor
// used to overwrite the previous run's seed file — and, because the seed path is
// folded into checkpoint.InputHash, could hand the incremental re-run the same
// hash as a previous run's. The generation is monotonic across restarts, so each
// re-feed gets its own file and its own hash. The path is not consumed anywhere
// outside this file (checked by grep before renaming).
func writeNewAssetSeedFile(workDir string, generation uint64, newFQDNs []string) (string, error) {
	dir := MonitorStateDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("monitor: mkdir %s: %w", dir, err)
	}
	seedPath := filepath.Join(dir, fmt.Sprintf("newassets-gen-%d.txt", generation))
	content := strings.Join(newFQDNs, "\n") + "\n"
	if err := os.WriteFile(seedPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("monitor: write seed file: %w", err)
	}
	return seedPath, nil
}

// formatFindingNotification formats a per-cycle finding notification line.
// The location is included because a fingerprint that distinguishes hosts is
// useless to an operator if the message still does not say which host.
func formatFindingNotification(generation uint64, templateSig, severity, host, locator string) string {
	where := firstNonEmptyString(locator, host, "(unknown location)")
	return fmt.Sprintf("[gen %d] new finding: %s (%s) at %s",
		generation, templateSig, severity, where)
}

// ---------------------------------------------------------------------------
// Loop
// ---------------------------------------------------------------------------

// runMonitorLoop runs runCycle in a loop with after-completion delay.
// maxCycles == 0 means indefinite. Context cancellation (e.g. SIGINT)
// causes a clean exit after the current runCycle returns (MON-08).
//
// Pattern: after-completion delay (not time.Ticker) so that a slow cycle does
// not cause interval drift or concurrent overlapping cycles.
//
// interval is clamped here as well as in ResolveMonitorInterval. That is
// deliberate belt-and-braces: this function is the ONLY place the monitor
// sleeps, so making it structurally incapable of a zero-wait loop means no
// future caller can reintroduce the continuous-scan defect by forgetting to
// resolve first.
func runMonitorLoop(
	ctx context.Context,
	interval time.Duration,
	maxCycles int,
	wait monitorWaitFunc,
	runCycle func(context.Context, int) error,
) error {
	if interval < minMonitorInterval {
		interval = ResolveMonitorInterval(interval, 0)
	}
	if wait == nil {
		wait = realMonitorWait
	}
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
		if ctx.Err() != nil {
			return nil
		}
		if !wait(ctx, interval) {
			return nil
		}
	}
	return nil
}

// RunMonitorAsync executes the monitor loop: per-cycle RunCompositeAsync,
// post-cycle diff, suppression, EventFilter dispatch, and Flusher flush.
//
// SIGINT handling (Pitfall 7): the caller (runMonitorCmd in CLI layer) installs
// the OS interrupt handler and passes a signal-aware context into this function.
// RunMonitorAsync does NOT own signal wiring — that is the CLI layer's responsibility.
func RunMonitorAsync(ctx context.Context, opts RunOptions, monCfg MonitorOptions) error {
	if opts.Scheduler == nil {
		return fmt.Errorf("mcp/monitor: RunOptions.Scheduler must not be nil")
	}

	// F1: a dry run resolves the plan and stops — before the pre-boot creates a
	// workspace and opens checkpoints.db, before the notifier is constructed,
	// before store.db is touched, before <workDir>/monitor/state.db exists, and
	// before the loop starts.
	if opts.DryRun {
		boot, err := ResolveDryRunBoot(opts)
		if err != nil {
			return fmt.Errorf("mcp/monitor: %w", err)
		}
		if opts.AfterBoot != nil {
			opts.AfterBoot(boot)
		}
		return nil
	}

	// INTEG-02: suppress the in-scan notification seam for every per-cycle
	// RunCompositeAsync (and the pre-boot below). The monitor owns its own
	// cross-cycle diff notifications (steps 5/7 via EventFilter); firing the
	// in-scan seam per cycle would re-alert every critical finding on every
	// cycle. opts is a value copy, so this scopes to this monitor run only, and
	// incrementalOpts (a copy of cycleOpts) inherits the flag. INTEG-04 owns
	// monitor notifications.
	opts.SuppressScanNotify = true

	// Single Boot to obtain workDir and config for the DB path + EventFilter.
	// Per-cycle pipeline calls go to RunCompositeAsync which boots internally.
	// This pre-boot is read-only (for workDir, cfg, notifier wiring) and its
	// checkpoint is closed immediately after.
	boot, err := BootReconApp(ctx, opts)
	if err != nil {
		return fmt.Errorf("mcp/monitor: initial boot: %w", err)
	}
	// Close the pre-boot checkpoint AND RELEASE THE PRE-BOOT'S WORKSPACE LOCK —
	// cycle boots own their own checkpoints and their own lock.
	//
	// MONITOR SELF-DEADLOCK (F4, plan 15-09). This pre-boot exists only to read
	// workDir, cfg and the notifier; the actual work happens in the per-cycle
	// RunCompositeAsync, which calls BootReconApp AGAIN and therefore acquires
	// the same per-target lock. If the pre-boot held its lock for the monitor's
	// lifetime, EVERY cycle would be rejected by its own process with "target
	// already running" — the monitor would deadlock against itself on cycle 1.
	// Releasing here means exactly one holder at a time: the current cycle.
	// The window between this release and the first cycle's acquisition is
	// unprotected by design; the monitor holds no run-scoped state there, and an
	// external run that wins that race is correctly serialised against the cycle
	// (the cycle is then rejected) rather than silently interleaved.
	//
	// NOTHING BELOW THIS LINE MAY REACQUIRE OR HOLD THE WORKSPACE LOCK. The
	// monitor state store opened further down writes to <workDir>/monitor/ but
	// takes no lock, by design.
	//
	// GUARD: TestMonitorTwoCyclesDoNotSelfDeadlock in monitor_test.go asserts
	// both cycles execute. Any rework of this function must keep that test (or
	// an equivalent assertion that counts EXECUTED CYCLES — an assertion on
	// RunMonitorAsync's returned error passes against the deadlock, because the
	// loop swallows per-cycle errors and continues).
	_ = boot.Close()

	// Resolve every knob the loop needs from the config the boot just loaded.
	// cfg.Monitor was previously read by nobody: interval_minutes, max_cycles,
	// min_severity and alert_suppression were all orphaned settings.
	var monitorCfg config_MonitorView
	if boot.Cfg != nil {
		monitorCfg = config_MonitorView{
			IntervalMinutes:  boot.Cfg.Monitor.IntervalMinutes,
			MaxCycles:        boot.Cfg.Monitor.MaxCycles,
			MinSeverity:      boot.Cfg.Monitor.MinSeverity,
			AlertSuppression: boot.Cfg.Monitor.AlertSuppression,
		}
	}
	interval := ResolveMonitorInterval(monCfg.Interval, monitorCfg.IntervalMinutes)
	maxCycles := resolveMonitorMaxCycles(monCfg.MaxCycles, monitorCfg.MaxCycles)
	minSeverity := monCfg.MinSeverity
	if strings.TrimSpace(minSeverity) == "" {
		minSeverity = monitorCfg.MinSeverity
	}
	suppression := monitorCfg.AlertSuppression
	if monCfg.AlertSuppression != nil {
		suppression = *monCfg.AlertSuppression
	}
	wait := monCfg.waitFn
	if wait == nil {
		wait = realMonitorWait
	}

	// EventFilter for WARNING-4 fix: all finding notifications go through ef
	// so that notifications.events TOML rules gate dispatch (NOTIF-04).
	ef := notifier.NewEventFilter(boot.App.Notify, boot.App.Cfg.Notifications.Events)

	// Persistent monitor state (F13 / acceptance gate 10). Opened AFTER the
	// dry-run early return, so a preview never creates it.
	state, serr := OpenMonitorState(boot.WorkDir)
	if serr != nil {
		return fmt.Errorf("mcp/monitor: %w", serr)
	}
	defer func() { _ = state.Close() }()
	if err := state.PruneNotified(ctx, opts.Target, time.Now().Add(-monitorNotifiedTTL)); err != nil {
		slog.Warn("monitor: PruneNotified failed (continuing)", "err", err)
	}

	slog.Info("monitor: starting",
		"target", opts.Target, "interval", interval, "max_cycles", maxCycles,
		"min_severity", minSeverity, "alert_suppression", suppression,
		"state", state.Path())

	// INTEG-04: the diff store is the SHARED <dataDir>/store.db that the ingest
	// writes (persistScanToStore → ingest.ScanIntoStore), NOT <workDir>/store.db.
	// Per-run fresh workspaces never populated the <workDir> copy, so the diff
	// always saw an empty store and produced no deltas — a silent-failure bug.
	// Fall back to "data" when DataDir is unset, mirroring ScanIntoStore.
	dataDir := "data"
	if boot.Cfg != nil && boot.Cfg.Paths.DataDir != "" {
		dataDir = boot.Cfg.Paths.DataDir
	}
	dbPath := filepath.Join(dataDir, "store.db")

	// The store is opened LAZILY inside runCycle, AFTER the first cycle's
	// RunCompositeAsync → persistScanToStore has created <dataDir>/store.db.
	// Opening at loop-start would race a not-yet-created file (and "?mode=ro"
	// hard-fails on a missing file in modernc). Once opened, db/q persist across
	// cycles; the deferred close releases the handle when the loop exits.
	var db *sql.DB
	var q *sqlcgen.Queries
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()

	runCycle := func(cycleCtx context.Context, cycleNum int) error {
		cycleStart := time.Now()
		monCfg.NewAssetSeedPath = "" // reset per-cycle

		// Step 0: claim this cycle's generation.
		//
		// RunGeneration is what makes the cycle actually execute. Every other
		// input to checkpoint.InputHash is identical between cycles, so without
		// a distinct value every task hashes the same, Done() returns true, and
		// the cycle runs nothing at all — a monitor that polls forever and can
		// never observe a change. The counter is PERSISTENT, so that stays true
		// across a restart; the old fmt.Sprintf("cycle-%d", cycleNum) reset to
		// cycle-0 and made the first cycles of every restart no-ops.
		//
		// Obtained ONCE per cycle and reused for every task in it, so a crashed
		// cycle re-runs with the same generation and resumes from its
		// checkpoints. A failure here aborts the cycle rather than falling back
		// to an empty generation, which would be exactly the replay above.
		gen, gerr := state.NextGeneration(cycleCtx, opts.Target)
		if gerr != nil {
			return fmt.Errorf("monitor: cycle %d: generation: %w", cycleNum, gerr)
		}

		// Step 1: Run the composite pipeline. RunCompositeAsync boots internally
		// (D-01 single-boot-per-call) and owns its own checkpoint lifecycle.
		// Each cycle records a new scan row.
		cycleOpts := opts
		cycleOpts.RunGeneration = fmt.Sprintf("gen-%d", gen)
		if err := RunCompositeAsync(cycleCtx, cycleOpts, monCfg.Mode); err != nil {
			return fmt.Errorf("monitor: cycle %d (gen %d): pipeline: %w", cycleNum, gen, err)
		}

		// Lazy-open the shared store now that this cycle's pipeline has created
		// it. sql.Open is connection-lazy; a plain open (no "?mode=ro") tolerates
		// a first-cycle file that the ingest has just written. A genuinely empty
		// store still surfaces as ErrNoRows below (warn + skip), never an error.
		if q == nil {
			opened, oerr := sql.Open("sqlite", dbPath)
			if oerr != nil {
				slog.Warn("monitor: open store.db failed — skipping diff",
					"cycle", cycleNum, "path", dbPath, "err", oerr)
				return nil
			}
			db = opened
			q = sqlcgen.New(db)
		}

		// Step 2: Resolve current scan from the store.
		//
		// GetLatestCompletedScanForTarget filters status='completed', and plan
		// 15-10 made that state truthful: a run that died partway commits no scan
		// row at all, or commits as 'incomplete'. A partial cycle therefore
		// cannot become a baseline — a property to rely on, not re-implement.
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

		// Step 3: the baseline comes from persistent state, so a restarted
		// monitor diffs against the last scan the PREVIOUS process completed
		// instead of establishing a fresh baseline and skipping a whole delta.
		prevScanID, berr := state.Baseline(cycleCtx, opts.Target)
		if berr != nil {
			slog.Warn("monitor: Baseline read failed — treating this cycle as a fresh baseline",
				"cycle", cycleNum, "err", berr)
			prevScanID = ""
		}

		var newFQDNs []string
		newFindingCount := 0
		suppressedCount := 0
		filteredCount := 0

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
			urlRows, uerr := q.DiffScansURLs(cycleCtx, sqlcgen.DiffScansURLsParams{
				ScanA: currScan.ID,
				ScanB: prevScanID,
			})
			if uerr != nil {
				slog.Warn("monitor: DiffScansURLs failed", "cycle", cycleNum, "err", uerr)
			} else if len(urlRows) > 0 {
				slog.Info("monitor: new URLs observed", "cycle", cycleNum, "count", len(urlRows))
			}

			// Step 4: Collect new FQDNs for incremental seed file.
			for _, h := range hostRows {
				newFQDNs = append(newFQDNs, h.FQDN)
			}

			// Step 5: Dispatch new findings via EventFilter (D-04, WARNING-4 fix).
			for _, f := range findingRows {
				if !severityMeetsMin(f.Severity, minSeverity) {
					filteredCount++
					continue
				}
				host, locator := resolveFindingLocation(cycleCtx, q, f.FindingID)
				alert := FindingAlert{
					Fingerprint: findingFingerprint(f.TemplateSignature, f.Severity, host, locator),
					Severity:    f.Severity,
					Message:     formatFindingNotification(gen, f.TemplateSignature, f.Severity, host, locator),
				}
				sent, derr := dispatchFindingAlert(cycleCtx, ef, state, opts.Target, alert, suppression, wait)
				switch {
				case derr != nil:
					// NOT marked notified — the next cycle retries it.
					slog.Warn("monitor: finding notification failed after retries — will retry next cycle",
						"cycle", cycleNum, "template", f.TemplateSignature,
						"severity", f.Severity, "host", host, "err", derr)
				case sent:
					newFindingCount++
				default:
					suppressedCount++
				}
			}
		}

		// Step 6: Incremental re-feed (BLOCKER-1 fix, D-04/D-05).
		// Checkpoint InputHash = SHA-256(taskName+target+cfgSliceJSON+wordlistsLockContent+generation).
		// The seed file changes TargetListPath, which changes cfgSliceJSON, so the
		// re-feed re-executes for the new-asset partition only. It inherits
		// cycleOpts (NOT opts) so the run carries THIS cycle's generation — a
		// re-feed under an empty generation would hash like an ordinary scan.
		incrementalRan := false
		if monCfg.Incremental && len(newFQDNs) > 0 {
			seedPath, seedErr := writeNewAssetSeedFile(boot.WorkDir, gen, newFQDNs)
			if seedErr != nil {
				slog.Warn("monitor: writeNewAssetSeedFile failed — skipping incremental re-run",
					"cycle", cycleNum, "err", seedErr)
			} else {
				monCfg.NewAssetSeedPath = seedPath
				incrementalOpts := cycleOpts
				incrementalOpts.TargetListPath = seedPath
				if rerunErr := RunCompositeAsync(cycleCtx, incrementalOpts, monCfg.Mode); rerunErr != nil {
					slog.Warn("monitor: incremental re-run failed",
						"cycle", cycleNum, "err", rerunErr)
				} else {
					incrementalRan = true
					slog.Info("monitor: incremental re-run complete",
						"cycle", cycleNum, "new_assets", len(newFQDNs), "seed", seedPath)
				}
			}
		}

		// Step 7: Dispatch cycle-end notification via EventFilter (WARNING-4 fix).
		elapsed := time.Since(cycleStart)
		summaryMsg := fmt.Sprintf("[gen %d] cycle complete — new_findings=%d suppressed=%d below_min_severity=%d new_subs=%d elapsed=%s",
			gen, newFindingCount, suppressedCount, filteredCount, len(newFQDNs), elapsed.Round(time.Second))
		if err := ef.NotifyEvent(cycleCtx, notifier.EventScanComplete, notifier.LevelInfo, summaryMsg); err != nil {
			slog.Warn("monitor: NotifyEvent(ScanComplete) failed", "err", err)
		}

		// Step 8: Print cycle summary per OUTPUT_VERBOSITY (MON-07).
		verbosity := boot.App.Cfg.Output.Verbosity
		switch verbosity {
		case 0:
			// VerbosityQuiet — suppress cycle summary.
		case 1:
			// VerbosityNormal — one summary line.
			fmt.Fprintf(os.Stderr, "[OK  ] monitor cycle %d (gen %d)  new_findings=%d  new_subs=%d  elapsed=%s\n",
				cycleNum, gen, newFindingCount, len(newFQDNs), elapsed.Round(time.Second))
		default:
			// VerbosityVerbose — summary + per-category breakdown.
			fmt.Fprintf(os.Stderr, "[OK  ] monitor cycle %d (gen %d)  new_findings=%d  new_subs=%d  elapsed=%s\n",
				cycleNum, gen, newFindingCount, len(newFQDNs), elapsed.Round(time.Second))
			fmt.Fprintf(os.Stderr, "         findings_delta=%d  hosts_delta=%d  suppressed=%d  below_min_severity=%d\n",
				newFindingCount, len(newFQDNs), suppressedCount, filteredCount)
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

		// Step 10: Advance the baseline — LAST, and only now.
		//
		// Writing it earlier would mean a crash between the diff and the
		// notifications silently skipped that delta: the next cycle would diff
		// against a scan whose findings were never sent. Because the write is the
		// final act of a completed cycle, a crash anywhere above re-diffs the
		// same pair on the next cycle instead.
		//
		// When the incremental re-feed ran it produced ITS OWN scan row, which is
		// now the target's latest completed scan. Leaving the baseline on
		// currScan would make the next cycle re-diff the re-feed's assets as
		// "new". Re-resolve so the baseline is the scan the cycle actually ended
		// on. (Latest resolution is deterministic per plan 15-18's rowid
		// tie-break — scans.id is a UUID and does NOT sort chronologically.)
		baselineID := currScan.ID
		if incrementalRan {
			if latest, lerr := q.GetLatestCompletedScanForTarget(cycleCtx, opts.Target); lerr == nil && latest.ID != "" {
				baselineID = latest.ID
			} else if lerr != nil && !errors.Is(lerr, sql.ErrNoRows) {
				slog.Warn("monitor: post-incremental latest-scan lookup failed — baseline stays on the cycle scan",
					"cycle", cycleNum, "err", lerr)
			}
		}
		if err := state.SetBaseline(cycleCtx, opts.Target, baselineID); err != nil {
			slog.Warn("monitor: SetBaseline failed — the next cycle will re-diff this delta",
				"cycle", cycleNum, "err", err)
		}

		return nil
	}

	return runMonitorLoop(ctx, interval, maxCycles, wait, runCycle)
}

// config_MonitorView is the subset of config.MonitorConfig the loop consumes.
// Copying it keeps the resolution logic testable without a whole *config.Config
// and documents exactly which four settings the monitor honours.
type config_MonitorView struct { //nolint:revive // the underscore marks it as a config projection, not an exported type
	IntervalMinutes  int
	MaxCycles        int
	MinSeverity      string
	AlertSuppression bool
}

// resolveFindingLocation returns the host and locator for a finding id so the
// fingerprint can include them.
//
// DiffScansFindings returns only (id, template_signature, severity, title) —
// plan 15-18 deliberately kept that four-column subset — so the row itself
// cannot identify WHERE the finding is. GetFinding supplies the stored path and
// matched_at, and GetHost resolves host_id to an FQDN. Both lookups are
// best-effort: a finding whose host cannot be resolved still gets a fingerprint,
// just one built from fewer inputs, which can only cause an extra alert.
//
// Diffs are small (new findings for one cycle), so two point lookups per new
// finding is not a hot path.
func resolveFindingLocation(ctx context.Context, q *sqlcgen.Queries, findingID int64) (host, locator string) {
	if q == nil {
		return "", ""
	}
	f, err := q.GetFinding(ctx, findingID)
	if err != nil {
		slog.Debug("monitor: GetFinding failed — fingerprint degrades to template+severity",
			"finding_id", findingID, "err", err)
		return "", ""
	}
	locator = firstNonEmptyString(f.MatchedAt, f.Path)
	if f.HostID != nil {
		if h, herr := q.GetHost(ctx, *f.HostID); herr == nil {
			host = h.FQDN
		}
	}
	if host == "" {
		// No host row: recover the hostname from the locator. url.Parse reports a
		// BARE hostname as a path (u.Host == ""), which is what made plan 15-14's
		// F19 locator fix inert — findingHostFromLocator handles that shape.
		host = findingHostFromLocator(locator)
	}
	return host, locator
}

// Compile-time proof: *notifier.Multi implements notifier.Flusher.
// This verifies the BLOCKER-2 fix — the type assertion in RunMonitorAsync
// will succeed at runtime.
var _ notifier.Flusher = (*notifier.Multi)(nil)
