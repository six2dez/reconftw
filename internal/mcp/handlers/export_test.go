// export_test.go — white-box exports for monitor handler tests.
// This file is compiled only in test mode (package handlers, not handlers_test).
// It exposes unexported functions under exported names so the _test package
// can reach them without modifying the production API surface.
package handlers

import (
	"context"
	"time"

	"github.com/six2dez/reconftw/internal/core/notifier"
)

// ExportedRunMonitorLoop exposes the unexported runMonitorLoop for testing.
//
// wait replaces the inter-cycle sleep. Passing a non-nil wait is how tests
// exercise the loop without waiting for a real (floored, minutes-long)
// interval — see ExportedMonitorWaiter for the production behaviour.
func ExportedRunMonitorLoop(
	ctx context.Context,
	interval time.Duration,
	maxCycles int,
	wait func(context.Context, time.Duration) bool,
	runCycle func(context.Context, int) error,
) error {
	return runMonitorLoop(ctx, interval, maxCycles, wait, runCycle)
}

// ExportedWriteNewAssetSeedFile exposes writeNewAssetSeedFile for testing.
func ExportedWriteNewAssetSeedFile(workDir string, generation uint64, newFQDNs []string) (string, error) {
	return writeNewAssetSeedFile(workDir, generation, newFQDNs)
}

// ExportedSeverityMeetsMin exposes the MinSeverity gate for testing.
func ExportedSeverityMeetsMin(severity, minSeverity string) bool {
	return severityMeetsMin(severity, minSeverity)
}

// ExportedMonitorEventForSeverity exposes the severity → event-kind/level map.
func ExportedMonitorEventForSeverity(severity string) (notifier.EventKind, notifier.Level) {
	return monitorEventForSeverity(severity)
}

// ExportedNotifyWithRetry exposes the bounded notification retry for testing.
func ExportedNotifyWithRetry(
	ctx context.Context,
	ef *notifier.EventFilter,
	kind notifier.EventKind,
	lvl notifier.Level,
	msg string,
	wait func(context.Context, time.Duration) bool,
) error {
	return notifyWithRetry(ctx, ef, kind, lvl, msg, wait)
}

// ExportedDispatchFindingAlert exposes the notify-then-mark ordering for testing.
func ExportedDispatchFindingAlert(
	ctx context.Context,
	ef *notifier.EventFilter,
	st *MonitorState,
	target string,
	alert FindingAlert,
	suppression bool,
	wait func(context.Context, time.Duration) bool,
) (bool, error) {
	return dispatchFindingAlert(ctx, ef, st, target, alert, suppression, wait)
}

// ExportedMonitorConstants surfaces the tuning constants so tests can assert the
// retry budget stays below the interval floor without re-declaring the numbers.
func ExportedMonitorConstants() (defaultInterval, minInterval, retryBase time.Duration, retryAttempts int) {
	return defaultMonitorInterval, minMonitorInterval, monitorNotifyBaseDelay, monitorNotifyAttempts
}

// WithMonitorWaiter returns a copy of opts whose inter-cycle wait and
// notification-retry backoff are replaced by wait.
//
// The field is unexported precisely so no production caller can reach it: the
// interval floor exists to stop the monitor hammering third-party
// infrastructure, and a public override would be a way around it. Tests reach it
// through this file, which only exists in test builds.
func WithMonitorWaiter(opts MonitorOptions, wait func(context.Context, time.Duration) bool) MonitorOptions {
	opts.waitFn = wait
	return opts
}

// InstantMonitorWaiter is a wait function that returns immediately (honouring
// context cancellation), for tests that must not sleep.
func InstantMonitorWaiter(ctx context.Context, _ time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		return true
	}
}

// ExportedRealMonitorWait exposes the production inter-cycle wait, which every
// other test replaces with an instant fake. It is the only code path that
// actually sleeps between cycles, so it needs its own coverage.
func ExportedRealMonitorWait(ctx context.Context, d time.Duration) bool {
	return realMonitorWait(ctx, d)
}
