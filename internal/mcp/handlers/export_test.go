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
func ExportedRunMonitorLoop(
	ctx context.Context,
	interval time.Duration,
	maxCycles int,
	runCycle func(context.Context, int) error,
) error {
	return runMonitorLoop(ctx, interval, maxCycles, runCycle)
}

// ExportedFindingContentHash exposes findingContentHash for testing.
func ExportedFindingContentHash(templateSig, severity, matchedAt string) string {
	return findingContentHash(templateSig, severity, matchedAt)
}

// ExportedWriteNewAssetSeedFile exposes writeNewAssetSeedFile for testing.
func ExportedWriteNewAssetSeedFile(workDir string, cycleNum int, newFQDNs []string) (string, error) {
	return writeNewAssetSeedFile(workDir, cycleNum, newFQDNs)
}

// ApplyDedup simulates the per-finding dedup step from the monitor loop.
// It computes the content hash, checks notifiedHashes, and calls
// ef.NotifyEvent if not seen. Used by TestNoReNotify_SameHash and
// TestNoReNotify_NewHash.
func ApplyDedup(
	ctx context.Context,
	ef *notifier.EventFilter,
	notifiedHashes map[string]struct{},
	templateSig, severity, matchedAt string,
	cycleNum int,
) {
	hash := findingContentHash(templateSig, severity, matchedAt)
	if _, seen := notifiedHashes[hash]; seen {
		return
	}
	notifiedHashes[hash] = struct{}{}
	msg := formatFindingNotification(cycleNum, templateSig, severity, matchedAt)
	_ = ef.NotifyEvent(ctx, notifier.EventCriticalFinding, notifier.LevelWarn, msg)
}
