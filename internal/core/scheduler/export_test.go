// Source: Plan 05 Task 1 test helpers — exposes the unexported
// startHeartbeat function to the scheduler_test (external) package so the
// XCUT-09 heartbeat cadence tests can drive it without going through the
// full RunStage path (which would take seconds at HeartbeatSeconds=1).
//
// The convention follows the official Go idiom: declare exported wrappers
// in an export_test.go file in the same package, so the symbols are only
// visible at test build time.
package scheduler

import (
	"context"
	"log/slog"
	"time"
)

// HeartbeatForTest is the test-only export for startHeartbeat. Stop the
// goroutine by calling the returned function (which closes a done chan).
func HeartbeatForTest(ctx context.Context, log *slog.Logger, name, module string, cadence time.Duration) func() {
	return startHeartbeat(ctx, log, name, module, cadence)
}
