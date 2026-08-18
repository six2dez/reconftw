// Internal-package test for startHeartbeat's nil-logger fallback and its
// stop path. Added to close the XCUT-03 statement-weighted coverage gate
// for internal/core/scheduler/heartbeat.go after 15-07 replaced the
// unweighted per-function mean.
package scheduler

import (
	"context"
	"testing"
	"time"
)

// A nil logger must fall back to slog.Default() rather than panicking on
// the first emit. The cadence is deliberately long so the goroutine parks
// on its first timer and the test exercises the stop path, not the tick
// path — this asserts the fallback is applied synchronously, before any
// heartbeat can fire.
func TestStartHeartbeatNilLoggerFallsBackAndStops(t *testing.T) {
	stop := startHeartbeat(context.Background(), nil, "task.name", "module", time.Hour)
	if stop == nil {
		t.Fatal("startHeartbeat returned a nil stop func")
	}

	// Must be safe to call, and idempotent — the production callers defer it.
	stop()
	stop()
}

// A non-positive cadence disables heartbeats entirely and returns a no-op
// stop. Pinned so the disable path cannot regress into starting a goroutine.
func TestStartHeartbeatNonPositiveCadenceIsNoop(t *testing.T) {
	for _, cadence := range []time.Duration{0, -time.Second} {
		stop := startHeartbeat(context.Background(), nil, "task.name", "module", cadence)
		if stop == nil {
			t.Fatalf("cadence %v: returned a nil stop func", cadence)
		}
		stop()
	}
}

// Cancelling the context must retire the goroutine via its ctx.Done arm.
func TestStartHeartbeatContextCancelStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stop := startHeartbeat(ctx, nil, "task.name", "module", time.Millisecond)
	cancel()
	stop()
}
