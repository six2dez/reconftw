// Source: XCUT-09 (REQUIREMENTS.md):
//
//	every long-running task emits heartbeat events; failed tasks emit
//	structured error events with classification; CI test asserts heartbeat
//	cadence
//
// Implementation: startHeartbeat spawns a goroutine that emits
// `slog.Info("task_heartbeat", "task", name, "module", module, "elapsed", elapsed)`
// at the configured cadence. First emission is delayed by 2*cadence so
// short tasks (sub-cadence) never emit a heartbeat — this matches the
// XCUT-09 spec "long-running" qualifier.
//
// Lifecycle: startHeartbeat returns a `stop` function that must be called
// by the Scheduler's runOne defer to guarantee goroutine teardown. goleak
// (Plan 05 testfile init()) verifies no leaks on the per-task path.
//
// Threading: each call to startHeartbeat spawns ONE goroutine; the
// goroutine reads from a single time.Ticker channel + a done channel and
// exits on either signal.

package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// startHeartbeat begins emitting "task_heartbeat" slog records at cadence
// for the named task. First heartbeat fires at 2*cadence (so tasks
// completing under cadence emit nothing). Returns a stop function that
// MUST be called to stop the goroutine.
//
// If cadence is non-positive, startHeartbeat is a no-op and stop() is a
// no-op — used by tests that want to disable heartbeats entirely.
//
// log may be nil — in that case heartbeats fall back to slog.Default()
// which goes to stderr in JSON format.
func startHeartbeat(ctx context.Context, log *slog.Logger, name, module string, cadence time.Duration) (stop func()) {
	if cadence <= 0 {
		return func() {}
	}
	if log == nil {
		log = slog.Default()
	}
	done := make(chan struct{})
	var stopOnce sync.Once
	start := time.Now()
	go func() {
		// First heartbeat at 2*cadence — skip short tasks.
		firstTick := time.NewTimer(2 * cadence)
		defer firstTick.Stop()
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-firstTick.C:
		}
		emit(log, name, module, time.Since(start))

		ticker := time.NewTicker(cadence)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				emit(log, name, module, time.Since(start))
			}
		}
	}()
	// Idempotent stop — Scheduler.runOne defers stopHB AND some callers
	// invoke it explicitly; sync.Once prevents double-close panic.
	return func() {
		stopOnce.Do(func() { close(done) })
	}
}

// emit writes a "task_heartbeat" record at info level. Centralised so the
// event name is consistent and trivially searchable.
func emit(log *slog.Logger, name, module string, elapsed time.Duration) {
	log.Info("task_heartbeat",
		slog.String("task", name),
		slog.String("module", module),
		slog.Duration("elapsed", elapsed),
	)
}
