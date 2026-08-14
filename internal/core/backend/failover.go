// SPDX-License-Identifier: MIT
//
// FailoverBackend — decorator that retries on *AxiomFailure with kill-switch.
//
// Design:
//   - Exec: tries Primary; on *AxiomFailure increments failures; if failures >= Threshold
//     sets killSwitch=true; always calls Fallback on AxiomFailure; non-AxiomFailure errors
//     propagate without fallback. On Primary success, resets failure counter.
//   - Stream: if killSwitch → Fallback.Stream directly. If Primary.Stream returns
//     *AxiomFailure with a non-nil channel, spawns a ctx-bounded drain goroutine (W4 fix)
//     then returns Fallback.Stream. The drain goroutine uses select on primaryCh and
//     ctx.Done() so a hung channel cannot leak a goroutine.
//   - HealthCheck: Primary.HealthCheck; on *AxiomFailure → Fallback.HealthCheck.
//   - Capacity: Primary.Capacity() when killSwitch=false; Fallback.Capacity() when true.
//
// W4 fix: The partial-drain goroutine is ALWAYS ctx-bounded. A hung primary channel
// (e.g. fleet timeout) cannot leak a goroutine — it exits when context is cancelled.
//
// F6 (phase 15): a fleet tool can fail in a way Primary.Stream's return value never
// shows. Dispatch succeeds, the fleet runs the tool, the tool exits non-zero, and the
// only trace is Event.Err on the stream's terminal event. Both consumption paths now
// observe that field: the partial-drain goroutine and the success-path relay each
// record it as a fleet failure (counting toward Threshold exactly like an
// *AxiomFailure dispatch error), and the relay forwards the event to the caller
// unmodified so the task-level contract in backend/stream.go still applies. Before
// this, a fleet whose tools all crashed reported a clean run forever and the
// kill-switch never tripped.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-06-PLAN.md Task 1b.
package backend

import (
	"context"
	stderrors "errors"
	"sync"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// FailoverBackend wraps a Primary (e.g. AxiomBackend) and a Fallback (LocalBackend).
// It transparently retries Fallback operations on *AxiomFailure, implementing a
// kill-switch that disables Primary after Threshold consecutive failures.
type FailoverBackend struct {
	Primary   Backend
	Fallback  Backend
	Threshold int // number of consecutive *AxiomFailure before kill-switch trips

	mu         sync.Mutex
	failures   int
	killSwitch bool
}

// Exec dispatches to Primary unless the kill-switch has tripped.
//
// On *AxiomFailure from Primary:
//   - Increments the failure counter.
//   - If failures >= Threshold, sets killSwitch=true.
//   - Falls back to Fallback.Exec.
//
// On non-AxiomFailure errors from Primary, propagates without fallback (caller
// determines if the error is retriable — e.g. context cancellation is not).
//
// On Primary success, resets the failure counter to 0.
func (f *FailoverBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
	if f.isKillSwitched() {
		return f.Fallback.Exec(ctx, t, args)
	}

	res, err := f.Primary.Exec(ctx, t, args)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			f.recordFailure()
			return f.Fallback.Exec(ctx, t, args)
		}
		// Non-AxiomFailure: propagate without fallback.
		return nil, err
	}
	// Primary succeeded — reset failure counter.
	f.resetFailures()
	return res, nil
}

// ExecEnv mirrors Exec for the env seam: dispatches to Primary.ExecEnv unless the
// kill-switch has tripped, falling back to Fallback.ExecEnv on *AxiomFailure (which
// includes the AxiomBackend not-supported-when-env-set failure — env-requiring tools
// therefore transparently land on the local Fallback). Non-AxiomFailure errors
// propagate without fallback.
func (f *FailoverBackend) ExecEnv(ctx context.Context, t *Tool, args []string, env []string) (*Result, error) {
	if f.isKillSwitched() {
		return f.Fallback.ExecEnv(ctx, t, args, env)
	}

	res, err := f.Primary.ExecEnv(ctx, t, args, env)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			f.recordFailure()
			return f.Fallback.ExecEnv(ctx, t, args, env)
		}
		return nil, err
	}
	f.resetFailures()
	return res, nil
}

// StreamEnv mirrors Stream for the env seam (see ExecEnv). On *AxiomFailure from
// Primary it drains any partial channel (ctx-bounded, W4 fix) and falls back to
// Fallback.StreamEnv. On success the primary channel is wrapped by
// observePrimaryStream so a fleet tool's terminal Event.Err counts toward the
// failover threshold (F6).
func (f *FailoverBackend) StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error) {
	if f.isKillSwitched() {
		return f.Fallback.StreamEnv(ctx, t, args, env)
	}

	primaryCh, err := f.Primary.StreamEnv(ctx, t, args, env)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			f.drainPrimaryPartial(ctx, primaryCh)
			return f.Fallback.StreamEnv(ctx, t, args, env)
		}
		return nil, err
	}
	return f.observePrimaryStream(ctx, primaryCh), nil
}

// Stream dispatches to Primary.Stream unless the kill-switch has tripped.
//
// If Primary.Stream returns *AxiomFailure:
//   - If the returned channel is non-nil (partial results), spawns a ctx-bounded
//     drain goroutine (W4 fix) to prevent goroutine leaks. That goroutine records
//     a terminal Event.Err on the partial channel as a fleet failure (F6).
//   - Returns Fallback.Stream(ctx, t, args).
//
// If Primary.Stream succeeds, returns a relay over the Primary channel that
// forwards every event unmodified while watching for the terminal Event.Err.
func (f *FailoverBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
	if f.isKillSwitched() {
		return f.Fallback.Stream(ctx, t, args)
	}

	primaryCh, err := f.Primary.Stream(ctx, t, args)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			f.drainPrimaryPartial(ctx, primaryCh)
			return f.Fallback.Stream(ctx, t, args)
		}
		return nil, err
	}
	// Primary dispatch succeeded — but the tool it launched may still exit
	// non-zero, which only Event.Err reports.
	return f.observePrimaryStream(ctx, primaryCh), nil
}

// drainPrimaryPartial consumes an abandoned primary channel after Primary.Stream
// returned *AxiomFailure and the caller was handed the Fallback stream instead.
//
// W4: the goroutine is ALWAYS ctx-bounded, so a hung fleet channel that never
// closes cannot leak it. A nil channel is a no-op — the fleet reported the
// failure without opening a stream at all.
//
// F6: the partial channel can still carry a terminal Event.Err (the fleet started
// the tool, the tool exited non-zero, and only then did dispatch report failure).
// Recording it here is what makes such a run count toward Threshold. It is NOT
// forwarded to the caller: the caller is consuming the Fallback stream, and
// injecting the primary's error there would report the local retry as failed when
// it may well have succeeded — the exact outcome failover exists to produce.
func (f *FailoverBackend) drainPrimaryPartial(ctx context.Context, primaryCh <-chan Event) {
	if primaryCh == nil {
		return
	}
	go func() {
		observed := false
		for {
			select {
			case ev, ok := <-primaryCh:
				if !ok {
					return // channel closed — exit cleanly
				}
				if ev.Err != nil && !observed {
					observed = true
					f.recordFailure()
				}
			case <-ctx.Done():
				return // context cancelled — exit, no leak
			}
		}
	}()
}

// observePrimaryStream relays a successful primary stream to the caller while
// watching for the terminal Event.Err that reports a fleet tool exiting non-zero
// or overflowing its scanner.
//
// Events are forwarded WHOLESALE and never rewritten, so backend.Drain and
// backend.Collect behave over a failover stream exactly as they do over a local
// one. The relay's only side effect is bookkeeping: the first error-carrying event
// records a fleet failure (counting toward Threshold like an *AxiomFailure
// dispatch error), and a stream that ends without one resets the consecutive
// failure counter, mirroring Exec's on-success reset.
//
// The ctx.Done() arm is the same abandonment guard as runner.streamWithContract:
// a bare send would block this goroutine forever if the consumer stopped reading.
// The post-cancellation drain keeps watching for the terminal error so an
// abandoned fleet run still counts.
func (f *FailoverBackend) observePrimaryStream(ctx context.Context, primaryCh <-chan Event) <-chan Event {
	if primaryCh == nil {
		return nil
	}
	out := make(chan Event, 64)
	go func() {
		defer close(out)
		observed := false
		note := func(ev Event) {
			if ev.Err != nil && !observed {
				observed = true
				f.recordFailure()
			}
		}
		for ev := range primaryCh {
			note(ev)
			select {
			case out <- ev:
			case <-ctx.Done():
				for rest := range primaryCh {
					note(rest)
				}
				return
			}
		}
		if !observed {
			f.resetFailures()
		}
	}()
	return out
}

// HealthCheck calls Primary.HealthCheck; on *AxiomFailure falls back to Fallback.HealthCheck.
func (f *FailoverBackend) HealthCheck(ctx context.Context) error {
	err := f.Primary.HealthCheck(ctx)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			return f.Fallback.HealthCheck(ctx)
		}
		return err
	}
	return nil
}

// Capacity returns Primary.Capacity() when killSwitch=false; Fallback.Capacity() otherwise.
func (f *FailoverBackend) Capacity() int {
	if f.isKillSwitched() {
		return f.Fallback.Capacity()
	}
	return f.Primary.Capacity()
}

// isKillSwitched returns true if the kill-switch has tripped (locked read).
func (f *FailoverBackend) isKillSwitched() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitch
}

// recordFailure increments the failure counter and trips the kill-switch if
// the threshold is reached.
func (f *FailoverBackend) recordFailure() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures++
	if f.Threshold > 0 && f.failures >= f.Threshold {
		f.killSwitch = true
	}
}

// resetFailures resets the failure counter on Primary success.
func (f *FailoverBackend) resetFailures() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = 0
}
