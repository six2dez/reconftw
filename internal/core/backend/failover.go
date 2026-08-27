// SPDX-License-Identifier: MIT
//
// FailoverBackend — decorator that retries on *AxiomFailure with kill-switch.
//
// Design:
//   - Exec: tries Primary; on an infrastructure *AxiomFailure increments failures;
//     if failures >= Threshold sets killSwitch=true; always calls Fallback on
//     AxiomFailure. Capability refusals fall back without counting as fleet health.
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
// observe that field on a successfully opened primary stream. A typed stream
// dispatch failure is counted immediately before the partial channel is drained,
// exactly once; the success-path relay counts a terminal Event.Err and forwards it
// unmodified so the task-level contract in backend/stream.go still applies.
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
// kill-switch that disables Primary after Threshold consecutive infrastructure
// failures. Capability refusals retry locally without affecting fleet health.
type FailoverBackend struct {
	Primary   Backend
	Fallback  Backend
	Threshold int // consecutive infrastructure failures before kill-switch trips

	mu         sync.Mutex
	failures   int
	killSwitch bool
}

// Exec dispatches to Primary unless the kill-switch has tripped.
//
// On *AxiomFailure from Primary:
//   - Increments the failure counter unless this is a capability refusal.
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
			if !axErr.Capability {
				f.recordFailure()
			}
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
// kill-switch has tripped, falling back to Fallback.ExecEnv on *AxiomFailure.
// AxiomBackend's not-supported-when-env-set refusal therefore lands locally but,
// as a capability refusal, does not count as unhealthy fleet infrastructure.
func (f *FailoverBackend) ExecEnv(ctx context.Context, t *Tool, args []string, env []string) (*Result, error) {
	if f.isKillSwitched() {
		return f.Fallback.ExecEnv(ctx, t, args, env)
	}

	res, err := f.Primary.ExecEnv(ctx, t, args, env)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			if !axErr.Capability {
				f.recordFailure()
			}
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
			if !axErr.Capability {
				f.recordFailure()
			}
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
//   - Counts a non-capability dispatch failure exactly once.
//   - If the returned channel is non-nil, spawns a ctx-bounded drain goroutine
//     (W4 fix) to prevent goroutine leaks without counting partial events again.
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
			if !axErr.Capability {
				f.recordFailure()
			}
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
// The typed dispatch error is counted before this function starts. Events from
// the abandoned channel are deliberately not counted again: one primary attempt
// contributes at most one consecutive failure. They are not forwarded because
// the caller is consuming the fallback stream.
func (f *FailoverBackend) drainPrimaryPartial(ctx context.Context, primaryCh <-chan Event) {
	if primaryCh == nil {
		return
	}
	go func() {
		for {
			select {
			case _, ok := <-primaryCh:
				if !ok {
					return // channel closed — exit cleanly
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

// ExecOpts mirrors ExecEnv for the full options seam: dispatch to Primary.ExecOpts
// unless the kill-switch has tripped, falling back to Fallback.ExecOpts on
// *AxiomFailure. Since AxiomBackend refuses any dispatch carrying Stdin, StdinPath
// or Dir with exactly that error type, every option-requiring tool transparently
// lands on the local Fallback.
//
// T-18-01-04 — THE OPTIONS ARE FORWARDED ON BOTH LEGS, INCLUDING THE RETRY. A
// fallback that dropped the stdin would hand the tool an EMPTY standard input and
// return a clean zero-finding success, indistinguishable from a genuinely empty
// result. Because ExecOptions.Stdin is []byte and not an io.Reader, the second
// dispatch builds its own fresh reader and cannot be handed an exhausted one.
// Pinned by TestFailoverForwardsStdinToTheLocalLeg and by MUTATION 1.
func (f *FailoverBackend) ExecOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (*Result, error) {
	if f.isKillSwitched() {
		return f.Fallback.ExecOpts(ctx, t, args, opts)
	}

	res, err := f.Primary.ExecOpts(ctx, t, args, opts)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			if !axErr.Capability {
				f.recordFailure()
			}
			return f.Fallback.ExecOpts(ctx, t, args, opts)
		}
		return nil, err
	}
	f.resetFailures()
	return res, nil
}

// StreamOpts mirrors StreamEnv for the full options seam (see ExecOpts). The
// options are forwarded on the kill-switch leg, the primary leg and the fallback
// leg — all three.
func (f *FailoverBackend) StreamOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (<-chan Event, error) {
	if f.isKillSwitched() {
		return f.Fallback.StreamOpts(ctx, t, args, opts)
	}

	primaryCh, err := f.Primary.StreamOpts(ctx, t, args, opts)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			if !axErr.Capability {
				f.recordFailure()
			}
			f.drainPrimaryPartial(ctx, primaryCh)
			return f.Fallback.StreamOpts(ctx, t, args, opts)
		}
		return nil, err
	}
	return f.observePrimaryStream(ctx, primaryCh), nil
}
