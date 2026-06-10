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
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-06-PLAN.md Task 1b.
package backend

import (
	stderrors "errors"
	"context"
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
// Fallback.StreamEnv.
func (f *FailoverBackend) StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error) {
	if f.isKillSwitched() {
		return f.Fallback.StreamEnv(ctx, t, args, env)
	}

	primaryCh, err := f.Primary.StreamEnv(ctx, t, args, env)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			if primaryCh != nil {
				go func() {
					for {
						select {
						case _, ok := <-primaryCh:
							if !ok {
								return
							}
						case <-ctx.Done():
							return
						}
					}
				}()
			}
			return f.Fallback.StreamEnv(ctx, t, args, env)
		}
		return nil, err
	}
	return primaryCh, nil
}

// Stream dispatches to Primary.Stream unless the kill-switch has tripped.
//
// If Primary.Stream returns *AxiomFailure:
//   - If the returned channel is non-nil (partial results), spawns a ctx-bounded
//     drain goroutine (W4 fix) to prevent goroutine leaks.
//   - Returns Fallback.Stream(ctx, t, args).
//
// If Primary.Stream succeeds, returns the Primary channel directly.
func (f *FailoverBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
	if f.isKillSwitched() {
		return f.Fallback.Stream(ctx, t, args)
	}

	primaryCh, err := f.Primary.Stream(ctx, t, args)
	if err != nil {
		var axErr *coreerrors.AxiomFailure
		if stderrors.As(err, &axErr) {
			// W4 fix: drain the partial channel (if non-nil) in a ctx-bounded goroutine.
			// This goroutine exits cleanly when ctx is cancelled OR primaryCh is closed.
			// A hung fleet channel (never closes) does NOT leak a goroutine.
			if primaryCh != nil {
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
			return f.Fallback.Stream(ctx, t, args)
		}
		return nil, err
	}
	// Primary succeeded.
	return primaryCh, nil
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
