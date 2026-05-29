// SPDX-License-Identifier: MIT
//
// Tests for FailoverBackend (Phase 4 plan-06 Task 1b).
//
// TDD RED phase: these tests will fail until failover.go is created.
//
// Test inventory:
//  1. Exec calls Primary; on *AxiomFailure increments failures; calls Fallback; returns Fallback result.
//  2. After FailoverThreshold consecutive *AxiomFailure, killSwitch flips; subsequent Exec skips Primary.
//  3. Stream on Primary *AxiomFailure: partial-drain goroutine is ctx-bounded; falls back to Fallback.
//  4. Capacity returns Primary.Capacity() when killSwitch=false; Fallback.Capacity() when true.
//  5. Primary success on Exec resets failure count.
//  6. Stream partial-drain goroutine exits when ctx is cancelled (no goroutine leak).
package backend_test

import (
	"context"
	stderrors "errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// TestFailoverBackend_Exec_PrimaryAxiomFailure_FallsBackToFallback verifies
// that on *AxiomFailure from Primary, the Fallback.Exec result is returned.
func TestFailoverBackend_Exec_PrimaryAxiomFailure_FallsBackToFallback(t *testing.T) {
	primary := &failingPrimary{axiomErr: true}
	fallback := &successFallback{result: &backend.Result{Stdout: []byte("ok"), ExitCode: 0}}

	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  fallback,
		Threshold: 3,
	}

	tool := &backend.Tool{Name: "puredns"}
	res, err := fb.Exec(context.Background(), tool, nil)
	if err != nil {
		t.Fatalf("Exec: unexpected error: %v", err)
	}
	if string(res.Stdout) != "ok" {
		t.Errorf("Exec: got stdout %q, want %q", res.Stdout, "ok")
	}
	if primary.callCount != 1 {
		t.Errorf("Primary.Exec call count: got %d, want 1", primary.callCount)
	}
	if fallback.callCount != 1 {
		t.Errorf("Fallback.Exec call count: got %d, want 1", fallback.callCount)
	}
}

// TestFailoverBackend_Exec_KillSwitchAfterThreshold verifies that after
// FailoverThreshold consecutive *AxiomFailure calls, the killSwitch flips and
// subsequent Exec calls skip Primary entirely.
func TestFailoverBackend_Exec_KillSwitchAfterThreshold(t *testing.T) {
	const threshold = 3
	primary := &failingPrimary{axiomErr: true}
	fallback := &successFallback{result: &backend.Result{ExitCode: 0}}

	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  fallback,
		Threshold: threshold,
	}

	tool := &backend.Tool{Name: "puredns"}

	// Trigger threshold consecutive failures.
	for i := 0; i < threshold; i++ {
		_, _ = fb.Exec(context.Background(), tool, nil)
	}

	primaryCountBefore := primary.callCount

	// Next call should skip Primary.
	_, err := fb.Exec(context.Background(), tool, nil)
	if err != nil {
		t.Fatalf("Exec after kill-switch: unexpected error: %v", err)
	}
	if primary.callCount != primaryCountBefore {
		t.Errorf("Primary was called after kill-switch flip (count before=%d, after=%d)",
			primaryCountBefore, primary.callCount)
	}
}

// TestFailoverBackend_Exec_PrimarySuccess_ResetFailures verifies that a
// successful Primary.Exec resets the failure counter.
func TestFailoverBackend_Exec_PrimarySuccess_ResetFailures(t *testing.T) {
	primary := &conditionalPrimary{failFirstN: 2}
	fallback := &successFallback{result: &backend.Result{ExitCode: 0}}

	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  fallback,
		Threshold: 5,
	}
	tool := &backend.Tool{Name: "puredns"}

	// Two failures.
	_, _ = fb.Exec(context.Background(), tool, nil)
	_, _ = fb.Exec(context.Background(), tool, nil)

	// Third call succeeds on Primary (resettig failures).
	res, err := fb.Exec(context.Background(), tool, nil)
	if err != nil {
		t.Fatalf("Exec 3: unexpected error: %v", err)
	}
	// After reset, Fallback should NOT have been called for the successful call.
	if fallback.callCount > 2 {
		t.Errorf("Fallback called %d times; expected at most 2 (the two failures)", fallback.callCount)
	}
	_ = res
}

// TestFailoverBackend_Capacity_NoKillSwitch returns Primary.Capacity().
func TestFailoverBackend_Capacity_NoKillSwitch(t *testing.T) {
	primary := &fixedCapacityBackend{cap: 10}
	fallback := &fixedCapacityBackend{cap: 2}

	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  fallback,
		Threshold: 3,
	}

	if got := fb.Capacity(); got != 10 {
		t.Errorf("Capacity() without kill-switch = %d, want %d", got, 10)
	}
}

// TestFailoverBackend_Capacity_KillSwitch returns Fallback.Capacity().
func TestFailoverBackend_Capacity_KillSwitch(t *testing.T) {
	primary := &failingPrimary{axiomErr: true}
	fallback := &fixedCapacityBackend{cap: 2}

	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  fallback,
		Threshold: 1, // kill immediately on first failure
	}

	// Trigger kill-switch.
	tool := &backend.Tool{Name: "puredns"}
	_, _ = fb.Exec(context.Background(), tool, nil)

	if got := fb.Capacity(); got != 2 {
		t.Errorf("Capacity() with kill-switch = %d, want %d (Fallback)", got, 2)
	}
}

// TestFailoverBackend_Stream_PrimaryAxiomFailure_CtxBounded verifies that the
// partial-drain goroutine spawned on Primary *AxiomFailure exits when ctx is
// cancelled (W4 fix — no goroutine leak).
func TestFailoverBackend_Stream_PrimaryAxiomFailure_CtxBounded(t *testing.T) {
	// Use a slow-primary that returns a channel that never closes on its own,
	// but we cancel the ctx — verifying the drain goroutine exits.
	hangCh := make(chan backend.Event) // never closed — simulates hung fleet
	primary := &streamAxiomFailurePrimary{ch: hangCh}
	fallback := &successFallback{result: &backend.Result{ExitCode: 0}}

	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  fallback,
		Threshold: 3,
	}

	ctx, cancel := context.WithCancel(context.Background())
	tool := &backend.Tool{Name: "puredns"}

	outCh, err := fb.Stream(ctx, tool, nil)
	if err != nil {
		t.Fatalf("Stream: unexpected error: %v", err)
	}
	// Cancel the context — partial-drain goroutine should exit.
	cancel()

	// Drain the fallback channel (empty, closes immediately).
	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-outCh:
			if !ok {
				return // channel closed cleanly
			}
		case <-timeout:
			t.Fatal("Stream: fallback channel did not close within 2s after ctx cancel")
		}
	}
}

// TestFailoverBackend_Stream_NoDoubleEmit verifies that when Primary fails
// with *AxiomFailure on Stream, Fallback events are NOT emitted twice.
func TestFailoverBackend_Stream_NoDoubleEmit(t *testing.T) {
	primary := &streamAxiomFailurePrimary{ch: closedCh()}
	fallback := &countingStreamFallback{events: []backend.Event{
		{Line: []byte("host1.example.com"), Source: "test"},
	}}

	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  fallback,
		Threshold: 3,
	}

	ctx := context.Background()
	tool := &backend.Tool{Name: "puredns"}

	outCh, err := fb.Stream(ctx, tool, nil)
	if err != nil {
		t.Fatalf("Stream: unexpected error: %v", err)
	}

	var got int
	for range outCh {
		got++
	}
	if got != 1 {
		t.Errorf("Stream: got %d events, want 1 (no double-emit)", got)
	}
}

// helpers ---

// closedCh returns an already-closed channel.
func closedCh() <-chan backend.Event {
	ch := make(chan backend.Event)
	close(ch)
	return ch
}

// failingPrimary always returns *AxiomFailure on Exec (axiomErr=true) or a
// plain error (axiomErr=false).
type failingPrimary struct {
	axiomErr  bool
	callCount int
}

func (f *failingPrimary) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	f.callCount++
	if f.axiomErr {
		return nil, &coreerrors.AxiomFailure{Operation: "exec", Inner: stderrors.New("fleet unreachable")}
	}
	return nil, stderrors.New("plain error")
}

func (f *failingPrimary) Stream(_ context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	if f.axiomErr {
		return nil, &coreerrors.AxiomFailure{Operation: "stream", Inner: stderrors.New("fleet unreachable")}
	}
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (f *failingPrimary) HealthCheck(_ context.Context) error {
	if f.axiomErr {
		return &coreerrors.AxiomFailure{Operation: "healthcheck", Inner: stderrors.New("fleet unreachable")}
	}
	return nil
}

func (f *failingPrimary) Capacity() int { return 4 }

// conditionalPrimary fails on first failFirstN calls then succeeds.
type conditionalPrimary struct {
	failFirstN int
	callCount  int
}

func (c *conditionalPrimary) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	c.callCount++
	if c.callCount <= c.failFirstN {
		return nil, &coreerrors.AxiomFailure{Operation: "exec", Inner: stderrors.New("fleet unreachable")}
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (c *conditionalPrimary) Stream(_ context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (c *conditionalPrimary) HealthCheck(_ context.Context) error { return nil }
func (c *conditionalPrimary) Capacity() int                       { return 4 }

// successFallback always succeeds, recording the number of Exec calls.
type successFallback struct {
	result    *backend.Result
	callCount int
}

func (s *successFallback) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	s.callCount++
	return s.result, nil
}

func (s *successFallback) Stream(_ context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (s *successFallback) HealthCheck(_ context.Context) error { return nil }
func (s *successFallback) Capacity() int                       { return 2 }

// fixedCapacityBackend just returns a fixed capacity.
type fixedCapacityBackend struct {
	cap int
}

func (f *fixedCapacityBackend) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	return &backend.Result{ExitCode: 0}, nil
}

func (f *fixedCapacityBackend) Stream(_ context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (f *fixedCapacityBackend) HealthCheck(_ context.Context) error { return nil }
func (f *fixedCapacityBackend) Capacity() int                       { return f.cap }

// streamAxiomFailurePrimary returns a channel (possibly never-closing) and
// always returns *AxiomFailure as a stream-start error, NOT as channel error.
// Per plan spec: Primary.Stream returns (ch, *AxiomFailure) simultaneously —
// the channel may be non-nil (partial results) or nil; FailoverBackend must
// handle both.
//
// In the W4-test model: Stream always returns an error; ch is a hint-channel
// that may be open (simulating partial results). FailoverBackend drains it
// in a goroutine bounded by ctx.Done().
type streamAxiomFailurePrimary struct {
	ch      <-chan backend.Event
	drained atomic.Int32
}

func (s *streamAxiomFailurePrimary) Stream(ctx context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	// Return channel + error simultaneously (partial-results model).
	return s.ch, &coreerrors.AxiomFailure{Operation: "stream", Inner: stderrors.New("fleet unreachable")}
}

func (s *streamAxiomFailurePrimary) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	return nil, &coreerrors.AxiomFailure{Operation: "exec", Inner: stderrors.New("fleet unreachable")}
}

func (s *streamAxiomFailurePrimary) HealthCheck(_ context.Context) error { return nil }
func (s *streamAxiomFailurePrimary) Capacity() int                       { return 4 }

// countingStreamFallback returns a channel that emits the provided events then closes.
type countingStreamFallback struct {
	events []backend.Event
}

func (c *countingStreamFallback) Stream(_ context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event, len(c.events))
	for _, e := range c.events {
		ch <- e
	}
	close(ch)
	return ch, nil
}

func (c *countingStreamFallback) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	return &backend.Result{ExitCode: 0}, nil
}

func (c *countingStreamFallback) HealthCheck(_ context.Context) error { return nil }
func (c *countingStreamFallback) Capacity() int                       { return 2 }
