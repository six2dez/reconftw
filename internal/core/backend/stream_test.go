// SPDX-License-Identifier: MIT
//
// Tests for the terminal-error contract (audit finding F6, phase 15 plan 02).
//
// The tests come in matched pairs that pin the ESCALATION BOUNDARY from opposite
// sides, because getting it backwards is the regression this plan is most exposed
// to:
//
//   - TestLocalBackend_Stream_NonZeroExit_SurfacesTerminalError proves a tool that
//     RAN and exited non-zero reaches the consumer as a non-nil Drain/Collect
//     return (→ task.StatusErrored).
//   - TestLocalBackend_Stream_MissingBinary_ErrorsFromStreamNotEvent proves a tool
//     that never ran surfaces through Stream()'s own error return and NEVER as an
//     Event.Err (→ task.StatusSkipped stays task.StatusSkipped).
//
// If the second one ever starts failing because the error moved onto the channel,
// every host missing an optional tool (arjun, commix, ghauri) becomes a failed
// scan, and internal/core/scheduler/policy.go fail-fasts the whole subdomains
// spine on it.
package backend_test

import (
	"context"
	stderrors "errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// --- Drain -----------------------------------------------------------------

// TestDrain_ReturnsTerminalError asserts the terminal Event.Err is what Drain
// returns — the whole point of the helper.
func TestDrain_ReturnsTerminalError(t *testing.T) {
	ch := make(chan backend.Event, 3)
	ch <- backend.Event{Line: []byte("partial finding")}
	ch <- backend.Event{Source: "sqlmap", IsErr: true, Err: stderrors.New("exit status 7")}
	close(ch)

	err := backend.Drain(ch)
	if err == nil {
		t.Fatal("Drain: got nil, want the terminal error")
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("Drain: error %q does not mention exit code 7", err.Error())
	}
}

// TestDrain_CleanStreamReadsEverything asserts Drain returns nil on a clean
// stream AND consumes every event. A helper that returned early would strand the
// producer goroutine and the child process its context bounds — the leak the
// Backend.Stream contract's "caller MUST drain until closed" clause exists to
// prevent.
func TestDrain_CleanStreamReadsEverything(t *testing.T) {
	const n = 100
	ch := make(chan backend.Event) // unbuffered: the producer can only finish if Drain reads all n

	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for i := 0; i < n; i++ {
			ch <- backend.Event{Line: []byte("line")}
		}
		close(ch)
	}()

	if err := backend.Drain(ch); err != nil {
		t.Fatalf("Drain: got %v, want nil on a clean stream", err)
	}
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("Drain: producer did not finish — Drain returned before consuming all events")
	}
}

// TestDrain_KeepsDrainingAfterError asserts Drain does not bail out the moment it
// latches an error. Returning early there is the subtle version of the leak
// above: the error is reported correctly and the producer hangs anyway.
func TestDrain_KeepsDrainingAfterError(t *testing.T) {
	ch := make(chan backend.Event) // unbuffered

	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		ch <- backend.Event{Err: stderrors.New("boom")}
		for i := 0; i < 10; i++ {
			ch <- backend.Event{Line: []byte("trailing")}
		}
		close(ch)
	}()

	if err := backend.Drain(ch); err == nil {
		t.Fatal("Drain: got nil, want the terminal error")
	}
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("Drain: producer did not finish — Drain stopped reading after latching the error")
	}
}

// TestDrain_FirstErrorWins pins which error is reported when a (buggy) producer
// emits more than one.
func TestDrain_FirstErrorWins(t *testing.T) {
	ch := make(chan backend.Event, 3)
	ch <- backend.Event{Err: stderrors.New("first")}
	ch <- backend.Event{Err: stderrors.New("second")}
	close(ch)

	err := backend.Drain(ch)
	if err == nil || err.Error() != "first" {
		t.Fatalf("Drain: got %v, want the first error", err)
	}
}

// TestDrain_NilChannel asserts a (nil, nil) backend return cannot deadlock the
// caller. Guarded by an explicit deadline so a regression fails loudly instead of
// hanging the package's test binary until the go-test timeout.
func TestDrain_NilChannel(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- backend.Drain(nil) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Drain(nil): got %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Drain(nil): blocked — a nil channel must return immediately")
	}
}

// --- Collect ---------------------------------------------------------------

// TestCollect_CallbackPerCleanEventAndTerminalError asserts the callback fires
// once per error-free event, NOT for the terminal error-carrying event, and that
// the terminal error is returned.
//
// The terminal event carries an empty Line: handing it to a line parser would
// push an empty record into the finding pipeline.
func TestCollect_CallbackPerCleanEventAndTerminalError(t *testing.T) {
	ch := make(chan backend.Event, 4)
	ch <- backend.Event{Line: []byte("a")}
	ch <- backend.Event{Line: []byte("b")}
	ch <- backend.Event{Line: []byte("c")}
	ch <- backend.Event{Source: "nuclei", IsErr: true, Err: stderrors.New("exit status 7")}
	close(ch)

	var got []string
	err := backend.Collect(ch, func(ev backend.Event) { got = append(got, string(ev.Line)) })

	if err == nil {
		t.Fatal("Collect: got nil, want the terminal error")
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("Collect: error %q does not mention exit code 7", err.Error())
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("Collect: callback saw %v, want %v (the terminal event must not be delivered)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Collect: callback saw %v, want %v", got, want)
		}
	}
}

// TestCollect_CleanStreamReturnsNil asserts the success path: every event
// delivered, nil returned.
func TestCollect_CleanStreamReturnsNil(t *testing.T) {
	const n = 100
	ch := make(chan backend.Event, n)
	for i := 0; i < n; i++ {
		ch <- backend.Event{Line: []byte("line")}
	}
	close(ch)

	calls := 0
	if err := backend.Collect(ch, func(backend.Event) { calls++ }); err != nil {
		t.Fatalf("Collect: got %v, want nil", err)
	}
	if calls != n {
		t.Errorf("Collect: callback invoked %d times, want %d", calls, n)
	}
}

// TestCollect_NilCallback asserts Collect degrades to a pure drain rather than
// panicking — this is how Drain is implemented.
func TestCollect_NilCallback(t *testing.T) {
	ch := make(chan backend.Event, 2)
	ch <- backend.Event{Line: []byte("x")}
	ch <- backend.Event{Err: stderrors.New("boom")}
	close(ch)

	if err := backend.Collect(ch, nil); err == nil {
		t.Fatal("Collect(ch, nil): got nil, want the terminal error")
	}
}

// TestCollect_NilChannel mirrors TestDrain_NilChannel for the callback form.
func TestCollect_NilChannel(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- backend.Collect(nil, func(backend.Event) {
			t.Error("Collect(nil): callback must never be invoked")
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Collect(nil): got %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Collect(nil): blocked — a nil channel must return immediately")
	}
}

// --- LocalBackend integration: the escalation boundary ----------------------

// TestLocalBackend_Stream_NonZeroExit_SurfacesTerminalError is the Gate-5
// scenario end to end: a tool emits partial output, exits 7, and the consumer
// must be able to tell.
//
// Before F6 was fixed this was indistinguishable from success — the only signal
// was the channel closing — so the task was marked done and its parser happily
// read a truncated (or entirely stale) staging file.
func TestLocalBackend_Stream_NonZeroExit_SurfacesTerminalError(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available on this host")
	}

	b := backend.NewLocalBackend(0)
	tool := &backend.Tool{Name: "exit7", Path: sh}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, streamErr := b.Stream(ctx, tool, []string{"-c", "echo partial; exit 7"})
	if streamErr != nil {
		t.Fatalf("Stream: unexpected dispatch error: %v", streamErr)
	}

	var lines []string
	termErr := backend.Collect(ch, func(ev backend.Event) {
		if s := strings.TrimSpace(string(ev.Line)); s != "" {
			lines = append(lines, s)
		}
	})

	if !containsLine(lines, "partial") {
		t.Errorf("Stream: partial output %v does not contain the line the tool printed before exiting", lines)
	}
	if termErr == nil {
		t.Fatal("Stream: Collect returned nil for a tool that exited 7 — the terminal error was dropped")
	}
}

// TestLocalBackend_Stream_NonZeroExit_DrainAgrees runs the same scenario through
// Drain, since 9 of the 23 migration sites are bare drains with no line parsing.
func TestLocalBackend_Stream_NonZeroExit_DrainAgrees(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available on this host")
	}

	b := backend.NewLocalBackend(0)
	tool := &backend.Tool{Name: "exit7", Path: sh}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, streamErr := b.Stream(ctx, tool, []string{"-c", "echo partial; exit 7"})
	if streamErr != nil {
		t.Fatalf("Stream: unexpected dispatch error: %v", streamErr)
	}
	if termErr := backend.Drain(ch); termErr == nil {
		t.Fatal("Stream: Drain returned nil for a tool that exited 7")
	}
}

// TestLocalBackend_Stream_CleanExit_NoTerminalError is the control: an
// exit-0 tool must NOT produce a terminal error, or every successful scan
// becomes a failure.
func TestLocalBackend_Stream_CleanExit_NoTerminalError(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available on this host")
	}

	b := backend.NewLocalBackend(0)
	tool := &backend.Tool{Name: "exit0", Path: sh}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, streamErr := b.Stream(ctx, tool, []string{"-c", "echo fine; exit 0"})
	if streamErr != nil {
		t.Fatalf("Stream: unexpected dispatch error: %v", streamErr)
	}
	if termErr := backend.Drain(ch); termErr != nil {
		t.Fatalf("Stream: got terminal error %v for a tool that exited 0", termErr)
	}
}

// TestLocalBackend_Stream_MissingBinary_ErrorsFromStreamNotEvent is the guard on
// the OTHER side of the escalation boundary, and the one that protects every host
// with an incomplete toolchain.
//
// A tool that is not on PATH must fail at DISPATCH — Stream's own error return —
// so the best-effort modules keep returning task.StatusSkipped
// (internal/modules/web/arjun.go:130-138). It must NOT arrive as an Event.Err,
// because Drain/Collect promote Event.Err to task.StatusErrored and
// internal/core/scheduler/policy.go fail-fasts the `subdomains` module on errors.
func TestLocalBackend_Stream_MissingBinary_ErrorsFromStreamNotEvent(t *testing.T) {
	b := backend.NewLocalBackend(0)
	tool := &backend.Tool{
		Name: "definitely-not-installed",
		Path: "/nonexistent/definitely-not-installed-reconftw-f6",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, streamErr := b.Stream(ctx, tool, nil)
	if streamErr == nil {
		t.Fatal("Stream: missing binary must fail at dispatch — a nil error here breaks the StatusSkipped path")
	}
	if ch != nil {
		// Not fatal on its own, but the channel must not be the error carrier.
		if termErr := backend.Drain(ch); termErr != nil {
			t.Errorf("Stream: missing binary also surfaced as Event.Err (%v) — it must ONLY surface via Stream's return", termErr)
		}
	}
}

// TestLocalBackend_Stream_AbandonedConsumer_ReleasesOnCtxCancel asserts the
// terminal-error send is bounded by the context, not by a wall clock.
//
// The send used to race a fixed one-second time.After, so every abandoned stream
// pinned the closer goroutine — and the context bounding the child process — for
// a full second. Cancelling the context must release it promptly instead.
func TestLocalBackend_Stream_AbandonedConsumer_ReleasesOnCtxCancel(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available on this host")
	}

	b := backend.NewLocalBackend(0)
	tool := &backend.Tool{Name: "chatty7", Path: sh}
	ctx, cancel := context.WithCancel(context.Background())

	// Emit more events than the channel's 64-slot buffer so the closer goroutine
	// is guaranteed to block on its terminal send once we stop reading.
	ch, streamErr := b.Stream(ctx, tool, []string{"-c", "i=0; while [ $i -lt 500 ]; do echo line$i; i=$((i+1)); done; exit 7"})
	if streamErr != nil {
		cancel()
		t.Fatalf("Stream: unexpected dispatch error: %v", streamErr)
	}

	// Abandon the stream, then cancel. A correct implementation closes the
	// channel promptly; a wall-clock implementation would too, but only after its
	// fixed timeout, so this asserts the ctx path with a margin well under the
	// backstop.
	cancel()

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for range ch { //nolint:revive // intentional drain
		}
	}()

	select {
	case <-closed:
	case <-time.After(15 * time.Second):
		t.Fatal("Stream: channel did not close after ctx cancel — the terminal send is not ctx-bounded")
	}
}

// TestDrain_ConcurrentStreams is a -race guard: the helpers hold no shared state,
// so many streams may be drained at once. This is how the scheduler actually
// calls them.
func TestDrain_ConcurrentStreams(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ch := make(chan backend.Event, 2)
			ch <- backend.Event{Line: []byte("x")}
			if i%2 == 0 {
				ch <- backend.Event{Err: stderrors.New("boom")}
			}
			close(ch)

			err := backend.Drain(ch)
			if i%2 == 0 && err == nil {
				t.Errorf("Drain: goroutine %d got nil, want error", i)
			}
			if i%2 == 1 && err != nil {
				t.Errorf("Drain: goroutine %d got %v, want nil", i, err)
			}
		}(i)
	}
	wg.Wait()
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// --- FailoverBackend: observing a fleet tool's terminal error ---------------
//
// The kill-switch is the only externally observable consequence of the failure
// counter, and Capacity() is the only way to read it: it returns Primary.Capacity()
// until the switch trips and Fallback.Capacity() afterwards. These tests give the
// two backends distinct capacities and assert on the switch.

const (
	fleetPrimaryCapacity   = 99
	fleetFallbackCapacity  = 7
	fleetKillSwitchTimeout = 2 * time.Second
)

// TestFailover_Stream_FleetToolExitsNonZero_CountsAndForwards is the must-have:
// dispatch SUCCEEDS, the fleet runs the tool, the tool exits non-zero, and the
// only trace is Event.Err on the terminal event. That error must both reach the
// caller and count toward the failover threshold — previously it did neither.
func TestFailover_Stream_FleetToolExitsNonZero_CountsAndForwards(t *testing.T) {
	primary := &fleetStreamBackend{events: []backend.Event{
		{Line: []byte("host1.example.com")},
		{Source: "puredns", IsErr: true, Err: stderrors.New("exit status 7")},
	}}
	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  &fleetStreamBackend{capacity: fleetFallbackCapacity},
		Threshold: 1,
	}

	if got := fb.Capacity(); got != fleetPrimaryCapacity {
		t.Fatalf("Capacity before the run: got %d, want %d (kill-switch must start untripped)", got, fleetPrimaryCapacity)
	}

	ch, err := fb.Stream(context.Background(), &backend.Tool{Name: "puredns"}, nil)
	if err != nil {
		t.Fatalf("Stream: unexpected dispatch error: %v", err)
	}

	var lines []string
	termErr := backend.Collect(ch, func(ev backend.Event) {
		if s := strings.TrimSpace(string(ev.Line)); s != "" {
			lines = append(lines, s)
		}
	})

	if !containsLine(lines, "host1.example.com") {
		t.Errorf("Stream: relay dropped fleet output: got %v", lines)
	}
	if termErr == nil {
		t.Fatal("Stream: terminal Event.Err was swallowed by the failover relay")
	}
	if got := fb.Capacity(); got != fleetFallbackCapacity {
		t.Errorf("Capacity after a failed fleet tool: got %d, want %d (the failure did not count toward Threshold)",
			got, fleetFallbackCapacity)
	}
}

// TestFailover_Stream_CleanFleetRun_DoesNotTrip is the control: a fleet stream
// that ends cleanly must not count as a failure, or the kill-switch would trip on
// healthy fleets.
func TestFailover_Stream_CleanFleetRun_DoesNotTrip(t *testing.T) {
	primary := &fleetStreamBackend{events: []backend.Event{{Line: []byte("host1.example.com")}}}
	fb := &backend.FailoverBackend{
		Primary:   primary,
		Fallback:  &fleetStreamBackend{capacity: fleetFallbackCapacity},
		Threshold: 1,
	}

	ch, err := fb.Stream(context.Background(), &backend.Tool{Name: "puredns"}, nil)
	if err != nil {
		t.Fatalf("Stream: unexpected dispatch error: %v", err)
	}
	if termErr := backend.Drain(ch); termErr != nil {
		t.Fatalf("Stream: got terminal error %v on a clean fleet run", termErr)
	}
	if got := fb.Capacity(); got != fleetPrimaryCapacity {
		t.Errorf("Capacity after a clean fleet run: got %d, want %d (kill-switch tripped on success)",
			got, fleetPrimaryCapacity)
	}
}

// TestFailover_Stream_PartialChannelError_Counts covers the other half: dispatch
// reports *AxiomFailure but hands back a partial channel that still carries the
// terminal error. The caller is served by the fallback, so the error is NOT
// forwarded there — but it must still count.
func TestFailover_Stream_PartialChannelError_Counts(t *testing.T) {
	partial := make(chan backend.Event, 2)
	partial <- backend.Event{Line: []byte("host1.example.com")}
	partial <- backend.Event{Source: "puredns", IsErr: true, Err: stderrors.New("exit status 7")}
	close(partial)

	fb := &backend.FailoverBackend{
		Primary:   &fleetStreamBackend{partialCh: partial, dispatchAxiomFailure: true},
		Fallback:  &fleetStreamBackend{capacity: fleetFallbackCapacity},
		Threshold: 1,
	}

	ch, err := fb.Stream(context.Background(), &backend.Tool{Name: "puredns"}, nil)
	if err != nil {
		t.Fatalf("Stream: unexpected error: %v", err)
	}
	if termErr := backend.Drain(ch); termErr != nil {
		t.Fatalf("Stream: the fallback stream must be clean, got %v", termErr)
	}

	// The partial drain runs in its own goroutine, so poll rather than assume.
	deadline := time.Now().Add(fleetKillSwitchTimeout)
	for time.Now().Before(deadline) {
		if fb.Capacity() == fleetFallbackCapacity {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("Capacity stayed %d — the partial channel's terminal error never counted toward Threshold", fb.Capacity())
}

// fleetStreamBackend is a Backend stand-in for the failover tests. As a Primary it
// either streams `events` after a successful dispatch, or reports *AxiomFailure
// while handing back `partialCh`. As a Fallback it streams `events` (usually none)
// and reports `capacity`.
type fleetStreamBackend struct {
	events               []backend.Event
	partialCh            <-chan backend.Event
	dispatchAxiomFailure bool
	capacity             int
}

func (f *fleetStreamBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	if f.dispatchAxiomFailure {
		return f.partialCh, &coreerrors.AxiomFailure{Operation: "stream", Inner: stderrors.New("fleet unreachable")}
	}
	ch := make(chan backend.Event, len(f.events)+1)
	for _, ev := range f.events {
		ch <- ev
	}
	close(ch)
	return ch, nil
}

func (f *fleetStreamBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return f.Stream(ctx, t, args)
}

func (f *fleetStreamBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	return &backend.Result{}, nil
}

func (f *fleetStreamBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return f.Exec(ctx, t, args)
}

func (f *fleetStreamBackend) HealthCheck(_ context.Context) error { return nil }

func (f *fleetStreamBackend) Capacity() int {
	if f.capacity != 0 {
		return f.capacity
	}
	return fleetPrimaryCapacity
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (f *fleetStreamBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return f.ExecEnv(ctx, t, args, opts.Env)
	}
	return f.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (f *fleetStreamBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return f.StreamEnv(ctx, t, args, opts.Env)
	}
	return f.Stream(ctx, t, args)
}
