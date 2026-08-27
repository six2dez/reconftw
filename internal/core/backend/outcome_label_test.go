// outcome_label_test.go — the four outcome labels must PARTITION the outcomes
// they claim to (plan 17-02, requirement TC-C).
//
// WHY THIS FILE EXISTS. Plan 16-01 shipped a closed outcome vocabulary and the
// must_haves truth D3: "A dispatch failure (binary absent / not registered) is
// recorded under a DIFFERENT outcome label than a tool that ran and failed."
// Production falsified it. In the 2026-08-24 parity run 150 of 319 exit_non_zero
// outcomes were absent tools wearing the wrong label, and the phase verifier
// reproduced it against a PATH holding a single stub tool: 4 dispatch_failed
// versus 19 exit_non_zero with all 23 tools absent, `dnsx` under BOTH labels in
// one log. Two tests guarded that truth and BOTH passed — the unit test asserted
// the UNREGISTERED case (which always routed correctly) and the E2E test asserted
// only that AT LEAST ONE record carried the label.
//
// So the guards here are about the arms of the switch itself, one per label, with
// a fake backend that can produce each situation deterministically. The counting,
// whole-run versions live in cmd/reconftw/tool_recorder_e2e_test.go; these are
// the fast ones that say WHICH arm broke.
package backend_test

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// readInvocationRecords parses logs/tools.jsonl from OUTSIDE the package, the way
// an operator's tooling sees it: through the exported JSON tags, not the struct.
func readInvocationRecords(t *testing.T, path string) []backend.InvocationRecord {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v — the recorder wrote nothing", path, err)
	}
	var out []backend.InvocationRecord
	for i, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var rec backend.InvocationRecord
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON (%v): %s", i+1, err, ln)
		}
		out = append(out, rec)
	}
	return out
}

// scriptedBackend produces an exact (result, error) pair and can run an arbitrary
// side effect first — which is how "the context was cancelled before the label was
// computed" becomes deterministic rather than a race against a real process.
type scriptedBackend struct {
	before func()
	res    *backend.Result
	err    error
}

func (b *scriptedBackend) Exec(ctx context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	return b.ExecEnv(ctx, t, args, nil)
}

func (b *scriptedBackend) ExecEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (*backend.Result, error) {
	if b.before != nil {
		b.before()
	}
	return b.res, b.err
}

func (b *scriptedBackend) Stream(ctx context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	return b.StreamEnv(ctx, t, args, nil)
}

func (b *scriptedBackend) StreamEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (<-chan backend.Event, error) {
	if b.err != nil {
		return nil, b.err
	}
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *scriptedBackend) HealthCheck(context.Context) error { return nil }
func (b *scriptedBackend) Capacity() int                     { return 1 }

// labelRunner wires a scripted backend to a real recorder and returns both the
// runner and a reader for the outcome the run recorded.
func labelRunner(t *testing.T, b backend.Backend, tool *backend.Tool) (*backend.Runner, func(*testing.T) []backend.InvocationRecord) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	reg := backend.NewToolRegistry()
	reg.Register(tool)
	r := backend.NewRunner(b, reg, nil)
	r.Recorder = backend.NewToolRecorder(logPath, nil)
	return r, func(t *testing.T) []backend.InvocationRecord {
		t.Helper()
		if err := r.Recorder.Close(); err != nil {
			t.Fatalf("recorder Close: %v", err)
		}
		return readInvocationRecords(t, logPath)
	}
}

// showExit renders a *int exit code for a failure message. `%v` on a pointer
// prints an ADDRESS, which is exactly the kind of unreadable diagnostic this plan
// exists to stop producing.
func showExit(p *int) string {
	if p == nil {
		return "<absent>"
	}
	return strconv.Itoa(*p)
}

// endOutcome returns the single end record's outcome, failing if there is not
// exactly one — a guard that only reads "the first end record" would pass on a run
// that recorded three.
func endOutcome(t *testing.T, views []backend.InvocationRecord) backend.InvocationRecord {
	t.Helper()
	var ends []backend.InvocationRecord
	for _, v := range views {
		if v.Phase == "end" {
			ends = append(ends, v)
		}
	}
	if len(ends) != 1 {
		t.Fatalf("got %d end records, want exactly 1: %+v", len(ends), views)
	}
	return ends[0]
}

// ---------------------------------------------------------------------------
// Arm 1 — dispatch_failed
// ---------------------------------------------------------------------------

// TestExecPathLabelsAbsentBinaryAsDispatchFailure is the unit-level counterpart
// of the E2E count, and it uses a REAL LocalBackend against a REAL absent binary
// rather than a scripted error: the fact under test is precisely what os/exec
// does when Tool.Path is empty, which a hand-built error would assume instead of
// demonstrate.
//
// recorder_test.go's existing dispatch assertion covers the UNREGISTERED tool,
// which took a different code path and was never broken. This one is the case the
// parity run found: REGISTERED, and absent.
func TestExecPathLabelsAbsentBinaryAsDispatchFailure(t *testing.T) {
	// Path "" is exactly what registry_seed.go leaves on a registered tool whose
	// binary exec.LookPath could not find.
	r, records := labelRunner(t, backend.NewLocalBackend(time.Second),
		&backend.Tool{Name: "absenttool", Path: ""})

	_, err := r.Run(context.Background(), "absenttool", []string{"-silent"})
	if err == nil {
		t.Fatal("running a registered tool with no binary returned no error")
	}
	if !coreerrors.IsDispatchFailure(err) {
		t.Errorf("errors.IsDispatchFailure(err) = false for err=%v (%T) — the backend did not carry "+
			"the fact that the process never started, so no consumer can recover it", err, err)
	}
	if !stderrors.Is(err, coreerrors.ErrTool) {
		t.Errorf("errors.Is(err, ErrTool) = false — ErrDispatch must NARROW the tool-failure category, " +
			"not leave it; existing callers branch on ErrTool")
	}

	end := endOutcome(t, records(t))
	if end.Outcome != backend.OutcomeDispatchFailed {
		t.Errorf("outcome = %q, want %q.\n"+
			"An absent tool recorded as %q tells the operator it ran and failed. It never ran. Those\n"+
			"two facts have opposite remedies, and conflating them hid dnstake's broken arg vector for\n"+
			"months and mislabelled 150 of the parity run's 319 failures.",
			end.Outcome, backend.OutcomeDispatchFailed, backend.OutcomeExitNonZero)
	}
	// T-17-02-04: a dispatch failure has no tool stderr BY CONSTRUCTION, so the OS
	// error string must not be smuggled into the field an operator reads as the
	// tool's own account of itself.
	if end.StderrTail != "" {
		t.Errorf("stderr_tail = %q on a process that never ran — nothing produced it", end.StderrTail)
	}
	if end.ExitCode == nil || *end.ExitCode != -1 {
		t.Errorf("exit_code = %s, want -1: a process that never ran has no exit code", showExit(end.ExitCode))
	}
}

// ---------------------------------------------------------------------------
// Arm 2 — timeout, and what it must NOT capture
// ---------------------------------------------------------------------------

// TestSuccessfulToolUnderCancelledContextIsNotTimeout is WR-04.
//
// The switch used to read `case ctx.Err() != nil:` FIRST and unconditionally, so
// a tool that completed successfully microseconds before the parent context was
// cancelled — a Ctrl-C, a sibling task failing the group, a parent deadline
// landing on an unrelated stage — was recorded as `timeout, exit_code=-1`. The
// cancellation is real; the claim that the TOOL timed out is not.
//
// The cancellation is triggered from inside the backend call so it is ordered
// before the label computation by construction, not by a sleep.
func TestSuccessfulToolUnderCancelledContextIsNotTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := &scriptedBackend{
		before: cancel, // cancelled BEFORE execRecorded computes the label
		res:    &backend.Result{ExitCode: 0, Stdout: []byte("done\n")},
	}
	r, records := labelRunner(t, b, &backend.Tool{Name: "quicktool", Path: "/nonexistent"})

	res, err := r.Run(ctx, "quicktool", nil)
	if err != nil {
		t.Fatalf("the scripted backend returned err=%v; the fixture is wrong", err)
	}
	if res == nil || res.ExitCode != 0 {
		t.Fatalf("the scripted backend returned res=%+v; the fixture is wrong", res)
	}
	if ctx.Err() == nil {
		t.Fatal("the context was NOT cancelled by the time Run returned — this guard would be vacuous")
	}

	end := endOutcome(t, records(t))
	if end.Outcome != backend.OutcomeSuccess {
		t.Errorf("outcome = %q, want %q.\n"+
			"The tool ran and exited 0. Something else was cancelled. Recording that as a timeout\n"+
			"invents a stall the operator will then go looking for, and — when the tool DID fail —\n"+
			"discards its real exit code and its stderr tail on the way past.",
			end.Outcome, backend.OutcomeSuccess)
	}
	if end.ExitCode == nil || *end.ExitCode != 0 {
		t.Errorf("exit_code = %s, want 0", showExit(end.ExitCode))
	}
}

// TestToolKilledByItsOwnDeadlineIsStillTimeout is the other half: the fix must
// stop the timeout label capturing successes WITHOUT removing it. Driven by a real
// /bin/sleep past a real Tool.Timeout, reusing tool_timeout_test.go's fixture so
// there is one definition of what a timeout run looks like.
func TestToolKilledByItsOwnDeadlineIsStillTimeout(t *testing.T) {
	runner, logPath := timeoutRunner(t, 200*time.Millisecond)

	_, err := runner.Run(context.Background(), "slowtool", []string{"30"})
	if err == nil {
		t.Fatal("a tool that outlived its deadline returned no error — the fixture is wrong")
	}
	if err := runner.Recorder.Close(); err != nil {
		t.Fatalf("recorder Close: %v", err)
	}

	end := endOutcome(t, readInvocationRecords(t, logPath))
	if end.Outcome != backend.OutcomeTimeout {
		t.Errorf("outcome = %q, want %q — a stall recorded as anything else is invisible to a grep "+
			"looking for stalls, which is the only way a multi-hour timeout is ever diagnosed",
			end.Outcome, backend.OutcomeTimeout)
	}
}

// TestConsumerCancellationIsNotADeadlineAndNotADispatchFailure records the third
// case in the plan's behaviour list AND the limit of this seam.
//
// WHAT IS DISTINGUISHABLE HERE: a consumer cancellation (context.Canceled) from
// the tool's own deadline (context.DeadlineExceeded plus a *ToolTimeout). This
// test asserts that.
//
// WHAT IS NOT, STATED RATHER THAN ASSERTED AWAY: a deadline on the CALLER's
// context is indistinguishable from Tool.Timeout, because applyToolContract
// derives the second from the first and both surface as DeadlineExceeded. A run
// whose whole scan deadline expires will therefore see its in-flight tools
// recorded as `timeout`, which is true of the invocation even though the tool's
// own bound was not what fired. Writing a test that claimed to tell those apart
// would be a guard passing for the wrong reason — the exact defect class this
// plan exists to remove.
//
// A cancelled tool lands in exit_non_zero carrying its real *ToolError. Of the
// four labels that misleads least: the closed vocabulary has no `cancelled`
// member, the process DID start (so dispatch_failed would be false), and no
// deadline fired (so timeout would be false).
func TestConsumerCancellationIsNotADeadlineAndNotADispatchFailure(t *testing.T) {
	for _, p := range []string{"/bin/sleep"} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s is absent, so a real cancelled process cannot be demonstrated", p)
		}
	}
	logPath := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	reg := backend.NewToolRegistry()
	// Timeout 0: NO Tool.Timeout, so nothing but the caller can end this run and
	// the two causes cannot be confused inside the fixture itself.
	reg.Register(&backend.Tool{Name: "sleeper", Path: "/bin/sleep", Timeout: 0})
	r := backend.NewRunner(backend.NewLocalBackend(200*time.Millisecond), reg, nil)
	r.Recorder = backend.NewToolRecorder(logPath, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	_, err := r.Run(ctx, "sleeper", []string{"30"})
	cancel()

	if err == nil {
		t.Fatal("a cancelled tool returned no error — the fixture is wrong")
	}
	if !stderrors.Is(ctx.Err(), context.Canceled) || stderrors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("ctx.Err() = %v, want context.Canceled — this guard would be testing the wrong cause", ctx.Err())
	}
	if err := r.Recorder.Close(); err != nil {
		t.Fatalf("recorder Close: %v", err)
	}

	end := endOutcome(t, readInvocationRecords(t, logPath))
	if end.Outcome == backend.OutcomeTimeout {
		t.Errorf("a CONSUMER-cancelled tool is recorded as %q. No deadline fired; the operator "+
			"cancelled. Reporting that as a stall sends the reader looking for a timeout that does "+
			"not exist.", end.Outcome)
	}
	if end.Outcome == backend.OutcomeDispatchFailed {
		t.Errorf("a cancelled tool is recorded as %q, but the process DID start — %q must stay a "+
			"statement about tools that never ran", end.Outcome, backend.OutcomeDispatchFailed)
	}
	if end.Outcome != backend.OutcomeExitNonZero {
		t.Errorf("outcome = %q, want %q (the label that misleads least — see this test's doc comment)",
			end.Outcome, backend.OutcomeExitNonZero)
	}
}

// ---------------------------------------------------------------------------
// Arm 3 — the distinction must not collapse in the other direction
// ---------------------------------------------------------------------------

// TestPresentToolExitingNonZeroStaysExitNonZero is the guard against overfitting
// the fix: making everything a dispatch failure would satisfy every assertion
// above and destroy the label's meaning.
func TestPresentToolExitingNonZeroStaysExitNonZero(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is absent")
	}
	r, records := labelRunner(t, backend.NewLocalBackend(time.Second),
		&backend.Tool{Name: "failer", Path: "/bin/sh"})

	_, err := r.Run(context.Background(), "failer", []string{"-c", "echo boom >&2; exit 7"})
	if err == nil {
		t.Fatal("a tool exiting 7 returned no error")
	}
	if coreerrors.IsDispatchFailure(err) {
		t.Error("a tool that RAN and exited 7 is reported as a dispatch failure — the fix has " +
			"collapsed the distinction in the other direction")
	}

	end := endOutcome(t, records(t))
	if end.Outcome != backend.OutcomeExitNonZero {
		t.Errorf("outcome = %q, want %q", end.Outcome, backend.OutcomeExitNonZero)
	}
	if end.ExitCode == nil || *end.ExitCode != 7 {
		t.Errorf("exit_code = %s, want 7 — the record must carry the code the process returned, "+
			"which is also the proof it ran", showExit(end.ExitCode))
	}
	if end.StderrTail == "" {
		t.Error("stderr_tail is empty though the tool wrote to stderr — the tool's own account of " +
			"why it failed is the thing that turns an ssh session into a grep")
	}
}

// ---------------------------------------------------------------------------
// The fact must survive every Backend that WRAPS another one
// ---------------------------------------------------------------------------
//
// Plan 17-02's action says to apply the distinction at every implementation of
// Exec/ExecEnv, and phase 15's F19 precedent says a code reading is not evidence
// that it landed: two independent reads there certified a fix that was inert in
// production. So the wrappers are exercised rather than inspected.
//
// The four production implementations are LocalBackend (sets the fact),
// FailoverBackend and PassiveBackend (below), and AxiomBackend — which is always
// constructed inside a FailoverBackend (appctx.pickBackend) and deliberately
// converts an axiom-scan failure into *AxiomFailure so the tool RE-RUNS LOCALLY;
// the label then comes from that local run, which is the correct source. That is
// why AxiomBackend is not changed and not asserted here: on the production path it
// never supplies the outcome.

// axiomLikeBackend fails every call the way AxiomBackend does, which is the
// trigger for FailoverBackend's fallback.
type axiomLikeBackend struct{ scriptedBackend }

func (b *axiomLikeBackend) Exec(ctx context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	return b.ExecEnv(ctx, t, args, nil)
}

func (b *axiomLikeBackend) ExecEnv(_ context.Context, t *backend.Tool, _ []string, _ []string) (*backend.Result, error) {
	return nil, &coreerrors.AxiomFailure{Operation: "exec", Inner: stderrors.New("fleet unreachable")}
}

// TestDispatchFailureSurvivesTheWrappingBackends.
//
// A wrapper that swallows or re-wraps the fact would reproduce this whole defect
// on the distributed and passive paths — where it is far harder to see, because
// there the operator cannot simply check the box's PATH.
func TestDispatchFailureSurvivesTheWrappingBackends(t *testing.T) {
	absent := &backend.Tool{Name: "absenttool", Path: ""}

	t.Run("FailoverBackend propagating a non-Axiom error from its primary", func(t *testing.T) {
		be := &backend.FailoverBackend{
			Primary:   backend.NewLocalBackend(time.Second),
			Fallback:  backend.NewLocalBackend(time.Second),
			Threshold: 2,
		}
		r, records := labelRunner(t, be, absent)
		if _, err := r.Run(context.Background(), "absenttool", nil); !coreerrors.IsDispatchFailure(err) {
			t.Errorf("FailoverBackend lost the fact: err=%v (%T)", err, err)
		}
		if got := endOutcome(t, records(t)).Outcome; got != backend.OutcomeDispatchFailed {
			t.Errorf("outcome = %q, want %q", got, backend.OutcomeDispatchFailed)
		}
	})

	t.Run("FailoverBackend falling back to local after an AxiomFailure", func(t *testing.T) {
		be := &backend.FailoverBackend{
			Primary:   &axiomLikeBackend{},
			Fallback:  backend.NewLocalBackend(time.Second),
			Threshold: 2,
		}
		r, records := labelRunner(t, be, absent)
		if _, err := r.Run(context.Background(), "absenttool", nil); !coreerrors.IsDispatchFailure(err) {
			t.Errorf("the fallback's dispatch failure did not survive the failover: err=%v (%T)", err, err)
		}
		if got := endOutcome(t, records(t)).Outcome; got != backend.OutcomeDispatchFailed {
			t.Errorf("outcome = %q, want %q — a fleet that fell back to a box where the tool is "+
				"absent must still say the tool never ran", got, backend.OutcomeDispatchFailed)
		}
	})

	t.Run("PassiveBackend blocking an active tool", func(t *testing.T) {
		// nmap is in the passive-mode hard-block set (D-09), and /bin/sh exists,
		// so the ONLY reason it does not run is the policy block.
		if _, err := os.Stat("/bin/sh"); err != nil {
			t.Skip("/bin/sh is absent")
		}
		be := backend.NewPassiveBackend(backend.NewLocalBackend(time.Second))
		r, records := labelRunner(t, be, &backend.Tool{Name: "nmap", Path: "/bin/sh"})

		_, err := r.Run(context.Background(), "nmap", []string{"-c", "exit 0"})
		if !stderrors.Is(err, coreerrors.ErrPassiveViolation) {
			t.Fatalf("err = %v, want a passive violation — the fixture is wrong (is nmap still in "+
				"the hard-block set?)", err)
		}
		if got := endOutcome(t, records(t)).Outcome; got != backend.OutcomeDispatchFailed {
			t.Errorf("a tool BLOCKED by passive mode is recorded as %q.\n"+
				"It never ran, so %q is a false statement about it — and in passive mode this is the\n"+
				"EXPECTED path, which makes the wrong label the easiest one to never notice.",
				got, backend.OutcomeExitNonZero)
		}
	})
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
func (b *scriptedBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return b.ExecEnv(ctx, t, args, opts.Env)
	}
	return b.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (b *scriptedBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return b.StreamEnv(ctx, t, args, opts.Env)
	}
	return b.Stream(ctx, t, args)
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
func (b *axiomLikeBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return b.ExecEnv(ctx, t, args, opts.Env)
	}
	return b.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (b *axiomLikeBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return b.StreamEnv(ctx, t, args, opts.Env)
	}
	return b.Stream(ctx, t, args)
}
