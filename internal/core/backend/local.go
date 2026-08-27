// SPDX-License-Identifier: MIT
//
// LocalBackend — kill-tree-safe subprocess execution.
// Ports spike/go/internal/proc/proc.go verbatim with the production additions
// (typed errors, Result/Event materialization, stderr-truncation cap).
//
// PROCESS-GROUP KILL-TREE PATTERN (the FOUND-09 ROADMAP success criterion 3):
//
//  1. Setpgid: true                      → every subprocess is its OWN process-group leader.
//  2. cmd.WaitDelay = b.KillGrace        → stdlib pause between Cancel and stdlib SIGKILL.
//  3. cmd.Cancel = SIGTERM(-pgid)        → ctx cancel sends SIGTERM to the WHOLE group.
//  4. Supplementary group-SIGKILL goroutine — after WaitDelay+500ms, sends SIGKILL to the
//     WHOLE group via syscall.Kill(-pgid, SIGKILL). This is required because Go's stdlib
//     WaitDelay only fires kill(pid, SIGKILL) on the DIRECT child — orphaned grandchildren
//     that ignore SIGTERM survive. Source: spike/go/internal/proc/proc.go header lines 8-12.
//
// Pitfall reference: .planning/research/PITFALLS.md §1.2 (process-group escape, top-impact).
package backend

import (
	"bufio"
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// stderrCap bounds the size of ToolError.Stderr per ADR §6 line 1806. W9 — explicit.
const stderrCap = 1024

// scannerInitialBuf and scannerMaxBuf are the bufio.Scanner buffer sizes per
// RESEARCH.md §Pattern 3 + spike/go/internal/proc/proc.go lines 92-94.
// 1MiB initial / 10MiB max handles long httpx JSON objects + nuclei verbose lines.
const (
	scannerInitialBuf = 1024 * 1024      // 1 MiB
	scannerMaxBuf     = 10 * 1024 * 1024 // 10 MiB
)

// defaultKillGrace is the duration from ctx-cancel to group-SIGKILL escalation.
const defaultKillGrace = 5 * time.Second

// terminalSendBackstop bounds the terminal-error send in StreamEnv's closer
// goroutine when the caller's context can never be cancelled.
//
// The primary release path is ctx.Done(): every dispatch through Runner wraps the
// stream in a cancellable context (see runner.streamWithContract) whose cancel
// fires as soon as the relay stops, so an abandoned stream frees this goroutine
// immediately. Only a caller that passes an uncancellable context AND stops
// reading reaches this arm, which is why it is generous rather than tight — it
// exists to guarantee termination, not to bound latency.
const terminalSendBackstop = 30 * time.Second

// LocalBackend executes external tools as local subprocesses with kill-tree safety.
type LocalBackend struct {
	// KillGrace is the duration cmd.WaitDelay waits between Cancel and stdlib SIGKILL.
	// Defaults to 5s if zero-value. The supplementary group-SIGKILL goroutine fires at
	// KillGrace + 500ms after ctx cancellation.
	KillGrace time.Duration
}

// NewLocalBackend constructs a LocalBackend with the provided kill-grace duration.
// If killGrace == 0, the default (5s) is used.
func NewLocalBackend(killGrace time.Duration) *LocalBackend {
	if killGrace <= 0 {
		killGrace = defaultKillGrace
	}
	return &LocalBackend{KillGrace: killGrace}
}

// Capacity returns runtime.NumCPU() * 2 — the Scheduler uses this as a hint.
func (b *LocalBackend) Capacity() int { return runtime.NumCPU() * 2 }

// HealthCheck returns nil — LocalBackend is always healthy in Phase 3 (no fleet to check).
func (b *LocalBackend) HealthCheck(_ context.Context) error { return nil }

// Exec runs tool with args, buffers stdout+stderr, returns a *Result on clean
// exit or *coreerrors.ToolError on non-zero exit (Stderr truncated to last 1KB
// per ADR §6 line 1806 + W9 assertion). Returns *coreerrors.ToolTimeout when
// ctx deadline exceeded.
func (b *LocalBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
	return b.ExecOpts(ctx, t, args, ExecOptions{})
}

// ExecEnv is Exec with additional "KEY=VALUE" child-env entries appended onto the
// os.Environ() baseline. When env is empty, cmd.Env is left nil — preserving the
// EXACT current Exec behavior (child inherits the parent environment via os/exec's
// default). When env is non-empty, cmd.Env = append(os.Environ(), env...).
//
// No-extra-parent-vars property (T-07-09-02) holds BY CONSTRUCTION: the child env
// is the os.Environ() baseline plus EXACTLY the requested env entries — this append
// cannot introduce any variable that is neither in os.Environ nor the explicit env
// slice, so no separate negative-env test is required.
func (b *LocalBackend) ExecEnv(ctx context.Context, t *Tool, args []string, env []string) (*Result, error) {
	return b.ExecOpts(ctx, t, args, ExecOptions{Env: env})
}

// applyExecOptions validates ExecOptions and applies its stdin and working-directory
// settings to cmd. It returns a cleanup func that MUST be called only AFTER
// cmd.Wait() has returned — closing the stdin file earlier would take the child's
// standard input away mid-read.
//
// The mutual-exclusion violation is reported as a *ToolError carrying NeverStarted,
// which is what places it in the dispatch_failed bucket (coreerrors.IsDispatchFailure
// is satisfied through ToolError.NeverStarted). NO PROCESS IS CREATED, so labelling
// it as a tool that ran and failed would be a false statement — that is the label
// partition documented at Runner.execRecorded, and it must keep holding here.
func applyExecOptions(cmd *exec.Cmd, t *Tool, opts ExecOptions) (func(), error) {
	noop := func() {}

	// WR-08: `!= nil`, NOT `len() > 0`. ExecOptions documents "a NIL Stdin with an
	// empty StdinPath leaves the child's stdin exactly as it is today"; `len() > 0`
	// implements "nil OR EMPTY", a different and more dangerous contract. With
	// ExecOptions{Stdin: []byte{}} the old test (a) let a simultaneous StdinPath
	// silently win instead of reporting the programming error, and (b) left
	// cmd.Stdin nil so the child INHERITED THE OPERATOR'S TERMINAL — every seam
	// tool that reads stdin to EOF (gxss, mantra, nomore403, hakip2host,
	// roboxtractor, dalfox pipe, brutus) would block until its deadline fired.
	if opts.Stdin != nil && opts.StdinPath != "" {
		return noop, &coreerrors.ToolError{
			Tool:         t.Name,
			ExitCode:     -1,
			Stderr:       "",
			Inner:        stderrors.New("ExecOptions.Stdin and ExecOptions.StdinPath are mutually exclusive; exactly one may be set"),
			NeverStarted: true,
		}
	}

	// Working directory precedence: opts.Dir wins over Tool.WorkDir. With neither
	// set, cmd.Dir stays empty — os/exec's "inherit the parent's cwd", which is
	// today's behaviour byte for byte.
	switch {
	case opts.Dir != "":
		cmd.Dir = opts.Dir
	case t.WorkDir != "":
		cmd.Dir = t.WorkDir
	}

	switch {
	case opts.Stdin != nil:
		// An EMPTY-but-non-nil slice means "empty stdin", not "inherit" (WR-08).
		// A FRESH reader per dispatch, which is exactly why the field is []byte:
		// FailoverBackend's fallback leg is a second call and builds its own
		// reader, so a retry cannot be handed an exhausted one.
		cmd.Stdin = bytes.NewReader(opts.Stdin)
	case opts.StdinPath != "":
		f, err := os.Open(opts.StdinPath) //nolint:gosec // caller-supplied in-process path
		if err != nil {
			return noop, &coreerrors.ToolError{
				Tool:         t.Name,
				ExitCode:     -1,
				Inner:        fmt.Errorf("open stdin path: %w", err),
				NeverStarted: true,
			}
		}
		cmd.Stdin = f
		return func() { _ = f.Close() }, nil
	}

	return noop, nil
}

// ExecOpts is the single real buffered dispatch body; Exec and ExecEnv are defined
// in terms of it, so a zero-valued ExecOptions is byte-for-byte identical to Exec.
func (b *LocalBackend) ExecOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (*Result, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, t.Path, args...)

	// Process-group isolation: every subprocess gets its own pgid.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Env seam: only override cmd.Env when explicit entries are requested. The
	// nil-env path leaves cmd.Env nil (os/exec default = inherit parent env),
	// byte-for-byte identical to the pre-seam behavior.
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}

	// Stdin + working-directory seam (18-01). Applied and VALIDATED before
	// cmd.Start, so a mutual-exclusion error creates no process at all.
	cleanup, optErr := applyExecOptions(cmd, t, opts)
	if optErr != nil {
		return nil, optErr
	}
	// Deferred, not called inline: the stdin file must outlive cmd.Wait().
	defer cleanup()

	// WaitDelay: stdlib pause between Cancel and stdlib SIGKILL (kills direct child only).
	cmd.WaitDelay = b.KillGrace

	// Cancel: ctx cancellation → SIGTERM to the WHOLE process group (negative pid).
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		// THE PROCESS WAS NEVER CREATED. Binary absent (Tool.Path == "" for a
		// registered-but-uninstalled tool, which os/exec reports as "exec: no
		// command"), not executable, or permission denied.
		//
		// NeverStarted is the whole point of this arm. Runner.execRecorded gets
		// back an error and CANNOT tell a process that never started from one that
		// started and failed — both are just `err != nil` by the time it looks. This
		// backend is the only layer that knows, so it says so as data rather than
		// leaving the Runner to guess from a message string. Without it, every
		// absent tool on the Exec path was recorded as exit_non_zero: 150 of the
		// 2026-08-24 parity run's 319 (16-06-PARITY §6.4).
		//
		// ExitCode is -1 and Stderr is "" BY CONSTRUCTION — a process that never ran
		// produced neither — which is also T-17-02-04's mitigation: no OS error
		// string is smuggled into the record's stderr field.
		return nil, &coreerrors.ToolError{
			Tool:         t.Name,
			ExitCode:     -1,
			Stderr:       "",
			Inner:        err,
			NeverStarted: true,
		}
	}

	// Supplementary group-SIGKILL goroutine: stdlib WaitDelay only kills the direct
	// child. We escalate to the WHOLE group (kill(-pgid, SIGKILL)) WaitDelay+500ms
	// after ctx cancellation, ensuring grandchildren are reaped within the SLA.
	pgid := cmd.Process.Pid
	doneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Sleep WaitDelay + 500ms for stdlib's pass to complete, then group-SIGKILL.
			select {
			case <-time.After(cmd.WaitDelay + 500*time.Millisecond):
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			case <-doneCh:
				// cmd finished cleanly before the escalation fired.
			}
		case <-doneCh:
			// cmd finished cleanly before ctx was cancelled.
		}
	}()

	waitErr := cmd.Wait()
	close(doneCh)

	duration := time.Since(start)

	stderrBytes := stderrBuf.Bytes()
	stdoutBytes := stdoutBuf.Bytes()

	// Distinguish deadline-exceeded from a plain non-zero exit.
	if stderrors.Is(ctx.Err(), context.DeadlineExceeded) {
		// Report the TOOL'S OWN deadline. b.KillGrace is the post-signal grace
		// period, not the bound that fired, so it rendered as "timed out after 2s"
		// for a one-hour deadline — a message that sends the reader looking for a
		// two-second timeout that does not exist.
		reported := t.Timeout
		if reported == 0 {
			reported = b.KillGrace
		}
		// 17-07 (CR-07), STATED DECISION: stdoutBytes collected before the kill is
		// DISCARDED. v1's `subfinder … -o file` keeps whatever reached the file, so
		// this is a real divergence and it is deliberate, not an oversight.
		//
		// Every caller is `res, err := Run(...); if err != nil { return errored }`.
		// Returning a partial Result would only change anything if a caller then
		// published it as a complete one — a passive source reporting Done on a
		// truncated set is the outcome-mislabelling shape phase 16 removed. The
		// callers that would each have had to make that judgement: runPassiveTask
		// (subfinder, crt, github-subdomains, gitlab-subdomains, urlfinder),
		// SubRecursivePassiveTask's per-target loop, and every other buffered
		// app.Tools.Run call site in internal/modules.
		//
		// THE COST: a bounded tool's partial work is unrecoverable. The remedy is
		// therefore a deadline that does not fire on a healthy run — see the
		// derivation on subfinder's tools.lock entry. Pinned by
		// TestDeadlineDiscardsBufferedStdout; change both together or they lie.
		return nil, &coreerrors.ToolTimeout{Tool: t.Name, Timeout: reported}
	}

	if waitErr != nil {
		// Non-zero exit OR I/O error.
		exitCode := -1
		if ee, ok := waitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		return nil, &coreerrors.ToolError{
			Tool:     t.Name,
			ExitCode: exitCode,
			Stderr:   lastKB(stderrBytes),
			Inner:    waitErr,
		}
	}

	return &Result{
		Stdout:   stdoutBytes,
		Stderr:   stderrBytes,
		ExitCode: 0,
		Duration: duration,
	}, nil
}

// Stream runs tool with args, yields stdout+stderr lines as Events on the returned
// channel. Channel closes when tool exits (clean or error). The caller MUST drain
// the channel until closed to avoid a goroutine leak.
//
// Uses bufio.Scanner with 1MiB initial / 10MiB max buffer (RESEARCH.md §Pattern 3 +
// spike proc.go lines 92-94).
func (b *LocalBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
	return b.StreamOpts(ctx, t, args, ExecOptions{})
}

// StreamEnv is Stream with additional "KEY=VALUE" child-env entries (see ExecEnv
// for the env-scoping contract). When env is empty, cmd.Env is left nil — the
// nil-env path is byte-for-byte identical to the pre-seam Stream behavior.
func (b *LocalBackend) StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error) {
	return b.StreamOpts(ctx, t, args, ExecOptions{Env: env})
}

// StreamOpts is the single real streaming dispatch body; Stream and StreamEnv are
// defined in terms of it, so a zero-valued ExecOptions is byte-for-byte identical
// to Stream. The stdin file (when StdinPath is used) is closed by the same
// goroutine that reaps the process, after cmd.Wait() returns.
func (b *LocalBackend) StreamOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (<-chan Event, error) {
	cmd := exec.CommandContext(ctx, t.Path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	cmd.WaitDelay = b.KillGrace
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	// All three failures below happen BEFORE the child exists, so each carries
	// NeverStarted (see the Exec site for why the fact travels as data). The
	// Stream path already labels a failed dispatch correctly — Runner.Stream gets
	// the error back before it writes any record — but the two paths must agree on
	// the FACT, not merely arrive at the same label by different routes: a future
	// caller that buffers a stream, or a backend that wraps this one, would
	// otherwise silently lose it.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, &coreerrors.ToolError{Tool: t.Name, ExitCode: -1, Inner: err, NeverStarted: true}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		// WR-02: os/exec closes parentIOPipes only inside Start's error path or
		// Wait, so every pre-Start return must close what it already created.
		_ = stdoutPipe.Close()
		return nil, &coreerrors.ToolError{Tool: t.Name, ExitCode: -1, Inner: err, NeverStarted: true}
	}

	// Stdin + working-directory seam (18-01), installed after the pipes and before
	// Start so a mutual-exclusion error creates no process.
	cleanup, optErr := applyExecOptions(cmd, t, opts)
	if optErr != nil {
		// WR-02: four descriptors per occurrence otherwise, and this arm is
		// reachable from ordinary input — a StdinPath naming a file that cannot be
		// opened, or a Stdin+StdinPath programming error.
		_ = stdoutPipe.Close()
		_ = stderrPipe.Close()
		return nil, optErr
	}

	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, &coreerrors.ToolError{Tool: t.Name, ExitCode: -1, Inner: err, NeverStarted: true}
	}

	// Group-SIGKILL escalation goroutine (see Exec for the rationale).
	pgid := cmd.Process.Pid
	doneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-time.After(cmd.WaitDelay + 500*time.Millisecond):
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			case <-doneCh:
			}
		case <-doneCh:
		}
	}()

	out := make(chan Event, 64)

	// Two reader goroutines, one per pipe.
	var wg sync.WaitGroup
	wg.Add(2)

	// scanErrs collects a scanner failure from either pipe so the closer can
	// report it as a terminal event.
	var scanErrMu sync.Mutex
	var scanErr error

	// stderrBuf TEES stderr so the closer can attach the tool's own account of
	// its failure to the terminal error. This is a tee, NOT a redirect: stderr
	// lines keep being forwarded as Events below, because modules filter them
	// with `if ev.IsErr { continue }` and that behaviour must not change.
	//
	// Guarded by the SAME mutex as scanErr rather than a second one — one lock
	// for the two facts the closer reads, so there is no ordering to get wrong.
	var stderrBuf []byte

	scanPipe := func(p io.Reader, isErr bool) {
		defer wg.Done()
		scanner := bufio.NewScanner(p)
		scanner.Buffer(make([]byte, scannerInitialBuf), scannerMaxBuf)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...) // copy — Scan reuses its buffer
			if isErr {
				scanErrMu.Lock()
				// Trim as we go so a chatty tool cannot grow this without bound
				// between lines; lastKB below applies the same cap once more at
				// the end. stderrCap is the EXISTING ADR-fixed bound — do not
				// introduce a second one.
				stderrBuf = append(append(stderrBuf, line...), '\n')
				if len(stderrBuf) > stderrCap*2 {
					stderrBuf = append([]byte(nil), stderrBuf[len(stderrBuf)-stderrCap:]...)
				}
				scanErrMu.Unlock()
			}
			select {
			case out <- Event{Line: line, Source: t.Name, IsErr: isErr}:
			case <-ctx.Done():
				return
			}
		}
		// A scanner error means the tool's output was TRUNCATED — typically a
		// line longer than scannerMaxBuf. Dropping it made a partial parse look
		// like a complete one, which for a findings parser means silently
		// missing results.
		if err := scanner.Err(); err != nil {
			scanErrMu.Lock()
			if scanErr == nil {
				scanErr = err
			}
			scanErrMu.Unlock()
		}
	}

	go scanPipe(stdoutPipe, false)
	go scanPipe(stderrPipe, true)

	// Close the channel after both readers AND cmd.Wait() are done.
	go func() {
		wg.Wait()
		waitErr := cmd.Wait()
		close(doneCh)
		// AFTER Wait, never before: closing the stdin file earlier would take the
		// child's standard input away mid-read.
		cleanup()

		// Surface a non-clean termination as a final event before closing.
		// Without it a tool that died mid-stream was indistinguishable from one
		// that finished, because the only signal the consumer got was the
		// channel closing.
		scanErrMu.Lock()
		termErr := scanErr
		stderrTail := lastKB(stderrBuf)
		scanErrMu.Unlock()

		// PRECEDENCE IS PRESERVED: a scanner error still wins over a wait error.
		// A truncated stream is a worse fact than a non-zero exit — it means the
		// output was silently incomplete — and must not be hidden by it.
		if termErr == nil {
			termErr = waitErr
		}

		// Enrich the terminal error with the tool's own stderr. Before this, the
		// consumer got cmd.Wait()'s raw error, which is literally where the string
		// "exit status 1" came from — the single most expensive string in the
		// first live v2 run, because it was the ONLY thing an operator ever saw
		// for five different root causes.
		//
		// Wrapped as *ToolError so errors.Is(err, ErrTool) keeps holding and the
		// sentinel-bridge discipline (ADR §6: no string matching) still works.
		// A DEADLINE IS NOT AN ORDINARY FAILURE, and the stream path did not
		// distinguish it. ExecEnv has checked ctx.Err() for DeadlineExceeded
		// since phase 3; StreamEnv never did, so a tool killed by its own
		// Tool.Timeout reached the consumer as a generic ToolError carrying
		// cmd.Wait()'s "signal: killed" — indistinguishable from a crash. Plan
		// 16-05 gives httpx, naabu, nuclei and notify real deadlines, and
		// katana/dnsx have had 4h ones since the manifest was written, so this
		// path is now reachable for six tools rather than none.
		if stderrors.Is(ctx.Err(), context.DeadlineExceeded) {
			// Report the TOOL'S OWN deadline when it has one. KillGrace is the
			// post-signal grace period, not the bound that fired, and reporting
			// it produced "timed out after 2s" for a one-hour deadline.
			reported := t.Timeout
			if reported == 0 {
				reported = b.KillGrace
			}
			termErr = &coreerrors.ToolTimeout{Tool: t.Name, Timeout: reported}
		} else if termErr != nil {
			termErr = &coreerrors.ToolError{
				Tool:     t.Name,
				ExitCode: exitCodeOf(cmd, termErr),
				Stderr:   stderrTail,
				Inner:    termErr,
			}
		}
		if termErr != nil {
			// ctx.Done() fires for BOTH consumer abandonment and the tool's own
			// deadline, and treating them alike dropped the terminal event
			// exactly when it mattered most: the deadline killed the tool and the
			// consumer saw a clean channel close — the F6 shape phase 15 spent
			// two plans closing, reappearing on the timeout path only.
			//
			// On a deadline the consumer is usually still reading, so the send is
			// attempted with the same bounded backstop that protects an abandoned
			// stream. It cannot wedge: the backstop arm always exists.
			deadlineFired := stderrors.Is(ctx.Err(), context.DeadlineExceeded)
			done := ctx.Done()
			if deadlineFired {
				done = nil // disable the abandonment arm; the backstop still bounds us
			}
			select {
			case out <- Event{Source: t.Name, IsErr: true, Err: termErr}:
			case <-done:
				// The consumer abandoned the stream. ctx is the same context that
				// bounds the child process, so its cancellation is the earliest
				// truthful signal that nobody is listening — a fixed wall-clock
				// timeout instead pinned this goroutine (and the context) for a
				// full second on EVERY abandoned invocation.
			case <-time.After(terminalSendBackstop):
				// Backstop for a caller that passed a context with neither a
				// deadline nor a cancel (e.g. context.Background()) and then
				// stopped reading: ctx.Done() would never fire, so without this
				// arm the goroutine would block forever.
			}
		}
		close(out)
	}()

	return out, nil
}

// exitCodeOf derives a tool's exit code the SAME way ExecEnv does, so the Exec
// and Stream paths cannot report different codes for the same failure.
func exitCodeOf(cmd *exec.Cmd, err error) int {
	var ee *exec.ExitError
	if stderrors.As(err, &ee) {
		return ee.ExitCode()
	}
	if cmd != nil && cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	return -1
}

// lastKB returns the last `stderrCap` bytes of buf as a string. Used to bound
// ToolError.Stderr per ADR §6 line 1806 (1KB cap; W9 explicit assertion).
func lastKB(buf []byte) string {
	if len(buf) <= stderrCap {
		return string(buf)
	}
	return string(buf[len(buf)-stderrCap:])
}
