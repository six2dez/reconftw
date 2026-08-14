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
	return b.ExecEnv(ctx, t, args, nil)
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
	start := time.Now()

	cmd := exec.CommandContext(ctx, t.Path, args...)

	// Process-group isolation: every subprocess gets its own pgid.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Env seam: only override cmd.Env when explicit entries are requested. The
	// nil-env path leaves cmd.Env nil (os/exec default = inherit parent env),
	// byte-for-byte identical to the pre-seam behavior.
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

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
		// Binary not found, permission denied, etc.
		return nil, &coreerrors.ToolError{
			Tool:     t.Name,
			ExitCode: -1,
			Stderr:   "",
			Inner:    err,
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
		return nil, &coreerrors.ToolTimeout{
			Tool:    t.Name,
			Timeout: b.KillGrace,
		}
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
	return b.StreamEnv(ctx, t, args, nil)
}

// StreamEnv is Stream with additional "KEY=VALUE" child-env entries (see ExecEnv
// for the env-scoping contract). When env is empty, cmd.Env is left nil — the
// nil-env path is byte-for-byte identical to the pre-seam Stream behavior.
func (b *LocalBackend) StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error) {
	cmd := exec.CommandContext(ctx, t.Path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.WaitDelay = b.KillGrace
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, &coreerrors.ToolError{Tool: t.Name, ExitCode: -1, Inner: err}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, &coreerrors.ToolError{Tool: t.Name, ExitCode: -1, Inner: err}
	}

	if err := cmd.Start(); err != nil {
		return nil, &coreerrors.ToolError{Tool: t.Name, ExitCode: -1, Inner: err}
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

	scanPipe := func(p io.Reader, isErr bool) {
		defer wg.Done()
		scanner := bufio.NewScanner(p)
		scanner.Buffer(make([]byte, scannerInitialBuf), scannerMaxBuf)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...) // copy — Scan reuses its buffer
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

		// Surface a non-clean termination as a final event before closing.
		// Without it a tool that died mid-stream was indistinguishable from one
		// that finished, because the only signal the consumer got was the
		// channel closing.
		scanErrMu.Lock()
		termErr := scanErr
		scanErrMu.Unlock()
		if termErr == nil {
			termErr = waitErr
		}
		if termErr != nil {
			select {
			case out <- Event{Source: t.Name, IsErr: true, Err: termErr}:
			case <-time.After(time.Second):
				// Consumer stopped reading; nothing more we can do.
			}
		}
		close(out)
	}()

	return out, nil
}

// lastKB returns the last `stderrCap` bytes of buf as a string. Used to bound
// ToolError.Stderr per ADR §6 line 1806 (1KB cap; W9 explicit assertion).
func lastKB(buf []byte) string {
	if len(buf) <= stderrCap {
		return string(buf)
	}
	return string(buf[len(buf)-stderrCap:])
}
