// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 2
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
// Pitfall reference: .planning/research/PITFALLS.md §1.2 (process-group escape, top-impact)
//
// IMPORTANT NOTE on WaitDelay + process-group kill escalation:
// Go's exec.CommandContext WaitDelay fires cmd.Process.Kill() which sends SIGKILL only to
// the DIRECT child process (kill(pid, SIGKILL)), NOT to the process group (kill(-pgid, SIGKILL)).
// This means children that ignore SIGTERM are left orphaned after WaitDelay. We work around
// this by spawning a goroutine that sends SIGKILL to the ENTIRE process group after WaitDelay.
package proc

import (
	"bufio"
	"context"
	"os/exec"
	"syscall"
	"time"
)

// Run executes name+args under process-group isolation (Setpgid: true). On ctx cancel,
// the entire process group receives SIGTERM, then SIGKILL after 5s WaitDelay grace.
// stdout is streamed line-by-line through lineFn; nil lineFn means stdout is discarded.
//
// lineFn signature is `func([]byte) error` (B4 fix per cross-AI review):
//   - For streaming-friendly sources (NDJSON like subfinder, httpx), callers parse
//     each line and may return a non-nil error to abort the subprocess early.
//   - For buffered sources (JSON-array like crt.sh), callers simply append the line
//     to a bytes.Buffer and return nil; the source-specific package then parses
//     the accumulated buffer AFTER proc.Run returns. This dual-mode usage is the
//     reason lineFn returns error: it removes the ambiguity Task 3 crt.go would
//     otherwise face (mid-implementation workaround for missing abort semantics).
//
// Returns the cmd's wait error (nil = clean exit).
//
// Source pattern: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
// Pitfall reference: .planning/research/PITFALLS.md §1.2 (process-group escape, top-impact)
func Run(ctx context.Context, name string, args []string, lineFn func([]byte) error) error {
	cmd := exec.CommandContext(ctx, name, args...)

	// Process-group isolation: every subprocess runs as its own process-group leader.
	// This is the key difference from bash v1's _kill_tree() pgrep walk —
	// v2 uses OS primitives directly, no job-control constraint.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// WaitDelay: after ctx cancels, SIGTERM is sent via Cancel below; if process
	// doesn't exit within WaitDelay, Go sends SIGKILL to the DIRECT child only.
	// We supplement this with our own group-SIGKILL goroutine (see below).
	cmd.WaitDelay = 5 * time.Second

	// Cancel: when ctx is done, kill the ENTIRE process group (negative PID = group).
	// This replaces bash v1's recursive pgrep walk in lib/parallel.sh:_kill_tree().
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative PID targets the process group (SIGTERM first).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	if lineFn != nil {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}

		if err := cmd.Start(); err != nil {
			return err
		}

		// SIGKILL escalation goroutine: Go's WaitDelay fires cmd.Process.Kill()
		// (kill(pid, SIGKILL) — direct child only). We need kill(-pgid, SIGKILL)
		// to reap stubborn grandchildren. Start a timer that fires WaitDelay+1s
		// after ctx cancellation to kill the whole group.
		pgid := cmd.Process.Pid
		killGroupDone := make(chan struct{})
		go func() {
			defer close(killGroupDone)
			select {
			case <-ctx.Done():
				// Wait for WaitDelay grace period, then kill group.
				time.Sleep(cmd.WaitDelay + 500*time.Millisecond)
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			case <-killGroupDone:
				// cmd finished before ctx was cancelled; nothing to do.
			}
		}()

		// Streaming with explicit buffer size per RESEARCH.md §Pattern 3:
		// 1MiB initial / 10MiB max handles long httpx JSON objects.
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

		for scanner.Scan() {
			if err := lineFn(scanner.Bytes()); err != nil {
				// B4 fix: non-nil lineFn error aborts the stream early.
				_ = cmd.Wait()
				return err
			}
		}

		if err := scanner.Err(); err != nil {
			_ = cmd.Wait()
			return err
		}

		return cmd.Wait()
	}

	// No lineFn: run to completion with the same SIGKILL escalation.
	if err := cmd.Start(); err != nil {
		return err
	}

	pgid := cmd.Process.Pid
	killGroupDone := make(chan struct{})
	go func() {
		defer close(killGroupDone)
		select {
		case <-ctx.Done():
			time.Sleep(cmd.WaitDelay + 500*time.Millisecond)
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		case <-killGroupDone:
		}
	}()

	return cmd.Wait()
}
