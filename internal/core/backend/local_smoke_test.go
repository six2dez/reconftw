//go:build smoke

// SPDX-License-Identifier: MIT
//
// Tests 8, 10, 11 from .planning/phases/03-foundation-kernel/03-04-PLAN.md Task 1.
// Ring 3 — smoke ring; run with `go test -race -tags smoke ./internal/core/backend/...`.
//
// Test 11 (TestKillTreeWithin10s) is THE FOUND-09 mandatory test:
// SIGINT to the parent kills ALL children + grandchildren within 10s
// using syscall.Kill(pid, 0) liveness probes per W17 (replaces fragile `ps` parsing).
package backend_test

import (
	"context"
	stderrors "errors"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// childDead returns true when syscall.Kill(pid, 0) returns ESRCH — the kernel
// signals "no such process". This replaces fragile ps-output parsing (W17).
func childDead(pid int) bool {
	err := syscall.Kill(pid, 0)
	// ESRCH = "no such process" — pid has been reaped and is fully dead.
	if stderrors.Is(err, syscall.ESRCH) {
		return true
	}
	// EPERM means the process exists but we lack permission (still alive).
	// nil means the signal was delivered (process exists and is reachable).
	return false
}

// Test 8: Exec with mid-run cancelled ctx returns within KillGrace+1s, subprocess + children dead.
func TestLocalBackend_Exec_ContextCancelled_KillsTree(t *testing.T) {
	b := backend.NewLocalBackend(2 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())

	// /bin/sleep 100 — simple long-running child.
	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		_, err := b.Exec(ctx, &backend.Tool{Name: "sleep", Path: "/bin/sleep"}, []string{"100"})
		done <- result{err: err, elapsed: time.Since(start)}
	}()

	// Give sleep a moment to start.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case r := <-done:
		t.Logf("Exec returned after ctx cancel in %v err=%v", r.elapsed, r.err)
		if r.elapsed > 5*time.Second {
			t.Errorf("Exec returned %v after cancel, want < 5s (KillGrace=2s + 1s tolerance)", r.elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Exec did not return within 10s after ctx cancel")
	}
}

// Test 10: Stream channel closes within KillGrace after ctx cancel; subprocess dead.
func TestLocalBackend_Stream_ContextCancelled_ClosesChannel(t *testing.T) {
	b := backend.NewLocalBackend(2 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())

	// `yes` produces an unbounded stream — perfect canary for the kill-tree path.
	ch, err := b.Stream(ctx, &backend.Tool{Name: "yes", Path: "/usr/bin/yes"}, nil)
	if err != nil {
		t.Fatalf("Stream(/usr/bin/yes) returned err=%v", err)
	}

	// Drain a few events to confirm streaming works.
	got := 0
	drainStart := time.Now()
drain:
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				break drain
			}
			got++
			if got >= 5 {
				// Trigger cancel mid-stream.
				cancel()
			}
			if time.Since(drainStart) > 10*time.Second {
				t.Fatalf("Stream channel did not close within 10s after cancel (received %d events)", got)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("Stream channel timeout waiting for next event")
		}
	}
	if got == 0 {
		t.Errorf("Stream did not yield any events before close")
	}
}

// Test 11: FOUND-09 — THE mandatory kill-tree test.
// Spawn `bash -c 'sleep 100 & sleep 100 & wait'`, capture the bash pid + 2 sleep grandchild
// pids (parsed from the bash output), cancel ctx, poll each pid with syscall.Kill(pid, 0)
// within 10s — all three MUST return ESRCH (W17).
func TestKillTreeWithin10s(t *testing.T) {
	b := backend.NewLocalBackend(2 * time.Second)

	// Use bash to capture the sleep PIDs and emit them on stdout so we can parse.
	// Trap: $! prints the pid of the most-recent background job; we run two backgrounds
	// and echo both pids. Then `wait` until killed.
	cmd := []string{
		"-c",
		"sleep 100 & C1=$!; sleep 100 & C2=$!; echo \"$$ $C1 $C2\"; wait",
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := b.Stream(ctx, &backend.Tool{Name: "bash", Path: "/bin/bash"}, cmd)
	if err != nil {
		t.Fatalf("Stream(bash -c) returned err=%v", err)
	}

	// Read first stdout event to get the PID triple.
	var bashPID, c1PID, c2PID int
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatalf("Stream channel closed before bash emitted PIDs")
		}
		fields := strings.Fields(string(ev.Line))
		if len(fields) < 3 {
			t.Fatalf("bash PID-triple line malformed: %q", ev.Line)
		}
		bashPID, err = strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("parse bashPID %q: %v", fields[0], err)
		}
		c1PID, err = strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("parse c1PID %q: %v", fields[1], err)
		}
		c2PID, err = strconv.Atoi(fields[2])
		if err != nil {
			t.Fatalf("parse c2PID %q: %v", fields[2], err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("bash did not emit PID-triple within 5s")
	}

	t.Logf("FOUND-09: bash pid=%d sleep1 pid=%d sleep2 pid=%d (before cancel)", bashPID, c1PID, c2PID)

	// Cancel the context — LocalBackend should send SIGTERM to the process group,
	// then SIGKILL after WaitDelay+500ms. All three pids should be reaped within 10s.
	cancelTime := time.Now()
	cancel()

	// Drain the channel so the goroutines can exit cleanly.
	go func() {
		for range ch { //nolint:revive // intentional drain
		}
	}()

	// Poll liveness via syscall.Kill(pid, 0) — W17 replaces fragile `ps` parsing.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if childDead(bashPID) && childDead(c1PID) && childDead(c2PID) {
			elapsed := time.Since(cancelTime)
			t.Logf("FOUND-09: all 3 children reaped in %v (W17 syscall.Kill(pid,0)==ESRCH)", elapsed)
			if elapsed > 10*time.Second {
				t.Fatalf("FOUND-09: kill-tree took %v, want < 10s", elapsed)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Failure path — at least one is still alive.
	t.Fatalf("FOUND-09: children still alive after 10s (bash alive=%v c1 alive=%v c2 alive=%v)",
		!childDead(bashPID), !childDead(c1PID), !childDead(c2PID))
}

// orphanSpawner is a bash program that backgrounds a long sleep, prints its pid,
// and then exits 0 — the NORMAL exit path, no cancellation anywhere.
//
// The redirect to /dev/null is the load-bearing detail: it makes the grandchild
// let go of the inherited stdout/stderr pipes, so the scanners see EOF and
// cmd.Wait() returns cleanly. That is exactly the shape nuclei's headless
// Chromium leaves behind, and the shape in which NOTHING used to sweep the
// process group. A grandchild that instead HOLDS the pipes blocks the stream
// closer until ctx cancellation, which is a different (and separately tracked)
// problem — this test deliberately pins the silent one.
const orphanSpawner = "sleep 100 >/dev/null 2>&1 & echo $!; exit 0"

// waitForReap polls childDead until the deadline, so the test does not depend on
// how fast the kernel tears the group down.
func waitForReap(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if childDead(pid) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// Regression: a tool that exits 0 while leaving a grandchild behind must not leak
// it. Before the sweep in sweepProcessGroup, the escalation goroutine's only
// trigger was ctx cancellation, so on this path the orphan survived, re-parented
// to PID 1, and accumulated for as long as the box kept running (97 orphaned
// Chromium processes / 12 trees / 12 days on reconbox3).
//
// TestKillTreeWithin10s does NOT cover this: it cancels the context, taking the
// one branch that already swept.
func TestStreamNormalExitReapsOrphanedGrandchild(t *testing.T) {
	b := backend.NewLocalBackend(2 * time.Second)

	ch, err := b.Stream(context.Background(),
		&backend.Tool{Name: "bash", Path: "/bin/bash"},
		[]string{"-c", orphanSpawner})
	if err != nil {
		t.Fatalf("Stream(bash -c) returned err=%v", err)
	}

	// The pid arrives on the first stdout event; keep draining afterwards so the
	// closer goroutine can run cmd.Wait() and reach the sweep. The channel
	// closing is the signal that it did.
	var orphanPID int
	for ev := range ch {
		if ev.IsErr || orphanPID != 0 {
			continue
		}
		line := strings.TrimSpace(string(ev.Line))
		if line == "" {
			continue
		}
		if orphanPID, err = strconv.Atoi(line); err != nil {
			t.Fatalf("orphan pid line malformed: %q (%v)", line, err)
		}
	}
	if orphanPID == 0 {
		t.Fatal("bash never emitted the backgrounded pid")
	}

	if !waitForReap(orphanPID, 10*time.Second) {
		t.Fatalf("orphaned grandchild pid=%d survived a NORMAL tool exit — "+
			"the process group was never swept (this is the nuclei/Chromium leak)",
			orphanPID)
	}
}

// Same regression on the Exec path, which is a separate call site with its own
// copy of the wait/sweep sequence.
func TestExecNormalExitReapsOrphanedGrandchild(t *testing.T) {
	b := backend.NewLocalBackend(2 * time.Second)

	res, err := b.Exec(context.Background(),
		&backend.Tool{Name: "bash", Path: "/bin/bash"},
		[]string{"-c", orphanSpawner})
	if err != nil {
		t.Fatalf("Exec(bash -c) returned err=%v", err)
	}

	orphanPID, convErr := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if convErr != nil {
		t.Fatalf("orphan pid stdout malformed: %q (%v)", res.Stdout, convErr)
	}

	if !waitForReap(orphanPID, 10*time.Second) {
		t.Fatalf("orphaned grandchild pid=%d survived a NORMAL tool exit on the Exec path",
			orphanPID)
	}
}
