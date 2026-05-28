//go:build smoke

// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 2 (Ring 3).
// Plan 03-01 W12 revision iter 1: FOUND-04 atomicity smoke test must include
// a real-subprocess SIGKILL scenario, because the Ring 1 hook simulation
// in atomic_test.go cannot prove the OS-level guarantees against an
// actual signal interruption.
//
// This file is build-tagged `smoke` so the unit ring (go test -race -short)
// never executes it. The CI pipeline's `smoke` job (PR + scheduled cron)
// runs `go test -race -tags smoke ./...` and is the canonical gate.
package output

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestFOUND04SubprocessSIGKILL spawns a child process invoking the smoke
// binary (the test binary re-invoked with SMOKE_CHILD=1), which calls
// writeJSONLWithHook with a slow hook (time.Sleep). The parent SIGKILLs
// the child during the sleep — that is, after the tempfile is fsynced
// but before the rename. After collecting the child, the parent asserts:
//
//   - The target file is either ABSENT (no prior version existed) or
//     contains the ORIGINAL pre-seeded content (never the new payload,
//     never a torn write).
//   - No leftover .tmp.* files remain in the target directory.
//
// The child reports its tempfile path via stdout so the parent can verify
// it was cleaned up by the OS / next-startup sweep — for this test the
// parent simply confirms no .tmp.* survives in the directory after the
// child is gone. A lingering tempfile is fine architecturally (a real
// crash cannot run defer) but the test prints a warning if observed
// so the rotation policy can be revisited.
func TestFOUND04SubprocessSIGKILL(t *testing.T) {
	// Pre-seed: write an ORIGINAL file. The atomic guarantee says even
	// after the child is SIGKILLed mid-write, this content must survive.
	dir := t.TempDir()
	target := filepath.Join(dir, "atomic-smoke.jsonl")
	if err := WriteJSONL(target, [][]byte{[]byte("ORIGINAL")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	origBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("seed read: %v", err)
	}

	// Spawn the child: re-invoke this test binary with SMOKE_CHILD=1.
	// The child runs the helper TestFOUND04SubprocessChild below.
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestFOUND04SubprocessChild$",
		"-test.v",
	)
	cmd.Env = append(os.Environ(),
		"SMOKE_CHILD=1",
		"SMOKE_TARGET="+target,
	)
	// Stash combined output for diagnostics.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the child time to: start, run the test runner overhead, enter
	// writeJSONLWithHook, write the tempfile, fsync, and enter the slow
	// hook. 1500ms is generous on CI; the child's hook sleeps for 5s.
	time.Sleep(1500 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}

	_ = cmd.Wait() // SIGKILL produces a non-nil error — expected.
	buf := make([]byte, 4096)
	n, _ := stdoutPipe.Read(buf)
	if n > 0 {
		t.Logf("child stdout: %s", string(buf[:n]))
	}

	// CANONICAL FOUND-04 ASSERTION: the target file still contains ORIGINAL.
	gotBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("post-SIGKILL read: %v", err)
	}
	if string(gotBytes) != string(origBytes) {
		t.Fatalf("FOUND-04 VIOLATION: target was modified by SIGKILLed write\noriginal: %q\nactual:   %q",
			origBytes, gotBytes)
	}

	// Tempfile cleanup is best-effort under SIGKILL (defer cannot run).
	// We log if we see one, but do not fail — a stranded *.tmp.* after a
	// real crash is recoverable: rotation policy lives in Plan 10 monitor.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Logf("post-SIGKILL tempfile observed (expected under SIGKILL — defer cannot run): %s", e.Name())
		}
	}
}

// TestFOUND04SubprocessChild is the child-process helper. It is only
// executed when SMOKE_CHILD=1 is in the environment; when invoked as part
// of the normal test run it returns early.
func TestFOUND04SubprocessChild(t *testing.T) {
	if os.Getenv("SMOKE_CHILD") != "1" {
		t.Skip("not running as smoke child")
	}
	target := os.Getenv("SMOKE_TARGET")
	if target == "" {
		t.Fatal("SMOKE_TARGET not set")
	}
	// Sleep for 5s INSIDE the hook — between fsync and rename. Parent
	// SIGKILLs us at ~1.5s, so the rename never executes.
	_ = writeJSONLWithHook(target, [][]byte{[]byte("NEW")}, func(tmpName string) error {
		t.Logf("child: tempfile created at %s, sleeping in hook", tmpName)
		time.Sleep(5 * time.Second)
		return nil
	})
	t.Log("child: returned cleanly (parent did not SIGKILL — unexpected)")
}
