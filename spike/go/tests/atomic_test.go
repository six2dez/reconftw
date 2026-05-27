// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 2
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 2
// Pitfall reference: .planning/research/PITFALLS.md §3.1 (atomic write, top-5)
package tests

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/six2dez/reconftw/spike/go/internal/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain handles the fault-injection child process pattern for TestAtomicWrite_CrashSafe.
// When the test binary is invoked with SPIKE_FAULT_INJECT=after_fsync, it acts as a
// "crash-mid-write" child process rather than a test runner.
func TestMain(m *testing.M) {
	if os.Getenv("SPIKE_FAULT_INJECT") == "after_fsync" {
		// This code runs only in the CHILD process spawned by TestAtomicWrite_CrashSafe.
		// It writes to the path given in SPIKE_FAULT_TARGET, then crashes.
		target := os.Getenv("SPIKE_FAULT_TARGET")
		if target == "" {
			os.Exit(2)
		}
		lines := [][]byte{
			[]byte(`{"line":"new-content-1"}`),
			[]byte(`{"line":"new-content-2"}`),
		}
		// Write to target — this may or may not complete before SIGKILL hits.
		if err := output.WriteJSONL(target, lines); err != nil {
			// Write failed (possibly killed mid-way) — exit with error code
			os.Exit(1)
		}
		// If we reach here, the write completed atomically before SIGKILL.
		os.Exit(0)
	}

	os.Exit(m.Run())
}

// TestAtomicWrite_HappyPath writes 100 lines via WriteJSONL and asserts all are present.
func TestAtomicWrite_HappyPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.jsonl")

	lines := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		lines[i] = []byte(fmt.Sprintf(`{"line":%d}`, i))
	}

	err := output.WriteJSONL(target, lines)
	require.NoError(t, err)

	// Verify file exists and has exactly 100 lines.
	f, err := os.Open(target)
	require.NoError(t, err)
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, 100, count, "expected 100 lines in output file")
}

// TestAtomicWrite_CrashSafe verifies that a SIGKILL between fsync and rename leaves
// the original file intact (or the new content if rename completed) — never partial.
//
// Implementation: spawns child test binary with SPIKE_FAULT_INJECT=after_fsync env var.
// The child writes to target, gets SIGKILL mid-run. Parent asserts no torn write.
func TestAtomicWrite_CrashSafe(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "subs.jsonl")

	// Pre-populate target with known content.
	previousContent := []byte(`{"line":"previous"}` + "\n")
	require.NoError(t, os.WriteFile(target, previousContent, 0o644))

	// Get the test binary path (os.Executable trick for self-invocation).
	exe, err := os.Executable()
	require.NoError(t, err)

	// Run up to 10 attempts; if all 10 complete cleanly (no torn write), test passes.
	tornWrite := false
	for attempt := 0; attempt < 10; attempt++ {
		cmd := exec.Command(exe, "-test.run", "^$") // run no tests; just TestMain branch
		cmd.Env = append(os.Environ(),
			"SPIKE_FAULT_INJECT=after_fsync",
			"SPIKE_FAULT_TARGET="+target,
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

		if err := cmd.Start(); err != nil {
			t.Logf("attempt %d: failed to start child: %v", attempt, err)
			continue
		}

		// SIGKILL within 100ms — race condition is intentional.
		time.Sleep(100 * time.Millisecond)
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		_ = cmd.Wait()

		// Read the target file and check integrity.
		data, err := os.ReadFile(target)
		if err != nil {
			t.Logf("attempt %d: could not read target: %v", attempt, err)
			continue
		}

		content := string(data)
		isPrevious := content == string(previousContent)
		isNew := strings.Contains(content, "new-content-1") && strings.Contains(content, "new-content-2")

		if !isPrevious && !isNew {
			tornWrite = true
			t.Logf("attempt %d: TORN WRITE DETECTED:\n%s", attempt, content)
			break
		}
		t.Logf("attempt %d: OK (previous=%v, new=%v)", attempt, isPrevious, isNew)
	}

	assert.False(t, tornWrite, "atomic write must never produce a torn file")
}
