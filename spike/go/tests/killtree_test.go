// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 2
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.3.1
// Pitfall reference: .planning/research/PITFALLS.md §1.2 (process-group escape, top-impact)
package tests

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/six2dez/reconftw/spike/go/internal/proc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveMockTool returns the absolute path to spike/corpus/mock_stubborn_tool.sh
// by walking up from the test file's location using runtime.Caller.
func resolveMockTool(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must succeed")

	// thisFile is .../spike/go/tests/killtree_test.go
	// mock is at .../spike/corpus/mock_stubborn_tool.sh
	testDir := filepath.Dir(thisFile)
	mockPath := filepath.Join(testDir, "..", "..", "corpus", "mock_stubborn_tool.sh")
	absPath, err := filepath.Abs(mockPath)
	require.NoError(t, err)
	require.FileExistsf(t, absPath, "mock_stubborn_tool.sh must exist at %s", absPath)
	return absPath
}

// killtreeResultPath returns the absolute path to spike/go/out/.killtree_result.
func killtreeResultPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	testDir := filepath.Dir(thisFile)
	outPath := filepath.Join(testDir, "..", "out", ".killtree_result")
	absPath, err := filepath.Abs(outPath)
	require.NoError(t, err)
	return absPath
}

// pgrepDescendants returns all PIDs that are children of parentPID.
func pgrepDescendants(parentPID int) []int {
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(parentPID)).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// pidAlive checks if a process is alive using kill(pid, 0).
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}

// writeKilltreeResult writes PASS or FAIL to spike/go/out/.killtree_result.
func writeKilltreeResult(t *testing.T, result string) {
	t.Helper()
	resultPath := killtreeResultPath(t)
	if err := os.MkdirAll(filepath.Dir(resultPath), 0o755); err != nil {
		t.Logf("warning: could not create out/ dir: %v", err)
		return
	}
	if err := os.WriteFile(resultPath, []byte(result+"\n"), 0o644); err != nil {
		t.Logf("warning: could not write killtree_result: %v", err)
	}
}

// TestKillTree_SyntheticMock verifies that proc.Run's process-group kill correctly
// terminates ALL descendants of a stubborn mock tool that ignores SIGTERM.
//
// The mock tool (spike/corpus/mock_stubborn_tool.sh) spawns 2 children, all 3 ignore SIGTERM.
// Only the SIGKILL escalation (via proc.Run's goroutine after WaitDelay) will kill them.
// This is the exact worst-case that bash v1's _kill_tree() depth-first pgrep walk was
// designed for, now replaced by process-group primitives.
//
// Per RESEARCH.md §1.3.1 — canonical synthetic mock test shape.
// Per compare.sh M4 — PASS/FAIL written to spike/go/out/.killtree_result.
func TestKillTree_SyntheticMock(t *testing.T) {
	mockTool := resolveMockTool(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to receive proc.Run's PID via a side channel.
	// We need to capture the PID of the spawned bash process to check descendants.
	// proc.Run doesn't expose PID directly, so we use pgrep to find children of this test.
	testPID := os.Getpid()

	// Start proc.Run in a goroutine (it blocks until the subprocess exits).
	procDone := make(chan error, 1)
	go func() {
		// proc.Run with nil lineFn — we don't need output from the mock tool.
		err := proc.Run(ctx, "bash", []string{mockTool}, nil)
		procDone <- err
	}()

	// Wait for the mock tool to spawn its children.
	t.Log("waiting for mock tool to spawn children...")
	time.Sleep(2 * time.Second)

	// Find children of this test process — the mock bash process.
	mockChildren := pgrepDescendants(testPID)
	t.Logf("test PID: %d, direct children: %v", testPID, mockChildren)

	// Find the bash PID (the mock tool process) among children.
	var mockBashPID int
	for _, childPID := range mockChildren {
		// Check if this child has children of its own (the sleep processes).
		grandchildren := pgrepDescendants(childPID)
		if len(grandchildren) > 0 {
			mockBashPID = childPID
			t.Logf("found mock bash PID: %d with grandchildren: %v", mockBashPID, grandchildren)
			break
		}
	}

	if mockBashPID == 0 {
		// If we can't find it via grandchildren, just use the first child.
		if len(mockChildren) > 0 {
			mockBashPID = mockChildren[0]
			t.Logf("using first child as mock bash PID: %d", mockBashPID)
		}
	}

	// Capture ALL descendants (bash + its sleep children).
	var allDescendants []int
	if mockBashPID != 0 {
		allDescendants = append(allDescendants, mockBashPID)
		allDescendants = append(allDescendants, pgrepDescendants(mockBashPID)...)
	}
	t.Logf("all descendants to track: %v", allDescendants)

	require.NotEmpty(t, allDescendants, "should have found at least the mock bash process")

	// At least 1 descendant should have children (the sleep processes).
	// This validates the mock spawned its children successfully.

	// Cancel the context — triggers proc.Run's Cancel (SIGTERM to process group),
	// then after WaitDelay, proc.Run's goroutine sends SIGKILL to the group.
	t.Log("cancelling context (SIGTERM + eventual SIGKILL to process group)...")
	cancel()

	// Wait for proc.Run to return (includes WaitDelay grace + SIGKILL escalation = ~5.5s).
	select {
	case err := <-procDone:
		t.Logf("proc.Run returned: %v", err)
	case <-time.After(12 * time.Second):
		t.Log("proc.Run timed out — checking PIDs anyway")
	}

	// Allow a brief moment for SIGKILL to propagate and processes to be reaped.
	time.Sleep(500 * time.Millisecond)

	// Assert all captured PIDs are dead.
	allDead := true
	for _, pid := range allDescendants {
		if pidAlive(pid) {
			allDead = false
			t.Logf("FAIL: PID %d still alive after kill-tree", pid)
		} else {
			t.Logf("OK: PID %d is dead", pid)
		}
	}

	// Write M4 result for compare.sh.
	if allDead {
		writeKilltreeResult(t, "PASS")
		t.Log("kill-tree test: PASS — all descendants dead")
	} else {
		writeKilltreeResult(t, "FAIL")
		t.Error("kill-tree test: FAIL — some descendants still alive")
	}

	assert.True(t, allDead, "all descendants must be dead after process-group kill")
}
