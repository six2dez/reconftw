// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.3.2

//go:build integration

package tests

import (
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKillTree_RealTools invokes the real spike binary against hackerone.com and
// validates that SIGINT kills all descendant subprocesses within 12s.
//
// This test is gated by //go:build integration and is intended for nightly CI,
// NOT per-push. It requires:
//   - spike binary to be pre-built (or this test builds it via make)
//   - subfinder and httpx to be installed
//   - Internet access to hackerone.com
//
// Per RESEARCH.md §1.3.2 — real-tool kill-tree integration test shape.
func TestKillTree_RealTools(t *testing.T) {
	// Get the spike binary path relative to this test file.
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	spikeBin := thisFile[:len(thisFile)-len("/tests/integration_test.go")] + "/bin/spike"

	// Build spike if not present.
	if _, err := exec.LookPath(spikeBin); err != nil {
		t.Logf("spike binary not found at %s, building...", spikeBin)
		buildCmd := exec.Command("make", "-C", thisFile[:len(thisFile)-len("/tests/integration_test.go")], "build")
		if out, err := buildCmd.CombinedOutput(); err != nil {
			t.Fatalf("make build failed: %v\n%s", err, out)
		}
	}

	// Start the spike binary in the background.
	cmd := exec.Command(spikeBin, "--target", "hackerone.com")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	spikePID := cmd.Process.Pid

	// Wait for at least one descendant to appear (subfinder or httpx).
	t.Log("waiting for spike to spawn subprocesses...")
	var descendants []int
	for i := 0; i < 60; i++ { // wait up to 30s
		time.Sleep(500 * time.Millisecond)
		descendants = pgrepDescendants(spikePID)
		if len(descendants) > 0 {
			break
		}
	}

	if len(descendants) == 0 {
		t.Skip("no descendants found — spike may have completed before first poll (tools very fast or not installed)")
	}

	t.Logf("spike PID: %d, descendants: %v", spikePID, descendants)

	// Send SIGINT to the spike parent.
	t.Log("sending SIGINT to spike...")
	require.NoError(t, cmd.Process.Signal(syscall.SIGINT))

	// Wait for spike to exit.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Logf("spike exited: %v", err)
	case <-time.After(12 * time.Second):
		t.Log("spike timed out — checking PIDs anyway")
	}

	// Allow brief propagation time for SIGKILL escalation.
	time.Sleep(500 * time.Millisecond)

	// Assert all captured descendants are dead.
	allDead := true
	for _, pid := range descendants {
		if err := syscall.Kill(pid, 0); err == nil {
			allDead = false
			t.Logf("FAIL: PID %d still alive", pid)
		} else {
			t.Logf("OK: PID %d dead (%v)", pid, err)
		}
	}

	t.Logf("checked %d descendants", len(descendants))
	assert.True(t, allDead, "all %s descendants must be dead after SIGINT", strconv.Itoa(len(descendants)))
}
