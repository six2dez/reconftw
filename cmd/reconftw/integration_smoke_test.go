// integration_smoke_test.go — Phase 4 plan-01: kernel-demo integration test
// replaced. The Phase 3 TestKernelDemoEndToEnd is removed because:
//   1. kernel_demo.go deleted (Phase 4 plan-01 acceptance).
//   2. internal/modules/demo/noop.go deleted (Phase 4 plan-01 acceptance).
//   3. The binary no longer has a `kernel-demo` subcommand.
//
// A new integration smoke test will be added in Phase 4 plan-02 when the
// `subs` subcommand is wired end-to-end via the Scheduler + passive Tasks.
// Until then this file is intentionally minimal to satisfy the package
// build without a running binary test.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-01-PLAN.md
// (deletion accepted; TestKernelDemoEndToEnd superseded).

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestBinaryBuilds verifies the reconftw binary builds cleanly with the
// subdomains module wired (modules.go blank import of subdomains package).
// This is a lightweight build-smoke test that replaces the Phase 3 demo.
func TestBinaryBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build smoke (-short)")
	}
	repoRoot := findRepoRoot(t)
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "reconftw")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	buildCmd := exec.Command("go", "build",
		"-ldflags=-s -w",
		"-trimpath",
		"-o", binPath,
		"./cmd/reconftw",
	)
	buildCmd.Dir = repoRoot
	buildCmd.Env = os.Environ()
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\noutput: %s", err, out)
	}

	// Binary must exist and be non-empty.
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("binary not found at %s: %v", binPath, err)
	}
	if info.Size() == 0 {
		t.Errorf("binary is empty (0 bytes)")
	}
}

// findRepoRoot walks up from this test file's directory to the first
// directory containing go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod walking up from %s", wd)
	return ""
}
