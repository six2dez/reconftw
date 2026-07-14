// Tests for WorkspaceInit — the STABLE per-target workspace (INTEG-03).
//
// The central property under test is stability + persistence: two calls for the
// same (rootDir, target) MUST return the identical path and MUST NOT destroy a
// file written between them. That persistence is exactly what lets
// <workspace>/checkpoints.db survive across runs so the scheduler can resume.
//
// External test package — WorkspaceInit is exercised through its exported API;
// sanitization is asserted via the returned path (no internal coupling).
package output_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
)

// TestWorkspaceInitStablePath: two calls with the same target return the SAME
// path (no timestamp component) and it equals filepath.Join(root, slug).
func TestWorkspaceInitStablePath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	first, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("first WorkspaceInit: %v", err)
	}
	second, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("second WorkspaceInit: %v", err)
	}

	if first != second {
		t.Errorf("workspace not stable: first=%q second=%q (timestamp suffix not removed?)", first, second)
	}
	want := filepath.Join(root, "example.com")
	if first != want {
		t.Errorf("workspace path = %q, want %q (no timestamp suffix)", first, want)
	}
}

// TestWorkspaceInitSubdirs: the five standard subdirs exist after the call and a
// second call does not error (idempotent MkdirAll).
func TestWorkspaceInitSubdirs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	for _, sub := range []string{"inputs", "artefacts", "raw", "reports", "logs"} {
		info, statErr := os.Stat(filepath.Join(ws, sub))
		if statErr != nil {
			t.Errorf("subdir %q missing: %v", sub, statErr)
			continue
		}
		if !info.IsDir() {
			t.Errorf("subdir %q is not a directory", sub)
		}
	}
	// Idempotent: second call must not error.
	if _, err := output.WorkspaceInit(root, "example.com"); err != nil {
		t.Errorf("second WorkspaceInit errored (not idempotent): %v", err)
	}
}

// TestWorkspaceInitPersistsFiles: a file written into the workspace after the
// first call is STILL present after the second call. This proves the dir is not
// recreated fresh — the exact property that lets checkpoints.db persist so the
// scheduler resumes across runs (INTEG-03).
func TestWorkspaceInitPersistsFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	ws1, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("first WorkspaceInit: %v", err)
	}
	// Simulate the checkpoints.db (or any run artefact) landing in the workspace.
	marker := filepath.Join(ws1, "checkpoints.db")
	if err := os.WriteFile(marker, []byte("run-1-state"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	ws2, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("second WorkspaceInit: %v", err)
	}
	if ws1 != ws2 {
		t.Fatalf("second run used a different workspace: %q vs %q", ws1, ws2)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker did not survive the second WorkspaceInit: %v", err)
	}
	if string(data) != "run-1-state" {
		t.Errorf("marker content changed across runs: got %q", string(data))
	}
}

// TestWorkspaceInitSanitizes: scheme is stripped, path dropped, and the slug is
// lowercased — regression guard on the EXISTING sanitizeTargetName behavior,
// asserted via the returned path. (Scheme strip is case-sensitive on the
// lowercase "https://" prefix, then the host is lowercased — unchanged by this
// plan.)
func TestWorkspaceInitSanitizes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	ws, err := output.WorkspaceInit(root, "https://Example.COM/some/path")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	want := filepath.Join(root, "example.com")
	if ws != want {
		t.Errorf("sanitized workspace = %q, want %q (scheme strip + path drop + lowercase)", ws, want)
	}
}

// TestWorkspaceInitValidation: empty rootDir, empty target, and sanitize-to-empty
// targets are all rejected (existing validation preserved).
func TestWorkspaceInitValidation(t *testing.T) {
	t.Parallel()

	if _, err := output.WorkspaceInit("", "example.com"); err == nil {
		t.Error("empty rootDir did not error")
	}
	if _, err := output.WorkspaceInit(t.TempDir(), "   "); err == nil {
		t.Error("empty target did not error")
	}
	if _, err := output.WorkspaceInit(t.TempDir(), "///"); err == nil {
		t.Error("sanitize-to-empty target did not error")
	}
}
