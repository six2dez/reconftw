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
	"strings"
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
	// F2: the directory name is now the canonical identity slug
	// ("<readable>-<hash8>"), not the bare sanitized hostname. The fixture is
	// derived from CanonicalTargetID rather than hardcoded so the assertion
	// keeps testing STABILITY, which is what checkpoints.db resume depends on.
	id, err := output.CanonicalTargetID("example.com")
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	want := filepath.Join(root, id.Slug)
	if first != want {
		t.Errorf("workspace path = %q, want %q (no timestamp suffix)", first, want)
	}
	if !strings.HasPrefix(filepath.Base(first), "example.com-") {
		t.Errorf("workspace name %q lost its readable component", filepath.Base(first))
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

// TestWorkspaceInitSanitizes: scheme is stripped, path dropped, and the host is
// lowercased — the URL form and the bare hostname must address the SAME
// workspace. Asserted against the plain-hostname workspace rather than a
// hardcoded name, because the directory is now the canonical identity slug
// (F2) and the property under test is the fold, not the spelling.
func TestWorkspaceInitSanitizes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	ws, err := output.WorkspaceInit(root, "https://Example.COM/some/path")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	plain, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit(example.com): %v", err)
	}
	if ws != plain {
		t.Errorf("sanitized workspace = %q, want %q (scheme strip + path drop + lowercase)", ws, plain)
	}
}

// TestWorkspaceInitDistinctPrefixes is ACCEPTANCE GATE 2 asserted at the
// workspace layer: /24, /16 and the bare IP must be three directories.
func TestWorkspaceInitDistinctPrefixes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	seen := make(map[string]string, 3)
	for _, tgt := range []string{"10.0.0.0/24", "10.0.0.0/16", "10.0.0.0"} {
		ws, err := output.WorkspaceInit(root, tgt)
		if err != nil {
			t.Fatalf("WorkspaceInit(%q): %v", tgt, err)
		}
		if prev, dup := seen[ws]; dup {
			t.Errorf("workspace collision: %q and %q both use %q", prev, tgt, ws)
		}
		seen[ws] = tgt
	}
	if len(seen) != 3 {
		t.Fatalf("gate 2 FAILED: got %d workspaces for 3 targets: %v", len(seen), seen)
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
