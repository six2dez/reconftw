// SPDX-License-Identifier: MIT
//
// Regression tests for two clone-path defects found by running the installer on
// a real box (reconbox3, 2026-09-03) rather than against stubs.

package installer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// findBuiltBinary must see an artefact in bin/, not just the clone root.
// massdns's Makefile writes bin/massdns; a root-only search called that build a
// failure ("make produced no executable") when it had actually succeeded.
func TestFindBuiltBinaryLooksInBinSubdir(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artefact := filepath.Join(binDir, "massdns")
	if err := os.WriteFile(artefact, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	got, err := findBuiltBinary(dir, "massdns")
	if err != nil {
		t.Fatalf("findBuiltBinary did not find bin/massdns: %v", err)
	}
	if got != artefact {
		t.Errorf("found %q, want %q", got, artefact)
	}
}

// The clone root still wins, so dnscewl's root-level artefact is unaffected.
func TestFindBuiltBinaryStillPrefersTheCloneRoot(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "DNScewl")
	if err := os.WriteFile(root, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "dnscewl"), []byte("x"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	got, err := findBuiltBinary(dir, "dnscewl")
	if err != nil {
		t.Fatalf("findBuiltBinary: %v", err)
	}
	if filepath.Dir(got) != dir {
		t.Errorf("resolved %q, want the clone-root artefact in %q", got, dir)
	}
}

// A clone left WITHOUT a venv — the state an interrupted or uv-less run leaves
// behind — must be resumed, not re-cloned. Re-cloning fails with "destination
// path already exists", which made every affected tool permanently unfixable by
// re-running an installer that documents itself as idempotent.
func TestPythonVenvResumesAnExistingCloneInsteadOfReCloning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tool := &backend.Tool{
		Name:    "cmseek",
		Kind:    "python_venv",
		RepoURL: "https://github.com/Tuhinshubhra/CMSeeK",
	}
	// Pre-create the wreckage: a git checkout with no venv/.
	dir := filepath.Join(toolsRepoDir(), cloneTargetName(tool))
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	var ranClone bool
	var dirCmds []string
	swapRunCmd(t, func(_ context.Context, name string, args, _ []string) error {
		if name == "git" && len(args) > 0 && args[0] == "clone" {
			ranClone = true
		}
		return nil
	})
	origDir := runCmdDir
	runCmdDir = func(_ context.Context, _ string, name string, args, _ []string) error {
		dirCmds = append(dirCmds, name+" "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { runCmdDir = origDir })

	c := NewCloneToolInstaller()
	if err := c.Install(context.Background(), tool); err != nil {
		t.Fatalf("Install over an existing clone returned %v, want nil", err)
	}
	if ranClone {
		t.Error("re-cloned over an existing checkout — git fails with " +
			"\"destination path already exists\", so the tool can never be repaired")
	}
	joined := strings.Join(dirCmds, "; ")
	if !strings.Contains(joined, "uv venv venv") {
		t.Errorf("did not create the venv it resumed for; commands were: %s", joined)
	}
}

// A python_venv upstream that ships pyproject.toml/setup.py instead of
// requirements.txt must still get its package installed. gato is that shape:
// before this, its venv was created and left holding only activate scripts, so
// the declared clone_entry venv/bin/gato never existed and the tool resolved as
// "INSTALLED BUT UNRESOLVABLE" — with the install reporting success.
func TestPythonVenvInstallsAPackagedProjectWithoutRequirements(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tool := &backend.Tool{
		Name:    "gato",
		Kind:    "python_venv",
		RepoURL: "https://github.com/praetorian-inc/gato",
	}
	dir := filepath.Join(toolsRepoDir(), cloneTargetName(tool))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// The clone stub materialises a packaged project: no requirements.txt.
	swapRunCmd(t, func(_ context.Context, name string, args, _ []string) error {
		if name == "git" && len(args) > 0 && args[0] == "clone" {
			return os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\n"), 0o644) //nolint:gosec
		}
		return nil
	})
	var dirCmds []string
	origDir := runCmdDir
	runCmdDir = func(_ context.Context, _ string, name string, args, _ []string) error {
		dirCmds = append(dirCmds, name+" "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { runCmdDir = origDir })

	if err := NewCloneToolInstaller().Install(context.Background(), tool); err != nil {
		t.Fatalf("Install returned %v", err)
	}
	joined := strings.Join(dirCmds, "; ")
	if !strings.Contains(joined, "uv pip install .") {
		t.Errorf("a packaged project was cloned but never installed into its venv — "+
			"the venv holds only activate scripts and clone_entry never appears.\n"+
			"  commands run: %s", joined)
	}
	// Without an explicit target uv picks its OWN environment, succeeds, and
	// leaves this venv empty — a silent no-op that looks like a good install.
	if !strings.Contains(joined, "--python venv/bin/python3") {
		t.Errorf("uv pip install ran without --python venv/bin/python3, so it "+
			"installed into some other environment and the venv stays empty.\n"+
			"  commands run: %s", joined)
	}
}
