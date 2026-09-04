// SPDX-License-Identifier: MIT
//
// Regression tests for the bootstrap-then-unreachable defect.
//
// Observed live on reconbox3, 2026-09-03: uv was present at ~/.local/bin/uv,
// that directory was not on the process PATH, bootstrapUV ran the upstream
// installer and returned nil, and all 24 python/python_venv tools then failed
// with `exec: "uv": executable file not found in $PATH`. None of them is in the
// critical tier, so `install` finished with a warning and `health-check` exited
// 0 — a completely broken toolchain reported as a good install.

package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCleanPATH points PATH at an empty temp dir so nothing from the developer's
// real environment can satisfy a lookup.
func withCleanPATH(t *testing.T) {
	t.Helper()
	orig := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	t.Cleanup(func() { _ = os.Setenv("PATH", orig) })
}

// fakeBin drops an executable file named bin into a new temp dir and returns it.
func fakeBin(t *testing.T, bin string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec
		t.Fatalf("write fake %s: %v", bin, err)
	}
	return dir
}

// THE reconbox3 case: the binary exists in a known install dir but is not on
// PATH. ensureOnPath must put it there, so the invocations that follow work.
func TestEnsureOnPathAddsABootstrappedBinary(t *testing.T) {
	withCleanPATH(t)
	dir := fakeBin(t, "uv")

	if onPath("uv") {
		t.Fatal("test setup is wrong: uv resolved before the fix ran")
	}
	if err := ensureOnPath("uv", dir); err != nil {
		t.Fatalf("ensureOnPath returned %v, want nil — uv is sitting in %s", err, dir)
	}
	if !onPath("uv") {
		t.Fatal("ensureOnPath reported success but uv still does not resolve — " +
			"every `uv tool install` after this point fails with " +
			"\"executable file not found in $PATH\"")
	}
}

// Not finding it anywhere must be an ERROR, never a silent success. Returning
// nil here is precisely what made the failure invisible.
func TestEnsureOnPathFailsWhenTheBinaryIsNowhere(t *testing.T) {
	withCleanPATH(t)
	empty := t.TempDir()

	err := ensureOnPath("uv", empty)
	if err == nil {
		t.Fatal("ensureOnPath returned nil for a binary that exists nowhere — " +
			"the caller would proceed to install 24 tools that all fail")
	}
	if !strings.Contains(err.Error(), "uv") || !strings.Contains(err.Error(), empty) {
		t.Errorf("error must name the binary and the directories searched, got: %v", err)
	}
}

// An already-resolvable binary must be left alone: no PATH churn on the common path.
func TestEnsureOnPathIsANoOpWhenAlreadyResolvable(t *testing.T) {
	dir := fakeBin(t, "uv")
	t.Setenv("PATH", dir)
	before := os.Getenv("PATH")

	if err := ensureOnPath("uv", "/nonexistent"); err != nil {
		t.Fatalf("ensureOnPath returned %v for an already-resolvable binary", err)
	}
	if os.Getenv("PATH") != before {
		t.Errorf("PATH was modified for an already-resolvable binary:\n  before %q\n  after  %q",
			before, os.Getenv("PATH"))
	}
}

// The first directory holding the binary wins, so a freshly bootstrapped
// toolchain takes precedence over an older copy further down the list.
func TestEnsureOnPathPrefersTheFirstDirectoryThatHasIt(t *testing.T) {
	withCleanPATH(t)
	first := fakeBin(t, "uv")
	second := fakeBin(t, "uv")

	if err := ensureOnPath("uv", first, second); err != nil {
		t.Fatalf("ensureOnPath returned %v", err)
	}
	got, err := lookPath("uv")
	if err != nil {
		t.Fatalf("lookPath after ensureOnPath: %v", err)
	}
	if filepath.Dir(got) != first {
		t.Errorf("resolved uv from %s, want the first directory %s", filepath.Dir(got), first)
	}
}

// userBinDirs must name the directory the upstream uv installer actually writes
// to. Getting this wrong reintroduces the whole defect with a green test suite.
func TestUserBinDirsNamesTheUVInstallDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	_, _, uvBin, cargoBin := userBinDirs()
	if want := filepath.Join(home, ".local", "bin"); uvBin != want {
		t.Errorf("uv install dir = %q, want %q (the uv installer's default)", uvBin, want)
	}
	if want := filepath.Join(home, ".cargo", "bin"); cargoBin != want {
		t.Errorf("cargo bin = %q, want %q", cargoBin, want)
	}

	// UV_INSTALL_DIR overrides it, and the installer honours that.
	t.Setenv("UV_INSTALL_DIR", "/opt/uvbin")
	if _, _, override, _ := userBinDirs(); override != "/opt/uvbin" {
		t.Errorf("UV_INSTALL_DIR override = %q, want /opt/uvbin", override)
	}
}
