package installer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The make_clone kind exists because dnscewl's upstream is a C++ Makefile
// project, and its `make` emits `DNScewl` while the registry, permut.go and
// exec.LookPath all say `dnscewl`. Building without reconciling those two names
// leaves the tool "not installed" on any case-sensitive filesystem, which is the
// half of the bug that a build-succeeded check would not catch. These tests pin
// that reconciliation.

func TestFindBuiltBinaryMatchesCaseInsensitively(t *testing.T) {
	dir := t.TempDir()
	// What DNSCewl's Makefile actually produces.
	built := filepath.Join(dir, "DNScewl")
	if err := os.WriteFile(built, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findBuiltBinary(dir, "dnscewl")
	if err != nil {
		t.Fatalf("findBuiltBinary(%q) failed: %v\n"+
			"  `make` emits DNScewl; the tool is looked up as dnscewl. An exact-name match here\n"+
			"  reports 'no executable produced' for a build that in fact succeeded.", "dnscewl", err)
	}
	if got != built {
		t.Errorf("resolved %q, want %q", got, built)
	}
}

func TestFindBuiltBinaryRejectsNonExecutableMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not the artefact discriminator on Windows")
	}
	dir := t.TempDir()
	// A same-named NON-executable file: DNSCewl's tree carries sources and
	// objects beside the binary, so name alone is not evidence of an artefact.
	if err := os.WriteFile(filepath.Join(dir, "dnscewl"), []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := findBuiltBinary(dir, "dnscewl"); err == nil {
		t.Error("a non-executable file matched by name was accepted as the build artefact; " +
			"installing it would put an unrunnable file on PATH under a name the scanner invokes")
	}
}

func TestFindBuiltBinaryReportsWhenMakeProducedNothing(t *testing.T) {
	if _, err := findBuiltBinary(t.TempDir(), "dnscewl"); err == nil {
		t.Error("empty clone root reported success; a make that built nothing must not look installed")
	}
}

func TestCopyExecutableSetsExecBitAndReplaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec bit is not meaningful on Windows")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "DNScewl")
	if err := os.WriteFile(src, []byte("new build"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "bin", "dnscewl")
	// A previous, stale install must be replaced rather than appended to.
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("stale build from an older clone"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := copyExecutable(src, dst); err != nil {
		t.Fatalf("copyExecutable failed: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new build" {
		t.Errorf("destination holds %q, want the freshly built bytes", string(data))
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("installed file is not executable — exec.LookPath would find it and the run would fail at exec time")
	}
}
