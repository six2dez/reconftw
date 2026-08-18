// e2e_binary_test.go — end-to-end at the PROCESS boundary.
//
// The other TestE2E* tests exercise packages. This one builds the real binary
// and runs it, which is the only level that catches wiring defects invisible to
// package tests: flags parsed before cobra dispatches, side effects that happen
// during startup rather than inside a handler, and exit codes.
//
// It is hermetic — no network, no external tools, no scan. Every case is either
// a dry run or a local inspection subcommand.
package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildBinary compiles the CLI once for the whole file.
func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary E2E (-short)")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "reconftw")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// assertNoEntries fails the test unless dir contains exactly zero entries,
// naming everything it found. Acceptance gate 1 is "the filesystem is unchanged",
// so the assertion is on ABSENCE, never on emptiness: an earlier version of this
// test tolerated a created-but-empty `wanted` directory and therefore passed
// against the very defect it was written for.
func assertNoEntries(t *testing.T, dir, label string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	if len(entries) == 0 {
		return
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	t.Errorf("%s created %d entr(ies) in a pristine working directory: %v — "+
		"a dry run must leave the filesystem byte-for-byte unchanged",
		label, len(entries), names)
}

// TestE2EBinaryDryRunHasNoSideEffects enforces acceptance gate 1 at the process
// boundary: `--dry-run` creates NOTHING.
//
// Two defects met here. The startup boot ran before cobra had parsed -o and knew
// nothing about --dry-run, so `recon --target X --dry-run -o ./wanted` created
// ./workspaces/X under the configured root; and every RunXxxAsync booted before
// checking opts.DryRun, so ./wanted/X plus its checkpoints.db appeared too.
//
// Tolerating any created entry is exactly the regression this test exists to
// prevent — assert on absence, and assert stdout still carries the plan so the
// test cannot be satisfied by a binary that simply does nothing.
func TestE2EBinaryDryRunHasNoSideEffects(t *testing.T) {
	bin := buildBinary(t)
	work := t.TempDir()
	wanted := filepath.Join(work, "wanted")

	cmd := exec.Command(bin, "recon", "--target", "example.com", "--dry-run",
		"-o", wanted)
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run should succeed: %v\n%s", err, out)
	}

	// The feature must still work — a dry run that prints nothing is not a fix.
	s := string(out)
	if strings.TrimSpace(s) == "" {
		t.Error("dry-run produced no output at all — the plan preview was removed, not fixed")
	}
	if !strings.Contains(s, "subdomains.") {
		t.Errorf("dry-run output does not name any task (expected a 'subdomains.*' entry):\n%s", s)
	}

	if _, statErr := os.Stat(filepath.Join(work, "workspaces")); statErr == nil {
		t.Error("dry-run created ./workspaces/ — something is still booting a workspace")
	}
	if _, statErr := os.Stat(wanted); statErr == nil {
		t.Errorf("dry-run created the -o root %s", wanted)
	}
	// Explicit absence checks for the two artefacts a partial regression would
	// leave behind even if the tree above were suppressed.
	matches, _ := filepath.Glob(filepath.Join(wanted, "*", "checkpoints.db"))
	if len(matches) > 0 {
		t.Errorf("dry-run created a checkpoint store: %v", matches)
	}
	matches, _ = filepath.Glob(filepath.Join(wanted, "*", "inputs"))
	if len(matches) > 0 {
		t.Errorf("dry-run created workspace subdirectories: %v", matches)
	}

	assertNoEntries(t, work, "dry-run with -o")
}

// TestE2EBinaryDryRunWithoutOutputFlagCreatesNothing covers the default-root
// path: with no -o, an unfixed build falls back to ./workspaces relative to the
// process working directory, which is the operator's cwd.
func TestE2EBinaryDryRunWithoutOutputFlagCreatesNothing(t *testing.T) {
	bin := buildBinary(t)
	work := t.TempDir()

	cmd := exec.Command(bin, "recon", "--target", "example.com", "--dry-run")
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run should succeed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(work, "workspaces")); statErr == nil {
		t.Error("dry-run created ./workspaces/ in the working directory")
	}
	assertNoEntries(t, work, "dry-run without -o")
}

// TestE2EBinaryNoTargetCommandsCreateNoWorkspace covers F18's second cost: a
// command that needs no workspace must not get one. `version` and `health-check`
// take no --target, and the pre-cobra boot is gone, so neither may write.
//
// health-check legitimately exits non-zero on a clean PATH (dnsx/httpx/subfinder
// are CRITICAL tools), so this asserts on the filesystem only — never the exit
// code. See TestE2EBinaryHealthCheckIsSelfConsistent for the exit-code contract.
func TestE2EBinaryNoTargetCommandsCreateNoWorkspace(t *testing.T) {
	bin := buildBinary(t)

	for _, args := range [][]string{
		{"version"},
		{"health-check"},
		{"--target", "example.com", "version"},
	} {
		label := strings.Join(args, " ")
		t.Run(label, func(t *testing.T) {
			work := t.TempDir()
			cmd := exec.Command(bin, args...)
			cmd.Dir = work
			_, _ = cmd.CombinedOutput() // exit code intentionally ignored
			assertNoEntries(t, work, label)
		})
	}
}

// TestE2EBinaryHealthCheckIsSelfConsistent covers `install --health-check`,
// which exited 1 with "[FAIL] config.parse" because it passed a nil config,
// while printing "0 critical health checks failed".
//
// It deliberately does NOT require exit 0. dnsx, httpx and subfinder are
// CRITICAL tools, so a correct health-check exits 1 on any machine that has
// not installed them — including every clean CI runner. An earlier version of
// this test asserted exit 0 and so encoded "the runner happens to have my
// toolchain" as a contract; it passed locally and would have failed on CI.
//
// What is actually invariant is self-consistency: config.parse must succeed
// (that was the bug), and the exit code must agree with the summary.
func TestE2EBinaryHealthCheckIsSelfConsistent(t *testing.T) {
	bin := buildBinary(t)

	for _, args := range [][]string{
		{"health-check"},
		{"install", "--health-check"},
	} {
		out, err := exec.Command(bin, args...).CombinedOutput()
		label := strings.Join(args, " ")
		s := string(out)

		// The config must parse regardless of which tools are installed.
		if strings.Contains(s, "[FAIL ] config.parse") {
			t.Errorf("%s reports config.parse FAIL despite a loadable config:\n%s", label, s)
		}
		if err == nil {
			continue // fully healthy machine — nothing left to check
		}
		// Non-zero exit is legitimate (missing critical tools), but it must say
		// WHAT failed and must not simultaneously claim nothing did.
		if strings.Contains(s, "0 critical health check") {
			t.Errorf("%s exited non-zero while claiming zero critical failures:\n%s", label, s)
		}
		if !strings.Contains(s, "critical health check(s) failed:") {
			t.Errorf("%s exited non-zero without naming the failed checks:\n%s", label, s)
		}
	}
}

// TestE2EBinaryVersionAndConfig exercises the read-only inspection surface an
// operator reaches for first when something is wrong.
func TestE2EBinaryVersionAndConfig(t *testing.T) {
	bin := buildBinary(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"version subcommand", []string{"version"}, "reconftw"},
		{"version flag", []string{"--version"}, "reconftw"},
		{"config sources", []string{"config", "sources"}, "config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(bin, tc.args...).CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %v\n%s", tc.args, err, out)
			}
			if !strings.Contains(strings.ToLower(string(out)), tc.want) {
				t.Errorf("%v output missing %q:\n%s", tc.args, tc.want, out)
			}
		})
	}
}

// TestE2EBinaryRejectsBadInput checks user mistakes produce a readable error
// and a non-zero exit, not a JSON log record.
func TestE2EBinaryRejectsBadInput(t *testing.T) {
	bin := buildBinary(t)

	out, err := exec.Command(bin, "recon", "--targt", "example.com").CombinedOutput()
	if err == nil {
		t.Fatal("an unknown flag must exit non-zero")
	}
	s := string(out)
	if !strings.Contains(s, "Error:") {
		t.Errorf("expected a plain 'Error:' line, got:\n%s", s)
	}
	if strings.Contains(s, `"level":"ERROR"`) {
		t.Errorf("a user mistake was rendered as a JSON log record:\n%s", s)
	}
}
