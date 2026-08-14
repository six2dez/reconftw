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

// TestE2EBinaryDryRunHasNoSideEffects is the regression for the pre-cobra boot.
//
// `recon --target X --dry-run -o ./wanted` used to create BOTH ./wanted/X and
// ./workspaces/X — the second under the configured root, because the startup
// boot ran before cobra had parsed -o and knew nothing about --dry-run. A dry
// run that writes to a directory the operator never named is the kind of thing
// only a process-level test sees.
func TestE2EBinaryDryRunHasNoSideEffects(t *testing.T) {
	bin := buildBinary(t)
	work := t.TempDir()

	cmd := exec.Command(bin, "recon", "--target", "example.com", "--dry-run",
		"-o", filepath.Join(work, "wanted"))
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run should succeed: %v\n%s", err, out)
	}

	if _, statErr := os.Stat(filepath.Join(work, "workspaces")); statErr == nil {
		t.Error("dry-run created ./workspaces/ — the startup boot is ignoring -o/--output")
	}
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		if e.Name() != "wanted" {
			t.Errorf("dry-run created unexpected entry %q in the working directory", e.Name())
		}
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
