// release_gates_test.go — phase 15 plan 17. The cross-cutting acceptance-gate
// checks that no single package owns.
//
// Phase 15's CONTEXT.md defines twelve acceptance gates as the definition of
// done for the Phase 14 cutover. Eleven of them are owned by a Go test in the
// package that implements the behaviour, and gate 11 is owned by a CI workflow
// step (.github/workflows/docker_nightly.yml). This file adds only what is
// genuinely UNCOVERED after those seventeen plans:
//
//   - Gate 2 at the PROCESS boundary. internal/core/output owns it at the unit
//     level (TestCanonicalTargetIDDistinctPrefixes /
//     TestWorkspaceInitDistinctPrefixes). Those prove the identity function and
//     the workspace initialiser are injective. They cannot prove the assembled
//     BINARY reaches them: a CLI that stripped the prefix while parsing
//     --target, or a cobra flag that swallowed the `/`, would leave both unit
//     tests green and still collapse three engagements into one workspace.
//
//   - Gate 12 at the PROCESS boundary, including the clean-PATH health-check.
//     "A clean checkout builds and runs the full suite" is only half about
//     compiling. The half `go test ./...` cannot see is what the binary does on
//     a machine that does not have the developer's populated PATH, which is
//     every user's machine on day one.
//
// Everything else is cited, not duplicated — see the gate table in
// .planning/phases/15-release-gates-run-isolation-store-integrity/15-17-SUMMARY.md
// and the named `go test -run` invocations in scripts/release-gates.sh.
package main_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalPATH is a PATH that contains no recon tooling. It is deliberately NOT
// empty: `go test` and the binary itself still need a shell and the standard
// utilities, and an empty PATH would test "the binary cannot exec anything"
// rather than "the binary has no recon tools".
const minimalPATH = "/usr/bin:/bin:/usr/sbin:/sbin"

// TestReleaseGate2DistinctWorkspacesThroughTheBinary is acceptance gate 2 —
// "`/24`, `/16` and a bare IP get different workspaces" — asserted through the
// real binary rather than through output.CanonicalTargetID.
//
// The run is NOT a dry run. A dry run creates nothing (that is gate 1), so it
// cannot demonstrate that three workspaces exist. It is made hermetic by
// reducing PATH instead: every external tool then fails to resolve, every task
// is skipped or best-effort, and the run completes in about a second having
// touched no network — while still performing the real WorkspaceInit the gate
// is about.
//
// The assertion is a SET-SIZE check on the directories the binary created, not
// three individual name comparisons. A name comparison passes if two of the
// three happen to match the expected slug while the third collides with one of
// them; only a set-size check fails on any collapse.
func TestReleaseGate2DistinctWorkspacesThroughTheBinary(t *testing.T) {
	bin := buildBinary(t)

	work := t.TempDir()
	dataDir := filepath.Join(work, "data")

	// The three targets audit finding F2 showed collapsing onto one workspace:
	// sanitizeTargetName split on the first '/', so all three became
	// "cidrs/10.0.0.0".
	targets := []string{"10.0.0.0/24", "10.0.0.0/16", "10.0.0.0"}

	for _, target := range targets {
		// Bounded: if run isolation regressed into a real scan, the deadline
		// turns a hung CI job into a named failure.
		//
		// cancel() runs on the DEFER, after ctx.Err() has been read. Calling it
		// before the check makes ctx.Err() non-nil unconditionally, which turns
		// the deadline guard into an assertion that always fires — the exact
		// shape of check that looks like a guard and is not one.
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, bin, "subs", "--target", target, "-o", dataDir)
			cmd.Dir = work
			cmd.Env = append(os.Environ(), "PATH="+minimalPATH)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("subs --target %s did not finish within the deadline — with no tools on "+
					"PATH it must skip every task and return:\n%s", target, out)
			}
			if err != nil {
				t.Fatalf("subs --target %s: %v\n%s", target, err, out)
			}
		}()
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dataDir, err)
	}
	dirs := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			dirs[e.Name()] = true
		}
	}
	if len(dirs) != len(targets) {
		names := make([]string, 0, len(dirs))
		for d := range dirs {
			names = append(names, d)
		}
		t.Fatalf("acceptance gate 2 FAILED: %d target(s) %v produced %d workspace director(ies) %v.\n"+
			"  Two engagements sharing a workspace share artefacts, checkpoints.db and staging — "+
			"one\n  overwrites the other's results with no warning (audit finding F2).",
			len(targets), targets, len(dirs), names)
	}

	// And each workspace must be a real one, not an empty stub: a run that
	// created three differently-named but unusable directories would pass a
	// bare count.
	for d := range dirs {
		art := filepath.Join(dataDir, d, "artefacts")
		if fi, statErr := os.Stat(art); statErr != nil || !fi.IsDir() {
			t.Errorf("workspace %s has no artefacts/ directory — it is a name, not a workspace", d)
		}
	}
}

// TestReleaseGate12CleanTreeBuildsAndRuns is acceptance gate 12 — "a clean
// checkout builds and runs the full suite" — at the level the words describe.
//
// buildBinary(t) compiles ./cmd/reconftw from the tree under test, which is the
// "builds" half. The "runs" half is the three invocations below.
//
// health-check is asserted on its OUTPUT, never on its exit code. It exits 1 BY
// DESIGN when critical tools are absent, which is the correct behaviour and the
// normal state of a fresh checkout. Treating exit 1 as failure would make this
// gate permanently red on any machine without 103 recon tools installed;
// treating exit 0-or-1 as success without reading the output would make it
// permanently green even if the subcommand had been reduced to a no-op. So the
// assertion is: it names at least one missing tool, and it does not panic.
func TestReleaseGate12CleanTreeBuildsAndRuns(t *testing.T) {
	bin := buildBinary(t)

	t.Run("version exits 0", func(t *testing.T) {
		out, err := exec.Command(bin, "version").CombinedOutput()
		if err != nil {
			t.Fatalf("version: %v\n%s", err, out)
		}
		if !strings.Contains(strings.ToLower(string(out)), "reconftw") {
			t.Errorf("version output does not name the program:\n%s", out)
		}
	})

	t.Run("help exits 0", func(t *testing.T) {
		out, err := exec.Command(bin, "--help").CombinedOutput()
		if err != nil {
			t.Fatalf("--help: %v\n%s", err, out)
		}
		for _, want := range []string{"subs", "health-check"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("--help does not list %q:\n%s", want, out)
			}
		}
	})

	t.Run("health-check on a clean PATH reports missing tools", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		cmd := exec.CommandContext(ctx, bin, "health-check")
		cmd.Dir = t.TempDir()
		cmd.Env = append(os.Environ(), "PATH="+minimalPATH)
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("health-check did not finish within the deadline:\n%s", out)
		}
		s := string(out)

		// err is deliberately NOT asserted. Exit 1 is the DESIGNED outcome when
		// critical tools are missing, which is exactly the state this subtest
		// constructs. It is referenced so a reader cannot mistake the omission
		// for an oversight.
		_ = err

		if !strings.Contains(s, "missing") {
			t.Errorf("health-check on a clean PATH does not report anything as missing. Either the "+
				"tool probe\n  stopped running, or the reduced PATH did not take effect — both make "+
				"the check useless\n  to a user setting the project up for the first time:\n%s", s)
		}
		// Naming the tools is the actionable part; "102 missing" alone tells an
		// operator nothing about what to install.
		if !strings.Contains(s, "subfinder") && !strings.Contains(s, "httpx") {
			t.Errorf("health-check does not NAME a missing tool — an operator cannot act on the "+
				"result:\n%s", s)
		}
		if strings.Contains(s, "panic:") || strings.Contains(s, "goroutine 1 [running]") {
			t.Fatalf("health-check PANICKED on a machine with no tools installed — that is the "+
				"first thing\n  every new user runs:\n%s", s)
		}
	})
}
