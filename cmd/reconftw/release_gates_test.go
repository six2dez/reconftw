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
			// A resolving mode refuses to start without a resolver list; seed one
			// rather than letting the binary download it (see hermeticResolverEnv).
			cmd.Env = hermeticResolverEnv(t, "PATH="+minimalPATH)
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

// --- Gate 13: the arg-vector census parser ------------------------------------
//
// The gate itself needs the 70-tool runtime and can never run in CI. Its RULE,
// though — "a partial run is not a pass" — is pure parsing, and that is where
// the rule actually lives. So the parser is exposed as
// `release-gates.sh --census-verdict <rc>` and tested here, in the suite that
// does run on every push.
//
// Without these, "the gate reports PASS only when the skipped set is exactly the
// known-absent list" would be a claim backed by nothing a CI run ever executes.

// repoRoot walks up from the test's working directory to the module root, so the
// tests can reach scripts/ no matter where `go test` is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// runCensusVerdict feeds synthetic census text to the parser and returns its
// single verdict line.
func runCensusVerdict(t *testing.T, rc string, census string) string {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "release-gates.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("release-gates.sh not found: %v", err)
	}
	cmd := exec.Command("bash", script, "--census-verdict", rc)
	cmd.Stdin = strings.NewReader(census)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--census-verdict failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestReleaseGateArgVectorStepExists(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "release-gates.sh"))
	if err != nil {
		t.Fatalf("read release-gates.sh: %v", err)
	}
	src := string(data)
	for _, want := range []string{
		"gate_argvector",           // the gate function
		"argvector_census_verdict", // the parser it decides with
		"REALTOOLS_REFERENCE=1",    // it must run in the mode where the ratchet is enforced
		"--census-verdict",         // the seam this test uses
	} {
		if !strings.Contains(src, want) {
			t.Errorf("release-gates.sh no longer contains %q — the arg-vector gate was removed or "+
				"renamed, and a gate that is silently omitted is exactly what phase 16 exists to stop", want)
		}
	}
}

func TestReleaseGateArgVectorCensusVerdict(t *testing.T) {
	const refLine = "REALTOOLS_CENSUS test=TestRealToolArgVectors mode=REFERENCE present=37 skipped=9 " +
		"skipped_tools=arjun,dnscewl,p1radup,regulator,subwiz,subzy,urless,wafw00f,waymore\n"

	tests := []struct {
		name   string
		rc     string
		census string
		want   string
	}{
		{
			// The skipped set was verified against the known-absent list by the
			// Go-side ratchet, which is what REFERENCE mode means.
			name: "reference mode, clean exit, matching skip set", rc: "0",
			census: refLine, want: "PASS",
		},
		{
			// THE RULE. A partial run reports CENSUS_ONLY because the ratchet was
			// not enforced, and an unenforced ratchet cannot tell a correct
			// known-absent list from a stale one.
			name: "partial run is NOT a pass", rc: "0",
			census: strings.Replace(refLine, "mode=REFERENCE", "mode=CENSUS_ONLY", 1), want: "FAIL",
		},
		{
			name: "a probe failed", rc: "1",
			census: refLine, want: "FAIL",
		},
		{
			// No tool tree: SKIPPED, never PASS, and never a wall of failures.
			name: "no toolchain", rc: "1",
			census: strings.Replace(refLine, "mode=REFERENCE", "mode=NOT_EXECUTED", 1) +
				"REALTOOLS_CENSUS_REASON test=X only 1 of 25 probed tools are on PATH\n",
			want: "SKIPPED",
		},
		{
			// A run that emitted no census says nothing about its own coverage.
			name: "no census emitted", rc: "0",
			census: "some unrelated go test output\n", want: "FAIL",
		},
		{
			// One test in REFERENCE and one not is still a partial run.
			name: "mixed modes", rc: "0",
			census: refLine + strings.Replace(refLine, "mode=REFERENCE", "mode=CENSUS_ONLY", 1), want: "FAIL",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := runCensusVerdict(t, tc.rc, tc.census)
			status := got
			if i := strings.Index(got, " "); i > 0 {
				status = got[:i]
			}
			if status != tc.want {
				t.Errorf("verdict = %q, want status %s\n  full: %s", status, tc.want, got)
			}
		})
	}
}
