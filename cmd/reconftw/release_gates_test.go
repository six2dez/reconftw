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
	"fmt"
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
			// The not-executed branch must survive a log that carries no REASON
			// line: `m612Fd` on CI run 33372377017 was exactly that shape. Until
			// 19-01 the reason extraction exited non-zero here and `set -e` killed
			// the script, so the "no reason recorded" fallback was dead code.
			name: "no toolchain, no reason line", rc: "1",
			census: strings.Replace(refLine, "mode=REFERENCE", "mode=NOT_EXECUTED", 1),
			want:   "SKIPPED",
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

// bigCensusLog builds a realtools log with the SHAPE observed on CI run
// 33372377017: a census block partway through the stream, a second copy of it in
// Go's end-of-run summary, and enough surrounding test output that the whole
// thing is far larger than a pipe buffer.
//
// The size is the point, not padding. The defect this test exists for was
// size-dependent: `argvector_census_verdict` tested the not-executed mode with
// `printf '%s\n' "$out" | grep -q ...`, and under `set -o pipefail` the early
// exiting `grep -q` closed the pipe, `printf` died of SIGPIPE, and the pipeline
// reported 141 — so the `if` took the FALSE path on a log where every census line
// matched. Gate 13 recorded FAIL through the nonref branch on a runner that
// simply has no tool tree. The 110042-byte log did this; a 1070-byte log of the
// same shape did not. A small fixture would therefore have passed against the
// broken script and proved nothing.
func bigCensusLog() string {
	var b strings.Builder

	censusBlock := func() {
		for _, p := range []struct {
			test    string
			present int
			total   int
		}{
			{"TestRealtoolsVulnsPhase6", 1, 19},
			{"TestRealtoolsOSINTPhase7", 0, 25},
			{"TestRealtoolsFixedArgVectors", 0, 5},
			{"TestRealToolArgVectors", 0, 39},
		} {
			tools := make([]string, 0, p.total)
			for i := 0; i < p.total; i++ {
				tools = append(tools, fmt.Sprintf("tool%02d", i))
			}
			list := strings.Join(tools, ",")
			fmt.Fprintf(&b, "    backend_realtools_test.go:392: REALTOOLS_CENSUS test=%s mode=NOT_EXECUTED "+
				"present=%d skipped=%d skipped_tools=%s absent=%d absent_tools=%s unresolvable=0 "+
				"unresolvable_tools=(none)\n", p.test, p.present, p.total, list, p.total, list)
			fmt.Fprintf(&b, "    backend_realtools_test.go:392: REALTOOLS_CENSUS_REASON test=%s only %d of %d "+
				"probed tools are on PATH (%d%%, floor 34%%) — this is a box without the toolchain, "+
				"not a box with findings\n", p.test, p.present, p.total, p.present*100/p.total)
		}
	}

	noise := func(n int, tag string) {
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "=== RUN   Test%s%d\n    %s_test.go:%d: TOOLS_JSONL tool=x task=y records=2 "+
				"argv=[-ua Mozilla/5.0 (X11; Linux x86_64) -c 100] %s\n", tag, i, tag, i, strings.Repeat("z", 48))
		}
	}

	noise(500, "Head")
	censusBlock() // mid-stream, exactly where the real run emits it
	noise(900, "Tail")
	censusBlock() // Go's end-of-run summary repeats it
	b.WriteString("realtools: all 4 real-tool + 1 coverage + 1 jsonl + 1 presence test(s) executed\n")
	b.WriteString("make[1]: *** [Makefile:173: realtools-args] Error 1\n")
	return b.String()
}

// TestReleaseGateArgVectorCensusVerdictIsSizeIndependent pins the property that
// was actually broken: the verdict must depend on the census lines and nothing
// else. The same census content, read from a large log and from a small one, must
// produce the same verdict. Before 19-01 it produced SKIPPED from the small log
// and FAIL from the large one.
func TestReleaseGateArgVectorCensusVerdictIsSizeIndependent(t *testing.T) {
	big := bigCensusLog()

	// Guard the fixture itself. If a later edit shrinks it below a pipe buffer,
	// or moves the census to the tail, it stops reproducing the defect and this
	// test would keep passing while covering nothing.
	const pipeBuf = 64 << 10
	if len(big) <= pipeBuf {
		t.Fatalf("fixture is %d bytes, which is not larger than a %d-byte pipe buffer — it cannot "+
			"reproduce the SIGPIPE the verdict used to trip on", len(big), pipeBuf)
	}
	first := strings.Index(big, "REALTOOLS_CENSUS test=")
	if first < 0 || first > len(big)-pipeBuf {
		t.Fatalf("first census line is at byte %d of %d; it must sit far enough from the end that a "+
			"reader stopping there leaves the writer with bytes still to write", first, len(big))
	}

	// The small log is the SAME census content with the surrounding test output
	// removed — the `m612Fd` shape from the same CI run.
	var small strings.Builder
	for _, line := range strings.Split(big, "\n") {
		if strings.Contains(line, "REALTOOLS_CENSUS") {
			small.WriteString(line + "\n")
		}
	}

	// rc=1 on purpose: `make realtools-args` exits 1 on a box with no tool tree,
	// and the not-executed branch must still win over the exit-code branch.
	gotBig := runCensusVerdict(t, "1", big)
	gotSmall := runCensusVerdict(t, "1", small.String())

	for _, tc := range []struct{ name, got string }{{"large log", gotBig}, {"small log", gotSmall}} {
		if !strings.HasPrefix(tc.got, "SKIPPED ") {
			t.Errorf("%s: verdict = %q, want a SKIPPED verdict — every census line reports the "+
				"not-executed mode, which is a box with no tool tree, not a partial run", tc.name, tc.got)
		}
	}
	if gotBig != gotSmall {
		t.Errorf("verdict depends on log SIZE, not on the census:\n  large: %s\n  small: %s", gotBig, gotSmall)
	}
}

// --- Phase 17 (TC-D): the gate rule itself ------------------------------------
//
// Two defects in scripts/release-gates.sh, both of the class the script was
// written to detect:
//
//   1. gate() counted `--- PASS` lines and failed only at zero, so a gate citing
//      nine tests passed with eight of them deleted. Counting answers "did
//      anything run"; only a by-name assertion answers "did the cited things
//      run".
//   2. `trap 'rm -rf "$LOGDIR"' EXIT` deleted the directory every FAIL note
//      names as `full log: $LOGDIR/...`, so a failing run destroyed the one
//      artefact it existed to produce.
//
// Both are asserted here rather than by reading the script, because this repo's
// standing precedent (phase 15, finding F19) is that two independent code reads
// certified a fix that was inert in production.

// runGateVerdict feeds a synthetic `go test -v` log to the by-name rule through
// the script's --gate-verdict seam and returns its single verdict line.
func runGateVerdict(t *testing.T, pattern, rc, log string) string {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "release-gates.sh")
	cmd := exec.Command("bash", script, "--gate-verdict", pattern, rc)
	cmd.Stdin = strings.NewReader(log)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--gate-verdict failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestReleaseGatePatternRequiresEveryCitedTest(t *testing.T) {
	const threeCited = "TestAlpha|TestBeta|TestGamma"
	allThree := "=== RUN   TestAlpha\n--- PASS: TestAlpha (0.01s)\n" +
		"--- PASS: TestBeta (0.01s)\n--- PASS: TestGamma (0.01s)\nPASS\n"

	tests := []struct {
		name    string
		pattern string
		rc      string
		log     string
		want    string
		// mustName, when set, has to appear in the verdict note: an operator
		// needs to know WHICH cited test vanished, not that a count was short.
		mustName []string
	}{
		{
			name: "every cited test passed", pattern: threeCited, rc: "0",
			log: allThree, want: "PASS",
		},
		{
			// THE DEFECT. Under the old count-based rule this passed: one
			// `--- PASS` line was enough for a gate citing three tests.
			name: "only one of three cited tests passed", pattern: threeCited, rc: "0",
			log:  "--- PASS: TestAlpha (0.01s)\nPASS\n",
			want: "FAIL", mustName: []string{"TestBeta", "TestGamma"},
		},
		{
			// The original countermeasure must survive the change.
			name: "no tests ran at all", pattern: threeCited, rc: "0",
			log: "testing: warning: no tests to run\nPASS\n", want: "FAIL",
		},
		{
			name: "a cited test failed", pattern: threeCited, rc: "1",
			log:  strings.Replace(allThree, "--- PASS: TestGamma", "--- FAIL: TestGamma", 1),
			want: "FAIL", mustName: []string{"TestGamma"},
		},
		{
			// Real pattern from gate 5. An exact citation must not be satisfied
			// by a LONGER test name that merely starts with it — the two are
			// separately cited and a prefix match would conflate them.
			name:    "an anchored citation is not satisfied by a longer name",
			pattern: "TestStreamContract$|TestStreamContractRatchetIsClosed", rc: "0",
			log:  "--- PASS: TestStreamContractRatchetIsClosed (0.01s)\n",
			want: "FAIL", mustName: []string{"TestStreamContract"},
		},
		{
			// Also real: gate 5 cites `ExitSevenErrors`, a suffix shared by six
			// per-module tests. A substring citation is legitimate and must keep
			// working — and must be declared as such in the note.
			name:    "a substring citation is satisfied and declared",
			pattern: "TestStreamContract$|ExitSevenErrors", rc: "0",
			log:  "--- PASS: TestStreamContract (0.01s)\n--- PASS: TestWebExitSevenErrors (0.01s)\n",
			want: "PASS", mustName: []string{"substring citation"},
		},
		{
			name:    "an unsatisfied substring citation fails",
			pattern: "TestStreamContract$|ExitSevenErrors", rc: "0",
			log:  "--- PASS: TestStreamContract (0.01s)\n",
			want: "FAIL", mustName: []string{"ExitSevenErrors"},
		},
		{
			// THE HARNESS ASSERTS ON ITSELF. A pattern that parses to zero cited
			// names would make the by-name check vacuously true and report PASS
			// having asserted nothing — the same shape as the extraction bug
			// that produced 0-byte command files during this phase's planning
			// and reported PASS having run nothing.
			name: "a pattern citing no names is not a pass", pattern: "|", rc: "0",
			log:  "--- PASS: TestAnything (0.01s)\n",
			want: "FAIL", mustName: []string{"ZERO cited test names"},
		},
		{
			// Subtests are not a substitute for their parent: if the parent
			// failed, Go prints no top-level PASS for it.
			name:    "a passing subtest does not satisfy its parent's citation",
			pattern: "TestAlpha", rc: "1",
			log:  "    --- PASS: TestAlpha/sub (0.00s)\n--- FAIL: TestAlpha (0.01s)\n",
			want: "FAIL", mustName: []string{"TestAlpha"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := runGateVerdict(t, tc.pattern, tc.rc, tc.log)
			status := got
			if i := strings.Index(got, " "); i > 0 {
				status = got[:i]
			}
			if status != tc.want {
				t.Fatalf("verdict = %s, want %s\n  full: %s", status, tc.want, got)
			}
			for _, want := range tc.mustName {
				if !strings.Contains(got, want) {
					t.Errorf("the verdict does not mention %q — an operator cannot act on it:\n  %s",
						want, got)
				}
			}
		})
	}
}

// writeStubGo installs a fake `go` on a private PATH so the release-gates script
// can be driven end to end in milliseconds, without running the real suite.
//
// failing=true makes every invocation exit 1, which is how the retention branch
// is reached. failing=false makes it echo a `--- PASS` line for every test the
// -run pattern cites (and a well-formed realtools census for `make
// realtools-args`), which is how the removal branch is reached.
func writeStubGo(t *testing.T, failing bool) string {
	t.Helper()
	dir := t.TempDir()
	body := "#!/bin/sh\n"
	if failing {
		body += "echo 'stub go: build failed' >&2\nexit 1\n"
	} else {
		body += `case " $* " in
  *" -tags realtools "*)
    for t in TestRealToolArgVectors TestRealtoolsVulnsPhase6 TestRealtoolsOSINTPhase7; do
      echo "=== RUN   $t"
      echo "REALTOOLS_CENSUS test=$t mode=REFERENCE present=37 skipped=0 skipped_tools=(none)"
      echo "--- PASS: $t (0.00s)"
    done
    echo PASS
    exit 0
    ;;
esac
pattern=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-run" ]; then pattern="$a"; fi
  prev="$a"
done
if [ -n "$pattern" ]; then
  echo "$pattern" | tr '|' '\n' | sed 's/^\^//; s/\$$//' | while read -r n; do
    [ -n "$n" ] || continue
    echo "=== RUN   $n"
    echo "--- PASS: $n (0.00s)"
  done
fi
echo PASS
exit 0
`
	}
	p := filepath.Join(dir, "go")
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatalf("write stub go: %v", err)
	}
	return dir
}

// logDirFrom pulls the printed LOGDIR path out of the script's output.
func logDirFrom(t *testing.T, out, marker string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			return strings.TrimSpace(line[i+len(marker):])
		}
	}
	t.Fatalf("release-gates.sh never printed %q, so a reader is left guessing where its logs\n"+
		"  are:\n%s", marker, out)
	return ""
}

// TestReleaseGateKeepsLogDirOnFailure drives the REAL script to a real failure
// and asserts the log directory its FAIL note cites still exists afterwards.
//
// It is not a source read. `trap 'rm -rf "$LOGDIR"' EXIT` ran on every path, so
// the failure output referenced files that were already gone by the time anyone
// opened the summary — the exact defect a source read would have called fixed
// while it kept happening.
func TestReleaseGateKeepsLogDirOnFailure(t *testing.T) {
	script := filepath.Join(repoRoot(t), "scripts", "release-gates.sh")

	t.Run("a failing run RETAINS the logs its FAIL note cites", func(t *testing.T) {
		cmd := exec.Command("bash", script, "--gates-only", "--fail-fast")
		cmd.Dir = repoRoot(t)
		cmd.Env = append(os.Environ(), "PATH="+writeStubGo(t, true)+":"+minimalPATH)
		raw, err := cmd.CombinedOutput()
		out := string(raw)
		if err == nil {
			t.Fatalf("the script exited 0 with a stub `go` that always fails — the harness itself is\n"+
				"  broken, so nothing below would prove anything:\n%s", out)
		}

		dir := logDirFrom(t, out, "logs RETAINED (a step FAILED):")
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		fi, statErr := os.Stat(dir)
		if statErr != nil || !fi.IsDir() {
			t.Fatalf("the log directory %s does NOT exist after a failing run. Every FAIL note in the\n"+
				"  summary above ends with `full log: %s/<step>.log`, so the script's own failure\n"+
				"  output points at files it deleted on the way out:\n%s", dir, dir, out)
		}

		// And it must hold the log the note names, not merely exist.
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatalf("ReadDir(%s): %v", dir, readErr)
		}
		var logs int
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".log") {
				logs++
			}
		}
		if logs == 0 {
			t.Errorf("the retained directory %s holds no .log file — it is a name, not evidence:\n%s",
				dir, out)
		}
		if !strings.Contains(out, "full log: "+dir) {
			t.Errorf("no FAIL note cites a path under the retained directory %s, so retention and the\n"+
				"  notes have drifted apart:\n%s", dir, out)
		}
	})

	t.Run("a fully passing run REMOVES the logs and says so", func(t *testing.T) {
		cmd := exec.Command("bash", script, "--gates-only")
		cmd.Dir = repoRoot(t)
		cmd.Env = append(os.Environ(), "PATH="+writeStubGo(t, false)+":"+minimalPATH)
		raw, err := cmd.CombinedOutput()
		out := string(raw)
		if err != nil {
			t.Skipf("the all-pass stub harness did not reach a clean run in this environment "+
				"(%v); the retention branch above is the mutation-backed assertion:\n%s", err, out)
		}
		dir := logDirFrom(t, out, "logs removed (every step passed):")
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Errorf("a fully passing run left %s behind; one temp directory per run is a real cost "+
				"and the removal branch is what pays it", dir)
		}
	})
}
