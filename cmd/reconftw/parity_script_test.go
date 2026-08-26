// parity_script_test.go — phase 17 plan 03 (TC-D). The parity harness's own
// decision rules, asserted by `go test` on a machine with no tool tree.
//
// WHY THESE LIVE IN GO AT ALL. scripts/parity-full.sh is an OPERATOR-RUN harness:
// it drives two full recon engines against a live target over the network and can
// never run in CI. Its offline half (`--self-check`, `--attribution`) touches no
// network and no toolchain, and until this file existed nothing but a human
// typing the command ever executed it. A check reachable only by hand is the same
// class of false green the harness was built to detect, so the rules that decide
// what a parity report SAYS are driven from the suite that runs on every push.
//
// The two behaviours asserted here are the two that failed on 2026-08-24:
//
//  1. attribution_section() renders whenever a removed list is non-empty — not
//     only when a removed-ratio breaches --tolerance. Two reproducible
//     regressions (keycloak-openid-config, oidc-detect) sat inside a set the
//     harness called OK, and the section that exists to explain them never ran.
//
//  2. its SKIP block reads <workspace>/run.log — the path
//     cmd/reconftw/composite_subcommands.go actually writes
//     (filepath.Join(workdir, "run.log")). It used to read
//     <workspace>/logs/run.log, where only tools.jsonl lives, so on every run
//     ever made it reported "no SKIP lines found": a file-not-found dressed up
//     as an observation.
package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// parityScript returns the absolute path to scripts/parity-full.sh, failing the
// test if it has been moved or renamed. repoRoot is defined in
// release_gates_test.go (same package).
func parityScript(t *testing.T) string {
	t.Helper()
	p := filepath.Join(repoRoot(t), "scripts", "parity-full.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("scripts/parity-full.sh not found: %v", err)
	}
	return p
}

// runParity executes the harness with the given arguments and returns its
// combined output plus the error, so a caller can assert on a non-zero exit
// rather than aborting on it.
func runParity(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{parityScript(t)}, args...)...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// seedToolLog writes a minimal, well-formed logs/tools.jsonl so
// attribution_section proceeds past its "NO TOOL LOG PRESENT" early return. The
// SKIP block is downstream of that return, so without this the path assertions
// below would pass for the wrong reason.
func seedToolLog(t *testing.T, ws string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(ws, "logs"), 0o755); err != nil {
		t.Fatalf("mkdir %s/logs: %v", ws, err)
	}
	const rec = "{\"id\":\"1\",\"phase\":\"start\",\"tool\":\"nuclei\",\"argv\":[\"-duc\"]}\n" +
		"{\"id\":\"1\",\"phase\":\"end\",\"exit_code\":0,\"outcome\":\"success\"}\n"
	if err := os.WriteFile(filepath.Join(ws, "logs", "tools.jsonl"), []byte(rec), 0o600); err != nil {
		t.Fatalf("write tools.jsonl: %v", err)
	}
}

// TestParityAttributionReadsRealRunLogPath drives attribution_section directly
// through the harness's --attribution mode.
//
// The negative subtest is the one that pins the path. A block that read BOTH
// paths would satisfy the positive case while still being wrong, and reverting
// to the logs/ path would then only require moving the fixture.
func TestParityAttributionReadsRealRunLogPath(t *testing.T) {
	t.Run("a SKIP line at <ws>/run.log is read and its source named", func(t *testing.T) {
		ws := t.TempDir()
		seedToolLog(t, ws)
		const marker = "task=subdomains.brute reason=no-input"
		if err := os.WriteFile(filepath.Join(ws, "run.log"),
			[]byte("level=INFO msg=\"task skipped\" "+marker+"\n"), 0o600); err != nil {
			t.Fatalf("write run.log: %v", err)
		}

		out, err := runParity(t, "--attribution", ws)
		if err != nil {
			t.Fatalf("--attribution %s: %v\n%s", ws, err, out)
		}
		if !strings.Contains(out, marker) {
			t.Fatalf("the attribution did not carry the SKIP line written to %s/run.log.\n"+
				"  That is the defect this test exists for: the block read <ws>/logs/run.log, where\n"+
				"  run.log is never written, and answered \"no SKIP lines found\" on every run ever\n"+
				"  made.\n--- attribution ---\n%s", ws, out)
		}
		if !strings.Contains(out, filepath.Join(ws, "run.log")) {
			t.Errorf("the attribution does not NAME the path it read, so a reader cannot check the\n"+
				"  claim:\n%s", out)
		}
	})

	t.Run("a run.log under logs/ is NOT read", func(t *testing.T) {
		ws := t.TempDir()
		seedToolLog(t, ws)
		const decoy = "task=decoy.at.the.wrong.path"
		if err := os.WriteFile(filepath.Join(ws, "logs", "run.log"),
			[]byte("level=INFO msg=\"task skipped\" "+decoy+"\n"), 0o600); err != nil {
			t.Fatalf("write logs/run.log: %v", err)
		}

		out, err := runParity(t, "--attribution", ws)
		if err != nil {
			t.Fatalf("--attribution %s: %v\n%s", ws, err, out)
		}
		if strings.Contains(out, decoy) {
			t.Fatalf("the attribution read <ws>/logs/run.log. run.log is written to <ws>/run.log by\n"+
				"  composite_subcommands.go (filepath.Join(workdir, \"run.log\")); only tools.jsonl\n"+
				"  lives under logs/.\n--- attribution ---\n%s", out)
		}
		if !strings.Contains(out, "run.log is ABSENT") {
			t.Errorf("with no run.log at the real path the section must say the file is ABSENT — an\n"+
				"  absent file and a silent one are different facts:\n%s", out)
		}
	})

	t.Run("present-but-silent renders differently from absent", func(t *testing.T) {
		ws := t.TempDir()
		seedToolLog(t, ws)
		if err := os.WriteFile(filepath.Join(ws, "run.log"),
			[]byte("level=INFO msg=\"task complete\" task=subdomains.passive\n"), 0o600); err != nil {
			t.Fatalf("write run.log: %v", err)
		}
		out, err := runParity(t, "--attribution", ws)
		if err != nil {
			t.Fatalf("--attribution %s: %v\n%s", ws, err, out)
		}
		if !strings.Contains(out, "run.log is PRESENT") {
			t.Errorf("a run.log that was READ and held no SKIP lines is an OBSERVATION, and must not\n"+
				"  render as the absent case:\n%s", out)
		}

		bare := t.TempDir()
		seedToolLog(t, bare)
		out2, err := runParity(t, "--attribution", bare)
		if err != nil {
			t.Fatalf("--attribution %s: %v\n%s", bare, err, out2)
		}
		if !strings.Contains(out2, "run.log is ABSENT") {
			t.Errorf("an absent run.log must say so:\n%s", out2)
		}
		if strings.Contains(out2, "run.log is PRESENT") {
			t.Errorf("an absent run.log rendered as present:\n%s", out2)
		}
	})
}

// TestParityAttributionRendersOnNonEmptyRemovedList drives the harness's offline
// self-check, which builds a fixture whose three core sets are ALL within
// tolerance (machine verdict PASS) and whose subdomain removed list is non-empty,
// then emits a real report through emit_markdown and greps it for the attribution
// heading.
//
// It asserts on the NAMED self-check lines rather than on the exit code alone.
// A self-check that quietly lost the assertion would still exit 0, and "the
// suite is green because the check was deleted" is the failure mode this whole
// plan is about.
func TestParityAttributionRendersOnNonEmptyRemovedList(t *testing.T) {
	out, err := runParity(t, "--self-check")
	if err != nil {
		t.Fatalf("parity-full.sh --self-check exited non-zero: %v\n%s", err, out)
	}
	if !strings.Contains(out, "SELF-CHECK: PASS") {
		t.Fatalf("--self-check did not report PASS:\n%s", out)
	}

	for _, want := range []string{
		// The fixture must genuinely be a PASSING one. If it drifted into a
		// tolerance breach, the assertion below would also be satisfied by the
		// OLD `CORE_FAILS > 0` gate and would prove nothing.
		"ok   passing-set fixture really passes (CORE_FAILS=0, verdict PASS)",
		// The behaviour itself.
		"ok   attribution RENDERS on a passing set with a non-empty removed list",
		// Rendered from the run.log path that exists, closing both halves of the
		// defect in one report.
		"ok   the rendered attribution carries the SKIP line from <ws>/run.log",
		// And the report still reads PASS: this is attribution ON a pass, not a
		// downgrade of the verdict.
		"ok   the attributed report still reads Machine verdict PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--self-check no longer reports %q.\n"+
				"  Either the behaviour regressed or the assertion was removed; both leave the\n"+
				"  2026-08-24 failure (two reproducible regressions inside a PASSING set, with no\n"+
				"  attribution) able to recur undetected.\n--- self-check output ---\n%s", want, out)
		}
	}
}

// TestParityCoreSetDiffFlagsEmptyBaselineSide is phase 17's fourth TC-D guard:
// a core set whose v1 side is empty must not be reported OK.
//
// core_set_diff computed its removed-ratio inside `if [ "$v1total" -gt 0 ]` with
// no else branch, so a v1 side of zero fell through carrying verdict="OK" and
// left CORE_FAILS untouched. A baseline that was never read — a wrong
// --baseline-dir, a wrong extraction, an empty file — therefore produced
// `VERDICT: PASS` over a comparison the harness had not made. Nothing else in
// the run's output distinguishes that from a genuinely clean one.
//
// Driven through --self-check because that is where the fixtures live, and
// asserted on the NAMED lines: a self-check that quietly lost these assertions
// would still exit 0.
func TestParityCoreSetDiffFlagsEmptyBaselineSide(t *testing.T) {
	out, err := runParity(t, "--self-check")
	if err != nil {
		t.Fatalf("parity-full.sh --self-check exited non-zero: %v\n%s", err, out)
	}

	for _, want := range []string{
		// v1 empty, v2 non-empty: unambiguously a baseline that was not read.
		"ok   empty-v1 side counts into CORE_FAILS (=1)",
		"ok   empty v1 + non-empty v2 verdict is NO-BASELINE",
		// Both sides empty: the harness compared nothing, and must not say so in
		// the same word it uses for a verified match.
		"ok   empty-both counts into CORE_FAILS (=1)",
		"ok   both sides empty verdict is EMPTY-BOTH, not OK",
		// The whole-tree guard that composes with the per-set verdict.
		"baseline: an ABSENT or EMPTY baseline is refused ......... PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--self-check no longer reports %q.\n"+
				"  An empty v1 side reported OK is how a mis-pathed baseline prints VERDICT: PASS\n"+
				"  over a comparison that never happened.\n--- self-check output ---\n%s", want, out)
		}
	}

	// The OK and REVIEW paths must still work: a guard that turned every set
	// non-OK would satisfy every assertion above and destroy the harness.
	for _, want := range []string{
		"SELF-CHECK: PASS",
		"ok   passing-set fixture really passes (CORE_FAILS=0, verdict PASS)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--self-check no longer reports %q — the new non-OK verdicts appear to have\n"+
				"  swallowed the passing path:\n%s", want, out)
		}
	}
}
