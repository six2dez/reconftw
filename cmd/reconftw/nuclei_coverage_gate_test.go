// nuclei_coverage_gate_test.go — plan 17-05 Task 4, requirement TC-A.
//
// The nuclei coverage gate's DECISION RULE, asserted in CI on a runner with no
// tool tree and no workspace.
//
// Same seam as --census-verdict and --gate-verdict: judging a real workspace
// needs a real 23-minute nuclei run, but the rule that decides it is pure
// parsing, and a rule nothing exercises is how release-gates.sh acquired four
// separate false greens in the first place. Every case below is a workspace
// built in a temp dir and fed to `release-gates.sh --nuclei-coverage-verdict`.
package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// basis is the proxy declaration a real record carries. Cases that omit it are
// asserting the gate's refusal to accept an undeclared coverage number.
const basis = `"execution_basis":"requests_sent is a PROXY for template execution, not a count of it"`

// covRecord builds one coverage JSONL line.
func covRecord(group string, selected, loaded, sent, planned, dropped string, early bool) string {
	e := "false"
	if early {
		e = "true"
	}
	return `{"schema":"nuclei-coverage/v1",` + basis + `,"tool":"nuclei","group":"` + group +
		`","filter_selected":` + selected + `,"templates_loaded":` + loaded +
		`,"hosts_submitted":12,"requests_planned":` + planned + `,"requests_sent":` + sent +
		`,"hosts_dropped":` + dropped + `,"hosts_dropped_detail":[],"matched":49,"findings_parsed":49` +
		`,"terminated_early":` + e + `,"argv":["-l","hosts.txt","-stats","-sj"]}`
}

// nucleiCoverageVerdict runs the gate's rule against a workspace and returns its
// single verdict line.
func nucleiCoverageVerdict(t *testing.T, ws string) string {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "release-gates.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("release-gates.sh not found: %v", err)
	}
	out, err := exec.Command("bash", script, "--nuclei-coverage-verdict", ws).CombinedOutput()
	if err != nil {
		t.Fatalf("--nuclei-coverage-verdict exited non-zero: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if got == "" {
		t.Fatalf("--nuclei-coverage-verdict printed NOTHING for %s.\n"+
			"  A checker that says nothing is indistinguishable from one that passed, and this\n"+
			"  exact shape (an absent field aborting the rule under `set -e`) was a real bug in\n"+
			"  this gate before the absent-field case was actually RUN rather than reasoned about.", ws)
	}
	return got
}

// writeWS materialises a workspace. A nil/absent entry means the file is not created.
func writeWS(t *testing.T, coverage, toolLog string) string {
	t.Helper()
	ws := t.TempDir()
	logs := filepath.Join(ws, "logs")
	if err := os.MkdirAll(logs, 0o750); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if coverage != "" {
		if err := os.WriteFile(filepath.Join(logs, "nuclei-coverage.jsonl"), []byte(coverage), 0o600); err != nil {
			t.Fatalf("write coverage: %v", err)
		}
	}
	if toolLog != "" {
		if err := os.WriteFile(filepath.Join(logs, "tools.jsonl"), []byte(toolLog), 0o600); err != nil {
			t.Fatalf("write tools.jsonl: %v", err)
		}
	}
	return ws
}

const (
	nucleiWasInvoked = `{"id":"1","phase":"start","tool":"nuclei","argv":["-l","hosts.txt"]}` + "\n"
	onlyHTTPXInvoked = `{"id":"1","phase":"start","tool":"httpx","argv":["-json"]}` + "\n"
)

// TestNucleiCoverageGate is the gate's decision rule, case by case.
func TestNucleiCoverageGate(t *testing.T) {
	// The measured healthy fixture: probe arm F1 sent 18,481 of 18,715 planned
	// requests (98.75%) over 13k templates against a responsive host.
	healthy := covRecord("normal", "13143", "13100", "18481", "18715", "0", false) + "\n"
	// The measured collapse: probe arms G1/G2 reached 778 of 18,715 (4.2%)
	// against ONE blackholed host before the bound.
	collapsed := covRecord("normal", "13143", "13100", "778", "18715", "0", false) + "\n"

	tests := []struct {
		name     string
		coverage string
		toolLog  string
		want     string
		mustSay  string
	}{
		{
			name: "healthy run passes", coverage: healthy, toolLog: nucleiWasInvoked,
			want: "PASS", mustSay: "98%",
		},
		{
			// THE CASE MUTATION 1 REMOVES. A run that sent 4% of its planned
			// requests covered almost nothing and exited 0 while doing it.
			name: "implausibly low executed fraction fails", coverage: collapsed, toolLog: nucleiWasInvoked,
			want: "FAIL", mustSay: "sent only 4%",
		},
		{
			// THE 2026-08-24 STATE EXACTLY: nuclei ran, exited 0, and left no
			// account of what it had covered.
			name: "nuclei ran and wrote no record fails", coverage: "", toolLog: nucleiWasInvoked,
			want: "FAIL", mustSay: "wrote NO coverage record",
		},
		{
			// Not a pass and not a failure: there is nothing to account for.
			// SKIPPED is never PASS, and this script's whole posture is that an
			// unjudged step is not a passed step.
			name: "nuclei never ran is SKIPPED", coverage: "", toolLog: onlyHTTPXInvoked,
			want: "SKIPPED", mustSay: "not invoked",
		},
		{
			// T-17-05-01. A null is UNKNOWN, and a run that cannot say what it
			// loaded has not accounted for itself. Reporting this as 0% — or as
			// a pass — would reproduce the defect class inside its own remedy.
			name:     "unknown counts fail, and are not read as zero",
			coverage: covRecord("normal", "null", "null", "null", "null", "null", false) + "\n",
			toolLog:  nucleiWasInvoked, want: "FAIL", mustSay: "a null is UNKNOWN",
		},
		{
			// The record shape changed under the gate. The fields are ABSENT,
			// not null. Before the fix this aborted the rule mid-loop under
			// `set -e` and printed no verdict at all.
			name:     "an absent field is named, never silently zero",
			coverage: `{"schema":"nuclei-coverage/v1",` + basis + `,"group":"normal","terminated_early":false}` + "\n",
			toolLog:  nucleiWasInvoked, want: "FAIL", mustSay: "record shape changed",
		},
		{
			// An undeclared proxy read as a count is what produced the
			// 49-template misreading. The gate refuses the record.
			name: "a record with no proxy declaration fails",
			coverage: `{"schema":"nuclei-coverage/v1","execution_basis":"","tool":"nuclei","group":"normal",` +
				`"filter_selected":13143,"templates_loaded":13100,"requests_planned":18715,` +
				`"requests_sent":18481,"hosts_dropped":0,"terminated_early":false}` + "\n",
			toolLog: nucleiWasInvoked, want: "FAIL", mustSay: "no execution_basis",
		},
		{
			name:     "a terminated group fails even with a high fraction",
			coverage: covRecord("waf", "13143", "13100", "18000", "18715", "0", true) + "\n",
			toolLog:  nucleiWasInvoked, want: "FAIL", mustSay: "terminated_early",
		},
		{
			// The WORST group decides. A healthy `normal` group must not
			// average away a collapsed `waf` group.
			name:     "the worst group decides, not the average",
			coverage: healthy + collapsed, toolLog: nucleiWasInvoked,
			want: "FAIL", mustSay: "sent only 4%",
		},
		{
			name:     "a present-but-empty record is not an account",
			coverage: "\n", toolLog: nucleiWasInvoked,
			want: "FAIL", mustSay: "EMPTY",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ws := writeWS(t, tc.coverage, tc.toolLog)
			got := nucleiCoverageVerdict(t, ws)
			status := got
			if i := strings.Index(got, " "); i > 0 {
				status = got[:i]
			}
			if status != tc.want {
				t.Fatalf("verdict = %q, want %s\n  full line: %s", status, tc.want, got)
			}
			if tc.mustSay != "" && !strings.Contains(got, tc.mustSay) {
				t.Errorf("the note does not contain %q, so a reader cannot act on it.\n  got: %s",
					tc.mustSay, got)
			}
		})
	}
}

// TestNucleiCoverageGateStepExists pins the gate into release-gates.sh by name.
// A gate that is silently omitted is exactly the class phase 17 workstream (D)
// exists to close.
func TestNucleiCoverageGateStepExists(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "release-gates.sh"))
	if err != nil {
		t.Fatalf("read release-gates.sh: %v", err)
	}
	src := string(data)
	for _, want := range []string{
		"gate_nuclei_coverage",       // the gate function
		"nuclei_coverage_verdict",    // the rule it decides with
		"NUCLEI_COVERAGE_MIN_PCT=50", // the threshold
		"--nuclei-coverage-verdict",  // the seam this test uses
		"TestNucleiCoverageEndToEnd", // it must cite the tests by name
		"98.75%",                     // the healthy measurement the floor derives from
		"4.2%",                       // the collapsed measurement the floor derives from
	} {
		if !strings.Contains(src, want) {
			t.Errorf("release-gates.sh no longer contains %q — the nuclei coverage gate was removed, "+
				"renamed, or its threshold lost the derivation that stops it being 'adjusted' to "+
				"turn a red gate green (T-17-05-02)", want)
		}
	}
	// The gate must be INVOKED, not merely defined. A defined-but-uncalled gate
	// is a false green with extra steps.
	if !strings.Contains(src, "\ngate_nuclei_coverage\n") {
		t.Error("gate_nuclei_coverage is defined but never called from the gate list")
	}
}

// TestParityAttribution asserts the parity report's nuclei-coverage block on a
// canned workspace — the offline half of the plan's `parity-full.sh --self-check`
// assertions, so CI runs them on every push.
func TestParityAttribution(t *testing.T) {
	script := filepath.Join(repoRoot(t), "scripts", "parity-full.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("parity-full.sh not found: %v", err)
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Logf("SKIP: parity-full.sh --self-check requires jq: %v", err)
		t.Skip()
	}

	out, err := exec.Command("bash", script, "--self-check").CombinedOutput()
	if err != nil {
		t.Fatalf("parity-full.sh --self-check failed: %v\n%s", err, out)
	}
	text := string(out)

	// Every assertion the plan requires, by its printed name. Asserting the PASS
	// line rather than counting them means a renamed or deleted assertion is
	// caught instead of averaged away.
	for _, want := range []string{
		"attribution: nuclei coverage numbers are rendered ........ PASS",
		"attribution: the proxy declaration reaches the report .... PASS",
		"attribution: an ABSENT coverage record is named .......... PASS",
		"attribution RENDERS on a passing set with a non-empty removed list",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("parity-full.sh --self-check did not report %q.\n"+
				"  The nuclei-coverage block was removed from attribution_section, or its\n"+
				"  self-check assertion was. A removed finding class must arrive with the run's\n"+
				"  own coverage account attached; that is the whole deliverable.\n\nfull output:\n%s",
				want, text)
		}
	}
	// Scan for an assertion line that FAILED, not for the substring "FAIL"
	// anywhere. The self-check legitimately prints lines like
	// `ok   empty-v1 side counts into CORE_FAILS (=1)`, and a blanket
	// strings.Contains matched that and reported a failure on a passing run —
	// a false RED, which erodes trust in the gate exactly as fast as a false
	// green does. Assertion lines end in the verdict, so anchor on that.
	for _, line := range strings.Split(text, "\n") {
		if strings.HasSuffix(strings.TrimRight(line, " \t\r"), "FAIL") {
			t.Errorf("parity-full.sh --self-check assertion FAILED: %s\n\nfull output:\n%s", line, text)
		}
	}
	if !strings.Contains(text, "SELF-CHECK: PASS") {
		t.Errorf("parity-full.sh --self-check did not print its own PASS line — it did not run to "+
			"completion, and a self-check that stops early has verified only a prefix of itself:\n%s", text)
	}
}
