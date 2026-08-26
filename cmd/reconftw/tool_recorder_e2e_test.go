// tool_recorder_e2e_test.go — the tracer's end-to-end proof, made through the
// COMPILED binary rather than a package-level API.
//
// The question this answers is the one that cost the most time in the first live
// v2 run: "what did it ACTUALLY run?" Every blocker there presented as the same
// string — "tool stream ended badly: exit status 1" — and each had to be
// diagnosed by hand-reproducing the invocation over ssh. The proof therefore has
// to be that the argv on disk is byte-identical to the argv the process received,
// not merely that a file appeared.

package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// stubToolSpec describes a fake tool binary planted on a temp PATH.
type stubToolSpec struct {
	name string
	// script is the shell body. $ARGV_SINK is exported to it.
	script string
}

// plantStubTool writes an executable shell stub that records the argv it received
// into a side-channel file, then behaves as `script` says. Returns the PATH dir
// and the argv sink path.
//
// The stub is what makes this test hermetic: no real tool, no network, and the
// argv it observed is independent evidence rather than a re-reading of the same
// code under test.
func plantStubTool(t *testing.T, spec stubToolSpec) (pathDir, argvSink string) {
	t.Helper()
	pathDir = t.TempDir()
	return pathDir, plantStubToolIn(t, pathDir, spec)
}

// plantStubToolIn is plantStubTool against a CALLER-OWNED PATH dir, so several
// stubs can share one PATH. The stripped-PATH guards below need exactly that: a
// PATH holding a named handful of tools and nothing else, so "absent" is a fact
// about the filesystem rather than an assumption about the box.
func plantStubToolIn(t *testing.T, pathDir string, spec stubToolSpec) (argvSink string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub tool uses a POSIX shell")
	}
	argvSink = filepath.Join(t.TempDir(), "argv.txt")

	body := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" >> \"" + argvSink + "\"\n" +
		spec.script + "\n"
	p := filepath.Join(pathDir, spec.name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("plant stub %s: %v", spec.name, err)
	}
	return argvSink
}

// toolRecords parses <workspace>/logs/tools.jsonl.
func toolRecords(t *testing.T, workspaceRoot string) []map[string]any {
	t.Helper()
	var found string
	err := filepath.Walk(workspaceRoot, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() &&
			filepath.Base(p) == "tools.jsonl" && filepath.Base(filepath.Dir(p)) == "logs" {
			found = p
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", workspaceRoot, err)
	}
	if found == "" {
		t.Fatalf("no logs/tools.jsonl anywhere under %s", workspaceRoot)
	}
	data, err := os.ReadFile(found) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", found, err)
	}
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("tools.jsonl line is not valid JSON (%v): %s", err, ln)
		}
		out = append(out, rec)
	}
	return out
}

// TestE2EToolRecorderCapturesRealArgv is the tracer proof.
func TestE2EToolRecorderCapturesRealArgv(t *testing.T) {
	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "ws")

	// subfinder is dispatched by subdomains.passive.subfinder on a subs run.
	pathDir, argvSink := plantStubTool(t, stubToolSpec{
		name:   "subfinder",
		script: `printf 'stub.example.com\n'; exit 0`,
	})

	cmd := exec.Command(bin, "subs", "--target", "example.com", "-o", dataDir)
	cmd.Dir = work
	cmd.Env = hermeticResolverEnv(t, "PATH="+pathDir+":"+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput() // a task may skip; the recording is what matters

	recs := toolRecords(t, dataDir)
	if len(recs) == 0 {
		t.Fatalf("logs/tools.jsonl is empty — nothing was recorded\nrun output:\n%s", out)
	}

	// The stub's own account of what it received.
	sinkData, err := os.ReadFile(argvSink)
	if err != nil {
		t.Skipf("the stub tool was never dispatched by this mode (%v) — "+
			"nothing to compare argv against", err)
	}
	observed := strings.Split(strings.TrimSpace(string(sinkData)), "\n")

	// Find subfinder's start record and compare its argv to the stub's.
	var recorded []string
	var haveStart bool
	for _, rec := range recs {
		if rec["tool"] != "subfinder" || rec["phase"] != "start" {
			continue
		}
		haveStart = true
		raw, _ := rec["argv"].([]any)
		recorded = recorded[:0]
		for _, a := range raw {
			recorded = append(recorded, a.(string))
		}
		break
	}
	if !haveStart {
		t.Fatalf("no start record for subfinder in tools.jsonl; records: %+v", recs)
	}

	if strings.Join(recorded, "\x00") != strings.Join(observed, "\x00") {
		t.Errorf("recorded argv does not match what the process received\n"+
			"  recorded: %q\n  observed: %q\n"+
			"an argv the operator cannot trust is worse than none", recorded, observed)
	}
}

// TestE2EToolRecorderDispatchFailureIsLabelled: a tool that never ran must be
// distinguishable from one that ran and failed. dnstake's broken arg vector hid
// behind exactly that conflation for months.
//
// THIS ASSERTION USED TO SAMPLE, AND THAT IS WHY IT PASSED THROUGHOUT THE DEFECT.
// It read "at least one end record carries dispatch_failed", which is true of
// 4-of-23 and of 23-of-23 alike — and 4-of-23 is what the box was actually doing
// (16-06-PARITY §6.4). Under an EMPTY PATH every registered tool is absent, so the
// honest assertion is that EVERY end record says dispatch_failed. It now counts.
func TestE2EToolRecorderDispatchFailureIsLabelled(t *testing.T) {
	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "ws")

	// Empty PATH dir: every tool is absent, so every dispatch fails.
	emptyPath := t.TempDir()
	cmd := exec.Command(bin, "subs", "--target", "example.com", "-o", dataDir)
	cmd.Dir = work
	cmd.Env = hermeticResolverEnv(t, "PATH="+emptyPath)
	out, _ := cmd.CombinedOutput()

	invs := joinInvocations(t, toolRecords(t, dataDir))

	// ---- PRESENCE GATE: assert the dispatch happened before judging its label ----
	var ended int
	byOutcome := map[string]int{}
	notDispatchFailed := map[string]string{}
	for _, iv := range invs {
		if !iv.Ended {
			continue
		}
		ended++
		byOutcome[iv.Outcome]++
		if iv.Outcome != "dispatch_failed" {
			notDispatchFailed[iv.Tool] = iv.Outcome
		}
	}
	if ended == 0 {
		t.Fatalf("nothing was recorded for a run where every tool is absent — this guard would pass "+
			"vacuously\nrun output:\n%s", out)
	}

	// ---- the count ----
	if len(notDispatchFailed) > 0 {
		t.Errorf("with an EMPTY PATH, %d of %d end records do NOT say dispatch_failed.\n"+
			"  outcomes: %v\n  offenders: %v\n"+
			"Every tool is absent by construction here, so every one of them never ran.\n"+
			"joined log:\n%s", len(notDispatchFailed), ended, byOutcome, notDispatchFailed,
			perToolOutcomes(invs))
	}
}

// TestE2EDryRunWritesNoToolLog composes with acceptance gate 1 ("a dry run leaves
// the filesystem byte-for-byte unchanged"). Asserts ABSENCE, not emptiness.
func TestE2EDryRunWritesNoToolLog(t *testing.T) {
	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "ws")

	cmd := exec.Command(bin, "recon", "--target", "example.com", "--dry-run", "-o", dataDir)
	cmd.Dir = work
	cmd.Env = hermeticResolverEnv(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dry run failed: %v\n%s", err, out)
	}

	var offenders []string
	_ = filepath.Walk(work, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && filepath.Base(p) == "tools.jsonl" {
			offenders = append(offenders, p)
		}
		return nil
	})
	if len(offenders) > 0 {
		t.Errorf("a dry run created %v — no tool was dispatched, so no tool log may exist", offenders)
	}
}

// ---------------------------------------------------------------------------
// TC-C — outcome-label correctness (plan 17-02)
// ---------------------------------------------------------------------------
//
// WHAT THESE REPLACE. TestE2EToolRecorderDispatchFailureIsLabelled above asserts
// that AT LEAST ONE end record carries dispatch_failed. That sampling assertion
// cannot distinguish 4-of-23 from 23-of-23 — and 4-of-23 is exactly what the
// phase-16 verifier measured on 2026-08-24 against a PATH holding only a stub
// subfinder: 4 dispatch_failed versus 19 exit_non_zero, with all 23 tools absent,
// and `dnsx` appearing under BOTH labels in one log. The parity run's own numbers
// were worse: 150 of 319 exit_non_zero outcomes were absent tools wearing the
// wrong label. The guards below therefore COUNT.
//
// EVERY ABSENCE ASSERTION HERE IS GATED BEHIND A PRESENCE ASSERTION. A guard that
// only asserts "nothing is mislabelled" passes on a run that dispatched nothing at
// all, which is the same vacuous shape as the "at least one" it replaces. So each
// test first proves the dispatch actually happened — on both paths, where the
// claim is about both paths — and only then judges the labels.

// invocation is one start/end pair from logs/tools.jsonl, joined by id.
type invocation struct {
	ID       string
	Tool     string // from the START record
	Mode     string // "exec" | "stream"
	Outcome  string
	ExitCode int
	// EndTool is the `tool` field as written ON THE END RECORD. Before plan
	// 17-02 it was always "" — see TestEndRecordCarriesToolName.
	EndTool string
	Ended   bool
}

// joinInvocations pairs start and end records by id, in start order.
func joinInvocations(t *testing.T, recs []map[string]any) []invocation {
	t.Helper()
	idx := map[string]int{}
	var out []invocation
	for _, rec := range recs {
		id, _ := rec["id"].(string)
		switch rec["phase"] {
		case "start":
			tool, _ := rec["tool"].(string)
			mode, _ := rec["mode"].(string)
			idx[id] = len(out)
			out = append(out, invocation{ID: id, Tool: tool, Mode: mode})
		case "end":
			i, ok := idx[id]
			if !ok {
				t.Errorf("end record id=%q has no matching start — the pairing that makes a hang "+
					"readable from this file is broken", id)
				continue
			}
			out[i].Ended = true
			out[i].Outcome, _ = rec["outcome"].(string)
			out[i].EndTool, _ = rec["tool"].(string)
			if ec, ok := rec["exit_code"].(float64); ok {
				out[i].ExitCode = int(ec)
			}
		}
	}
	return out
}

// strippedPathRun runs the real binary with a PATH containing EXACTLY the named
// stubs and nothing else, then returns the joined invocations and the PATH dir.
//
// The PATH dir is returned rather than a list of names because absence is then
// decided by stat(2) against the same directory the child process searched —
// independent evidence, not a restatement of the test's own expectation.
// tools.lock documents `name` as "exec.LookPath name", so the record's tool name
// and the file name on PATH are the same string by contract.
func strippedPathRun(t *testing.T, stubs ...stubToolSpec) (invs []invocation, pathDir string, runOutput []byte) {
	t.Helper()
	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "ws")

	pathDir = t.TempDir()
	for _, s := range stubs {
		plantStubToolIn(t, pathDir, s)
	}

	cmd := exec.Command(bin, "subs", "--target", "example.com", "-o", dataDir)
	cmd.Dir = work
	cmd.Env = hermeticResolverEnv(t, "PATH="+pathDir)
	runOutput, _ = cmd.CombinedOutput() // tasks are expected to degrade; the RECORD is the subject

	return joinInvocations(t, toolRecords(t, dataDir)), pathDir, runOutput
}

// onPath reports whether the child process could have found tool in pathDir.
func onPath(pathDir, tool string) bool {
	fi, err := os.Stat(filepath.Join(pathDir, tool))
	return err == nil && !fi.IsDir()
}

// perToolOutcomes renders the joined log the way the failure message needs it.
func perToolOutcomes(invs []invocation) string {
	type key struct{ tool, mode, outcome string }
	counts := map[key]int{}
	var order []key
	for _, iv := range invs {
		if !iv.Ended {
			continue
		}
		k := key{iv.Tool, iv.Mode, iv.Outcome}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].tool != order[j].tool {
			return order[i].tool < order[j].tool
		}
		return order[i].mode < order[j].mode
	})
	var b strings.Builder
	for _, k := range order {
		fmt.Fprintf(&b, "    %-24s mode=%-7s outcome=%-16s x%d\n", k.tool, k.mode, k.outcome, counts[k])
	}
	return b.String()
}

// TestE2EAbsentBinaryIsLabelledDispatchFailedOnBothPaths is the verifier's
// 2026-08-24 reproduction, turned into a counting assertion.
//
// A registered tool with no binary has Tool.Path == "", cmd.Start() fails, and the
// process NEVER RAN. Whether that fact reaches the record must not depend on which
// dispatch mode the module happened to choose.
func TestE2EAbsentBinaryIsLabelledDispatchFailedOnBothPaths(t *testing.T) {
	invs, pathDir, out := strippedPathRun(t,
		// subfinder exists and exits 0 so the subs pipeline proceeds far enough
		// to dispatch on BOTH the Exec and the Stream path.
		stubToolSpec{name: "subfinder", script: `printf 'stub.example.com\n'; exit 0`},
		// crt exists and exits non-zero: the fix must not collapse the
		// distinction in the other direction (see the Test-3 block below).
		stubToolSpec{name: "crt", script: `echo 'crt stub failed' >&2; exit 3`},
	)

	var absentDispatched, absentAsDispatchFailed, absentAsExitNonZero int
	absentByMode := map[string]int{}
	mislabelled := map[string]int{}
	for _, iv := range invs {
		if !iv.Ended || onPath(pathDir, iv.Tool) {
			continue
		}
		absentDispatched++
		absentByMode[iv.Mode]++
		switch iv.Outcome {
		case "dispatch_failed":
			absentAsDispatchFailed++
		case "exit_non_zero":
			absentAsExitNonZero++
			mislabelled[iv.Tool]++
		}
	}

	// ---- PRESENCE GATE, before any judgement about labels ----
	if absentDispatched == 0 {
		t.Fatalf("no ABSENT tool was dispatched at all, so this guard would pass vacuously.\n"+
			"joined log:\n%s\nrun output:\n%s", perToolOutcomes(invs), out)
	}
	if absentByMode["exec"] == 0 || absentByMode["stream"] == 0 {
		t.Fatalf("absent tools were dispatched on only ONE path (exec=%d stream=%d), so a claim about "+
			"BOTH paths cannot be tested by this run.\njoined log:\n%s",
			absentByMode["exec"], absentByMode["stream"], perToolOutcomes(invs))
	}

	// ---- the counts ----
	if absentAsExitNonZero != 0 || absentAsDispatchFailed != absentDispatched {
		t.Errorf("absent tools are not all labelled as dispatch failures.\n"+
			"  absent tools dispatched:        %d  (exec=%d stream=%d)\n"+
			"  labelled dispatch_failed:       %d\n"+
			"  labelled exit_non_zero (WRONG): %d  %v\n"+
			"An absent tool wearing exit_non_zero tells the operator the tool ran and failed. It never\n"+
			"ran. Those two facts have opposite remedies — install it, versus debug it.\n"+
			"joined log:\n%s",
			absentDispatched, absentByMode["exec"], absentByMode["stream"],
			absentAsDispatchFailed, absentAsExitNonZero, mislabelled, perToolOutcomes(invs))
	}

	// ---- Test 3: the distinction must not collapse the other way ----
	var sawPresentFailure, sawPresentSuccess bool
	for _, iv := range invs {
		if !iv.Ended || !onPath(pathDir, iv.Tool) {
			continue
		}
		switch iv.Tool {
		case "crt":
			sawPresentFailure = true
			if iv.Outcome != "exit_non_zero" {
				t.Errorf("crt is ON PATH and exits 3, but is labelled %q — a tool that RAN and failed "+
					"must stay exit_non_zero", iv.Outcome)
			}
			if iv.ExitCode != 3 {
				t.Errorf("crt exit_code = %d, want 3 — the record must carry the exit code the process "+
					"actually returned, which is also the proof it ran", iv.ExitCode)
			}
		case "subfinder":
			sawPresentSuccess = true
			if iv.Outcome != "success" {
				t.Errorf("subfinder is ON PATH and exits 0, but is labelled %q", iv.Outcome)
			}
		}
	}
	if !sawPresentFailure || !sawPresentSuccess {
		t.Errorf("the present stubs were not both dispatched (crt=%v subfinder=%v), so the "+
			"does-not-collapse-the-other-way half of this guard is vacuous.\njoined log:\n%s",
			sawPresentFailure, sawPresentSuccess, perToolOutcomes(invs))
	}
}

// TestNoToolAppearsUnderBothLabels is the phase-16 verifier's decisive
// observation, made permanent.
//
// `dnsx` appeared under dispatch_failed (1, via Stream) and exit_non_zero (4, via
// Exec) in a SINGLE log, from a box where dnsx was absent throughout. One tool,
// one run, one fact about it — two labels. That is a stronger and cheaper
// invariant than any per-tool expectation, because it needs no knowledge of which
// tools happen to be installed.
func TestNoToolAppearsUnderBothLabels(t *testing.T) {
	invs, _, out := strippedPathRun(t,
		stubToolSpec{name: "subfinder", script: `printf 'stub.example.com\n'; exit 0`},
	)

	labels := map[string]map[string]bool{}
	modes := map[string]map[string]bool{}
	for _, iv := range invs {
		if !iv.Ended {
			continue
		}
		if labels[iv.Tool] == nil {
			labels[iv.Tool] = map[string]bool{}
			modes[iv.Tool] = map[string]bool{}
		}
		labels[iv.Tool][iv.Outcome] = true
		modes[iv.Tool][iv.Mode] = true
	}

	// ---- PRESENCE GATE ----
	// The invariant is only falsifiable if some tool was dispatched on BOTH
	// dispatch modes in this run — that is the seam the defect lived in. Without
	// this gate the test would pass on a run that dispatched one tool once, and
	// would go on passing after a regression that split the labels by mode.
	var bothModes []string
	for tool, m := range modes {
		if len(m) > 1 {
			bothModes = append(bothModes, tool)
		}
	}
	if len(bothModes) == 0 {
		t.Fatalf("no tool was dispatched on BOTH exec and stream in this run, so a label split BY "+
			"DISPATCH MODE could not be detected and this guard would pass vacuously.\n"+
			"joined log:\n%s\nrun output:\n%s", perToolOutcomes(invs), out)
	}
	sort.Strings(bothModes)
	t.Logf("tools dispatched on both paths in this run: %v", bothModes)

	// ---- the invariant ----
	for tool, l := range labels {
		if len(l) <= 1 {
			continue
		}
		var got []string
		for o := range l {
			got = append(got, o)
		}
		sort.Strings(got)
		t.Errorf("tool %q appears under %d outcome labels in ONE run: %v.\n"+
			"Whether a tool ran is a fact about the tool and the box, not about which dispatch mode a\n"+
			"module chose. Two labels for one tool in one run means the label is reporting the code\n"+
			"path rather than the fact.\njoined log:\n%s", tool, len(l), got, perToolOutcomes(invs))
	}
}

// TestEndRecordCarriesToolName is the operator's first triage command, asserted.
//
// 16-06-PARITY §6.2 opens by noting that end records carry `"tool":""`, so
//
//	jq -r 'select(.phase=="end") | "\(.tool) \(.outcome)"' logs/tools.jsonl | sort | uniq -c
//
// — the first thing anyone tries — returns nothing but blanks, and the parity
// decomposition had to be done with an id-join. This asserts the grouping works
// WITHOUT the join, against a log written by the real binary rather than a fixture:
// a fixture would encode the shape the test wants instead of the shape the code
// writes.
func TestEndRecordCarriesToolName(t *testing.T) {
	invs, _, out := strippedPathRun(t,
		stubToolSpec{name: "subfinder", script: `printf 'stub.example.com\n'; exit 0`},
	)

	// The grouping an operator gets with NO id-join: end records only.
	byTool := map[string]map[string]int{}
	var ended, unnamed int
	for _, iv := range invs {
		if !iv.Ended {
			continue
		}
		ended++
		if iv.EndTool == "" {
			unnamed++
			continue
		}
		if byTool[iv.EndTool] == nil {
			byTool[iv.EndTool] = map[string]int{}
		}
		byTool[iv.EndTool][iv.Outcome]++
	}

	// ---- PRESENCE GATE ----
	if ended == 0 {
		t.Fatalf("the run produced no end records at all, so a grouping assertion would be vacuous.\n"+
			"run output:\n%s", out)
	}

	// ---- every end record names its tool ----
	if unnamed != 0 {
		t.Errorf("%d of %d end records carry an empty tool name.\n"+
			"`select(.phase==\"end\") | .tool` is the first command an operator types, and it returns\n"+
			"blanks. The parity decomposition of 319 failures had to be done with an id-join because of\n"+
			"exactly this.\njoined log:\n%s", unnamed, ended, perToolOutcomes(invs))
	}

	// ---- and it names the RIGHT tool: the join and the direct grouping agree ----
	for _, iv := range invs {
		if iv.Ended && iv.EndTool != "" && iv.EndTool != iv.Tool {
			t.Errorf("invocation id=%s: start record says tool=%q, end record says tool=%q — a name that "+
				"disagrees with the pairing is worse than no name", iv.ID, iv.Tool, iv.EndTool)
		}
	}

	// ---- and the grouping actually names a tool this run dispatched ----
	if byTool["subfinder"]["success"] == 0 {
		t.Errorf("grouping the end records by tool does not show subfinder succeeding, though it is the "+
			"one tool on PATH and it exits 0.\ngrouping: %v\njoined log:\n%s", byTool, perToolOutcomes(invs))
	}
	t.Logf("group-by-tool over END records alone (no id-join): %v", byTool)
}
