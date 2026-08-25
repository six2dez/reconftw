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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS == "windows" {
		t.Skip("stub tool uses a POSIX shell")
	}
	pathDir = t.TempDir()
	argvSink = filepath.Join(t.TempDir(), "argv.txt")

	body := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" >> \"" + argvSink + "\"\n" +
		spec.script + "\n"
	p := filepath.Join(pathDir, spec.name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("plant stub %s: %v", spec.name, err)
	}
	return pathDir, argvSink
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

	recs := toolRecords(t, dataDir)
	if len(recs) == 0 {
		t.Fatalf("nothing recorded for a run where every tool is absent\n%s", out)
	}
	sawDispatchFailed := false
	for _, rec := range recs {
		if rec["phase"] == "end" && rec["outcome"] == "dispatch_failed" {
			sawDispatchFailed = true
		}
	}
	if !sawDispatchFailed {
		t.Errorf("no end record carries outcome=dispatch_failed with an empty PATH — "+
			"a tool that never ran is indistinguishable from one that ran and failed; records: %+v", recs)
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
