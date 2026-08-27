// shortscan_test.go — the proof that web.shortscan came home to backend.Runner
// (18-04) by an EXPLICIT VERDICT rather than by grandfathering.
//
// THE CONTROL IS THE PRE-MOVE ARG VECTOR, captured from shortscan.go as it stood
// at f436d2e BEFORE the edit:
//
//	cmd := exec.CommandContext(cmdCtx, shortscanPath, targetURL, "-F", "-s", "-p", "1")
//
// Note the POSITIONAL target first. That ordering is part of the vector, so the
// assertion below is on the complete slice IN ORDER, not on a set of flags.
//
// This file had no stdin, no cmd.Dir, resolved through exec.LookPath like any
// registered tool, and its `shortscan` row in tools.lock already declared
// timeout_seconds = 300 — the same 300 the file applied itself. There was no
// capability the seam lacked; there was only a blanket comment claiming two it
// never needed.
package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// shortscanTarget is the IIS target seeded into the nuclei staging file.
const shortscanTarget = "https://iis.example.com/"

// seedShortscanWorkspace writes inputs/findings.nuclei.jsonl with one
// iis-version record, which is the only input ShortscanTask gates on.
func seedShortscanWorkspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"inputs", "artefacts", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	rec := `{"template_id":"iis-version","matched_at":"` + shortscanTarget + `","host":"iis.example.com"}` + "\n"
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "findings.nuclei.jsonl"),
		[]byte(rec), 0o600); err != nil {
		t.Fatalf("seed nuclei staging: %v", err)
	}
	return workDir
}

// newShortscanTestApp wires a Runner whose "shortscan" entry points at toolPath
// (empty for the unavailable case) through the REAL LocalBackend.
func newShortscanTestApp(t *testing.T, workDir, toolPath string) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: shortscanToolName, Path: toolPath})
	cfg := config.Defaults()
	cfg.Web.IISShortname.Enabled = true
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}
}

// TestShortscanArgvUnchangedAcrossTheMove asserts the COMPLETE argv slice IN
// ORDER, positional target URL included.
func TestShortscanArgvUnchangedAcrossTheMove(t *testing.T) {
	workDir := seedShortscanWorkspace(t)
	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "Vulnerable: Yes\nfound: FOOBAR~1.ASP\n")

	app := newShortscanTestApp(t, workDir, script)
	res, err := (&ShortscanTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("ShortscanTask.Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want %v", res.Status, task.StatusDone)
	}

	want := []string{shortscanTarget, "-F", "-s", "-p", "1"}
	got := readRecordedArgv(t, recDir)
	if len(got) != len(want) {
		t.Fatalf("argv the process received = %v (%d args), want %v (%d args) — the pre-move "+
			"vector captured from shortscan.go at f436d2e", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q — the positional target comes FIRST and the flag "+
				"order is part of the vector (full: got %v, want %v)", i, got[i], want[i], got, want)
		}
	}

	// And the v1 output filter still holds: "Vulnerable: Yes" in stdout is what
	// turns a scan into a finding.
	if n := res.Stats["iis_findings"]; n != 1 {
		t.Fatalf("iis_findings = %d, want 1 — the tool's stdout was not parsed", n)
	}
}

// TestShortscanIsRecorded asserts the invocation lands in logs/tools.jsonl.
// PRESENCE FIRST, then content — an absence-or-content assertion over a file
// nothing wrote passes for a tool that was never dispatched.
func TestShortscanIsRecorded(t *testing.T) {
	workDir := seedShortscanWorkspace(t)
	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "Vulnerable: Yes\n")

	logPath := filepath.Join(workDir, "logs", "tools.jsonl")
	app := newShortscanTestApp(t, workDir, script)
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	if _, err := (&ShortscanTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("ShortscanTask.Run: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — shortscan was NOT recorded, which is the "+
			"whole point of a move that had no other justification: %v", err)
	}

	// 1. PRESENCE.
	var startArgv []string
	var sawStart bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Phase string   `json:"phase"`
			Tool  string   `json:"tool"`
			Argv  []string `json:"argv"`
		}
		if uErr := json.Unmarshal([]byte(line), &rec); uErr != nil {
			t.Fatalf("tools.jsonl line is not JSON: %v (%s)", uErr, line)
		}
		if rec.Tool == shortscanToolName && rec.Phase == "start" {
			sawStart, startArgv = true, rec.Argv
		}
	}
	if !sawStart {
		t.Fatalf("no start record naming %q in logs/tools.jsonl:\n%s", shortscanToolName, data)
	}

	// 2. Only now, content.
	want := []string{shortscanTarget, "-F", "-s", "-p", "1"}
	if len(startArgv) != len(want) {
		t.Fatalf("recorded argv = %v, want %v", startArgv, want)
	}
	for i := range want {
		if startArgv[i] != want[i] {
			t.Fatalf("recorded argv[%d] = %q, want %q (full: %v)", i, startArgv[i], want[i], startArgv)
		}
	}
}

// TestShortscanUnavailableToolStatusUnchanged pins the FAILURE POLICY across the
// move (T-18-04-04): the exec.LookPath gate returned StatusSkipped, and so must
// the dispatch-failure arm — including NOT clearing a previous run's staging.
func TestShortscanUnavailableToolStatusUnchanged(t *testing.T) {
	workDir := seedShortscanWorkspace(t)
	staging := filepath.Join(workDir, "inputs", "findings.shortscan.jsonl")
	if err := os.WriteFile(staging, []byte(`{"type":"iis-shortname"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed staging: %v", err)
	}

	app := newShortscanTestApp(t, workDir, "")
	res, err := (&ShortscanTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned an error for an unavailable tool: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status on an unavailable shortscan = %v, want %v — a best-effort task that "+
			"starts returning an errored status aborts the web pipeline", res.Status, task.StatusSkipped)
	}
	data, readErr := os.ReadFile(staging) //nolint:gosec // test-owned temp path
	if readErr != nil || !strings.Contains(string(data), "iis-shortname") {
		t.Fatalf("a run in which shortscan never started cleared the previous run's staging "+
			"(F3 did-not-run must preserve): err=%v content=%q", readErr, data)
	}
}

// TestShortscanKeepsFindingsCollectedBeforeADispatchFailure pins the WR-06 fix.
//
// The loop returned StatusSkipped from INSIDE itself on the first dispatch
// failure, throwing away every finding earlier iterations had collected. With
// CR-04 fixed a rate-limiter or context error mid-loop IS a dispatch failure, so a
// Ctrl-C or a task deadline part-way through reaches that arm and silently
// discarded a partial but perfectly valid result set.
//
// The tool here succeeds for the first target and then disappears, which is the
// cheapest faithful model of "it worked, then it stopped being dispatchable".
func TestShortscanKeepsFindingsCollectedBeforeADispatchFailure(t *testing.T) {
	recDir := t.TempDir()

	// TWO IIS targets, not the single-target fixture. With one target the loop
	// never reaches a second dispatch, the failure arm never fires, and this test
	// passes with the bug reintroduced — verified by mutation, which is how the
	// first version of it was caught being vacuous.
	workDir := t.TempDir()
	for _, d := range []string{"inputs", "artefacts", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	rec := `{"template_id":"iis-version","matched_at":"https://iis-one.example.com/","host":"iis-one.example.com"}` + "\n" +
		`{"template_id":"iis-version","matched_at":"https://iis-two.example.com/","host":"iis-two.example.com"}` + "\n"
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "findings.nuclei.jsonl"),
		[]byte(rec), 0o600); err != nil {
		t.Fatalf("seed nuclei staging: %v", err)
	}

	// A script that reports one finding and then DELETES ITSELF, so the second
	// dispatch cannot start — a genuine NeverStarted, not a simulated error.
	script := filepath.Join(recDir, "once.sh")
	body := "#!/bin/sh\n" +
		"printf 'Vulnerable: Yes\\nfound: FIRSTHIT~1.ASP\\n'\n" +
		"rm -f '" + script + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write script: %v", err)
	}

	app := newShortscanTestApp(t, workDir, script)
	res, err := (&ShortscanTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("ShortscanTask.Run: %v", err)
	}

	if res.Status == task.StatusSkipped {
		t.Fatal("THE WHOLE RUN WAS DISCARDED because a later dispatch failed — the " +
			"findings collected before it are a real observation and must survive (WR-06)")
	}
	if !res.Incomplete {
		t.Fatal("the partial run was checkpointable as done — the next run would skip the targets that never dispatched (V-04)")
	}

	stagingPath := filepath.Join(workDir, "inputs", "findings.shortscan.jsonl")
	data, err := os.ReadFile(stagingPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("nothing was staged, so the findings collected before the failure were "+
			"lost (WR-06): %v", err)
	}
	if !strings.Contains(string(data), "FIRSTHIT~1.ASP") {
		t.Errorf("the finding collected before the dispatch failure is missing:\n%s", data)
	}
}
