// fray_seam_test.go — FrayTask's dispatch shape: `fray test` takes
// ONE positional target and has no list flag, so the targets travel on
// standard input (the v1 `cat targets | fray test ...` shape) and the argv is
// the v1 vector verbatim. Also pins the absent-vs-failed policy and the
// bypass_rate parser fix (a string on the wire, not a float).
package vulns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// frayWantArgv is the v1 vulns.sh:1149 vector for one category with the
// defaults (--max 20, -t 10, -d 0.5). A literal on purpose.
var frayWantArgv = []string{"test", "-c", "ai_prompt_injection", "--max", "20", "-t", "10", "-d", "0.5", "--json"}

func seedFrayWorkspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"inputs", "artefacts", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	corpus := "{\"url\":\"https://api.example.com/search?q=1\"}\n{\"url\":\"https://www.example.com/p?id=7\"}\n"
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "urls.jsonl"), []byte(corpus), 0o600); err != nil {
		t.Fatalf("seed urls.jsonl: %v", err)
	}
	return workDir
}

func newFraySeamApp(t *testing.T, workDir, frayPath string) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "fray", Path: frayPath})
	cfg := config.Defaults()
	cfg.Vulns.Fray.Enabled = true
	cfg.Vulns.Fray.Categories = "ai_prompt_injection"
	cfg.Advanced.Deep = false
	tree, err := output.NewTree(workDir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	return &appctx.AppContext{
		Log:    appctx.NopLogger(),
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}
}

func TestFrayArgvIsV1VectorWithTargetsOnStdin(t *testing.T) {
	workDir := seedFrayWorkspace(t)
	frayDir := t.TempDir()
	// What `fray test --json` prints per target (observed 2026-10-07): bypass_rate
	// is a STRING. One bypass so the parser's output is observable.
	fray := writeSeamRecorderScript(t, frayDir,
		`{"target": "https://api.example.com/search?q=1", "total": 2, "bypassed": 1, "blocked": 1, "errors": 0, "bypass_rate": "50.0%"}`+"\n")

	app := newFraySeamApp(t, workDir, fray)
	res, err := (&FrayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("FrayTask.Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v (%q), want done", res.Status, res.Reason)
	}

	assertArgvExactly(t, "fray test", readSeamArgv(t, frayDir), frayWantArgv)

	stdin, sErr := os.ReadFile(filepath.Join(frayDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if sErr != nil {
		t.Fatalf("no standard input reached fray: %v", sErr)
	}
	if !strings.Contains(string(stdin), "https://api.example.com/search?q=1") ||
		!strings.Contains(string(stdin), "https://www.example.com/p?id=7") {
		t.Errorf("fray stdin does not carry the URL corpus — got:\n%s", stdin)
	}

	if got := res.Stats["total_bypassed"]; got != 1 {
		t.Fatalf("total_bypassed = %d, want 1 — the JSON line with a string bypass_rate was not parsed", got)
	}
	if _, statErr := os.Stat(filepath.Join(workDir, "inputs", "findings.fray.jsonl")); statErr != nil {
		t.Errorf("fray ran and bypassed once but wrote no staging file: %v", statErr)
	}
}

func TestFrayAbsentIsToolAbsentNotDone(t *testing.T) {
	workDir := seedFrayWorkspace(t)
	app := newFraySeamApp(t, workDir, "") // registered, no binary

	res, err := (&FrayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned an error for an unavailable fray: %v", err)
	}
	if res.Status != task.StatusSkipped || res.Reason != task.ReasonToolAbsent {
		t.Fatalf("absent fray: status=%v reason=%q, want skipped/%q", res.Status, res.Reason, task.ReasonToolAbsent)
	}
	if _, statErr := os.Stat(filepath.Join(workDir, "inputs", "findings.fray.jsonl")); statErr == nil {
		t.Error("a run in which fray never started wrote the staging file (did-not-run rule)")
	}
}

func TestFrayExitNonZeroIsDegradedNotAbsent(t *testing.T) {
	workDir := seedFrayWorkspace(t)
	frayDir := t.TempDir()
	script := filepath.Join(frayDir, "fail.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'fray: error: boom' >&2\nexit 2\n"), 0o700); err != nil { //nolint:gosec // executable fixture
		t.Fatalf("write script: %v", err)
	}
	app := newFraySeamApp(t, workDir, script)

	res, err := (&FrayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned an error for a failing fray: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status = %v, want skipped (best_effort)", res.Status)
	}
	if res.Reason == task.ReasonToolAbsent || !strings.Contains(res.Reason, "fray") {
		t.Fatalf("reason = %q — a tool that RAN and failed must not read as absent, and must name the tool", res.Reason)
	}
}

func TestParseFrayOutputAcceptsStringBypassRate(t *testing.T) {
	line := `{"target": "http://t/", "total": 3, "bypassed": 2, "blocked": 1, "errors": 0, "bypass_rate": "66.7%"}` + "\n"
	findings, n := parseFrayOutput([]byte(line), "api_security")
	if n != 2 || len(findings) != 1 {
		t.Fatalf("parseFrayOutput = %d bypassed, %d findings; want 2, 1 (bypass_rate is a string on the wire)", n, len(findings))
	}
	if findings[0].PayloadRedacted != "***" || findings[0].VulnClass != "waf-bypass-api_security" {
		t.Errorf("record = %+v", findings[0])
	}
}
