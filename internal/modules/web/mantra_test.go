// mantra_test.go — the proof that web.mantra came home to backend.Runner
// (18-04) without changing the command line mantra receives, and that an
// unavailable mantra still produces the SAME task status it always did.
//
// THE CONTROL IS THE PRE-MOVE ARG VECTOR, captured from mantra.go as it stood at
// f436d2e BEFORE the edit:
//
//	args := []string{"-ua", subjsUserAgent, "-s"}
//	cmd := exec.CommandContext(cmdCtx, mantraBin, args...)
//	cmd.Stdin = bytes.NewReader(jsData)
package web

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

// seedMantraWorkspace writes artefacts/urls.jsonl with JS URLs mantra will read.
func seedMantraWorkspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	body := `{"url":"https://api.example.com/static/app.js"}` + "\n" +
		`{"url":"https://www.example.com/js/vendor.js"}` + "\n"
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "urls.jsonl"),
		[]byte(body), 0o600); err != nil {
		t.Fatalf("seed urls.jsonl: %v", err)
	}
	return workDir
}

// newMantraTestApp wires a Runner whose "mantra" entry points at toolPath (empty
// for the unavailable-tool case) through the REAL LocalBackend.
func newMantraTestApp(t *testing.T, workDir, toolPath string) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "mantra", Path: toolPath})
	cfg := config.Defaults()
	cfg.Web.JS.Enabled = true
	tree, err := output.NewTree(workDir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}
}

// TestMantraArgvUnchangedAcrossTheMove asserts the COMPLETE argv slice the
// process received equals the pre-move one, and that the JS URL corpus crossed
// on standard input.
func TestMantraArgvUnchangedAcrossTheMove(t *testing.T) {
	workDir := seedMantraWorkspace(t)
	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "")

	app := newMantraTestApp(t, workDir, script)
	if _, err := (&MantraTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("MantraTask.Run: %v", err)
	}

	want := []string{"-ua", subjsUserAgent, "-s"}
	got := readRecordedArgv(t, recDir)
	if len(got) != len(want) {
		t.Fatalf("argv the process received = %v (%d args), want %v (%d args) — the pre-move "+
			"vector captured from mantra.go at f436d2e", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: got %v, want %v)", i, got[i], want[i], got, want)
		}
	}

	stdin, err := os.ReadFile(filepath.Join(recDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("no standard input reached mantra: %v", err)
	}
	for _, wantURL := range []string{"app.js", "vendor.js"} {
		if !strings.Contains(string(stdin), wantURL) {
			t.Errorf("stdin does not carry %q — got:\n%s", wantURL, stdin)
		}
	}
}

// TestMantraUnavailableToolStatusUnchanged pins the FAILURE POLICY across the
// move. Before 18-04 an absent mantra hit an exec.LookPath gate and returned
// StatusSkipped; a best-effort task that starts returning StatusErrored aborts
// the web pipeline (T-18-04-04). The registry entry has an empty Path, which is
// exactly the shape Discover leaves for a registered-but-uninstalled tool.
func TestMantraUnavailableToolStatusUnchanged(t *testing.T) {
	workDir := seedMantraWorkspace(t)
	app := newMantraTestApp(t, workDir, "")

	res, err := (&MantraTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("MantraTask.Run returned an error for an unavailable tool: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status on an unavailable mantra = %v, want %v — a best-effort task that starts "+
			"returning an errored status aborts the pipeline", res.Status, task.StatusSkipped)
	}
}

// TestHakoriginfinderArgvUnchangedAcrossTheMove asserts the per-host argv and
// the per-host stdin IP, both captured from hakoriginfinder.go at f436d2e:
//
//	cmd := exec.CommandContext(cmdCtx, hakoBin, "-h", "https://"+targetHost)
//	cmd.Stdin = strings.NewReader(inputIP + "\n")
func TestHakoriginfinderArgvUnchangedAcrossTheMove(t *testing.T) {
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		[]byte(`{"host":"api.example.com","ip":"203.0.113.7"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed hosts.jsonl: %v", err)
	}

	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "api.example.com -> 198.51.100.42\n")

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: hakoriginfinderToolName, Path: script})
	cfg := config.Defaults()
	cfg.Web.Probe.Enabled = true
	tree, err := output.NewTree(workDir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}

	res, runErr := (&HakoriginfinderTask{}).Run(context.Background(), app)
	if runErr != nil {
		t.Fatalf("HakoriginfinderTask.Run: %v", runErr)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want %v", res.Status, task.StatusDone)
	}

	want := []string{"-h", "https://api.example.com"}
	got := readRecordedArgv(t, recDir)
	if len(got) != len(want) {
		t.Fatalf("argv the process received = %v, want %v — the pre-move vector", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}

	stdin, sErr := os.ReadFile(filepath.Join(recDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if sErr != nil {
		t.Fatalf("no standard input reached hakoriginfinder: %v", sErr)
	}
	if strings.TrimSpace(string(stdin)) != "203.0.113.7" {
		t.Fatalf("stdin = %q, want the host's own IP %q — per-host attribution (CR-06) depends on it",
			strings.TrimSpace(string(stdin)), "203.0.113.7")
	}

	// And the parse survived: the origin the script printed is attributed to the
	// host whose IP was piped, not to an index guess.
	if got := res.Stats["origins_found"]; got != 1 {
		t.Fatalf("origins_found = %d, want 1 — the tool's stdout was not parsed", got)
	}
}

// TestHakoriginfinderUnavailableToolStatusUnchanged pins the failure policy: an
// unresolvable hakoriginfinder returned StatusSkipped before the move (the
// exec.LookPath gate) and must still, or a best-effort task becomes a pipeline
// abort (T-18-04-04). It must ALSO not publish an empty origins artefact — the
// tool did not run, so the previous run's origins are preserved (F3).
func TestHakoriginfinderUnavailableToolStatusUnchanged(t *testing.T) {
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		[]byte(`{"host":"api.example.com","ip":"203.0.113.7"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed hosts.jsonl: %v", err)
	}
	// A previous run's origins that must survive a run in which the tool is absent.
	originsPath := filepath.Join(workDir, "artefacts", "origins.jsonl")
	if err := os.WriteFile(originsPath,
		[]byte(`{"host":"old.example.com","origin_ip":"198.51.100.1"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed origins.jsonl: %v", err)
	}

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: hakoriginfinderToolName, Path: ""})
	cfg := config.Defaults()
	cfg.Web.Probe.Enabled = true
	tree, err := output.NewTree(workDir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}

	res, runErr := (&HakoriginfinderTask{}).Run(context.Background(), app)
	if runErr != nil {
		t.Fatalf("Run returned an error for an unavailable tool: %v", runErr)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status on an unavailable hakoriginfinder = %v, want %v", res.Status, task.StatusSkipped)
	}
	data, readErr := os.ReadFile(originsPath) //nolint:gosec // test-owned temp path
	if readErr != nil || !strings.Contains(string(data), "old.example.com") {
		t.Fatalf("the previous run's origins were destroyed by a run in which the tool never ran "+
			"(F3 did-not-run must preserve): err=%v content=%q", readErr, data)
	}
}
