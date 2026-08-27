// jsa_seam_test.go — the proof that web.jsa came home to backend.Runner (18-05)
// with the interpreter-plus-script argv INTACT.
//
// THE CONTROL IS THE PRE-MOVE ARG VECTOR, captured from jsa.go as it stood at
// f436d2e BEFORE the edit:
//
//	jsaPython := filepath.Join(toolsDir, "JSA", "venv", "bin", "python3")
//	jsaScript := filepath.Join(toolsDir, "JSA", "jsa.py")
//	cmd := exec.CommandContext(cmdCtx, jsaPython, jsaScript, "-f", jsURL)
//
// So the process must receive, in this order: the script path, "-f", the URL —
// with the interpreter as argv[0]. The script comes from Tool.ArgvPrefix, which
// applyToolContract prepends. THE WHOLE SLICE IS ASSERTED. A prefix check or a
// length check would pass with the script missing, and a python3 handed "-f"
// where it expects a script path is precisely the failure ArgvPrefix exists to
// prevent.
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

// jsaSeedJSURLs is the JS corpus JsaTask reads from artefacts/urls.jsonl.
var jsaSeedJSURLs = []string{"https://cdn.example.com/app.js"}

// seedJsaWorkspace writes artefacts/urls.jsonl with one JS URL.
func seedJsaWorkspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	var b strings.Builder
	for _, u := range jsaSeedJSURLs {
		line, err := json.Marshal(struct {
			URL string `json:"url"`
		}{URL: u})
		if err != nil {
			t.Fatalf("marshal seed url: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "urls.jsonl"),
		[]byte(b.String()), 0o600); err != nil {
		t.Fatalf("seed urls.jsonl: %v", err)
	}
	return workDir
}

// plantJsaClone builds a fake tools root holding JSA/venv/bin/python3 (a script
// that records its own argv) and JSA/jsa.py (a real file, because Discover
// os.Stats the entry). Returns the tools root.
func plantJsaClone(t *testing.T, recDir, stdout string) string {
	t.Helper()
	toolsRoot := t.TempDir()
	cloneDir := filepath.Join(toolsRoot, "JSA")
	if err := os.MkdirAll(filepath.Join(cloneDir, "venv", "bin"), 0o755); err != nil {
		t.Fatalf("mkdir venv/bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cloneDir, "jsa.py"),
		[]byte("# fake jsa.py\n"), 0o600); err != nil {
		t.Fatalf("write jsa.py: %v", err)
	}
	// The fake interpreter restores a minimal PATH for its own `cat`-free body;
	// the parent empties PATH so LookPath cannot shadow the clone.
	body := "#!/bin/sh\n" +
		"PATH=/bin:/usr/bin; export PATH\n" +
		": > '" + filepath.Join(recDir, "argv.txt") + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + filepath.Join(recDir, "argv.txt") + "'; done\n" +
		"printf '%s' '" + stdout + "'\n"
	interp := filepath.Join(cloneDir, "venv", "bin", "python3")
	if err := os.WriteFile(interp, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write fake interpreter: %v", err)
	}
	return toolsRoot
}

// newJsaTestApp resolves JSA through the REAL clone branch of Discover.
func newJsaTestApp(t *testing.T, workDir, toolsRoot string) *appctx.AppContext {
	t.Helper()
	t.Setenv("PATH", "")

	reg := backend.NewToolRegistry()
	reg.ToolsDir = toolsRoot
	reg.Register(&backend.Tool{
		Name:             jsaToolName,
		CloneDir:         "JSA",
		CloneInterpreter: "venv/bin/python3",
		CloneEntry:       "jsa.py",
	})
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	cfg := config.Defaults()
	cfg.Web.JS.Enabled = true
	cfg.Concurrency.MaxJobs = 2
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
}

// TestJsaArgvIncludesTheScriptPrefix asserts the FULL argv the fake interpreter
// received: the script, then "-f", then the URL — in that order.
func TestJsaArgvIncludesTheScriptPrefix(t *testing.T) {
	workDir := seedJsaWorkspace(t)
	recDir := t.TempDir()
	toolsRoot := plantJsaClone(t, recDir, "https://cdn.example.com/api/v1/users\n")

	app := newJsaTestApp(t, workDir, toolsRoot)
	if _, err := (&JsaTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("JsaTask.Run: %v", err)
	}

	got := readRecordedArgv2(t, recDir)
	// The clone directory is symlink-evaluated by Discover, so the script path in
	// argv is the evaluated one.
	wantScript := filepath.Join(toolsRoot, "JSA", "jsa.py")
	if evaluated, err := filepath.EvalSymlinks(filepath.Join(toolsRoot, "JSA")); err == nil {
		wantScript = filepath.Join(evaluated, "jsa.py")
	}
	want := []string{wantScript, "-f", jsaSeedJSURLs[0]}

	if len(got) != len(want) {
		t.Fatalf("argv the interpreter received = %v (%d args), want %v (%d args).\n"+
			"The SCRIPT is argv[0] here and it comes from Tool.ArgvPrefix; without it "+
			"python3 is handed \"-f\" where it expects a file to run.",
			got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: got %v, want %v)", i, got[i], want[i], got, want)
		}
	}
}

// TestJsaIsRecorded asserts the per-URL invocation lands in logs/tools.jsonl.
// PRESENCE FIRST, then content.
func TestJsaIsRecorded(t *testing.T) {
	workDir := seedJsaWorkspace(t)
	recDir := t.TempDir()
	toolsRoot := plantJsaClone(t, recDir, "https://cdn.example.com/api/v1/users\n")

	logPath := filepath.Join(workDir, "logs", "tools.jsonl")
	app := newJsaTestApp(t, workDir, toolsRoot)
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	if _, err := (&JsaTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("JsaTask.Run: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — JSA was NOT recorded, which is the "+
			"entire point of the move: %v", err)
	}
	var sawStart bool
	var startArgv []string
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
		if rec.Tool == jsaToolName && rec.Phase == "start" {
			sawStart, startArgv = true, rec.Argv
		}
	}
	if !sawStart {
		t.Fatalf("no start record naming %q in logs/tools.jsonl:\n%s", jsaToolName, data)
	}
	// The recorded argv is the one the process got, script included.
	if len(startArgv) != 3 || startArgv[1] != "-f" || startArgv[2] != jsaSeedJSURLs[0] {
		t.Fatalf("recorded argv = %v, want [<jsa.py> -f %s]", startArgv, jsaSeedJSURLs[0])
	}
	if !strings.HasSuffix(startArgv[0], "jsa.py") {
		t.Fatalf("recorded argv[0] = %q, want a path ending in jsa.py — the ArgvPrefix is "+
			"missing from the RECORD even if it reached the process", startArgv[0])
	}
}

// TestJsaSkipsWhenUnresolvable pins the FAILURE POLICY across the move.
//
// Before 18-05 an absent venv or jsa.py was caught by an os.Stat probe and the
// Task returned StatusSkipped BEFORE reading any URL. After the move there is no
// probe, so the same status has to fall out of the dispatch — otherwise an
// uninstalled JSA would report StatusDone over zero results, which is a tool
// that silently produced nothing dressed up as a clean run.
func TestJsaSkipsWhenUnresolvable(t *testing.T) {
	workDir := seedJsaWorkspace(t)
	t.Setenv("PATH", "")

	reg := backend.NewToolRegistry()
	reg.ToolsDir = t.TempDir() // exists, holds no JSA clone
	reg.Register(&backend.Tool{
		Name:             jsaToolName,
		CloneDir:         "JSA",
		CloneInterpreter: "venv/bin/python3",
		CloneEntry:       "jsa.py",
	})
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	cfg := config.Defaults()
	cfg.Web.JS.Enabled = true
	cfg.Concurrency.MaxJobs = 2
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}

	res, err := (&JsaTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("JsaTask.Run returned an ERROR for an unresolvable tool: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status on an unresolvable JSA = %v, want %v — an uninstalled tool must not "+
			"report a clean run over zero results", res.Status, task.StatusSkipped)
	}
	if _, statErr := os.Stat(filepath.Join(workDir, "inputs", "urls.jsa.jsonl")); statErr == nil {
		t.Errorf("a staging file was written for a run in which JSA never dispatched — that " +
			"would let the urls merge clear a previous run's JSA output (F3 did-not-run)")
	}
}

// TestJsaUnresolvableMidRunDoesNotPublishATruncatedCorpus pins the WR-07 fix.
//
// The skip condition also required len(allRecords) == 0. If a handful of the
// per-URL goroutines finished before the unresolvable latch was set, the task fell
// through to StageJSONL with a PARTIAL corpus and overwrote the previous run's
// COMPLETE one. The comment claimed "a run in which JSA never executed cannot
// clear a previous run's URLs (F3 did-not-run)" — true only for the
// all-or-nothing case, and a partial run is precisely the one that destroys more
// than it replaces.
//
// The clone here serves the first invocation and then removes its own entry
// point, so later goroutines get a genuine NeverStarted while earlier ones have
// already produced records.
func TestJsaUnresolvableMidRunDoesNotPublishATruncatedCorpus(t *testing.T) {
	recDir := t.TempDir()
	toolsRoot := plantJsaClone(t, recDir, "https://example.com/from-jsa.js\n")

	// TWO JS URLs, not the single-URL fixture: one goroutine must SUCCEED before
	// another hits the unresolvable latch, or the partial-corpus case this test is
	// named for never occurs and the test passes with the bug reintroduced.
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	corpus := `{"url":"https://cdn.example.com/app.js"}` + "\n" +
		`{"url":"https://cdn.example.com/vendor.js"}` + "\n"
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "urls.jsonl"),
		[]byte(corpus), 0o600); err != nil {
		t.Fatalf("seed urls.jsonl: %v", err)
	}

	entry := filepath.Join(toolsRoot, "JSA", "venv", "bin", "python3")
	// PATH is emptied in the parent so LookPath cannot shadow the clone; this
	// script restores a minimal one for its own `rm`, exactly as plantJsaClone
	// does for its `cat`. Without that the removal silently no-ops and the second
	// dispatch succeeds, so the partial case never happens and the test is vacuous.
	body := "#!/bin/sh\n" +
		"PATH=/bin:/usr/bin; export PATH\n" +
		"printf 'https://example.com/partial-record.js\\n'\n" +
		"rm -f '" + entry + "'\n"
	if err := os.WriteFile(entry, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("overwrite clone entry: %v", err)
	}

	stagingPath := filepath.Join(workDir, "inputs", "urls.jsa.jsonl")
	const previous = `{"url":"https://example.com/PREVIOUS-COMPLETE-CORPUS.js"}`
	if err := os.WriteFile(stagingPath, []byte(previous+"\n"), 0o600); err != nil {
		t.Fatalf("seed previous staging: %v", err)
	}

	app := newJsaTestApp(t, workDir, toolsRoot)
	// MaxJobs = 1 makes the per-URL loop STRICTLY SEQUENTIAL, which is what makes
	// this test deterministic instead of a race: the first URL is served and the
	// entry point removes itself, so the second URL is guaranteed to hit a genuine
	// NeverStarted with records already collected. With the default concurrency
	// both goroutines start before the removal and the partial case never occurs.
	app.Cfg.Concurrency.MaxJobs = 1

	res, err := (&JsaTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("JsaTask.Run: %v", err)
	}
	if !res.Incomplete {
		t.Fatal("the truncated JSA run was checkpointable as done — preserving staging is not enough if the retry is skipped forever (V-04)")
	}

	data, err := os.ReadFile(stagingPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("the previous run's complete corpus was DELETED by a run that could not "+
			"finish (WR-07): %v", err)
	}
	if !strings.Contains(string(data), "PREVIOUS-COMPLETE-CORPUS") {
		t.Errorf("A TRUNCATED CORPUS OVERWROTE THE COMPLETE ONE — JSA became unresolvable "+
			"mid-run, so this run has no standing to replace a corpus it never "+
			"finished collecting (WR-07):\n%s", data)
	}
}
