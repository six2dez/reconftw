// wordlistgen_seam_test.go — the proof that the ROBOXTRACTOR LEG of
// web.wordlistgen came home to backend.Runner (18-05) without changing the
// command line, and that the GETJSWORDS LEG deliberately did not.
//
// THE CONTROL IS THE PRE-MOVE ARG VECTOR, captured from wordlistgen.go as it
// stood at f436d2e BEFORE the edit:
//
//	bin, _ := exec.LookPath("roboxtractor")
//	cmd := exec.CommandContext(cmdCtx, bin, "-m", "1", "-wb")
//	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n") + "\n")
//	wordlistgenRoboxTimeout = 120 * time.Second     // == tools.lock
//
// This file is `package web` because it drives the unexported package-var runner
// seam directly — the roboxtractor leg is a `var wordlistgenRoboxtractorRunner`,
// which is its own top-level scope for the bypass walker and its own unit here.
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
)

// roboxtractorWantArgv is the PRE-MOVE arg vector, a literal on purpose.
var roboxtractorWantArgv = []string{"-m", "1", "-wb"}

// newRoboxtractorTestApp points the registry's roboxtractor entry at a script
// that records its own argv and stdin, through the REAL LocalBackend.
func newRoboxtractorTestApp(t *testing.T, toolPath string) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: roboxtractorToolName, Path: toolPath})
	cfg := config.Defaults()
	cfg.Web.Wordlist.Enabled = true
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
	}
}

// TestWordlistgenRoboxtractorArgvUnchangedAcrossTheMove asserts the COMPLETE
// argv slice and the stdin payload the process received.
func TestWordlistgenRoboxtractorArgvUnchangedAcrossTheMove(t *testing.T) {
	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "admin\nsearch\n")
	app := newRoboxtractorTestApp(t, script)

	urls := []string{"https://www.example.com", "https://api.example.com"}
	out, err := wordlistgenRoboxtractorRunner(context.Background(), app, urls)
	if err != nil {
		t.Fatalf("wordlistgenRoboxtractorRunner: %v", err)
	}

	got := readRecordedArgv2(t, recDir)
	if len(got) != len(roboxtractorWantArgv) {
		t.Fatalf("argv the process received = %v (%d args), want %v (%d args) — the pre-move "+
			"vector captured from wordlistgen.go at f436d2e",
			got, len(got), roboxtractorWantArgv, len(roboxtractorWantArgv))
	}
	for i := range roboxtractorWantArgv {
		if got[i] != roboxtractorWantArgv[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: got %v, want %v)",
				i, got[i], roboxtractorWantArgv[i], got, roboxtractorWantArgv)
		}
	}

	stdin, readErr := os.ReadFile(filepath.Join(recDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if readErr != nil {
		t.Fatalf("the recorder script never wrote stdin.txt — no standard input reached "+
			"roboxtractor, which is the ONLY way it receives its targets: %v", readErr)
	}
	for _, want := range urls {
		if !strings.Contains(string(stdin), want) {
			t.Errorf("stdin does not contain %q — got:\n%s", want, stdin)
		}
	}

	// And the tool's stdout came back to the caller for parsing.
	if !strings.Contains(string(out), "admin") {
		t.Fatalf("runner returned %q, want the tool's stdout", out)
	}
}

// TestWordlistgenRoboxtractorIsRecorded asserts the invocation lands in
// logs/tools.jsonl — PRESENCE first, then content — and that the target URL
// corpus on stdin does NOT (XCUT-07, re-asserted at this call site).
func TestWordlistgenRoboxtractorIsRecorded(t *testing.T) {
	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "admin\n")
	app := newRoboxtractorTestApp(t, script)

	logDir := filepath.Join(app.Target.WorkDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	logPath := filepath.Join(logDir, "tools.jsonl")
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	const canary = "https://CANARY-18-05-DO-NOT-RECORD.example.com"
	if _, err := wordlistgenRoboxtractorRunner(context.Background(), app,
		[]string{canary}); err != nil {
		t.Fatalf("wordlistgenRoboxtractorRunner: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — roboxtractor was NOT recorded: %v", err)
	}
	if !strings.Contains(string(data), `"tool":"`+roboxtractorToolName+`"`) {
		t.Fatalf("no record naming %q:\n%s", roboxtractorToolName, data)
	}
	if strings.Contains(string(data), "CANARY-18-05-DO-NOT-RECORD") {
		t.Errorf("STDIN CONTENT LEAKED INTO logs/tools.jsonl — the web target corpus is "+
			"visible in the invocation record:\n%s", data)
	}
}

// TestWordlistgenRoboxtractorSkipsWhenUnresolvable pins the failure policy: the
// runner returned (nil, nil) for a roboxtractor absent from PATH, and it must
// still return (nil, nil) for one the registry cannot resolve. wordlistgen's
// whole contract is that each generator degrades INDEPENDENTLY (T-13-04-02); an
// error here would take the other generator down with it.
func TestWordlistgenRoboxtractorSkipsWhenUnresolvable(t *testing.T) {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: roboxtractorToolName}) // registered, Path empty
	cfg := config.Defaults()
	cfg.Web.Wordlist.Enabled = true
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
	}

	out, err := wordlistgenRoboxtractorRunner(context.Background(), app,
		[]string{"https://www.example.com"})
	if err != nil {
		t.Fatalf("an unresolvable roboxtractor returned an ERROR (%v) — it used to return "+
			"(nil, nil) via the exec.LookPath graceful skip, and wordlistgen's independent-"+
			"degrade contract depends on that", err)
	}
	if out != nil {
		t.Fatalf("an unresolvable roboxtractor returned %q, want nil", out)
	}
}

// TestGetJSWordsStillResolvesItsScriptFromTheNamedToolsRoot pins the OTHER half
// of the getjswords verdict.
//
// The leg stays a declared bypass (see the file header for the adjudication),
// but the thing that made it one of THREE opinions about where the tools live is
// gone: it no longer calls a module-local resolveToolsDir over cfg.Paths.DataDir.
// It reads config.Config.ToolsRoot() over paths.tools_dir — the single name 18-02
// established. This test proves the script path follows paths.tools_dir, which is
// what "collapsed onto one root" has to MEAN to be worth asserting.
func TestGetJSWordsStillResolvesItsScriptFromTheNamedToolsRoot(t *testing.T) {
	toolsRoot := t.TempDir()
	recDir := t.TempDir()

	// A fake python3 that records the argv it is given, and a getjswords.py in
	// the tools root for the runner's os.Stat to find.
	if err := os.WriteFile(filepath.Join(toolsRoot, "getjswords.py"),
		[]byte("# fake\n"), 0o600); err != nil {
		t.Fatalf("write getjswords.py: %v", err)
	}
	python := writeArgvRecorderScript(t, recDir, "word1\nword2\n")

	cfg := config.Defaults()
	cfg.Web.Wordlist.Enabled = true
	cfg.Paths.ToolsDir = toolsRoot
	// DataDir points somewhere ELSE on purpose: the old resolveToolsDir read
	// this key, so a leftover copy would send the script path here and fail.
	cfg.Paths.DataDir = t.TempDir()
	cfg.Web.JS.GetJSWordsPython = python

	app := &appctx.AppContext{
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
	}

	out, err := wordlistgenGetJSWordsRunner(context.Background(), app,
		[]string{"https://cdn.example.com/app.js"})
	if err != nil {
		t.Fatalf("wordlistgenGetJSWordsRunner: %v", err)
	}
	if !strings.Contains(string(out), "word1") {
		t.Fatalf("runner returned %q — the fake interpreter did not run, so the script path "+
			"was not found under paths.tools_dir", out)
	}

	got := readRecordedArgv2(t, recDir)
	wantScript := filepath.Join(toolsRoot, "getjswords.py")
	if len(got) < 1 || got[0] != wantScript {
		t.Fatalf("argv[0] the interpreter received = %v, want %q — the getjswords script must "+
			"resolve under paths.tools_dir (Config.ToolsRoot()), not under paths.data_dir",
			got, wantScript)
	}
}
