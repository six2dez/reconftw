// nomore403_test.go — the proof that web.nomore403 came home to backend.Runner
// (18-05) using ALL THREE of 18-01's capabilities at once: an executable
// resolved from a repo clone, that clone as the working directory, and the
// candidate URLs on standard input.
//
// THE CONTROL IS THE PRE-MOVE INVOCATION, captured from nomore403.go as it
// stood at f436d2e BEFORE the edit:
//
//	toolsDir   := resolveToolsDir(cfg)                       // cfg.Paths.DataDir | $HOME/Tools
//	binaryPath := filepath.Join(toolsDir, "nomore403", "nomore403")
//	cmd := exec.CommandContext(cmdCtx, binaryPath)           // NO ARGUMENTS
//	cmd.Dir   = filepath.Join(toolsDir, "nomore403")
//	cmd.Stdin = bytes.NewReader([]byte(strings.Join(fuzzURLs, "\n") + "\n"))
//	toolTimeout := 300 * time.Second                         // == tools.lock
//
// EVERY TEST HERE DRIVES A REAL PROCESS through the REAL ToolRegistry.Discover
// clone branch and the REAL LocalBackend. The working-directory assertion reads
// what the CHILD PROCESS reported (it prints its own $PWD), never a struct
// field: a Tool.WorkDir that is set but never reaches cmd.Dir would satisfy a
// field check and still leave nomore403 unable to find its payload wordlists.
package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// nomore403WantArgv is the PRE-MOVE arg vector: EMPTY. nomore403 takes its
// target from standard input and the pre-18-05 dispatch passed no arguments at
// all. tools.lock declares default_args = [] and no clone_interpreter for this
// row, so applyToolContract must prepend nothing.
var nomore403WantArgv []string

// nomore403Seed4xx is the fuzz.jsonl corpus: two bypass candidates (4xx, not
// 404) and two records the filter must drop.
var nomore403Seed4xx = []FuzzRecord{
	{URL: "https://api.example.com/admin", Status: 403},
	{URL: "https://api.example.com/private", Status: 401},
	{URL: "https://api.example.com/gone", Status: 404}, // dropped: 404
	{URL: "https://api.example.com/ok", Status: 200},   // dropped: not 4xx
}

// seedNomore403Workspace writes artefacts/fuzz.jsonl and returns the workspace.
func seedNomore403Workspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	var b strings.Builder
	for _, rec := range nomore403Seed4xx {
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal fuzz record: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "fuzz.jsonl"),
		[]byte(b.String()), 0o600); err != nil {
		t.Fatalf("seed fuzz.jsonl: %v", err)
	}
	return workDir
}

// plantNomore403Clone builds a fake tools root holding a clone directory whose
// executable records its own WORKING DIRECTORY, argv and stdin, then prints a
// bypass line.
//
// It writes those files into recDir (OUTSIDE the clone) using absolute paths,
// so the recording itself cannot depend on the cwd it is trying to measure.
// Returns the tools root.
func plantNomore403Clone(t *testing.T, recDir, stdout string) string {
	t.Helper()
	toolsRoot := t.TempDir()
	cloneDir := filepath.Join(toolsRoot, "nomore403")
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		t.Fatalf("mkdir clone dir: %v", err)
	}
	// A "payloads" directory, exactly as the real clone has: what makes this
	// tool need its own cwd in the first place.
	if err := os.MkdirAll(filepath.Join(cloneDir, "payloads"), 0o755); err != nil {
		t.Fatalf("mkdir payloads: %v", err)
	}
	// PATH is emptied in the PARENT so exec.LookPath cannot resolve nomore403 and
	// shadow the clone branch. That empty PATH is inherited by this script, whose
	// `cat` is an external binary — so it restores a minimal one for itself. The
	// first version of this fixture did not, and `cat` silently failed while the
	// `> stdin.txt` redirect still created an empty file: the stdin assertion read
	// "" and blamed the seam for a fixture defect.
	body := "#!/bin/sh\n" +
		"PATH=/bin:/usr/bin; export PATH\n" +
		"pwd > '" + filepath.Join(recDir, "cwd.txt") + "'\n" +
		": > '" + filepath.Join(recDir, "argv.txt") + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + filepath.Join(recDir, "argv.txt") + "'; done\n" +
		"cat > '" + filepath.Join(recDir, "stdin.txt") + "'\n" +
		"printf '%s' '" + stdout + "'\n"
	entry := filepath.Join(cloneDir, "nomore403")
	if err := os.WriteFile(entry, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write clone entry: %v", err)
	}
	return toolsRoot
}

// newNomore403TestApp builds an AppContext whose registry resolves nomore403
// through the REAL clone branch of ToolRegistry.Discover against toolsRoot.
//
// PATH is emptied so LookPath cannot win and shadow the clone — the branch
// under test is the one that only runs when LookPath fails.
func newNomore403TestApp(t *testing.T, workDir, toolsRoot string, timeout ...time.Duration) *appctx.AppContext {
	t.Helper()
	t.Setenv("PATH", "")
	var toolTimeout time.Duration
	if len(timeout) > 0 {
		toolTimeout = timeout[0]
	}

	reg := backend.NewToolRegistry()
	reg.ToolsDir = toolsRoot
	reg.Register(&backend.Tool{
		Name:         nomore403ToolName,
		CloneDir:     "nomore403",
		CloneEntry:   "nomore403",
		CloneWorkDir: true,
		Timeout:      toolTimeout,
	})
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	cfg := config.Defaults()
	cfg.Vulns.Bypass4xx.Enabled = true
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
}

// TestNomore403ResolvesFromItsCloneDirectory is the tracer: the executable comes
// from the clone, the PROCESS runs in the clone directory, and the 4xx
// candidates arrive on standard input — the three capabilities that together
// were this file's reason for bypassing the seam.
func TestNomore403ResolvesFromItsCloneDirectory(t *testing.T) {
	workDir := seedNomore403Workspace(t)
	recDir := t.TempDir()
	toolsRoot := plantNomore403Clone(t, recDir, "https://api.example.com/admin/.\n")

	app := newNomore403TestApp(t, workDir, toolsRoot)
	tk := &Nomore403Task{}
	res, err := tk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Nomore403Task.Run: %v", err)
	}

	// 1. THE WORKING DIRECTORY, as the child process itself reported it. The
	//    clone directory is resolved through EvalSymlinks by Discover (macOS
	//    /var -> /private/var), and `pwd` in the child reports the evaluated
	//    path too, so both sides are compared after evaluation.
	gotCWD, readErr := os.ReadFile(filepath.Join(recDir, "cwd.txt")) //nolint:gosec // test-owned temp path
	if readErr != nil {
		t.Fatalf("the clone entry never wrote cwd.txt — nomore403 was not dispatched at all: %v", readErr)
	}
	wantCWD := filepath.Join(toolsRoot, "nomore403")
	if evaluated, evalErr := filepath.EvalSymlinks(wantCWD); evalErr == nil {
		wantCWD = evaluated
	}
	if got := strings.TrimSpace(string(gotCWD)); got != wantCWD {
		t.Fatalf("the PROCESS reported cwd = %q, want the clone directory %q.\n"+
			"nomore403 resolves its payload wordlists relative to its own directory "+
			"(its banner prints \"Payloads folder: payloads\"), so a dispatch that does "+
			"not land there finds no payloads — silently.", got, wantCWD)
	}

	// 2. THE ARGV: empty, exactly as the pre-move exec.CommandContext(binaryPath).
	gotArgv := readRecordedArgv2(t, recDir)
	if len(gotArgv) != len(nomore403WantArgv) {
		t.Fatalf("argv the process received = %v (%d args), want %v (%d args) — the "+
			"pre-move vector captured from nomore403.go at f436d2e",
			gotArgv, len(gotArgv), nomore403WantArgv, len(nomore403WantArgv))
	}

	// 3. THE STDIN: the 4xx candidates, filtered, newline-joined.
	stdin, readErr := os.ReadFile(filepath.Join(recDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if readErr != nil {
		t.Fatalf("the clone entry never wrote stdin.txt — no standard input reached the tool: %v", readErr)
	}
	for _, want := range []string{"https://api.example.com/admin", "https://api.example.com/private"} {
		if !strings.Contains(string(stdin), want) {
			t.Errorf("stdin the process received does not contain %q — got:\n%s", want, stdin)
		}
	}
	for _, unwanted := range []string{"/gone", "/ok"} {
		if strings.Contains(string(stdin), unwanted) {
			t.Errorf("stdin carries %q, which the 4xx-not-404 filter must drop:\n%s", unwanted, stdin)
		}
	}

	// 4. And the tool's stdout was parsed back into a finding.
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want %v", res.Status, task.StatusDone)
	}
	if got := res.Stats["bypasses"]; got != 1 {
		t.Fatalf("bypasses = %d, want 1 — the tool's stdout was not parsed", got)
	}
}

// readRecordedArgv2 reads the argv a fixture script captured. Separate from
// gxss_test.go's readRecordedArgv only because that one fails hard when the file
// is absent, which several tests here want to distinguish themselves.
func readRecordedArgv2(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "argv.txt")) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("the fixture never wrote argv.txt — the tool was not dispatched at all: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// TestNomore403IsRecorded asserts the invocation lands in logs/tools.jsonl —
// which it never did before 18-05, this file having dispatched outside the
// Runner for its whole life.
//
// PRESENCE FIRST, then content. An absence-or-content assertion over a file
// nothing wrote passes for a tool that was never dispatched.
func TestNomore403IsRecorded(t *testing.T) {
	workDir := seedNomore403Workspace(t)
	recDir := t.TempDir()
	toolsRoot := plantNomore403Clone(t, recDir, "https://api.example.com/admin/.\n")

	logPath := filepath.Join(workDir, "logs", "tools.jsonl")
	app := newNomore403TestApp(t, workDir, toolsRoot)
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	tk := &Nomore403Task{}
	if _, err := tk.Run(context.Background(), app); err != nil {
		t.Fatalf("Nomore403Task.Run: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — nomore403 was NOT recorded, which is the "+
			"entire point of the move: %v", err)
	}

	// 1. PRESENCE: a start record naming nomore403 exists.
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
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("tools.jsonl line is not JSON: %v (%s)", err, line)
		}
		if rec.Tool == nomore403ToolName && rec.Phase == "start" {
			sawStart = true
			startArgv = rec.Argv
		}
	}
	if !sawStart {
		t.Fatalf("no start record naming %q in logs/tools.jsonl — the tool did not cross the "+
			"recorder seam:\n%s", nomore403ToolName, data)
	}

	// 2. Only now, content: the recorded argv is the real (empty) one.
	if len(startArgv) != len(nomore403WantArgv) {
		t.Fatalf("recorded argv = %v, want %v", startArgv, nomore403WantArgv)
	}

	// 3. XCUT: the stdin payload must NOT be in the record. The 4xx URLs a scan
	//    fuzzed out of a target are exactly the kind of thing that must not land
	//    in a file operators paste into issue reports.
	if strings.Contains(string(data), "api.example.com/admin") {
		t.Errorf("STDIN CONTENT LEAKED INTO logs/tools.jsonl — the 4xx candidate corpus is "+
			"visible in the invocation record:\n%s", data)
	}
}

// TestNomore403SkipsWhenUnresolvable pins the FAILURE POLICY across the move.
//
// With an empty tools root AND an empty PATH the tool cannot be resolved at
// all. Before 18-05 the os.Stat probe returned StatusSkipped; after it the
// Runner returns a typed dispatch failure. The STATUS must be identical —
// a best-effort task that starts returning errored aborts the pipeline.
func TestNomore403SkipsWhenUnresolvable(t *testing.T) {
	workDir := seedNomore403Workspace(t)
	t.Setenv("PATH", "")

	reg := backend.NewToolRegistry()
	reg.ToolsDir = t.TempDir() // exists, but holds no nomore403 clone
	reg.Register(&backend.Tool{
		Name:         nomore403ToolName,
		CloneDir:     "nomore403",
		CloneEntry:   "nomore403",
		CloneWorkDir: true,
	})
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	cfg := config.Defaults()
	cfg.Vulns.Bypass4xx.Enabled = true
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}

	tk := &Nomore403Task{}
	res, err := tk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Nomore403Task.Run returned an ERROR for an unresolvable tool: %v — "+
			"a best-effort task must skip, not fail the DAG", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status on an unresolvable nomore403 = %v, want %v — a best-effort task "+
			"that starts returning an errored status aborts the pipeline",
			res.Status, task.StatusSkipped)
	}

	// And nothing was staged: a run in which nomore403 never ran must not clear
	// a previous run's bypasses (F3 did-not-run).
	if _, statErr := os.Stat(filepath.Join(workDir, "inputs", "findings.nomore403.jsonl")); statErr == nil {
		t.Errorf("a staging file was written for a run in which nomore403 never dispatched")
	}
}
