// gxss_test.go — the proof that web.gxss came home to backend.Runner (18-04)
// WITHOUT changing the command line Gxss receives.
//
// THE CONTROL IS THE PRE-MOVE ARG VECTOR, captured from gxss.go as it stood at
// f436d2e BEFORE the edit and written down here as a literal:
//
//	exec.CommandContext(cmdCtx, gxssPath, "-c", "100", "-p", "Xss")
//	cmd.Stdin = bytes.NewReader([]byte(strings.Join(fuzzedURLs, "\n") + "\n"))
//
// Deriving the "expected" argv from the post-move code would prove only that the
// code equals itself. gxssWantArgv below is that captured value; if the dispatch
// drifts, these tests fail against a number that predates the drift.
//
// EVERY TEST HERE DRIVES A REAL PROCESS. The registry entry points at a shell
// script in a t.TempDir() that records its own argv and stdin to files, so what
// is asserted is what the operating system actually handed the child — not what
// a mock recorded on the way past.
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

// gxssWantArgv is the PRE-MOVE arg vector, captured from gxss.go before 18-04
// touched it. It is deliberately a literal and not a call to gxssArgs().
var gxssWantArgv = []string{"-c", "100", "-p", "Xss"}

// gxssSeedURLs is the parameterized-URL corpus the Task reads from
// artefacts/urls.jsonl.
var gxssSeedURLs = []string{
	"https://api.example.com/search?q=hello",
	"https://www.example.com/p?id=7&ref=x",
}

// seedGxssWorkspace writes artefacts/urls.jsonl with the seed corpus and returns
// the workspace root.
func seedGxssWorkspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	var b strings.Builder
	for _, u := range gxssSeedURLs {
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

// writeArgvRecorderScript writes a shell script that appends its own argv to
// <dir>/argv.txt (one argument per line) and its whole standard input to
// <dir>/stdin.txt, then writes `stdout` to its own standard output.
//
// It is a REAL executable dispatched by LocalBackend, so the argv and stdin it
// records are the ones the kernel delivered.
func writeArgvRecorderScript(t *testing.T, dir, stdout string) string {
	t.Helper()
	script := filepath.Join(dir, "recorder.sh")
	body := "#!/bin/sh\n" +
		": > '" + filepath.Join(dir, "argv.txt") + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + filepath.Join(dir, "argv.txt") + "'; done\n" +
		"cat > '" + filepath.Join(dir, "stdin.txt") + "'\n" +
		"printf '%s' '" + stdout + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write recorder script: %v", err)
	}
	return script
}

// readRecordedArgv reads the argv the recorder script captured.
func readRecordedArgv(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "argv.txt")) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("the recorder script never wrote argv.txt — the tool was not dispatched at all: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// newGxssTestApp builds an AppContext whose Runner dispatches "Gxss" to the
// given executable through the REAL LocalBackend.
func newGxssTestApp(t *testing.T, workDir, toolPath string, timeout ...time.Duration) *appctx.AppContext {
	t.Helper()
	var toolTimeout time.Duration
	if len(timeout) > 0 {
		toolTimeout = timeout[0]
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: gxssToolName, Path: toolPath, Timeout: toolTimeout})
	cfg := config.Defaults()
	cfg.Web.ParamDiscover.Enabled = true
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
}

// TestGxssArgvUnchangedAcrossTheMove asserts the COMPLETE argv slice the process
// received equals the pre-move one — not a prefix, not a length.
//
// This is the guard against the tools.lock contract silently rewriting a command
// line: applyToolContract prepends Tool.DefaultArgs and Tool.ArgvPrefix, and the
// Gxss row declares neither, so the argv must be byte-for-byte identical.
func TestGxssArgvUnchangedAcrossTheMove(t *testing.T) {
	workDir := seedGxssWorkspace(t)
	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "https://api.example.com/search?q=Xss\n")

	app := newGxssTestApp(t, workDir, script)
	tk := &GxssTask{}
	if _, err := tk.Run(context.Background(), app); err != nil {
		t.Fatalf("GxssTask.Run: %v", err)
	}

	got := readRecordedArgv(t, recDir)
	if len(got) != len(gxssWantArgv) {
		t.Fatalf("argv the process received = %v (%d args), want %v (%d args) — the pre-move "+
			"vector captured from gxss.go at f436d2e", got, len(got), gxssWantArgv, len(gxssWantArgv))
	}
	for i := range gxssWantArgv {
		if got[i] != gxssWantArgv[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: got %v, want %v)",
				i, got[i], gxssWantArgv[i], got, gxssWantArgv)
		}
	}
}

// TestGxssStdinReachesTheTool asserts the FUZZ-replaced URLs cross the seam on
// standard input and that the Task parses what the tool wrote back.
//
// Real process, real pipe, no mock: the script writes its stdin to a file AND
// echoes a reflection line, so both directions are proven in one drive.
func TestGxssStdinReachesTheTool(t *testing.T) {
	workDir := seedGxssWorkspace(t)
	recDir := t.TempDir()
	const reflected = "https://api.example.com/search?q=Xss\n"
	script := writeArgvRecorderScript(t, recDir, reflected)

	app := newGxssTestApp(t, workDir, script)
	tk := &GxssTask{}
	res, err := tk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("GxssTask.Run: %v", err)
	}

	stdin, readErr := os.ReadFile(filepath.Join(recDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if readErr != nil {
		t.Fatalf("the recorder script never wrote stdin.txt — no standard input reached the tool: %v", readErr)
	}
	// The Task FUZZ-replaces every parameter value before piping.
	for _, want := range []string{"q=FUZZ", "id=FUZZ", "ref=FUZZ"} {
		if !strings.Contains(string(stdin), want) {
			t.Errorf("stdin the process received does not contain %q — got:\n%s", want, stdin)
		}
	}
	if strings.Contains(string(stdin), "q=hello") {
		t.Errorf("stdin carries an UNREPLACED parameter value (q=hello) — the FUZZ pass was skipped:\n%s", stdin)
	}

	// And the tool's stdout was parsed back into a finding.
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want %v", res.Status, task.StatusDone)
	}
	if got := res.Stats["xss_reflections"]; got != 1 {
		t.Fatalf("xss_reflections = %d, want 1 — the tool's stdout was not parsed", got)
	}
}

// TestGxssIsRecorded asserts the invocation lands in logs/tools.jsonl.
//
// PRESENCE FIRST, then content. An absence-or-content assertion on a file
// nothing wrote is worthless: it passes for a tool that was never dispatched.
func TestGxssIsRecorded(t *testing.T) {
	workDir := seedGxssWorkspace(t)
	recDir := t.TempDir()
	script := writeArgvRecorderScript(t, recDir, "https://api.example.com/search?q=Xss\n")

	logPath := filepath.Join(workDir, "logs", "tools.jsonl")
	app := newGxssTestApp(t, workDir, script)
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	tk := &GxssTask{}
	if _, err := tk.Run(context.Background(), app); err != nil {
		t.Fatalf("GxssTask.Run: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — Gxss was NOT recorded, which is the entire "+
			"point of the move: %v", err)
	}

	// 1. PRESENCE: a start record naming Gxss exists.
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
		if rec.Tool == gxssToolName && rec.Phase == "start" {
			sawStart = true
			startArgv = rec.Argv
		}
	}
	if !sawStart {
		t.Fatalf("no start record naming %q in logs/tools.jsonl — the tool did not cross the "+
			"recorder seam:\n%s", gxssToolName, data)
	}

	// 2. Only now, content: the recorded argv is the real one.
	if len(startArgv) != len(gxssWantArgv) {
		t.Fatalf("recorded argv = %v, want %v", startArgv, gxssWantArgv)
	}
	for i := range gxssWantArgv {
		if startArgv[i] != gxssWantArgv[i] {
			t.Fatalf("recorded argv[%d] = %q, want %q (full: %v)", i, startArgv[i], gxssWantArgv[i], startArgv)
		}
	}

	// 3. XCUT: the stdin payload must NOT be in the record (18-01's guarantee,
	//    re-asserted at this call site rather than assumed to survive the move).
	if strings.Contains(string(data), "q=FUZZ") {
		t.Errorf("STDIN CONTENT LEAKED INTO logs/tools.jsonl — the FUZZ-replaced URL corpus is "+
			"visible in the invocation record:\n%s", data)
	}
}

// TestGxssTimeoutDoesNotWipePreviousStaging pins the CR-03 fix.
//
// Bringing web.gxss onto backend.Runner removed its local context.WithTimeout —
// the tools.lock row now owns the deadline — and with it the partial-stdout path.
// On a deadline the Runner returns res == nil, so parseGxssOutput sees no bytes,
// `lines` is nil, and output.StageJSONL implements an empty input as os.Remove.
// The PREVIOUS run's reflections were deleted by a run that observed nothing, and
// the task still returned StatusDone.
//
// The file's own header argues the non-zero-EXIT case at length and never
// addressed the DEADLINE case — the one where output is guaranteed to exist.
//
// Observed before the fix:
//
//	PREVIOUS RUN'S STAGING WAS DELETED by a Gxss deadline timeout
func TestGxssTimeoutDoesNotWipePreviousStaging(t *testing.T) {
	workDir := seedGxssWorkspace(t)
	recDir := t.TempDir()

	// A tool that never exits within its deadline.
	script := filepath.Join(recDir, "hang.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write hang script: %v", err)
	}

	app := newGxssTestApp(t, workDir, script, 300*time.Millisecond)

	// A previous run's staged reflections.
	stagingPath := filepath.Join(workDir, "inputs", "findings.gxss.jsonl")
	const previous = `{"url":"https://example.com/?q=PREVIOUS-RUN-REFLECTION","type":"gxss"}`
	if err := os.WriteFile(stagingPath, []byte(previous+"\n"), 0o600); err != nil {
		t.Fatalf("seed previous staging: %v", err)
	}

	if _, err := (&GxssTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("GxssTask.Run: %v", err)
	}

	data, err := os.ReadFile(stagingPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("PREVIOUS RUN'S STAGING WAS DELETED by a Gxss deadline timeout — a run "+
			"that observed nothing has no standing to clear what a previous run "+
			"observed (CR-03): %v", err)
	}
	if !strings.Contains(string(data), "PREVIOUS-RUN-REFLECTION") {
		t.Errorf("the previous run's reflection was overwritten by an incomplete run:\n%s", data)
	}
}

// TestNomore403TimeoutDoesNotWipePreviousStaging and its bypass4xx sibling pin the
// two CR-03 legs that had no test of their own.
//
// The phase's verifier proved both by writing temporary deadline tests, observing
// them pass, removing each `res == nil` guard to watch them fail, and then deleting
// them. Proven-then-deleted is not pinned: nothing would catch a regression here.
// These are the same experiments, kept.
func TestNomore403TimeoutDoesNotWipePreviousStaging(t *testing.T) {
	workDir := seedNomore403Workspace(t)
	recDir := t.TempDir()

	// A clone whose entry point never returns, so the tools.lock deadline is what
	// ends the run — the exact shape CR-03 is about.
	toolsRoot := plantNomore403Clone(t, recDir, "")
	if err := os.WriteFile(filepath.Join(toolsRoot, "nomore403", "nomore403"),
		[]byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("overwrite clone entry with a hanging one: %v", err)
	}

	app := newNomore403TestApp(t, workDir, toolsRoot, 300*time.Millisecond)

	stagingPath := filepath.Join(workDir, "inputs", "findings.nomore403.jsonl")
	const previous = `{"url":"https://example.com/admin","type":"nomore403","evidence":"PREVIOUS-RUN-BYPASS"}`
	if err := os.WriteFile(stagingPath, []byte(previous+"\n"), 0o600); err != nil {
		t.Fatalf("seed previous staging: %v", err)
	}

	if _, err := (&Nomore403Task{}).Run(context.Background(), app); err != nil {
		t.Fatalf("Nomore403Task.Run: %v", err)
	}

	data, err := os.ReadFile(stagingPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("PREVIOUS RUN'S STAGING WAS DELETED by a nomore403 deadline timeout — a run "+
			"that observed nothing has no standing to clear what a previous run "+
			"observed (CR-03): %v", err)
	}
	if !strings.Contains(string(data), "PREVIOUS-RUN-BYPASS") {
		t.Errorf("the previous run's bypass was overwritten by an incomplete run:\n%s", data)
	}
}
