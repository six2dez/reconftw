// bypass4xx_seam_test.go — the proof that vulns.bypass4xx came home to
// backend.Runner (18-05) AND that it now resolves nomore403 by the same path
// web.nomore403 does.
//
// THE CONTROL IS THE PRE-MOVE INVOCATION, captured from bypass4xx.go as it stood
// at f436d2e BEFORE the edit:
//
//	toolsDir   := resolveToolsDirVulns(cfg)              // cfg.Paths.DataDir | $HOME/Tools
//	binaryPath := filepath.Join(toolsDir, "nomore403", "nomore403")
//	cmd := exec.CommandContext(cmdCtx, binaryPath)       // NO ARGUMENTS
//	cmd.Dir   = filepath.Join(toolsDir, "nomore403")
//	cmd.Stdin = bytes.NewReader([]byte(strings.Join(fuzzURLs, "\n") + "\n"))
//	toolTimeout := 300 * time.Second                     // == tools.lock
//
// THIS FILE IS `package vulns_test` AND IT IMPORTS `web` ON PURPOSE. The point of
// moving these two files together is that they stop being two independent
// opinions about where one binary lives, and the only way to ASSERT that is to
// drive both Tasks against one registry and compare what the two processes
// reported. `web` does not import `vulns`, so the direction is safe.
package vulns_test

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
	"github.com/six2dez/reconftw/internal/modules/vulns"
	"github.com/six2dez/reconftw/internal/modules/web"
)

// bypass4xxSeed4xx is the fuzz.jsonl corpus: two bypass candidates and two the
// 4xx-not-404 filter must drop.
var bypass4xxSeed4xx = []struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}{
	{"https://api.example.com/admin", 403},
	{"https://api.example.com/private", 401},
	{"https://api.example.com/gone", 404},
	{"https://api.example.com/ok", 200},
}

func seedBypass4xxWorkspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	var b strings.Builder
	for _, rec := range bypass4xxSeed4xx {
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
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

// plantNomore403CloneForVulns mirrors the web-package fixture: a clone whose
// executable records the path it was invoked as, its cwd, its argv and its
// stdin, all into recDir with absolute paths.
func plantNomore403CloneForVulns(t *testing.T, recDir, stdout string) string {
	t.Helper()
	toolsRoot := t.TempDir()
	cloneDir := filepath.Join(toolsRoot, "nomore403")
	if err := os.MkdirAll(filepath.Join(cloneDir, "payloads"), 0o755); err != nil {
		t.Fatalf("mkdir clone: %v", err)
	}
	body := "#!/bin/sh\n" +
		"PATH=/bin:/usr/bin; export PATH\n" +
		"printf '%s\\n' \"$0\" > '" + filepath.Join(recDir, "self.txt") + "'\n" +
		"pwd > '" + filepath.Join(recDir, "cwd.txt") + "'\n" +
		": > '" + filepath.Join(recDir, "argv.txt") + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + filepath.Join(recDir, "argv.txt") + "'; done\n" +
		"cat > '" + filepath.Join(recDir, "stdin.txt") + "'\n" +
		"printf '%s' '" + stdout + "'\n"
	if err := os.WriteFile(filepath.Join(cloneDir, "nomore403"), []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write clone entry: %v", err)
	}
	return toolsRoot
}

// newNomore403Registry resolves nomore403 through the REAL clone branch.
func newNomore403Registry(t *testing.T, toolsRoot string, timeout ...time.Duration) *backend.ToolRegistry {
	t.Helper()
	var toolTimeout time.Duration
	if len(timeout) > 0 {
		toolTimeout = timeout[0]
	}
	reg := backend.NewToolRegistry()
	reg.ToolsDir = toolsRoot
	reg.Register(&backend.Tool{
		Name:         "nomore403",
		CloneDir:     "nomore403",
		CloneEntry:   "nomore403",
		CloneWorkDir: true,
		Timeout:      toolTimeout,
	})
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return reg
}

func newBypass4xxApp(t *testing.T, workDir string, reg *backend.ToolRegistry) *appctx.AppContext {
	t.Helper()
	cfg := config.Defaults()
	cfg.Vulns.Bypass4xx.Enabled = true
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("the fixture never wrote %s — the tool was not dispatched at all: %v", path, err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// TestBypass4xxResolvesFromItsCloneDirectory is the vulns-side mirror of
// TestNomore403ResolvesFromItsCloneDirectory: clone-resolved executable, clone
// as cwd, candidates on stdin, empty argv.
func TestBypass4xxResolvesFromItsCloneDirectory(t *testing.T) {
	t.Setenv("PATH", "")
	workDir := seedBypass4xxWorkspace(t)
	recDir := t.TempDir()
	toolsRoot := plantNomore403CloneForVulns(t, recDir, "https://api.example.com/admin/.\n")

	app := newBypass4xxApp(t, workDir, newNomore403Registry(t, toolsRoot))
	res, err := (&vulns.Bypass4xxTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Bypass4xxTask.Run: %v", err)
	}

	wantCWD := filepath.Join(toolsRoot, "nomore403")
	if evaluated, evalErr := filepath.EvalSymlinks(wantCWD); evalErr == nil {
		wantCWD = evaluated
	}
	if got := readLines(t, filepath.Join(recDir, "cwd.txt")); len(got) != 1 || got[0] != wantCWD {
		t.Fatalf("the PROCESS reported cwd = %v, want the clone directory %q — nomore403 "+
			"resolves its payload wordlists relative to its own directory", got, wantCWD)
	}
	if got := readLines(t, filepath.Join(recDir, "argv.txt")); len(got) != 0 {
		t.Fatalf("argv the process received = %v, want [] — the pre-move vector was "+
			"exec.CommandContext(cmdCtx, binaryPath) with no arguments", got)
	}
	stdin, readErr := os.ReadFile(filepath.Join(recDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if readErr != nil {
		t.Fatalf("no standard input reached the tool: %v", readErr)
	}
	for _, want := range []string{"/admin", "/private"} {
		if !strings.Contains(string(stdin), want) {
			t.Errorf("stdin does not contain %q — got:\n%s", want, stdin)
		}
	}
	for _, unwanted := range []string{"/gone", "/ok"} {
		if strings.Contains(string(stdin), unwanted) {
			t.Errorf("stdin carries %q, which the 4xx-not-404 filter must drop:\n%s", unwanted, stdin)
		}
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want %v", res.Status, task.StatusDone)
	}
}

// TestBypass4xxSkipsWhenUnresolvable pins the failure policy across the move.
func TestBypass4xxSkipsWhenUnresolvable(t *testing.T) {
	t.Setenv("PATH", "")
	workDir := seedBypass4xxWorkspace(t)

	reg := backend.NewToolRegistry()
	reg.ToolsDir = t.TempDir() // exists, holds no clone
	reg.Register(&backend.Tool{
		Name: "nomore403", CloneDir: "nomore403", CloneEntry: "nomore403", CloneWorkDir: true,
	})
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	app := newBypass4xxApp(t, workDir, reg)
	res, err := (&vulns.Bypass4xxTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Bypass4xxTask.Run returned an ERROR for an unresolvable tool: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status on an unresolvable nomore403 = %v, want %v", res.Status, task.StatusSkipped)
	}
	if _, statErr := os.Stat(filepath.Join(workDir, "inputs", "findings.bypass4xx.jsonl")); statErr == nil {
		t.Errorf("a staging file was written for a run in which nomore403 never dispatched — " +
			"that lets the findings merge clear a previous run's bypasses (F3 did-not-run)")
	}
}

// TestBypass4xxAndNomore403ResolveTheSameBinary is the point of doing these two
// files together.
//
// Before 18-05, web/nomore403.go joined the tools root through
// web.resolveToolsDir and vulns/bypass4xx.go joined it through
// vulns.resolveToolsDirVulns — two module-local copies of one decision, which is
// how two call sites for one tool drift apart. Both now ask the registry.
//
// THE ASSERTION IS ON WHAT THE TWO PROCESSES REPORTED ($0), not on a struct
// field: a registry that resolved one path while a module still executed
// another would satisfy a field comparison and fail this one.
func TestBypass4xxAndNomore403ResolveTheSameBinary(t *testing.T) {
	t.Setenv("PATH", "")

	recDir := t.TempDir()
	toolsRoot := plantNomore403CloneForVulns(t, recDir, "https://api.example.com/admin/.\n")
	reg := newNomore403Registry(t, toolsRoot)

	// Leg 1: the vulns Task.
	vulnsApp := newBypass4xxApp(t, seedBypass4xxWorkspace(t), reg)
	if _, err := (&vulns.Bypass4xxTask{}).Run(context.Background(), vulnsApp); err != nil {
		t.Fatalf("Bypass4xxTask.Run: %v", err)
	}
	vulnsSelf := readLines(t, filepath.Join(recDir, "self.txt"))
	vulnsCWD := readLines(t, filepath.Join(recDir, "cwd.txt"))

	// Leg 2: the web Task, against THE SAME registry.
	webWork := seedBypass4xxWorkspace(t) // same fuzz.jsonl shape; web reads the same file
	webCfg := config.Defaults()
	webCfg.Vulns.Bypass4xx.Enabled = true
	webApp := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    webCfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: webWork},
	}
	if _, err := (&web.Nomore403Task{}).Run(context.Background(), webApp); err != nil {
		t.Fatalf("Nomore403Task.Run: %v", err)
	}
	webSelf := readLines(t, filepath.Join(recDir, "self.txt"))
	webCWD := readLines(t, filepath.Join(recDir, "cwd.txt"))

	if len(vulnsSelf) != 1 || len(webSelf) != 1 {
		t.Fatalf("one of the two Tasks did not dispatch: vulns=%v web=%v", vulnsSelf, webSelf)
	}
	if vulnsSelf[0] != webSelf[0] {
		t.Fatalf("THE TWO MODULES EXECUTED DIFFERENT BINARIES for one tool.\n"+
			"  vulns.bypass4xx ran %q\n"+
			"  web.nomore403   ran %q\n"+
			"Two modules independently deciding where a binary lives is how they drifted; "+
			"after 18-05 both must ask the registry.", vulnsSelf[0], webSelf[0])
	}
	if len(vulnsCWD) != 1 || len(webCWD) != 1 || vulnsCWD[0] != webCWD[0] {
		t.Fatalf("THE TWO MODULES RAN THE TOOL IN DIFFERENT DIRECTORIES: vulns=%v web=%v — "+
			"the working directory comes from Tool.WorkDir and must be identical for both",
			vulnsCWD, webCWD)
	}
	t.Logf("both modules executed %s in %s", webSelf[0], webCWD[0])
}

// TestBypass4xxTimeoutDoesNotWipePreviousStaging pins the third CR-03 leg.
//
// Like the nomore403 one, the phase's verifier proved this by writing a temporary
// deadline test, watching it fail with the `res == nil` guard removed, and then
// deleting it. Proven-then-deleted is not pinned — this keeps the experiment.
func TestBypass4xxTimeoutDoesNotWipePreviousStaging(t *testing.T) {
	workDir := seedBypass4xxWorkspace(t)
	recDir := t.TempDir()

	// A clone entry point that never returns, so the tools.lock deadline ends it.
	toolsRoot := plantNomore403CloneForVulns(t, recDir, "")
	if err := os.WriteFile(filepath.Join(toolsRoot, "nomore403", "nomore403"),
		[]byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("overwrite clone entry with a hanging one: %v", err)
	}

	reg := newNomore403Registry(t, toolsRoot, 300*time.Millisecond)

	app := newBypass4xxApp(t, workDir, reg)

	stagingPath := filepath.Join(workDir, "inputs", "findings.bypass4xx.jsonl")
	const previous = `{"url":"https://example.com/admin","type":"bypass4xx","evidence":"PREVIOUS-RUN-BYPASS"}`
	if err := os.MkdirAll(filepath.Dir(stagingPath), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(stagingPath, []byte(previous+"\n"), 0o600); err != nil {
		t.Fatalf("seed previous staging: %v", err)
	}

	if _, err := (&vulns.Bypass4xxTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("Bypass4xxTask.Run: %v", err)
	}

	data, err := os.ReadFile(stagingPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("PREVIOUS RUN'S STAGING WAS DELETED by a bypass4xx deadline timeout — a run "+
			"that observed nothing has no standing to clear what a previous run "+
			"observed (CR-03): %v", err)
	}
	if !strings.Contains(string(data), "PREVIOUS-RUN-BYPASS") {
		t.Errorf("the previous run's bypass was overwritten by an incomplete run:\n%s", data)
	}
}
