// xss_seam_test.go — the proof that BOTH of vulns/xss.go's dispatch sites came
// home to backend.Runner (18-04) with their command lines unchanged.
//
// THE CONTROLS ARE THE PRE-MOVE ARG VECTORS, captured from xss.go as it stood at
// f436d2e BEFORE the edit.
//
// site A — dalfox pipe mode (now StreamOpts, because dalfox exits non-zero WHEN
// IT HAS FINDINGS and the buffered path discards stdout on a non-zero exit):
//
//	args := []string{"pipe", "--silence", "--no-color", "--no-spinner",
//	                 "--only-poc", "r", "--ignore-return", "302,404,403",
//	                 "--skip-bav", "-w", <threads>, "-d", <depth>}
//	cmd.Stdin = bytes.NewReader([]byte(strings.Join(reflectedLines, "\n") + "\n"))
//
// site B — the Gxss reflection pre-pass (was gxssCmd.Output(), a shape the
// FOUND-10 walker does not even count):
//
//	gxssCmd := exec.CommandContext(ctx, gxssPath, "-c", "100", "-p", "Xss")
//	gxssCmd.Stdin = bytes.NewReader(fuzzed)
//
// Every test drives a REAL process through a temp script that records its own
// argv and stdin, so what is asserted is what the kernel handed the child.
package vulns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// xssWantDalfoxArgv is the PRE-MOVE dalfox arg vector for the default config
// (no XSS_SERVER, threads 5, depth 2). Deliberately a literal, not a call into
// the code under test.
var xssWantDalfoxArgv = []string{
	"pipe", "--silence", "--no-color", "--no-spinner",
	"--only-poc", "r", "--ignore-return", "302,404,403", "--skip-bav",
	"-w", "5", "-d", "2",
}

// xssWantGxssArgv is the PRE-MOVE reflection pre-pass arg vector.
var xssWantGxssArgv = []string{"-c", "100", "-p", "Xss"}

// writeSeamRecorderScript writes a shell script that records its own argv (one
// argument per line) to <dir>/argv.txt and its whole standard input to
// <dir>/stdin.txt, then prints `stdout`.
func writeSeamRecorderScript(t *testing.T, dir, stdout string) string {
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

// readSeamArgv reads the argv a recorder script captured, failing loudly when
// the script never ran at all.
func readSeamArgv(t *testing.T, dir string) []string {
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

func assertArgvExactly(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: argv the process received = %v (%d args), want %v (%d args) — the pre-move "+
			"vector captured at f436d2e", label, got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: argv[%d] = %q, want %q (full: got %v, want %v)", label, i, got[i], want[i], got, want)
		}
	}
}

// seedXSSWorkspace writes the gf/xss.txt bucket XSSTask reads.
func seedXSSWorkspace(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"inputs/gf", "artefacts", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	bucket := "https://api.example.com/search?q=hello\nhttps://www.example.com/p?id=7\n"
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "gf", "xss.txt"),
		[]byte(bucket), 0o600); err != nil {
		t.Fatalf("seed gf/xss.txt: %v", err)
	}
	return workDir
}

// newXSSSeamApp wires a Runner where "Gxss" and "dalfox" resolve to the given
// paths, through the REAL LocalBackend. An empty path is the shape Discover
// leaves for a registered-but-uninstalled tool.
func newXSSSeamApp(t *testing.T, workDir, gxssPath, dalfoxPath string) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "Gxss", Path: gxssPath})
	reg.Register(&backend.Tool{Name: "dalfox", Path: dalfoxPath})
	cfg := config.Defaults()
	cfg.Vulns.XSS.Enabled = true
	cfg.Vulns.XSS.Threads = 5
	cfg.Advanced.Deep = false
	cfg.APIKeys.XSSServer = ""
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

// TestXssGxssSiteArgvUnchangedAcrossTheMove asserts the reflection pre-pass's
// COMPLETE argv and that the FUZZ-replaced corpus crossed on standard input.
//
// This site used gxssCmd.Output(), which is NOT in the FOUND-10 walker's
// forbidden-pattern set — no census number would have complained had it been
// left behind. It is pinned here precisely because nothing else would.
func TestXssGxssSiteArgvUnchangedAcrossTheMove(t *testing.T) {
	workDir := seedXSSWorkspace(t)
	gxssDir := t.TempDir()
	dalfoxDir := t.TempDir()
	// Gxss echoes one reflected candidate so the pipeline reaches dalfox.
	gxss := writeSeamRecorderScript(t, gxssDir, "https://api.example.com/search?q=FUZZ\n")
	dalfox := writeSeamRecorderScript(t, dalfoxDir, "")

	app := newXSSSeamApp(t, workDir, gxss, dalfox)
	if _, err := (&XSSTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("XSSTask.Run: %v", err)
	}

	assertArgvExactly(t, "Gxss reflection pre-pass", readSeamArgv(t, gxssDir), xssWantGxssArgv)

	stdin, err := os.ReadFile(filepath.Join(gxssDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("no standard input reached the Gxss pre-pass: %v", err)
	}
	if !strings.Contains(string(stdin), "q=FUZZ") {
		t.Errorf("stdin does not carry the FUZZ-replaced corpus — got:\n%s", stdin)
	}
	if strings.Contains(string(stdin), "q=hello") {
		t.Errorf("stdin carries an UNREPLACED parameter value — the FUZZ pass was skipped:\n%s", stdin)
	}
}

// TestDalfoxArgvUnchangedAcrossTheMove asserts dalfox's COMPLETE argv and that
// the reflected candidates crossed on standard input — through StreamOpts, the
// streaming path the XCUT-09 heartbeat requires.
func TestDalfoxArgvUnchangedAcrossTheMove(t *testing.T) {
	workDir := seedXSSWorkspace(t)
	gxssDir := t.TempDir()
	dalfoxDir := t.TempDir()
	gxss := writeSeamRecorderScript(t, gxssDir, "https://api.example.com/search?q=FUZZ\n")
	dalfox := writeSeamRecorderScript(t, dalfoxDir, "https://api.example.com/search?q=<poc>\n")

	app := newXSSSeamApp(t, workDir, gxss, dalfox)
	res, err := (&XSSTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("XSSTask.Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want %v", res.Status, task.StatusDone)
	}

	assertArgvExactly(t, "dalfox pipe", readSeamArgv(t, dalfoxDir), xssWantDalfoxArgv)

	stdin, sErr := os.ReadFile(filepath.Join(dalfoxDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if sErr != nil {
		t.Fatalf("no standard input reached dalfox: %v", sErr)
	}
	if !strings.Contains(string(stdin), "FUZZ") {
		t.Errorf("dalfox stdin does not carry the reflected candidates — got:\n%s", stdin)
	}

	// The streamed PoC line became a finding: proof the streaming path carries
	// output, not just that it opened.
	if got := res.Stats["findings"]; got != 1 {
		t.Fatalf("findings = %d, want 1 — dalfox's streamed stdout was not collected", got)
	}
}

// TestXssUnavailableToolStatusUnchanged pins the FAILURE POLICY for both sites
// across the move (T-18-04-04).
//
//   - dalfox absent  → StatusSkipped, exactly what its exec.LookPath gate gave.
//   - Gxss absent    → the reflection filter falls back to the FUZZ-replaced
//     URLs, exactly what its exec.LookPath fallback gave, so the task carries on
//     to dalfox rather than skipping.
func TestXssUnavailableToolStatusUnchanged(t *testing.T) {
	t.Run("dalfox absent skips", func(t *testing.T) {
		workDir := seedXSSWorkspace(t)
		gxssDir := t.TempDir()
		gxss := writeSeamRecorderScript(t, gxssDir, "https://api.example.com/search?q=FUZZ\n")

		app := newXSSSeamApp(t, workDir, gxss, "")
		res, err := (&XSSTask{}).Run(context.Background(), app)
		if err != nil {
			t.Fatalf("Run returned an error for an unavailable dalfox: %v", err)
		}
		if res.Status != task.StatusSkipped {
			t.Fatalf("status on an unavailable dalfox = %v, want %v — a best-effort task that "+
				"starts returning an errored status aborts the vulns pipeline", res.Status, task.StatusSkipped)
		}
		if _, statErr := os.Stat(filepath.Join(workDir, "inputs", "findings.xss.jsonl")); statErr == nil {
			t.Error("a run in which dalfox never started wrote the findings staging file — " +
				"F3 did-not-run must preserve the previous run's findings")
		}
	})

	t.Run("Gxss absent falls back to the fuzzed corpus", func(t *testing.T) {
		workDir := seedXSSWorkspace(t)
		dalfoxDir := t.TempDir()
		dalfox := writeSeamRecorderScript(t, dalfoxDir, "")

		app := newXSSSeamApp(t, workDir, "", dalfox)
		res, err := (&XSSTask{}).Run(context.Background(), app)
		if err != nil {
			t.Fatalf("Run returned an error for an unavailable Gxss: %v", err)
		}
		if res.Status != task.StatusDone {
			t.Fatalf("status with Gxss absent = %v, want %v — the pre-pass is best-effort and the "+
				"task must carry on to dalfox with the FUZZ-replaced corpus", res.Status, task.StatusDone)
		}
		stdin, sErr := os.ReadFile(filepath.Join(dalfoxDir, "stdin.txt")) //nolint:gosec // test-owned temp path
		if sErr != nil {
			t.Fatalf("dalfox was not reached at all when Gxss was absent: %v", sErr)
		}
		if !strings.Contains(string(stdin), "FUZZ") {
			t.Errorf("dalfox did not receive the fallback FUZZ corpus — got:\n%s", stdin)
		}
	})
}

// TestGxssTimeoutFallsBackToUnfilteredCorpus pins the WR-05 fix.
//
// This site used gxssCmd.Output(), which returns captured stdout even on a
// non-zero exit or a cancelled context. RunOpts discards it, so after 18-04 a Gxss
// deadline produced zero reflected lines, the caller saw an empty candidate list
// and returned StatusSkipped — the WHOLE XSS scan went silent behind an Info line
// indistinguishable from a genuine zero-reflection result. The 120s bound the file
// header calls "a bound gained, not one lost" is exactly what makes it reachable.
//
// Gxss is a best-effort NARROWING pre-pass. Failing to narrow means testing the
// unfiltered corpus — more work, same coverage. It never means testing nothing.
func TestGxssTimeoutFallsBackToUnfilteredCorpus(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hang.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write hang script: %v", err)
	}

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{
		Name:    "Gxss",
		Path:    script,
		Timeout: 300 * time.Millisecond,
	})
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    config.Defaults(),
		Target: &appctx.Target{Domain: "example.com", WorkDir: dir},
	}

	// PLAIN URLs, one per line — xssFuzzReplaceParams parses each line with
	// url.Parse and drops anything without a query string.
	bucket := []byte("https://example.com/?q=1\nhttps://example.com/search?term=2\n")

	got, err := runGxssReflectionPipeline(context.Background(), bucket, app)
	if err != nil {
		t.Fatalf("pipeline returned an error: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("A Gxss DEADLINE SILENCED THE WHOLE XSS SCAN — the pipeline returned no " +
			"candidates, so the caller reports StatusSkipped and dalfox never runs. A " +
			"failed best-effort NARROWING pass must fall back to the unfiltered corpus, " +
			"not to nothing (WR-05)")
	}
	if !strings.Contains(string(got), "FUZZ") {
		t.Errorf("the fallback corpus is not the FUZZ-replaced one: %q", got)
	}
}
