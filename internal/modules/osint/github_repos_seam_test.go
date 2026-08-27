// github_repos_seam_test.go — the proof that osint.github_repos's `git clone`
// came home to backend.Runner (18-05 Verdict 2) WITH ITS HARDENING INTACT.
//
// THE CONTROL IS THE PRE-MOVE INVOCATION, captured from github_repos.go as it
// stood at f436d2e BEFORE the edit:
//
//	bin, _ := exec.LookPath("git")
//	cmd := exec.CommandContext(cmdCtx, bin,
//	        "-c", "protocol.ext.allow=never", "clone", "--", url, dest)
//	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
//	githubReposCloneTimeout = 300 * time.Second
//
// T-18-05-02 IS THE POINT OF THIS FILE. Those two hardening measures are the only
// mitigations standing between an attacker-influenced repository URL and git's
// ext:: transport (RCE) or an interactive credential prompt (a hung scan). The
// register requires them to survive the move WHICHEVER verdict was reached, so
// they are asserted against what the process and its environment actually
// received — not against the source that sets them.
package osint

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
)

// githubReposWantCloneArgv is the PRE-MOVE arg vector shape, a literal on
// purpose. The url and dest are filled in per call.
func githubReposWantCloneArgv(url, dest string) []string {
	return []string{"-c", "protocol.ext.allow=never", "clone", "--", url, dest}
}

// writeGitRecorderScript writes a fake `git` that records its argv and the two
// environment variables that matter, then exits 0 after creating dest.
func writeGitRecorderScript(t *testing.T, dir string) string {
	t.Helper()
	script := filepath.Join(dir, "fake-git")
	body := "#!/bin/sh\n" +
		"PATH=/bin:/usr/bin; export PATH\n" +
		": > '" + filepath.Join(dir, "argv.txt") + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + filepath.Join(dir, "argv.txt") + "'; done\n" +
		"printf 'GIT_TERMINAL_PROMPT=%s\\n' \"$GIT_TERMINAL_PROMPT\" > '" + filepath.Join(dir, "env.txt") + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write fake git: %v", err)
	}
	return script
}

func readGitRecordedArgv(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "argv.txt")) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("the fake git never wrote argv.txt — git was not dispatched at all: %v", err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func newGitCloneTestApp(t *testing.T, gitPath, workDir string) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: githubReposGitTool, Path: gitPath})
	return &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    config.Defaults(),
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
}

// TestGitCloneHardeningSurvivesTheMove asserts the COMPLETE argv the process
// received and that GIT_TERMINAL_PROMPT reached its ENVIRONMENT — the two halves
// of T-18-05-02.
func TestGitCloneHardeningSurvivesTheMove(t *testing.T) {
	recDir := t.TempDir()
	gitPath := writeGitRecorderScript(t, recDir)
	workDir := t.TempDir()
	app := newGitCloneTestApp(t, gitPath, workDir)

	const url = "https://github.com/example/repo"
	dest := filepath.Join(workDir, "clone-dest")

	if err := githubReposGitClone(context.Background(), app, url, dest); err != nil {
		t.Fatalf("githubReposGitClone: %v", err)
	}

	got := readGitRecordedArgv(t, recDir)
	want := githubReposWantCloneArgv(url, dest)
	if len(got) != len(want) {
		t.Fatalf("argv git received = %v (%d args), want %v (%d args) — the pre-move vector "+
			"captured from github_repos.go at f436d2e", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: got %v, want %v)", i, got[i], want[i], got, want)
		}
	}
	// Named explicitly as well as positionally: this one element is an RCE
	// mitigation, and "the slices are equal" would not say so at a failure site.
	if got[0] != "-c" || got[1] != "protocol.ext.allow=never" {
		t.Fatalf("the ext:: transport hardening is missing from argv: %v (T-18-05-02)", got)
	}

	envData, err := os.ReadFile(filepath.Join(recDir, "env.txt")) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("the fake git never wrote env.txt: %v", err)
	}
	if strings.TrimSpace(string(envData)) != "GIT_TERMINAL_PROMPT=0" {
		t.Fatalf("git's environment carried %q, want GIT_TERMINAL_PROMPT=0 — without it an "+
			"auth-required clone hangs on an interactive credential prompt instead of "+
			"failing fast (T-18-05-02)", strings.TrimSpace(string(envData)))
	}
	// And it must NOT be on argv: ExecOptions.Env is the argv-free seam (ARCH-02).
	for _, a := range got {
		if strings.Contains(a, "GIT_TERMINAL_PROMPT") {
			t.Errorf("GIT_TERMINAL_PROMPT reached ARGV (%q) — it must travel through "+
				"ExecOptions.Env, which is what keeps child-environment values out of "+
				"logs/tools.jsonl", a)
		}
	}
}

// TestGitCloneIsRecorded asserts the clone lands in logs/tools.jsonl with its
// hardening visible — the concrete gain that decided Verdict 2. PRESENCE first.
func TestGitCloneIsRecorded(t *testing.T) {
	recDir := t.TempDir()
	gitPath := writeGitRecorderScript(t, recDir)
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "logs"), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	logPath := filepath.Join(workDir, "logs", "tools.jsonl")

	app := newGitCloneTestApp(t, gitPath, workDir)
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	const url = "https://github.com/example/repo"
	if err := githubReposGitClone(context.Background(), app, url,
		filepath.Join(workDir, "dest")); err != nil {
		t.Fatalf("githubReposGitClone: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — the clone of an UNTRUSTED third-party "+
			"repo was not recorded, which is the whole reason Verdict 2 went the way it "+
			"did: %v", err)
	}
	var sawStart bool
	var argv []string
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
		if rec.Tool == githubReposGitTool && rec.Phase == "start" {
			sawStart, argv = true, rec.Argv
		}
	}
	if !sawStart {
		t.Fatalf("no start record naming %q in logs/tools.jsonl:\n%s", githubReposGitTool, data)
	}
	// The hardening is VISIBLE in the record — an operator reading tools.jsonl can
	// now confirm it was applied, which was impossible before 18-05.
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "protocol.ext.allow=never") {
		t.Fatalf("the recorded argv does not show the ext:: hardening: %v", argv)
	}
	// XCUT-07: the child-environment value must not appear in the record.
	if strings.Contains(string(data), "GIT_TERMINAL_PROMPT") {
		t.Errorf("GIT_TERMINAL_PROMPT appears in logs/tools.jsonl — ExecOptions.Env exists "+
			"precisely so child-environment values stay out of the invocation record:\n%s", data)
	}
}

// TestGitCloneDegradesWhenGitIsUnresolvable pins the failure policy across the
// move. github_repos is best_effort throughout (D-O8): an absent git used to
// surface as an exec.LookPath error the caller logged and continued past, and it
// must still be a non-nil error the caller can degrade on — never a panic, and
// never a nil that makes an un-cloned directory look cloned.
func TestGitCloneDegradesWhenGitIsUnresolvable(t *testing.T) {
	workDir := t.TempDir()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: githubReposGitTool}) // registered, Path empty
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    config.Defaults(),
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}

	dest := filepath.Join(workDir, "dest")
	err := githubReposGitClone(context.Background(), app, "https://github.com/example/repo", dest)
	if err == nil {
		t.Fatal("an unresolvable git returned nil — the caller would treat a directory that " +
			"was never cloned as a successful clone and scan an empty tree")
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Errorf("the destination directory exists after a failed clone: %s", dest)
	}
}
