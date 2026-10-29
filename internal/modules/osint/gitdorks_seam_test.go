// gitdorks_seam_test.go — GitDorksTask's dispatch shape: the v1
// vector WITH its -gd dorks file (osint.sh:44/49). Without -gd gitdorks_go
// prints "require keyword or dorkfile" and exits 0 having searched nothing,
// which this task reported as findings:0 / StatusDone for months.
package osint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/v5/internal/core/appctx"
	"github.com/six2dez/reconftw/v5/internal/core/backend"
	"github.com/six2dez/reconftw/v5/internal/core/config"
	"github.com/six2dez/reconftw/v5/internal/core/output"
	"github.com/six2dez/reconftw/v5/internal/core/task"
)

// writeGitDorksRecorder writes a script that records its argv one-per-line to
// <dir>/argv.txt and prints stdout.
func writeGitDorksRecorder(t *testing.T, dir, stdout string) string {
	t.Helper()
	script := filepath.Join(dir, "recorder.sh")
	body := "#!/bin/sh\n" +
		": > '" + filepath.Join(dir, "argv.txt") + "'\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + filepath.Join(dir, "argv.txt") + "'; done\n" +
		"printf '%s' '" + stdout + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // executable fixture
		t.Fatalf("write recorder: %v", err)
	}
	return script
}

type gitDorksFixture struct {
	app       *appctx.AppContext
	workDir   string
	tokenFile string
	dorksFile string
}

func newGitDorksFixture(t *testing.T, toolPath string, deep, withDorks bool) gitDorksFixture {
	t.Helper()
	workDir := t.TempDir()
	toolsRoot := t.TempDir()
	tokenFile := filepath.Join(t.TempDir(), "github_tokens.txt")
	if err := os.WriteFile(tokenFile, []byte("ghp_0000000000000000000000000000000000\n"), 0o600); err != nil {
		t.Fatalf("token file: %v", err)
	}
	name := "smalldorks.txt"
	if deep {
		name = "medium_dorks.txt"
	}
	dorksFile := filepath.Join(toolsRoot, "gitdorks_go", "Dorks", name)
	if withDorks {
		if err := os.MkdirAll(filepath.Dir(dorksFile), 0o755); err != nil {
			t.Fatalf("mkdir Dorks: %v", err)
		}
		if err := os.WriteFile(dorksFile, []byte("filename:.env\n"), 0o600); err != nil {
			t.Fatalf("dorks file: %v", err)
		}
	}

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gitdorks_go", Path: toolPath})
	cfg := config.Defaults()
	cfg.OSINT.GoogleDorks.Enabled = true
	cfg.Paths.GitHubTokens = tokenFile
	cfg.Paths.ToolsDir = toolsRoot
	cfg.Advanced.Deep = deep
	tree, err := output.NewTree(workDir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	app := &appctx.AppContext{
		Log:    appctx.NopLogger(),
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}
	return gitDorksFixture{app: app, workDir: workDir, tokenFile: tokenFile, dorksFile: dorksFile}
}

func readGitDorksArgv(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "argv.txt")) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("gitdorks_go was not dispatched at all: %v", err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestGitDorksArgvIsV1VectorWithDorksFile(t *testing.T) {
	for _, deep := range []bool{false, true} {
		t.Run(map[bool]string{false: "small", true: "medium"}[deep], func(t *testing.T) {
			recDir := t.TempDir()
			tool := writeGitDorksRecorder(t, recDir, "https://github.com/example/repo/blob/main/.env\n")
			fx := newGitDorksFixture(t, tool, deep, true)

			res, err := (&GitDorksTask{}).Run(context.Background(), fx.app)
			if err != nil {
				t.Fatalf("GitDorksTask.Run: %v", err)
			}
			if res.Status != task.StatusDone || res.Stats["findings"] != 1 {
				t.Fatalf("result = %+v, want done with 1 finding", res)
			}
			want := []string{"-gd", fx.dorksFile, "-nws", "20", "-target", "example.com", "-tf", fx.tokenFile, "-ew", "3"}
			got := readGitDorksArgv(t, recDir)
			if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("argv = %v, want %v (v1 osint.sh:44/49)", got, want)
			}
		})
	}
}

func TestGitDorksAbsentIsToolAbsentNotDone(t *testing.T) {
	fx := newGitDorksFixture(t, "", false, true) // registered, no binary
	res, err := (&GitDorksTask{}).Run(context.Background(), fx.app)
	if err != nil {
		t.Fatalf("Run returned an error for an unavailable gitdorks_go: %v", err)
	}
	if res.Status != task.StatusSkipped || res.Reason != task.ReasonToolAbsent {
		t.Fatalf("absent tool: status=%v reason=%q, want skipped/%q (was StatusDone findings:0)",
			res.Status, res.Reason, task.ReasonToolAbsent)
	}
	if _, statErr := os.Stat(filepath.Join(fx.workDir, "inputs", "findings.gitdorks.jsonl")); statErr == nil {
		t.Error("a run in which gitdorks_go never started wrote the staging file")
	}
}

func TestGitDorksMissingDorksFileIsNamedNotRun(t *testing.T) {
	recDir := t.TempDir()
	tool := writeGitDorksRecorder(t, recDir, "")
	fx := newGitDorksFixture(t, tool, false, false)
	res, err := (&GitDorksTask{}).Run(context.Background(), fx.app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != task.StatusSkipped || !strings.Contains(res.Reason, "dorks file missing") {
		t.Fatalf("missing dorks file: status=%v reason=%q", res.Status, res.Reason)
	}
	if _, statErr := os.Stat(filepath.Join(recDir, "argv.txt")); statErr == nil {
		t.Error("gitdorks_go was dispatched without a dorks file — it would answer 'require keyword or dorkfile'")
	}
}
