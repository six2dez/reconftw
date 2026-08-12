// brute_test.go — TDD tests for SubBruteTask + SubResolversHealthTask.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-02-PLAN.md
// Task 2 behavior tests (SUBD-02 resolver health gate).
package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"

	// Import (not blank-import) to call exported MergeStage.
	"github.com/six2dez/reconftw/internal/modules/subdomains"
)

// -------------------------------------------------------------------------
// Test helpers for brute/resolver tests
// -------------------------------------------------------------------------

// buildBruteApp creates an AppContext for brute tests.
// resolverContent is written to a temp file; cfg.Paths.Resolvers set to it.
func buildBruteApp(t *testing.T, resolverContent string) (*appctx.AppContext, string) {
	t.Helper()
	workDir := t.TempDir()

	// Write resolver file.
	resolverFile := filepath.Join(workDir, "resolvers.txt")
	if err := os.WriteFile(resolverFile, []byte(resolverContent), 0o644); err != nil {
		t.Fatalf("write resolvers: %v", err)
	}

	// Write subs wordlist file so puredns bruteforce can reference it.
	wordlistFile := filepath.Join(workDir, "wordlist.txt")
	if err := os.WriteFile(wordlistFile, []byte("admin\napi\nwww\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	// Create inputs/ and a minimal passive.merged.txt.
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}

	mockBe := &mockStreamBackend{lines: []string{"bruted.example.com"}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "puredns"})
	runner := backend.NewRunner(mockBe, reg, nil)

	app := &appctx.AppContext{
		Tools: runner,
		Tree:  &mockTree{},
		Target: &appctx.Target{
			Domain:  "example.com",
			WorkDir: workDir,
		},
		Cfg: &config.Config{},
	}
	app.Cfg.Subdomains.Brute.Enabled = true
	app.Cfg.Subdomains.Brute.MinResolvers = 3
	app.Cfg.Paths.Resolvers = resolverFile
	app.Cfg.Paths.SubsWordlist = wordlistFile

	return app, workDir
}

// resolverLine is a trivially valid resolver line.
const resolverLine = "1.1.1.1\n"

// -------------------------------------------------------------------------
// Test 1: SubResolversHealthTask.Run returns StatusSkipped when < MinResolvers
// -------------------------------------------------------------------------

func TestResolversHealthTaskSkipsOnInsufficientResolvers(t *testing.T) {
	// 2 resolvers, MinResolvers = 3 → should skip.
	resolvers := "8.8.8.8\n1.1.1.1\n"
	app, _ := buildBruteApp(t, resolvers)
	// Ensure MinResolvers > actual count.
	app.Cfg.Subdomains.Brute.MinResolvers = 3

	tsk, ok := task.Default.Lookup("subdomains.resolvers.health")
	if !ok {
		t.Fatal("subdomains.resolvers.health not registered in task.Default")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubResolversHealthTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("status = %q, want skipped (resolver count 2 < MinResolvers 3)", res.Status)
	}
}

// -------------------------------------------------------------------------
// Test 2: SubBruteTask.Run returns StatusSkipped + structured log when gate fails
// -------------------------------------------------------------------------

func TestBruteTaskSkipsOnInsufficientResolvers(t *testing.T) {
	// 1 resolver line, MinResolvers = 5 → gate should fire.
	resolvers := resolverLine // exactly 1 non-empty line
	app, _ := buildBruteApp(t, resolvers)
	app.Cfg.Subdomains.Brute.MinResolvers = 5

	tsk, ok := task.Default.Lookup("subdomains.brute")
	if !ok {
		t.Fatal("subdomains.brute not registered in task.Default")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubBruteTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("SUBD-02: status = %q, want skipped (resolver count 1 < MinResolvers 5)", res.Status)
	}
}

// -------------------------------------------------------------------------
// Test 3: SubBruteTask.Run calls puredns bruteforce when gate passes
// -------------------------------------------------------------------------

func TestBruteTaskRunsWhenGatePasses(t *testing.T) {
	// 5 resolvers, MinResolvers = 3 → gate passes.
	resolvers := "8.8.8.8\n1.1.1.1\n8.8.4.4\n9.9.9.9\n208.67.222.222\n"
	app, workDir := buildBruteApp(t, resolvers)
	app.Cfg.Subdomains.Brute.MinResolvers = 3

	tsk, ok := task.Default.Lookup("subdomains.brute")
	if !ok {
		t.Fatal("subdomains.brute not registered in task.Default")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubBruteTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done (gate passed)", res.Status)
	}

	// Staging file must exist.
	stagingPath := filepath.Join(workDir, "inputs", "resolved.brute.txt")
	if _, err := os.Stat(stagingPath); err != nil {
		t.Errorf("staging file not found at %s: %v", stagingPath, err)
	}
}

// -------------------------------------------------------------------------
// Test 4: SubBruteTask.Enabled returns false when Brute.Enabled == false
// -------------------------------------------------------------------------

func TestBruteTaskEnabledGate(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.brute")
	if !ok {
		t.Fatal("subdomains.brute not registered")
	}

	disabledCfg := &config.Config{}
	disabledCfg.Subdomains.Brute.Enabled = false
	if tsk.Enabled(disabledCfg) {
		t.Errorf("SubBruteTask.Enabled(brute.Enabled=false) = true, want false")
	}

	enabledCfg := &config.Config{}
	enabledCfg.Subdomains.Brute.Enabled = true
	if !tsk.Enabled(enabledCfg) {
		t.Errorf("SubBruteTask.Enabled(brute.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 5: SubBruteTask writes inputs/resolved.brute.txt (no Tree.Append)
// -------------------------------------------------------------------------

func TestBruteTaskWritesStagingFile(t *testing.T) {
	// 5 resolvers, MinResolvers = 2 → gate passes; mock returns 1 subdomain.
	resolvers := "8.8.8.8\n1.1.1.1\n8.8.4.4\n9.9.9.9\n208.67.222.222\n"
	app, workDir := buildBruteApp(t, resolvers)
	app.Cfg.Subdomains.Brute.MinResolvers = 2

	tsk, ok := task.Default.Lookup("subdomains.brute")
	if !ok {
		t.Fatal("subdomains.brute not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubBruteTask.Run: %v", err)
	}

	// Verify staging file exists and has content.
	stagingPath := filepath.Join(workDir, "inputs", "resolved.brute.txt")
	data, err := os.ReadFile(stagingPath)
	if err != nil {
		t.Fatalf("staging file not found: %v", err)
	}
	if !strings.Contains(string(data), "bruted.example.com") {
		t.Errorf("staging file content = %q, want to contain 'bruted.example.com'", string(data))
	}

	// Tree.Append must NOT have been called (staging contract).
	if app.Tree.(*mockTree).appendCalled {
		t.Errorf("SubBruteTask.Run called Tree.Append — staging contract violation")
	}
}

// -------------------------------------------------------------------------
// Test 6: MergeStage writes merged.txt for downstream consumers
// -------------------------------------------------------------------------

func TestMergeStageWritesMergedTxt(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}

	// Write two passive staging files.
	if err := os.WriteFile(filepath.Join(inputsDir, "passive.subfinder.txt"),
		[]byte("api.example.com\nmail.example.com\n"), 0o644); err != nil {
		t.Fatalf("write subfinder staging: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "passive.crt.txt"),
		[]byte("dev.example.com\napi.example.com\n"), 0o644); err != nil {
		t.Fatalf("write crt staging: %v", err)
	}

	mockTr := &mockTree{}
	app := &appctx.AppContext{
		Tree: mockTr,
		Target: &appctx.Target{
			Domain:  "example.com",
			WorkDir: workDir,
		},
		Cfg: &config.Config{},
	}

	ctx := context.Background()
	if err := subdomains.MergeStage(ctx, app, "passive"); err != nil {
		t.Fatalf("MergeStage: %v", err)
	}

	// After MergeStage, inputs/passive.merged.txt must exist.
	mergedPath := filepath.Join(inputsDir, "passive.merged.txt")
	if _, err := os.Stat(mergedPath); err != nil {
		t.Errorf("MergeStage did not write passive.merged.txt: %v", err)
	}

	// Tree.Append must have been called once.
	if !mockTr.appendCalled {
		t.Errorf("MergeStage did not call Tree.Append")
	}
}

// -------------------------------------------------------------------------
// Test 6: SubBruteTask.Run skips loudly when the subs wordlist is unusable
// -------------------------------------------------------------------------

// An unset or missing subs_wordlist used to run `puredns bruteforce "" -d <domain>`,
// which fails instantly; because the stream loop swallows tool errors the task still
// reported StatusDone, so a live `all` run showed a healthy "[OK] subdomains.brute 0s"
// while contributing zero candidates — the exact "why is brute 0s?" symptom chased
// across four paid axiom fleets before the logs showed brute was 0s locally too.
func TestBruteTaskSkipsWhenWordlistUnusable(t *testing.T) {
	resolvers := "8.8.8.8\n1.1.1.1\n8.8.4.4\n9.9.9.9\n208.67.222.222\n"

	cases := map[string]func(app *appctx.AppContext, workDir string){
		"unset wordlist": func(app *appctx.AppContext, _ string) { app.Cfg.Paths.SubsWordlist = "" },
		"missing file":   func(app *appctx.AppContext, wd string) { app.Cfg.Paths.SubsWordlist = filepath.Join(wd, "nope.txt") },
		"empty wordlist": func(app *appctx.AppContext, wd string) {
			p := filepath.Join(wd, "empty.txt")
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				t.Fatalf("write empty wordlist: %v", err)
			}
			app.Cfg.Paths.SubsWordlist = p
		},
	}

	tsk, ok := task.Default.Lookup("subdomains.brute")
	if !ok {
		t.Fatal("subdomains.brute not registered in task.Default")
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			app, workDir := buildBruteApp(t, resolvers)
			app.Cfg.Subdomains.Brute.MinResolvers = 3
			mutate(app, workDir)

			res, err := tsk.Run(context.Background(), app)
			if err != nil {
				t.Fatalf("SubBruteTask.Run: unexpected error: %v", err)
			}
			if res.Status != task.StatusSkipped {
				t.Errorf("status = %q, want skipped — a brute with no wordlist must not "+
					"report [OK] while producing nothing", res.Status)
			}
		})
	}
}
