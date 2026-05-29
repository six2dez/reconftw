// recursive_test.go — TDD RED tests for SubRecursivePassiveTask and SubRecursiveBruteTask.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-04-PLAN.md Task 2.
package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"

	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// -------------------------------------------------------------------------
// Test 7: SubRecursivePassiveTask.Run makes subfinder calls per subdomain
// -------------------------------------------------------------------------

// TestRecursivePassiveRunCallsSubfinder verifies SubRecursivePassiveTask.Run
// reads the resolved.merged.txt input and runs subfinder for each subdomain
// up to PassiveDepth levels, writing inputs/recursive.passive.txt.
func TestRecursivePassiveRunCallsSubfinder(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	// Write a resolved.merged.txt with 2 subdomains.
	mergedFile := filepath.Join(inputsDir, "resolved.merged.txt")
	if err := os.WriteFile(mergedFile, []byte("api.example.com\nmail.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	// mockSubfinderBackend tracks how many times subfinder is called.
	tracker := &callTracker{}
	mockBackend := &trackingBackend{tracker: tracker, result: &backend.Result{
		Stdout:   []byte("new.api.example.com\n"),
		ExitCode: 0,
	}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "subfinder"})
	runner := backend.NewRunner(mockBackend, reg, nil)

	app := buildRecursiveApp(workDir, runner)
	app.Cfg.Subdomains.Recursive.PassiveDepth = 1
	app.Cfg.Subdomains.Recursive.PassiveEnabled = true

	tsk, ok := task.Default.Lookup("subdomains.recursive.passive")
	if !ok {
		t.Fatal("subdomains.recursive.passive not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubRecursivePassiveTask.Run: unexpected error: %v", err)
	}

	// Status must be done or skipped (not errored).
	if res.Status == task.StatusErrored {
		t.Errorf("SubRecursivePassiveTask.Run returned StatusErrored")
	}

	// Staging file must be written (even if empty — passive may find nothing).
	stagingPath := filepath.Join(workDir, "inputs", "recursive.passive.txt")
	if _, err := os.Stat(stagingPath); err != nil {
		t.Errorf("staging file not found at %s: %v", stagingPath, err)
	}
}

// -------------------------------------------------------------------------
// Test: SubRecursiveBruteTask.Run writes inputs/recursive.brute.txt
// -------------------------------------------------------------------------

// TestRecursiveBruteRunWritesStagingFile verifies SubRecursiveBruteTask.Run
// writes inputs/recursive.brute.txt and does NOT call app.Tree.Append.
func TestRecursiveBruteRunWritesStagingFile(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	mergedFile := filepath.Join(inputsDir, "resolved.merged.txt")
	if err := os.WriteFile(mergedFile, []byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}
	// Write a short wordlist file.
	wordlistFile := filepath.Join(workDir, "subs.txt")
	if err := os.WriteFile(wordlistFile, []byte("dev\nstage\n"), 0o644); err != nil {
		t.Fatalf("write subs.txt: %v", err)
	}
	// Write a resolvers file.
	resolversFile := filepath.Join(workDir, "resolvers.txt")
	if err := os.WriteFile(resolversFile, []byte("8.8.8.8\n1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("write resolvers.txt: %v", err)
	}

	mockResult := &backend.Result{
		Stdout:   []byte("dev.api.example.com\n"),
		ExitCode: 0,
	}
	mockStreamB := &permutStreamBackend{result: mockResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "puredns"})
	runner := backend.NewRunner(mockStreamB, reg, nil)

	mockTree := &mockTree{}
	app := buildRecursiveApp(workDir, runner)
	app.Tree = mockTree
	app.Cfg.Subdomains.Recursive.BruteEnabled = true
	app.Cfg.Paths.Resolvers = resolversFile
	app.Cfg.Paths.SubsWordlist = wordlistFile

	tsk, ok := task.Default.Lookup("subdomains.recursive.brute")
	if !ok {
		t.Fatal("subdomains.recursive.brute not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubRecursiveBruteTask.Run: unexpected error: %v", err)
	}

	// Tree.Append must NOT be called.
	if mockTree.appendCalled {
		t.Errorf("SubRecursiveBruteTask.Run called Tree.Append — staging contract violation")
	}

	if res.Status == task.StatusErrored {
		t.Errorf("SubRecursiveBruteTask.Run returned StatusErrored")
	}

	// Staging file must exist.
	stagingPath := filepath.Join(workDir, "inputs", "recursive.brute.txt")
	if _, err := os.Stat(stagingPath); err != nil {
		t.Errorf("staging file not found at %s: %v", stagingPath, err)
	}
}

// -------------------------------------------------------------------------
// Test: All 2 recursive tasks registered
// -------------------------------------------------------------------------

// TestAllRecursiveTasksRegistered verifies both recursive tasks are registered
// with DependsOn() == nil.
func TestAllRecursiveTasksRegistered(t *testing.T) {
	wantNames := []string{
		"subdomains.recursive.passive",
		"subdomains.recursive.brute",
	}

	for _, name := range wantNames {
		t.Run(name, func(t *testing.T) {
			tsk, ok := task.Default.Lookup(name)
			if !ok {
				t.Errorf("task %q not registered", name)
				return
			}
			if tsk.Module() != "subdomains" {
				t.Errorf("task %q: Module() = %q, want subdomains", name, tsk.Module())
			}
			if deps := tsk.DependsOn(); deps != nil {
				t.Errorf("task %q: DependsOn() = %v, want nil", name, deps)
			}
		})
	}
}

// -------------------------------------------------------------------------
// Helper: buildRecursiveApp
// -------------------------------------------------------------------------

func buildRecursiveApp(workDir string, runner *backend.Runner) *appctx.AppContext {
	cfg := &config.Config{}
	cfg.Subdomains.Recursive.PassiveEnabled = true
	cfg.Subdomains.Recursive.BruteEnabled = true
	cfg.Subdomains.Recursive.PassiveDepth = 1
	cfg.Advanced.Tools.Subfinder.TimeoutMinutes = 3

	return &appctx.AppContext{
		Tools:  runner,
		Tree:   &mockTree{},
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}
}

// -------------------------------------------------------------------------
// Tracking backend helper
// -------------------------------------------------------------------------

type callTracker struct {
	count int
}

type trackingBackend struct {
	tracker *callTracker
	result  *backend.Result
	err     error
}

func (t *trackingBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	t.tracker.count++
	return t.result, t.err
}

func (t *trackingBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	t.tracker.count++
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (t *trackingBackend) HealthCheck(_ context.Context) error { return nil }

func (t *trackingBackend) Capacity() int { return 1 }
