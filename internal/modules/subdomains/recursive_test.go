// recursive_test.go — TDD RED tests for SubRecursivePassiveTask and SubRecursiveBruteTask.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-04-PLAN.md Task 2.
package subdomains_test

import (
	"context"
	"fmt"
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

// -------------------------------------------------------------------------
// Task 2 (13-02): dsieve top-N recursion seed selection
// -------------------------------------------------------------------------

// TestRecursivePassiveUsesDsieveSeeds verifies SubRecursivePassiveTask selects
// its subfinder seeds via `dsieve -if <resolved.merged> -f 3 -top <PassiveDepth>`
// (bash sub_recursive_passive parity) — NOT the naive subdomains[:depth] first-N
// slice. It asserts the dsieve arg vector AND that the dsieve-ranked output
// (d,c), not the list-order prefix (a,b), drives the per-seed subfinder loop.
func TestRecursivePassiveUsesDsieveSeeds(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	// 4 subs. first-N (depth 2) slice = {a,b}; dsieve returns the ranked {d,c}.
	mergedFile := filepath.Join(inputsDir, "resolved.merged.txt")
	if err := os.WriteFile(mergedFile,
		[]byte("a.example.com\nb.example.com\nc.example.com\nd.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	be := newRecordingMultiBackend()
	be.stdout["dsieve"] = "d.example.com\nc.example.com\n"
	be.stdout["subfinder"] = "found.example.com\n"
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dsieve"})
	reg.Register(&backend.Tool{Name: "subfinder"})
	runner := backend.NewRunner(be, reg, nil)

	app := buildRecursiveApp(workDir, runner)
	app.Cfg.Subdomains.Recursive.PassiveDepth = 2
	app.Cfg.Subdomains.Recursive.PassiveEnabled = true

	tsk, ok := task.Default.Lookup("subdomains.recursive.passive")
	if !ok {
		t.Fatal("subdomains.recursive.passive not registered")
	}
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if res.Status == task.StatusErrored {
		t.Fatalf("status errored")
	}

	// 1. dsieve invoked with the exact `-if <path> -f 3 -top 2` arg vector.
	dcalls := be.calls("dsieve")
	if len(dcalls) != 1 {
		t.Fatalf("dsieve call count = %d, want 1; calls=%v", len(dcalls), dcalls)
	}
	wantArgs := []string{"-if", mergedFile, "-f", "3", "-top", "2"}
	if !equalArgs(dcalls[0], wantArgs) {
		t.Errorf("dsieve args = %v, want %v", dcalls[0], wantArgs)
	}

	// 2. subfinder seeded from the dsieve output {d,c}, NOT the first-N {a,b}.
	gotSeeds := map[string]bool{}
	for _, call := range be.calls("subfinder") {
		if d := argValue(call, "-d"); d != "" {
			gotSeeds[d] = true
		}
	}
	for _, want := range []string{"d.example.com", "c.example.com"} {
		if !gotSeeds[want] {
			t.Errorf("subfinder not seeded with dsieve top-N host %q; seeds=%v", want, gotSeeds)
		}
	}
	for _, bad := range []string{"a.example.com", "b.example.com"} {
		if gotSeeds[bad] {
			t.Errorf("subfinder seeded with naive first-N host %q — dsieve output not used", bad)
		}
	}
}

// TestRecursivePassiveDsieveFallbackOnError verifies that a dsieve tool error
// degrades gracefully: the task falls back to the prior first-N slice selection,
// still seeds subfinder, and returns a non-errored status (recursion is a
// best-effort deep aux source — dsieve failure must never abort it).
func TestRecursivePassiveDsieveFallbackOnError(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	mergedFile := filepath.Join(inputsDir, "resolved.merged.txt")
	if err := os.WriteFile(mergedFile,
		[]byte("a.example.com\nb.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	be := newRecordingMultiBackend()
	be.failTools["dsieve"] = true // dsieve tool-exec error
	be.stdout["subfinder"] = "found.example.com\n"
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dsieve"})
	reg.Register(&backend.Tool{Name: "subfinder"})
	runner := backend.NewRunner(be, reg, nil)

	app := buildRecursiveApp(workDir, runner)
	app.Cfg.Subdomains.Recursive.PassiveDepth = 1
	app.Cfg.Subdomains.Recursive.PassiveEnabled = true

	tsk, _ := task.Default.Lookup("subdomains.recursive.passive")
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: dsieve error must not propagate: %v", err)
	}
	if res.Status == task.StatusErrored {
		t.Errorf("status errored — dsieve failure must degrade gracefully")
	}

	// Fallback to first-N (depth 1) slice: subfinder seeded with a.example.com.
	seeds := map[string]bool{}
	for _, call := range be.calls("subfinder") {
		if d := argValue(call, "-d"); d != "" {
			seeds[d] = true
		}
	}
	if !seeds["a.example.com"] {
		t.Errorf("fallback first-N seed a.example.com not used; seeds=%v", seeds)
	}
	if _, err := os.Stat(filepath.Join(workDir, "inputs", "recursive.passive.txt")); err != nil {
		t.Errorf("staging file not written: %v", err)
	}
}

// -------------------------------------------------------------------------
// recordingMultiBackend — per-tool arg-capturing + canned-stdout test backend
// -------------------------------------------------------------------------

// recordingMultiBackend records the arg vectors of each Exec/Stream call keyed by
// tool name and returns per-tool canned stdout. Tools listed in failTools return
// an error (to exercise the dsieve fallback path). Distinct from
// mockMultiToolBackend (scraping_test.go), which does not capture args.
type recordingMultiBackend struct {
	argsByTool map[string][][]string
	stdout     map[string]string
	failTools  map[string]bool
}

func newRecordingMultiBackend() *recordingMultiBackend {
	return &recordingMultiBackend{
		argsByTool: map[string][][]string{},
		stdout:     map[string]string{},
		failTools:  map[string]bool{},
	}
}

func (m *recordingMultiBackend) record(name string, args []string) {
	m.argsByTool[name] = append(m.argsByTool[name], append([]string(nil), args...))
}

func (m *recordingMultiBackend) calls(name string) [][]string { return m.argsByTool[name] }

func (m *recordingMultiBackend) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	m.record(t.Name, args)
	if m.failTools[t.Name] {
		return nil, fmt.Errorf("simulated %s failure", t.Name)
	}
	return &backend.Result{Stdout: []byte(m.stdout[t.Name]), ExitCode: 0}, nil
}

func (m *recordingMultiBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, t, args)
}

func (m *recordingMultiBackend) Stream(_ context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	m.record(t.Name, args)
	if m.failTools[t.Name] {
		return nil, fmt.Errorf("simulated %s failure", t.Name)
	}
	ch := make(chan backend.Event, 8)
	go func() {
		defer close(ch)
		for _, line := range permutSplitLines(m.stdout[t.Name]) {
			if line != "" {
				ch <- backend.Event{Line: []byte(line)}
			}
		}
	}()
	return ch, nil
}

func (m *recordingMultiBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, t, args)
}

func (m *recordingMultiBackend) HealthCheck(_ context.Context) error { return nil }
func (m *recordingMultiBackend) Capacity() int                       { return 4 }

// equalArgs reports whether two arg vectors are element-wise equal.
func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// argValue returns the value following flag in args, or "" if absent.
func argValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}
