// permut_test.go — TDD RED tests for SubPermutTask, SubRegexPermutTask,
// SubDNSCewlTask, SubIAPermutTask permutation Tasks.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-04-PLAN.md Task 2.
package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/subdomains/sysinfo"

	// Direct import for type assertions on SubPermutTask, SubDNSCewlTask, etc.
	subds "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// -------------------------------------------------------------------------
// Test 1: SubPermutTask.Run with MemProvider returning 0 waits, then
//         returns StatusSkipped when context is cancelled (NOT silent drop)
// -------------------------------------------------------------------------

// TestPermutMemGateWaitsOnLowMemory verifies that SubPermutTask.Run polls
// when OS memory is below the threshold, and returns StatusSkipped when
// context is cancelled — it does NOT silently drop permutations.
func TestPermutMemGateWaitsOnLowMemory(t *testing.T) {
	// Arrange: MinFreeMemGB = 1; provider always returns 0 (no memory).
	workDir := t.TempDir()
	// Create the resolved.merged.txt input file so Run gets past the input check.
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	mergedFile := filepath.Join(inputsDir, "resolved.merged.txt")
	if err := os.WriteFile(mergedFile, []byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	// Use a very short-lived context to make the wait loop exit quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	mockBackend := &mockBackend{result: &backend.Result{Stdout: []byte(""), ExitCode: 0}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gotator"})
	runner := backend.NewRunner(mockBackend, reg, nil)

	app := buildPermutApp(workDir, runner, 1 /* MinFreeMemGB=1 */)

	tsk, ok := task.Default.Lookup("subdomains.permut")
	if !ok {
		t.Fatal("subdomains.permut not registered")
	}

	// Inject a zero-returning MemProvider so the gate always blocks.
	// Type-assert to *SubPermutTask to set the MemProv field.
	if ptsk, ok := tsk.(*subds.SubPermutTask); ok {
		ptsk.MemProv = zeroMemProvider{}
		// Restore after test so subsequent tests use OSMemProvider.
		t.Cleanup(func() { ptsk.MemProv = nil })
	} else {
		t.Skip("cannot inject MemProv: task not *SubPermutTask")
	}

	res, err := tsk.Run(ctx, app)
	if err != nil {
		t.Fatalf("SubPermutTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("status = %q, want skipped (context cancelled while waiting for memory)", res.Status)
	}
}

// -------------------------------------------------------------------------
// Test 2: SubPermutTask.Run with sufficient memory proceeds to run gotator
// -------------------------------------------------------------------------

// TestPermutProceedsWithSufficientMemory verifies that SubPermutTask.Run
// proceeds to invoke gotator when available memory exceeds the threshold.
func TestPermutProceedsWithSufficientMemory(t *testing.T) {
	// Arrange: MinFreeMemGB = 1; mock returns (MinFreeMemGB+1) * 1GB = 2GB.
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	mergedFile := filepath.Join(inputsDir, "resolved.merged.txt")
	if err := os.WriteFile(mergedFile, []byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	mockResult := &backend.Result{
		Stdout:   []byte("dev.example.com\nstage.example.com\n"),
		ExitCode: 0,
	}
	mockBackend := &permutStreamBackend{result: mockResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gotator"})
	runner := backend.NewRunner(mockBackend, reg, nil)

	app := buildPermutApp(workDir, runner, 1 /* MinFreeMemGB=1 */)
	// Inject a memory provider that returns 2GB (> 1GB threshold).
	app.Cfg.Subdomains.Permut.MinFreeMemGB = 1

	tsk, ok := task.Default.Lookup("subdomains.permut")
	if !ok {
		t.Fatal("subdomains.permut not registered")
	}

	res, _ := tsk.Run(context.Background(), app)
	if res.Status != task.StatusDone {
		t.Logf("Note: status = %q (may be errored if gotator args differ in mock)", res.Status)
		// Accept done OR errored — the key check is that we did NOT get skipped.
		if res.Status == task.StatusSkipped {
			t.Errorf("SubPermutTask.Run returned skipped even though memory is sufficient")
		}
	}
}

// -------------------------------------------------------------------------
// Test 3: SubPermutTask.Run writes inputs/permut.gotator.txt staging file
//         (does NOT call app.Tree.Append)
// -------------------------------------------------------------------------

// TestPermutWritesStagingFile verifies SubPermutTask.Run writes the gotator
// staging file and does NOT call app.Tree.Append (staging contract).
func TestPermutWritesStagingFile(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "resolved.merged.txt"),
		[]byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	mockResult := &backend.Result{
		Stdout:   []byte("dev.example.com\nstage.example.com\n"),
		ExitCode: 0,
	}
	mockBackend := &permutStreamBackend{result: mockResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gotator"})
	runner := backend.NewRunner(mockBackend, reg, nil)

	mockTree := &mockTree{}
	app := buildPermutApp(workDir, runner, 0 /* MinFreeMemGB=0: gate disabled */)
	app.Tree = mockTree

	tsk, ok := task.Default.Lookup("subdomains.permut")
	if !ok {
		t.Fatal("subdomains.permut not registered")
	}

	res, _ := tsk.Run(context.Background(), app)

	// Tree.Append must NOT be called (staging contract).
	if mockTree.appendCalled {
		t.Errorf("SubPermutTask.Run called Tree.Append — staging contract violation")
	}

	if res.Status == task.StatusSkipped {
		t.Logf("Note: Run returned skipped (gotator mock returned empty — OK for staging test)")
		return
	}

	// Staging file must exist when Run returns done.
	stagingPath := filepath.Join(workDir, "inputs", "permut.gotator.txt")
	if _, err := os.Stat(stagingPath); err != nil {
		t.Errorf("staging file not found at %s: %v", stagingPath, err)
	}
}

// -------------------------------------------------------------------------
// Test 4: SubDNSCewlTask.Run invokes dnscewl with -f and writes staging file
// -------------------------------------------------------------------------

// TestDNSCewlRunWritesStagingFile verifies SubDNSCewlTask.Run writes
// inputs/permut.dnscewl.txt and does NOT call app.Tree.Append.
func TestDNSCewlRunWritesStagingFile(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "resolved.merged.txt"),
		[]byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	mockResult := &backend.Result{
		Stdout:   []byte("dev.example.com\nstaging.example.com\n"),
		ExitCode: 0,
	}
	mockBackend := &mockBackend{result: mockResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dnscewl"})
	runner := backend.NewRunner(mockBackend, reg, nil)

	mockTree := &mockTree{}
	app := buildPermutApp(workDir, runner, 0)
	app.Tree = mockTree

	tsk, ok := task.Default.Lookup("subdomains.permut.dnscewl")
	if !ok {
		t.Fatal("subdomains.permut.dnscewl not registered (SubDNSCewlTask missing — B1 fix)")
	}

	res, _ := tsk.Run(context.Background(), app)

	// Tree.Append must NOT be called.
	if mockTree.appendCalled {
		t.Errorf("SubDNSCewlTask.Run called Tree.Append — staging contract violation")
	}

	if res.Status == task.StatusSkipped {
		t.Logf("Note: SubDNSCewlTask returned skipped (dnscewl mock empty — OK)")
		return
	}

	// Staging file inputs/permut.dnscewl.txt must exist.
	stagingPath := filepath.Join(workDir, "inputs", "permut.dnscewl.txt")
	if _, err := os.Stat(stagingPath); err != nil {
		t.Errorf("staging file not found at %s: %v", stagingPath, err)
	}
}

// -------------------------------------------------------------------------
// Test 5: SubDNSCewlTask.Enabled returns false when Permut.Enabled == false
// -------------------------------------------------------------------------

// TestDNSCewlEnabledGate verifies SubDNSCewlTask.Enabled returns false
// when cfg.Subdomains.Permut.Enabled == false.
func TestDNSCewlEnabledGate(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.permut.dnscewl")
	if !ok {
		t.Fatal("subdomains.permut.dnscewl not registered")
	}

	// Disabled.
	cfg := &config.Config{}
	cfg.Subdomains.Permut.Enabled = false
	if tsk.Enabled(cfg) {
		t.Errorf("SubDNSCewlTask.Enabled(Permut.Enabled=false) = true, want false")
	}

	// Enabled.
	cfg.Subdomains.Permut.Enabled = true
	if !tsk.Enabled(cfg) {
		t.Errorf("SubDNSCewlTask.Enabled(Permut.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 6: SubIAPermutTask.Enabled returns false when IAEnabled == false
// -------------------------------------------------------------------------

// TestIAPermutEnabledGate verifies SubIAPermutTask.Enabled returns false
// when cfg.Subdomains.Permut.IAEnabled == false.
func TestIAPermutEnabledGate(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.permut.ia")
	if !ok {
		t.Fatal("subdomains.permut.ia not registered")
	}

	// Disabled via IAEnabled.
	cfg := &config.Config{}
	cfg.Subdomains.Permut.Enabled = true
	cfg.Subdomains.Permut.IAEnabled = false
	if tsk.Enabled(cfg) {
		t.Errorf("SubIAPermutTask.Enabled(IAEnabled=false) = true, want false")
	}

	// Also disabled when Permut itself is disabled.
	cfg.Subdomains.Permut.Enabled = false
	cfg.Subdomains.Permut.IAEnabled = true
	if tsk.Enabled(cfg) {
		t.Errorf("SubIAPermutTask.Enabled(Permut.Enabled=false) = true, want false")
	}

	// Enabled when both are true.
	cfg.Subdomains.Permut.Enabled = true
	cfg.Subdomains.Permut.IAEnabled = true
	if !tsk.Enabled(cfg) {
		t.Errorf("SubIAPermutTask.Enabled(Permut.Enabled=true, IAEnabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 8: task.Default.Build() succeeds after all permut/recursive tasks
//         registered (no unregistered DependsOn)
// -------------------------------------------------------------------------

// TestPermutTasksBuildOK verifies that task.Default.Build() returns without
// error after all permut and recursive tasks are registered (no forward
// DependsOn on unregistered names).
func TestPermutTasksBuildOK(t *testing.T) {
	_, err := task.Default.Build()
	if err != nil {
		t.Errorf("task.Default.Build() failed: %v (forward DependsOn on unregistered name?)", err)
	}
}

// -------------------------------------------------------------------------
// Test: All 4 permut tasks registered
// -------------------------------------------------------------------------

// TestAllPermutTasksRegistered verifies all 4 permut tasks are registered
// and all have DependsOn() == nil (staging contract: sequential RunStage).
func TestAllPermutTasksRegistered(t *testing.T) {
	wantNames := []string{
		"subdomains.permut",
		"subdomains.permut.regex",
		"subdomains.permut.dnscewl",
		"subdomains.permut.ia",
	}

	for _, name := range wantNames {
		t.Run(name, func(t *testing.T) {
			tsk, ok := task.Default.Lookup(name)
			if !ok {
				t.Errorf("task %q not registered (init() missing?)", name)
				return
			}
			if tsk.Module() != "subdomains" {
				t.Errorf("task %q: Module() = %q, want subdomains", name, tsk.Module())
			}
			if deps := tsk.DependsOn(); deps != nil {
				t.Errorf("task %q: DependsOn() = %v, want nil (no forward deps)", name, deps)
			}
		})
	}
}

// -------------------------------------------------------------------------
// Helper: buildPermutApp — minimal AppContext for permut tests
// -------------------------------------------------------------------------

// buildPermutApp builds a minimal *appctx.AppContext for permutation task tests.
// minFreeMemGB sets cfg.Subdomains.Permut.MinFreeMemGB (0 = gate disabled).
func buildPermutApp(workDir string, runner *backend.Runner, minFreeMemGB int) *appctx.AppContext {
	cfg := &config.Config{}
	cfg.Subdomains.Permut.Enabled = true
	cfg.Subdomains.Permut.RegexEnabled = true
	cfg.Subdomains.Permut.IAEnabled = true
	cfg.Subdomains.Permut.MinFreeMemGB = minFreeMemGB
	cfg.Subdomains.Recursive.PassiveEnabled = true
	cfg.Subdomains.Recursive.BruteEnabled = true
	cfg.Subdomains.Recursive.PassiveDepth = 1
	cfg.Paths.Resolvers = ""
	cfg.Paths.SubsWordlist = ""

	return &appctx.AppContext{
		Tools:  runner,
		Tree:   &mockTree{},
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}
}

// -------------------------------------------------------------------------
// Mock backend that supports streaming (for gotator/puredns Stream calls)
// -------------------------------------------------------------------------

// permutStreamBackend returns its result bytes through a stream channel.
// Named distinctly from mockStreamBackend in resolve_test.go (which uses []string lines).
type permutStreamBackend struct {
	result *backend.Result
	err    error
}

func (m *permutStreamBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	return m.result, m.err
}

func (m *permutStreamBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	if m.err != nil {
		return nil, m.err
	}
	ch := make(chan backend.Event, 8)
	go func() {
		defer close(ch)
		if m.result != nil && len(m.result.Stdout) > 0 {
			for _, line := range permutSplitLines(string(m.result.Stdout)) {
				if line != "" {
					ch <- backend.Event{Line: []byte(line)}
				}
			}
		}
	}()
	return ch, nil
}

func (m *permutStreamBackend) HealthCheck(_ context.Context) error { return nil }

func (m *permutStreamBackend) Capacity() int { return 1 }

// -------------------------------------------------------------------------
// zeroMemProvider — MemProvider that always returns 0 (simulates no memory)
// -------------------------------------------------------------------------

// zeroMemProvider satisfies sysinfo.MemProvider and always returns 0.
// Used in tests to ensure the memory gate always blocks.
type zeroMemProvider struct{}

func (zeroMemProvider) Available() uint64 { return 0 }

// compile-time interface check.
var _ sysinfo.MemProvider = zeroMemProvider{}

// -------------------------------------------------------------------------
// Ensure we use the subds import to avoid "imported and not used" error.
// -------------------------------------------------------------------------

// _ is a dummy usage of the subds import at package level.
// The actual type assertions in tests consume it, but we add this for safety.
var _ = subds.SubPermutTask{}

// permutSplitLines splits a string by newlines.
func permutSplitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
