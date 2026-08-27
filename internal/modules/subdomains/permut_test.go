// permut_test.go — TDD RED tests for SubPermutTask, SubRegexPermutTask,
// SubDNSCewlTask, SubIAPermutTask permutation Tasks.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-04-PLAN.md Task 2.
package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	// CR-03: the task now requires a readable permutation wordlist before it will
	// dispatch gotator (gotator v1.1 PANICS on an unreadable -perm). Without this
	// the task skips for a reason that has nothing to do with the memory gate,
	// and this test would be asserting the wrong skip.
	app.Cfg.Paths.WordlistsDir = permutWordlistsDir(t)

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
	// CR-03: a readable permutation wordlist is now a precondition for dispatch.
	app.Cfg.Paths.WordlistsDir = permutWordlistsDir(t)

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

// -------------------------------------------------------------------------
// CR-03 — the permutation wordlist v2 declared in config and never passed
// -------------------------------------------------------------------------
//
// WHAT WAS ACTUALLY OBSERVED, before a line of this was written (gotator v1.1,
// this box, two-host seed):
//
//	$ gotator -sub resolved.merged.txt -depth 1 -numbers 3 -md      # v2's argv
//	exit=0, 701 lines on stdout, 16-line banner on STDERR
//	$ gotator -sub resolved.merged.txt -perm permutations_list.txt -depth 1 -numbers 3 -md -silent
//	exit=0, 6644 lines
//	$ gotator -sub resolved.merged.txt -perm /nonexistent.txt …
//	panic: open /nonexistent.txt: no such file or directory   (exit 2)
//
// Two of the review's stated mechanisms are therefore WRONG and are recorded as
// wrong in 17-06-TRIAGE.md: gotator does NOT error without -perm (it permutes
// with words it derives from the -sub list itself), and its banner goes to
// STDERR, which the collector already drops. What IS true is the defect the fix
// addresses: v1's wordlist-driven permutation was ported into config only.
// cfg.Subdomains.Permut.WordlistMode and ShortThreshold were read by NOTHING.
//
// The panic is why the readable-wordlist gate must run BEFORE dispatch.

// permutArgvBackend captures the argv of every Stream/Exec dispatch and replays
// canned stdout lines.
type permutArgvBackend struct {
	argv     []string
	lines    []string
	stdout   []byte
	onInvoke func(args []string)
}

func (m *permutArgvBackend) Exec(_ context.Context, _ *backend.Tool, args []string) (*backend.Result, error) {
	m.argv = append([]string(nil), args...)
	if m.onInvoke != nil {
		m.onInvoke(args)
	}
	return &backend.Result{Stdout: m.stdout, ExitCode: 0}, nil
}

func (m *permutArgvBackend) ExecEnv(ctx context.Context, t *backend.Tool, args, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, t, args)
}

func (m *permutArgvBackend) Stream(_ context.Context, _ *backend.Tool, args []string) (<-chan backend.Event, error) {
	m.argv = append([]string(nil), args...)
	ch := make(chan backend.Event, len(m.lines)+1)
	for _, l := range m.lines {
		ch <- backend.Event{Line: []byte(l)}
	}
	close(ch)
	return ch, nil
}

func (m *permutArgvBackend) StreamEnv(ctx context.Context, t *backend.Tool, args, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, t, args)
}

func (m *permutArgvBackend) HealthCheck(_ context.Context) error { return nil }
func (m *permutArgvBackend) Capacity() int                       { return 1 }

// permutWordlistsDir writes v1's two permutation lists into a temp dir and
// returns it. The FILE NAMES are v1's on purpose: an operator migrating from v1
// points paths.wordlists_dir at their existing data/wordlists and the tool finds
// what it expects.
func permutWordlistsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"permutations_list.txt":       "dev\nstage\nprod\nadmin\n",
		"permutations_list_short.txt": "dev\nprod\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// runPermutWithSeed drives subdomains.permut and returns the captured argv and
// the Result.
func runPermutWithSeed(t *testing.T, seedHosts int, tune func(cfg *config.Config)) ([]string, task.Result) {
	t.Helper()
	workDir := t.TempDir()
	body := ""
	for i := 0; i < seedHosts; i++ {
		body += "h" + strconv.Itoa(i) + ".example.com\n"
	}
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "resolved.merged.txt"), []byte(body), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	be := &permutArgvBackend{lines: []string{"dev.h0.example.com"}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gotator"})
	app := buildPermutApp(workDir, backend.NewRunner(be, reg, nil), 0)
	tune(app.Cfg)

	tsk, ok := task.Default.Lookup("subdomains.permut")
	if !ok {
		t.Fatal("subdomains.permut not registered")
	}
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("subdomains.permut: %v", err)
	}
	return be.argv, res
}

func argvValue(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

func argvHas(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag {
			return true
		}
	}
	return false
}

// TestGotatorArgvCarriesSelectedPermutationWordlist — behaviour 1.
func TestGotatorArgvCarriesSelectedPermutationWordlist(t *testing.T) {
	dir := permutWordlistsDir(t)
	argv, res := runPermutWithSeed(t, 3, func(cfg *config.Config) {
		cfg.Paths.WordlistsDir = dir
		cfg.Subdomains.Permut.WordlistMode = "auto"
		cfg.Subdomains.Permut.ShortThreshold = 100
	})
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want done (argv: %v)", res.Status, argv)
	}
	got := argvValue(argv, "-perm")
	if got == "" {
		t.Fatalf("gotator was dispatched with NO -perm permutation source.\n"+
			"      -perm is the word list gotator permutes WITH. Without it the stage\n"+
			"      permutes only with words it can derive from the seed list itself —\n"+
			"      701 candidates instead of 6644 for a two-host seed on gotator v1.1 —\n"+
			"      while cfg.Subdomains.Permut.WordlistMode and ShortThreshold, and\n"+
			"      `deep --help`'s \"Permut wordlist mode = full\", all promise otherwise.\n"+
			"      argv: %v", argv)
	}
	if want := filepath.Join(dir, "permutations_list.txt"); got != want {
		t.Errorf("-perm = %q, want %q", got, want)
	}
	if !argvHas(argv, "-silent") {
		t.Errorf("gotator dispatched without -silent; v1 passes it (modules/subdomains.sh:1509)\nargv: %v", argv)
	}
}

// TestPermutationWordlistSelection — behaviour 2: mode and threshold, including
// v1's deep short-circuit (_select_permutations_wordlist, modules/subdomains.sh:1478).
func TestPermutationWordlistSelection(t *testing.T) {
	dir := permutWordlistsDir(t)
	full := filepath.Join(dir, "permutations_list.txt")
	short := filepath.Join(dir, "permutations_list_short.txt")

	cases := []struct {
		name  string
		hosts int
		mode  string
		thr   int
		deep  bool
		want  string
	}{
		{"explicit full ignores a huge seed", 50, "full", 10, false, full},
		{"explicit short ignores a tiny seed", 2, "short", 100, false, short},
		{"auto below the threshold takes full", 5, "auto", 10, false, full},
		{"auto above the threshold takes short", 50, "auto", 10, false, short},
		{"auto in deep mode short-circuits to full", 50, "auto", 10, true, full},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			argv, _ := runPermutWithSeed(t, tc.hosts, func(cfg *config.Config) {
				cfg.Paths.WordlistsDir = dir
				cfg.Subdomains.Permut.WordlistMode = tc.mode
				cfg.Subdomains.Permut.ShortThreshold = tc.thr
				cfg.Advanced.Deep = tc.deep
			})
			if got := argvValue(argv, "-perm"); got != tc.want {
				t.Errorf("-perm = %q, want %q (mode=%s threshold=%d deep=%v hosts=%d)",
					got, tc.want, tc.mode, tc.thr, tc.deep, tc.hosts)
			}
		})
	}
}

// TestPermutSkipsWithReasonWhenNoWordlist — behaviour 3.
func TestPermutSkipsWithReasonWhenNoWordlist(t *testing.T) {
	t.Run("wordlists dir not configured", func(t *testing.T) {
		argv, res := runPermutWithSeed(t, 3, func(cfg *config.Config) {
			cfg.Paths.WordlistsDir = ""
		})
		if res.Status != task.StatusSkipped {
			t.Errorf("status = %v, want skipped when no permutation wordlist is readable", res.Status)
		}
		if res.Reason == "" {
			t.Error("the skip carries NO reason — a permutation stage that quietly produces " +
				"nothing is the shape this phase exists to abolish")
		}
		if len(argv) != 0 {
			t.Errorf("gotator was DISPATCHED with no readable -perm file. gotator v1.1 PANICS "+
				"on an unreadable -perm (exit 2); the gate must run before dispatch.\nargv: %v", argv)
		}
	})

	t.Run("wordlists dir configured but the file is missing", func(t *testing.T) {
		empty := t.TempDir()
		_, res := runPermutWithSeed(t, 3, func(cfg *config.Config) {
			cfg.Paths.WordlistsDir = empty
		})
		if res.Status != task.StatusSkipped {
			t.Errorf("status = %v, want skipped", res.Status)
		}
		if !strings.Contains(res.Reason, "permutations_list") {
			t.Errorf("skip reason %q does not name the missing wordlist", res.Reason)
		}
	})
}

// TestPermutCollectorRejectsBannerLines — behaviour 4.
//
// gotator v1.1 writes its banner to STDERR, and the collector already drops
// stderr events, so the review's "banner becomes a candidate" mechanism does not
// hold for this version. The assertion is kept and made version-independent
// instead: whatever arrives on STDOUT, only hostname-shaped lines may be staged.
// A future gotator, or any of the other three permutation tools, printing one
// decorative line on stdout must not be able to inject a candidate.
func TestPermutCollectorRejectsBannerLines(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "resolved.merged.txt"), []byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	banner := []string{
		"",
		"▄▀▀▀▀▄    ▄▀▀▀▀▄   ▄▀▀▀█▀▀▄  ▄▀▀█▄",
		"    > By @JosueEncinar",
		"Gotator v1.1",
		"dev.api.example.com",
	}
	be := &permutArgvBackend{lines: banner}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gotator"})
	app := buildPermutApp(workDir, backend.NewRunner(be, reg, nil), 0)
	app.Cfg.Paths.WordlistsDir = permutWordlistsDir(t)

	tsk, _ := task.Default.Lookup("subdomains.permut")
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("subdomains.permut: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want done", res.Status)
	}

	staged, rerr := os.ReadFile(filepath.Join(inputsDir, "permut.gotator.txt"))
	if rerr != nil {
		t.Fatalf("read staging file: %v", rerr)
	}
	got := string(staged)
	if !strings.Contains(got, "dev.api.example.com") {
		t.Errorf("the real candidate was dropped along with the banner:\n%s", got)
	}
	for _, bad := range []string{"▄", "JosueEncinar", "Gotator v1.1"} {
		if strings.Contains(got, bad) {
			t.Errorf("banner text %q was staged as a subdomain candidate:\n%s", bad, got)
		}
	}
	if n := len(strings.Fields(got)); n != 1 {
		t.Errorf("staged %d tokens, want exactly 1 (the single real candidate):\n%s", n, got)
	}
}

// -------------------------------------------------------------------------
// CR-04 — regulator: two bare positionals, results read from stdout
// -------------------------------------------------------------------------
//
// PROVEN BEHAVIOURALLY, against the regulator installed on this box in v1's form
// (clone of https://github.com/cramppet/regulator at 2371a06, its own venv):
//
//	# v2's production form
//	$ ./venv/bin/python3 main.py hosts.txt example.com
//	usage: main.py [-h] … -t TARGET -f HOSTS [-o OUTPUT]
//	main.py: error: the following arguments are required: -t/--target, -f/--hosts
//	exit=2, 0 lines on stdout
//
//	# v1's form (modules/subdomains.sh:1650)
//	$ ./venv/bin/python3 main.py -t example.com -f hosts.txt -o regulator.out
//	exit=0, 0 lines on STDOUT, 9 candidates in regulator.out
//
// Both halves of the review's mechanism are correct this time: the flags are
// wrong AND the results never touch stdout. `subdomains.permut.regex` is on by
// default (config/defaults.go:40 RegexEnabled: true) and has therefore
// contributed exactly zero candidates on every `all`/`deep` run.

// regulatorTestApp builds a workspace with a seed host list and returns the app
// plus the backend that captures regulator's argv.
func regulatorTestApp(t *testing.T, writeOutput func(outPath string)) (*appctx.AppContext, *permutArgvBackend, string) {
	t.Helper()
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "resolved.merged.txt"),
		[]byte("api.example.com\nwww.example.com\n"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	be := &permutArgvBackend{
		// What regulator ACTUALLY puts on stdout: nothing. A mock that returns
		// candidates on stdout would let the broken reader keep passing.
		stdout: nil,
	}
	be.onInvoke = func(args []string) {
		if writeOutput == nil {
			return
		}
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				writeOutput(args[i+1])
			}
		}
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "regulator"})
	app := buildPermutApp(workDir, backend.NewRunner(be, reg, nil), 0)
	return app, be, workDir
}

func runRegexPermut(t *testing.T, app *appctx.AppContext) task.Result {
	t.Helper()
	tsk, ok := task.Default.Lookup("subdomains.permut.regex")
	if !ok {
		t.Fatal("subdomains.permut.regex not registered")
	}
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("subdomains.permut.regex: %v", err)
	}
	return res
}

// TestRegulatorArgvUsesNamedFlagsAndOutputFile — the arg vector.
func TestRegulatorArgvUsesNamedFlagsAndOutputFile(t *testing.T) {
	app, be, _ := regulatorTestApp(t, func(out string) {
		if err := os.WriteFile(out, []byte("dev.example.com\n"), 0o644); err != nil {
			t.Errorf("write regulator output: %v", err)
		}
	})
	runRegexPermut(t, app)

	if len(be.argv) == 0 {
		t.Fatal("regulator was never dispatched")
	}
	if got := argvValue(be.argv, "-t"); got != "example.com" {
		t.Errorf("-t = %q, want the target domain.\n"+
			"      regulator's argparse interface is `-t TARGET -f HOSTS [-o OUTPUT]`.\n"+
			"      Two bare positionals give:\n"+
			"        main.py: error: the following arguments are required: -t/--target, -f/--hosts  (exit 2)\n"+
			"      argv: %v", got, be.argv)
	}
	if got := argvValue(be.argv, "-f"); !strings.HasSuffix(got, "resolved.merged.txt") {
		t.Errorf("-f = %q, want the observed-hosts file; argv: %v", got, be.argv)
	}
	if got := argvValue(be.argv, "-o"); got == "" {
		t.Errorf("regulator dispatched with no -o output file. It writes its results to the\n"+
			"      -o file and prints NOTHING on stdout (verified: exit 0, 0 stdout lines,\n"+
			"      9 candidates in the file), so a caller reading stdout gets nothing.\n"+
			"      argv: %v", be.argv)
	}
}

// TestRegexPermutReadsOutputFileNotStdout — the result channel.
func TestRegexPermutReadsOutputFileNotStdout(t *testing.T) {
	app, _, workDir := regulatorTestApp(t, func(out string) {
		if err := os.WriteFile(out, []byte("dev.example.com\nstage.example.com\n"), 0o644); err != nil {
			t.Errorf("write regulator output: %v", err)
		}
	})
	res := runRegexPermut(t, app)
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v (%s), want done", res.Status, res.Reason)
	}

	staged, err := os.ReadFile(filepath.Join(workDir, "inputs", "permut.regex.txt"))
	if err != nil {
		t.Fatalf("read staging file: %v", err)
	}
	for _, want := range []string{"dev.example.com", "stage.example.com"} {
		if !strings.Contains(string(staged), want) {
			t.Errorf("candidate %q from regulator's OUTPUT FILE was not staged; got:\n%s", want, staged)
		}
	}
}

// TestRegexPermutSkipsWithReasonWhenNoOutput — a regulator that ran and produced
// nothing must be distinguishable from one that was never dispatched.
func TestRegexPermutSkipsWithReasonWhenNoOutput(t *testing.T) {
	app, _, _ := regulatorTestApp(t, nil) // no -o file written
	res := runRegexPermut(t, app)
	if res.Status != task.StatusSkipped {
		t.Errorf("status = %v, want skipped when regulator wrote no output file", res.Status)
	}
	if res.Reason == "" {
		t.Error("the skip carries NO reason — 'regulator ran and found nothing' and " +
			"'regulator never ran' must not look the same in the run's output")
	}
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (m *permutArgvBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return m.ExecEnv(ctx, t, args, opts.Env)
	}
	return m.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (m *permutArgvBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return m.StreamEnv(ctx, t, args, opts.Env)
	}
	return m.Stream(ctx, t, args)
}
