// scope_crosscheck_test.go — SUBD-05 scope cross-check test.
//
// Verifies DefaultScopeFilter matches v1 lib/validation.sh:is_in_scope_host
// semantics exactly: anchored matching, apex wildcard, userinfo rejection.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-01-PLAN.md
// Task 2 behavior tests 1-6 (scope + Task registration + Task semantics).
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
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"

	// Blank import triggers init() Task registrations in passive.go.
	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// -------------------------------------------------------------------------
// Test 1-5: SUBD-05 DefaultScopeFilter cross-check
// -------------------------------------------------------------------------

// TestScopeCrossCheck verifies DefaultScopeFilter semantics match the
// canonical v1 lib/validation.sh:is_in_scope_host anchored check.
func TestScopeCrossCheck(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		host    string
		wantIn  bool
	}{
		{
			// Test 1: wildcard pattern matches subdomain.
			name:    "wildcard_matches_subdomain",
			pattern: "*.example.com",
			host:    "api.example.com",
			wantIn:  true,
		},
		{
			// Test 2: anchored — substring "examplecom.evil" does NOT match
			// "*.example.com" (v1 substring false-positive closed).
			name:    "anchored_rejects_substring",
			pattern: "*.example.com",
			host:    "examplecom.evil",
			wantIn:  false,
		},
		{
			// Test 3: apex match — "*.example.com" matches "example.com" itself.
			name:    "wildcard_matches_apex",
			pattern: "*.example.com",
			host:    "example.com",
			wantIn:  true,
		},
		{
			// Test 4: userinfo rejection — URL with u:p@ userinfo must be
			// rejected by IsInScopeURL (SUBD-05).
			// NOTE: IsInScope is not called here; IsInScopeURL is tested
			// separately in TestScopeCrossCheckURL below.
			// This test asserts IsInScope("example.com") + pattern "*.example.com"
			// still returns true (apex match baseline).
			name:    "apex_baseline_for_url_test",
			pattern: "*.example.com",
			host:    "example.com",
			wantIn:  true,
		},
		{
			// Test 5: exact-only pattern — no subdomains allowed.
			name:    "exact_only_no_wildcard",
			pattern: "example.com",
			host:    "sub.example.com",
			wantIn:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &output.DefaultScopeFilter{Patterns: []string{tc.pattern}}
			got := f.IsInScope(tc.host)
			if got != tc.wantIn {
				t.Errorf("IsInScope(%q) with pattern %q = %v, want %v",
					tc.host, tc.pattern, got, tc.wantIn)
			}
		})
	}
}

// TestScopeCrossCheckURL verifies SUBD-05 userinfo rejection via IsInScopeURL.
// URL "http://u:p@example.com/path" must return false even though the host
// "example.com" is in scope for "*.example.com" — the URL userinfo u:p makes
// the URL unsafe regardless of the host match.
//
// Fix: scope.go IsInScopeURL now checks u.User != nil and returns false
// immediately, before any hostname match. This closes SUBD-05.
func TestScopeCrossCheckURL(t *testing.T) {
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}

	// Test 4 (SUBD-05): URL with userinfo must be rejected.
	got := f.IsInScopeURL("http://u:p@example.com/path")
	if got != false {
		t.Errorf("SUBD-05: IsInScopeURL(%q) = %v, want false (userinfo rejection)",
			"http://u:p@example.com/path", got)
	}

	// Sanity check: URL WITHOUT userinfo is still in scope (apex match).
	clean := f.IsInScopeURL("http://example.com/path")
	if !clean {
		t.Errorf("SUBD-05: IsInScopeURL(%q) = false, want true (no userinfo; apex match)",
			"http://example.com/path")
	}
}

// -------------------------------------------------------------------------
// Test 6: Task registration (init() self-registration)
// -------------------------------------------------------------------------

// TestPassiveTasksRegistered verifies that blank-importing the subdomains
// package results in task.Default containing all 6 passive tasks and
// NO barrier task.
func TestPassiveTasksRegistered(t *testing.T) {
	wantNames := []string{
		"subdomains.passive.subfinder",
		"subdomains.passive.crt",
		"subdomains.passive.github",
		"subdomains.passive.gitlab",
		"subdomains.passive.urlfinder",
		"subdomains.passive.hackertarget",
	}

	for _, name := range wantNames {
		t.Run(name, func(t *testing.T) {
			tsk, ok := task.Default.Lookup(name)
			if !ok {
				t.Errorf("task %q not registered in task.Default", name)
				return
			}
			// Verify Module() returns "subdomains".
			if tsk.Module() != "subdomains" {
				t.Errorf("task %q: Module() = %q, want %q", name, tsk.Module(), "subdomains")
			}
			// Verify DependsOn() returns nil (all passive Tasks are independent).
			if deps := tsk.DependsOn(); deps != nil {
				t.Errorf("task %q: DependsOn() = %v, want nil", name, deps)
			}
		})
	}

	// Verify NO barrier task is registered.
	for _, tsk := range task.Default.All() {
		if tsk.Module() == "subdomains" {
			if containsWord(tsk.Name(), "barrier") {
				t.Errorf("unexpected barrier task registered: %q (staging contract: sequential RunStage replaces barriers)", tsk.Name())
			}
		}
	}
}

// -------------------------------------------------------------------------
// Test 7: SubfinderTask.Enabled gate
// -------------------------------------------------------------------------

// TestSubfinderEnabled verifies SubfinderTask.Enabled returns false when
// cfg.Subdomains.Passive.Enabled == false.
func TestSubfinderEnabled(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.passive.subfinder")
	if !ok {
		t.Fatal("subdomains.passive.subfinder not registered")
	}

	disabledCfg := &config.Config{}
	disabledCfg.Subdomains.Passive.Enabled = false
	if tsk.Enabled(disabledCfg) {
		t.Errorf("SubfinderTask.Enabled(passive.Enabled=false) = true, want false")
	}

	enabledCfg := &config.Config{}
	enabledCfg.Subdomains.Passive.Enabled = true
	if !tsk.Enabled(enabledCfg) {
		t.Errorf("SubfinderTask.Enabled(passive.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 8: SubfinderTask.Run writes staging file, does NOT call Tree.Append
// -------------------------------------------------------------------------

// TestSubfinderRunWritesStagingFile verifies that SubfinderTask.Run with a
// MockBackend writes inputs/passive.subfinder.txt in WorkDir and does NOT
// call app.Tree.Append (staging contract).
func TestSubfinderRunWritesStagingFile(t *testing.T) {
	// Arrange: workspace with inputs/ directory.
	workDir := t.TempDir()

	// MockRunner returns "api.example.com\nmail.example.com\n" as stdout.
	mockResult := &backend.Result{
		Stdout:   []byte("api.example.com\nmail.example.com\n"),
		ExitCode: 0,
	}
	mockBackend := &mockBackend{result: mockResult}
	reg := backend.NewToolRegistry()
	// Register subfinder so the Runner.Run lookup succeeds.
	reg.Register(&backend.Tool{Name: "subfinder"})
	runner := backend.NewRunner(mockBackend, reg, nil)

	// MockTree records Append calls — should see ZERO after SubfinderTask.Run.
	mockTree := &mockTree{}

	app := &appctx.AppContext{
		Tools: runner,
		Tree:  mockTree,
		Target: &appctx.Target{
			Domain:  "example.com",
			WorkDir: workDir,
		},
		Cfg: &config.Config{},
	}
	app.Cfg.Subdomains.Passive.Enabled = true
	app.Cfg.Advanced.Tools.Subfinder.TimeoutMinutes = 3

	tsk, ok := task.Default.Lookup("subdomains.passive.subfinder")
	if !ok {
		t.Fatal("subdomains.passive.subfinder not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubfinderTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done", res.Status)
	}

	// Staging file must exist.
	stagingPath := filepath.Join(workDir, "inputs", "passive.subfinder.txt")
	data, err := os.ReadFile(stagingPath)
	if err != nil {
		t.Fatalf("staging file not found at %s: %v", stagingPath, err)
	}
	if string(data) == "" {
		t.Errorf("staging file is empty")
	}

	// Tree.Append must NOT have been called.
	if mockTree.appendCalled {
		t.Errorf("SubfinderTask.Run called Tree.Append — staging contract violation")
	}

	// Stats must include subdomains_found.
	if res.Stats == nil || res.Stats["subdomains_found"] == 0 {
		t.Errorf("Stats[subdomains_found] = 0, want >0")
	}
}

// -------------------------------------------------------------------------
// Test helpers / doubles
// -------------------------------------------------------------------------

// mockBackend is a minimal Backend implementation for tests.
type mockBackend struct {
	result *backend.Result
	err    error
}

func (m *mockBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	return m.result, m.err
}

func (m *mockBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (m *mockBackend) HealthCheck(_ context.Context) error { return nil }

func (m *mockBackend) Capacity() int { return 1 }

// mockTree records whether Append was called.
type mockTree struct {
	appendCalled bool
	appendLines  [][]byte
}

func (m *mockTree) Append(_ string, lines [][]byte) error {
	m.appendCalled = true
	m.appendLines = append(m.appendLines, lines...)
	return nil
}

// InScope admits all hosts (the mock does not model scope filtering).
func (m *mockTree) InScope(_ string) bool { return true }

// containsWord checks if s contains word as a complete dot-delimited component.
// For example, containsWord("subdomains.barrier.check", "barrier") == true,
// but containsWord("subdomains.noerror", "barrier") == false.
func containsWord(s, word string) bool {
	if s == word {
		return true
	}
	// Check as a dot-delimited segment anywhere in the string.
	return contains(s, "."+word+".") ||
		strings.HasPrefix(s, word+".") ||
		strings.HasSuffix(s, "."+word)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
