// scraping_test.go — TDD tests for SubScrapingTask, SubAnalyticsTask, SubNSDelegationTask.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-03-PLAN.md
// Task 2 behavior tests 1-4.
//
// Test infrastructure reuses mockBackend, mockTree, mockStreamBackend from
// scope_crosscheck_test.go / brute_test.go (same package subdomains_test).
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
	"github.com/six2dez/reconftw/internal/modules/subdomains"
)

// -------------------------------------------------------------------------
// mockStreamBackend is already defined in brute_test.go
// -------------------------------------------------------------------------

// buildScrapingApp creates an AppContext for scraping tests.
// The MockBackend returns different outputs depending on the tool name being called.
func buildScrapingApp(t *testing.T) (*appctx.AppContext, string) {
	t.Helper()
	workDir := t.TempDir()

	// Create raw/ directory for temp files.
	if err := os.MkdirAll(filepath.Join(workDir, "raw"), 0o755); err != nil {
		t.Fatalf("mkdir raw: %v", err)
	}

	mockBe := &mockMultiToolBackend{
		results: map[string]*backend.Result{
			"favirecon": {
				Stdout:   []byte("1234567890 api.example.com\n0987654321 mail.example.com\n"),
				ExitCode: 0,
			},
			"subjs": {
				Stdout:   []byte("https://api.example.com/js/app.js\nhttps://cdn.other.org/lib.js\n"),
				ExitCode: 0,
			},
			"jsluice": {
				// jsluice output: JSON lines
				Stdout:   []byte(`{"url":"https://api.example.com/v1","kind":"URL"}` + "\n" + `{"url":"https://dev.example.com/api","kind":"URL"}` + "\n"),
				ExitCode: 0,
			},
		},
	}

	reg := backend.NewToolRegistry()
	for _, name := range []string{"favirecon", "subjs", "jsluice"} {
		reg.Register(&backend.Tool{Name: name})
	}
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
	app.Cfg.Subdomains.Scraping.Enabled = true

	return app, workDir
}

// mockMultiToolBackend returns different results per tool name.
type mockMultiToolBackend struct {
	results map[string]*backend.Result
}

func (m *mockMultiToolBackend) Exec(_ context.Context, tool *backend.Tool, _ []string) (*backend.Result, error) {
	if r, ok := m.results[tool.Name]; ok {
		return r, nil
	}
	return &backend.Result{Stdout: []byte{}, ExitCode: 0}, nil
}

func (m *mockMultiToolBackend) Stream(_ context.Context, tool *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event, 8)
	data := []byte{}
	if r, ok := m.results[tool.Name]; ok {
		data = r.Stdout
	}
	go func() {
		defer close(ch)
		for _, b := range splitLines(data) {
			ch <- backend.Event{Line: b}
		}
	}()
	return ch, nil
}

func (m *mockMultiToolBackend) HealthCheck(_ context.Context) error { return nil }
func (m *mockMultiToolBackend) Capacity() int                       { return 4 }

// splitLines splits []byte into individual lines (without newline).
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// -------------------------------------------------------------------------
// Test 1: SubScrapingTask.Run writes inputs/resolved.scraping.txt with subdomain candidates
// -------------------------------------------------------------------------

func TestSubScrapingTaskWritesStagingFile(t *testing.T) {
	app, workDir := buildScrapingApp(t)

	tsk, ok := task.Default.Lookup("subdomains.scraping")
	if !ok {
		t.Fatal("subdomains.scraping not registered in task.Default")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubScrapingTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done", res.Status)
	}

	stagingPath := filepath.Join(workDir, "inputs", "resolved.scraping.txt")
	data, err := os.ReadFile(stagingPath)
	if err != nil {
		t.Fatalf("staging file not found at %s: %v", stagingPath, err)
	}
	if len(data) == 0 {
		t.Errorf("staging file is empty, want subdomain entries")
	}

	// Verify content is PLAIN hostnames (one per line) — the staging contract
	// (doc.go) that MergeStage's line-based readStagingFile consumes. JSON
	// lines here would be mangled by the merge reader (the bug this asserts
	// against).
	content := string(data)
	lines := splitStringLines(content)
	found := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, "{}\"") {
			t.Errorf("staging file line %q looks like JSON; staging files must be plain hostnames", line)
			continue
		}
		if strings.Contains(line, ".") {
			found = true
		}
	}
	if !found {
		t.Errorf("no plain hostname entries found in staging file")
	}
}

// -------------------------------------------------------------------------
// Test 2: SubScrapingTask.Run does NOT call app.Tree.Append (staging contract)
// -------------------------------------------------------------------------

func TestSubScrapingTaskDoesNotCallTreeAppend(t *testing.T) {
	app, _ := buildScrapingApp(t)

	tsk, ok := task.Default.Lookup("subdomains.scraping")
	if !ok {
		t.Fatal("subdomains.scraping not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubScrapingTask.Run: %v", err)
	}

	if app.Tree.(*mockTree).appendCalled {
		t.Errorf("SubScrapingTask.Run called Tree.Append — staging contract violation")
	}
}

// -------------------------------------------------------------------------
// Test 3: subjs→jsluice uses temp file (NOT stdin pipe)
// -------------------------------------------------------------------------

func TestSubScrapingTaskUsesTempFileForJsluice(t *testing.T) {
	app, workDir := buildScrapingApp(t)

	// Intercept backend calls to verify jsluice receives -i flag with a file path.
	tracker := &toolCallTracker{inner: app.Tools.Backend}
	reg := backend.NewToolRegistry()
	for _, name := range []string{"favirecon", "subjs", "jsluice"} {
		reg.Register(&backend.Tool{Name: name})
	}
	app.Tools = backend.NewRunner(tracker, reg, nil)

	tsk, ok := task.Default.Lookup("subdomains.scraping")
	if !ok {
		t.Fatal("subdomains.scraping not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubScrapingTask.Run: %v", err)
	}

	// Verify jsluice was called with -i flag (temp file pattern, not stdin).
	jsluiceArgs := tracker.argsFor("jsluice")
	if jsluiceArgs == nil {
		t.Fatal("jsluice was not called")
	}
	hasInputFlag := false
	for i, arg := range jsluiceArgs {
		if arg == "-i" && i+1 < len(jsluiceArgs) {
			hasInputFlag = true
			// The argument after -i must be an absolute path inside WorkDir.
			path := jsluiceArgs[i+1]
			if !filepath.IsAbs(path) {
				t.Errorf("jsluice -i path %q is not absolute", path)
			}
			if !isInsideDir(path, workDir) {
				t.Errorf("jsluice -i path %q is not inside WorkDir %q", path, workDir)
			}
			break
		}
	}
	if !hasInputFlag {
		t.Errorf("jsluice was called without -i flag (temp-file pattern required): args = %v", jsluiceArgs)
	}
}

// -------------------------------------------------------------------------
// Test 4: SubNSDelegationTask.Enabled returns false when NSDelegation.Enabled == false
// -------------------------------------------------------------------------

func TestNSDelegationTaskEnabledGate(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.ns_delegation")
	if !ok {
		t.Fatal("subdomains.ns_delegation not registered")
	}

	disabledCfg := &config.Config{}
	disabledCfg.Subdomains.NSDelegation.Enabled = false
	if tsk.Enabled(disabledCfg) {
		t.Errorf("SubNSDelegationTask.Enabled(ns_delegation.Enabled=false) = true, want false")
	}

	enabledCfg := &config.Config{}
	enabledCfg.Subdomains.NSDelegation.Enabled = true
	if !tsk.Enabled(enabledCfg) {
		t.Errorf("SubNSDelegationTask.Enabled(ns_delegation.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 5: 3 scraping Tasks are registered
// -------------------------------------------------------------------------

func TestScrapingTasksRegistered(t *testing.T) {
	names := []string{
		"subdomains.scraping",
		"subdomains.analytics",
		"subdomains.ns_delegation",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			tsk, ok := task.Default.Lookup(name)
			if !ok {
				t.Errorf("task %q not registered in task.Default", name)
				return
			}
			if tsk.Module() != "subdomains" {
				t.Errorf("task %q: Module() = %q, want subdomains", name, tsk.Module())
			}
		})
	}
}

// -------------------------------------------------------------------------
// Test 6: SubAnalyticsTask writes inputs/resolved.analytics.txt
// -------------------------------------------------------------------------

func TestSubAnalyticsTaskWritesStagingFile(t *testing.T) {
	workDir := t.TempDir()
	mockBe := &mockBackend{
		result: &backend.Result{
			Stdout:   []byte("related.example.com UA-12345678-1\napi.example.com UA-12345678-1\n"),
			ExitCode: 0,
		},
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "analyticsrelationships"})
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
	app.Cfg.Subdomains.Analytics.Enabled = true

	tsk, ok := task.Default.Lookup("subdomains.analytics")
	if !ok {
		t.Fatal("subdomains.analytics not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubAnalyticsTask.Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done", res.Status)
	}

	stagingPath := filepath.Join(workDir, "inputs", "resolved.analytics.txt")
	if _, err := os.Stat(stagingPath); err != nil {
		t.Fatalf("staging file not created at %s: %v", stagingPath, err)
	}

	if app.Tree.(*mockTree).appendCalled {
		t.Errorf("SubAnalyticsTask.Run called Tree.Append — staging contract violation")
	}
}

// -------------------------------------------------------------------------
// Test 7: SubNSDelegationTask writes inputs/resolved.ns_delegation.txt
// -------------------------------------------------------------------------

func TestSubNSDelegationTaskWritesStagingFile(t *testing.T) {
	workDir := t.TempDir()

	// Create a minimal subdomains.txt in the workspace (ns_delegation reads it).
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	subsFile := filepath.Join(workDir, "subdomains", "subdomains.txt")
	if err := os.MkdirAll(filepath.Dir(subsFile), 0o755); err != nil {
		t.Fatalf("mkdir subdomains: %v", err)
	}
	if err := os.WriteFile(subsFile, []byte("api.example.com\nmail.example.com\n"), 0o644); err != nil {
		t.Fatalf("write subdomains: %v", err)
	}

	// Mock dnsx returns NS records.
	mockBe := &mockBackend{
		result: &backend.Result{
			// dnsx NS response format: "subdomain [ns1.nameserver.com]"
			Stdout:   []byte("api.example.com [ns1.example.com]\n"),
			ExitCode: 0,
		},
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dnsx"})
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
	app.Cfg.Subdomains.NSDelegation.Enabled = true

	tsk, ok := task.Default.Lookup("subdomains.ns_delegation")
	if !ok {
		t.Fatal("subdomains.ns_delegation not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubNSDelegationTask.Run: %v", err)
	}
	// Should complete (done or skipped — depends on whether dnsx finds NS records).
	if res.Status != task.StatusDone && res.Status != task.StatusSkipped {
		t.Errorf("status = %q, want done or skipped", res.Status)
	}

	// Staging file must exist regardless of result count.
	stagingPath := filepath.Join(workDir, "inputs", "resolved.ns_delegation.txt")
	if _, err := os.Stat(stagingPath); err != nil {
		t.Fatalf("staging file not created at %s: %v", stagingPath, err)
	}

	if app.Tree.(*mockTree).appendCalled {
		t.Errorf("SubNSDelegationTask.Run called Tree.Append — staging contract violation")
	}
}

// -------------------------------------------------------------------------
// Test helpers
// -------------------------------------------------------------------------

// toolCallTracker wraps a Backend and records args per tool.
type toolCallTracker struct {
	inner   backend.Backend
	calls   map[string][]string
}

func (t *toolCallTracker) Exec(ctx context.Context, tool *backend.Tool, args []string) (*backend.Result, error) {
	if t.calls == nil {
		t.calls = make(map[string][]string)
	}
	t.calls[tool.Name] = args
	return t.inner.Exec(ctx, tool, args)
}

func (t *toolCallTracker) Stream(ctx context.Context, tool *backend.Tool, args []string) (<-chan backend.Event, error) {
	if t.calls == nil {
		t.calls = make(map[string][]string)
	}
	t.calls[tool.Name] = args
	return t.inner.Stream(ctx, tool, args)
}

func (t *toolCallTracker) HealthCheck(ctx context.Context) error { return t.inner.HealthCheck(ctx) }
func (t *toolCallTracker) Capacity() int                         { return t.inner.Capacity() }

func (t *toolCallTracker) argsFor(toolName string) []string {
	if t.calls == nil {
		return nil
	}
	return t.calls[toolName]
}

// isInsideDir returns true if path is inside dir.
func isInsideDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return len(rel) > 0 && rel[0] != '.'
}

// splitStringLines splits a string by newline, trimming empty trailing entry.
func splitStringLines(s string) []string {
	if s == "" {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// MergeStage re-export test: verify it handles resolved stage.
func TestMergeStageHandlesResolvedStage(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}

	// Write a resolved.scraping.txt staging file.
	scrapingJSON := `{"subdomain":"api.example.com","source":"scraping","first_seen":"2026-01-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(inputsDir, "resolved.scraping.txt"), []byte(scrapingJSON), 0o644); err != nil {
		t.Fatalf("write scraping staging: %v", err)
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
	if err := subdomains.MergeStage(ctx, app, "resolved"); err != nil {
		t.Fatalf("MergeStage(resolved): %v", err)
	}

	if !mockTr.appendCalled {
		t.Errorf("MergeStage(resolved) did not call Tree.Append")
	}
}
