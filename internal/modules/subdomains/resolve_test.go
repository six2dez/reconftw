// resolve_test.go — TDD tests for 6 active DNS resolution Tasks.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-02-PLAN.md
// Task 1 behavior tests.
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

	// Blank import triggers init() Task registrations in passive.go and resolve.go.
	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// -------------------------------------------------------------------------
// Test 1: SubActiveTask.Name()
// -------------------------------------------------------------------------

func TestSubActiveTaskName(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.active")
	if !ok {
		t.Fatal("subdomains.active not registered in task.Default")
	}
	if tsk.Name() != "subdomains.active" {
		t.Errorf("Name() = %q, want %q", tsk.Name(), "subdomains.active")
	}
}

// -------------------------------------------------------------------------
// Test 2: SubActiveTask.Run writes inputs/resolved.active.txt
// -------------------------------------------------------------------------

func TestSubActiveRunWritesStagingFile(t *testing.T) {
	workDir := t.TempDir()

	// MockStreamBackend returns two subdomain lines via Stream.
	mockBe := &mockStreamBackend{
		lines: []string{"api.example.com", "mail.example.com"},
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "puredns"})
	runner := backend.NewRunner(mockBe, reg, nil)
	mockTr := &mockTree{}

	// Create the passive merged file so SubActiveTask can read it as input.
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	passiveMerged := filepath.Join(inputsDir, "passive.merged.txt")
	if err := os.WriteFile(passiveMerged, []byte("sub.example.com\n"), 0o644); err != nil {
		t.Fatalf("write passive.merged.txt: %v", err)
	}

	app := newTestApp(workDir, runner, mockTr)

	tsk, ok := task.Default.Lookup("subdomains.active")
	if !ok {
		t.Fatal("subdomains.active not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubActiveTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done", res.Status)
	}

	// Staging file must exist.
	stagingPath := filepath.Join(workDir, "inputs", "resolved.active.txt")
	data, err := os.ReadFile(stagingPath)
	if err != nil {
		t.Fatalf("staging file not found at %s: %v", stagingPath, err)
	}
	content := string(data)
	if !strings.Contains(content, "api.example.com") {
		t.Errorf("staging file missing expected line: %q", content)
	}

	// Tree.Append must NOT have been called (staging contract).
	if mockTr.appendCalled {
		t.Errorf("SubActiveTask.Run called Tree.Append — staging contract violation")
	}
}

// -------------------------------------------------------------------------
// Test 3: SubActiveTask uses Stream (not Exec) — channel must be drained
// -------------------------------------------------------------------------

func TestSubActiveUsesStream(t *testing.T) {
	workDir := t.TempDir()

	// StreamTrackingBackend tracks which method was called.
	trackBe := &streamTrackingBackend{
		lines: []string{"api.example.com"},
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "puredns"})
	runner := backend.NewRunner(trackBe, reg, nil)

	// Create passive merged input file.
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	passiveMerged := filepath.Join(inputsDir, "passive.merged.txt")
	if err := os.WriteFile(passiveMerged, []byte("sub.example.com\n"), 0o644); err != nil {
		t.Fatalf("write passive.merged.txt: %v", err)
	}

	app := newTestApp(workDir, runner, &mockTree{})
	tsk, ok := task.Default.Lookup("subdomains.active")
	if !ok {
		t.Fatal("subdomains.active not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubActiveTask.Run: unexpected error: %v", err)
	}

	// Stream must have been called (not Exec).
	if !trackBe.streamCalled {
		t.Errorf("SubActiveTask.Run did not call Stream — XCUT-09 heartbeat contract violated (must use Stream for puredns)")
	}
	if trackBe.execCalled {
		t.Errorf("SubActiveTask.Run called Exec instead of Stream for puredns")
	}
}

// -------------------------------------------------------------------------
// Test 4: SubNoerrorTask.DependsOn() returns nil (no barriers)
// -------------------------------------------------------------------------

func TestSubNoerrorDependsOnNil(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.noerror")
	if !ok {
		t.Fatal("subdomains.noerror not registered in task.Default")
	}
	if deps := tsk.DependsOn(); deps != nil {
		t.Errorf("SubNoerrorTask.DependsOn() = %v, want nil (barriers removed; sequential RunStage handles ordering)", deps)
	}
}

// -------------------------------------------------------------------------
// Test 5: All 6 Tasks have Module() == "subdomains"
// -------------------------------------------------------------------------

func TestResolveTasks_Module(t *testing.T) {
	names := []string{
		"subdomains.active",
		"subdomains.tls",
		"subdomains.noerror",
		"subdomains.dns",
		"subdomains.srv",
		"subdomains.ptr",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			tsk, ok := task.Default.Lookup(name)
			if !ok {
				t.Fatalf("task %q not registered in task.Default", name)
			}
			if tsk.Module() != "subdomains" {
				t.Errorf("task %q: Module() = %q, want %q", name, tsk.Module(), "subdomains")
			}
		})
	}
}

// -------------------------------------------------------------------------
// Test 6: All 6 resolve Tasks registered (via task.Default.Build())
// -------------------------------------------------------------------------

func TestResolveTasksBuildNoPanic(t *testing.T) {
	// Build() returns error on cycles or missing DependsOn references.
	// All 6 resolve tasks have DependsOn() == nil, so Build() must succeed.
	_, err := task.Default.Build()
	if err != nil {
		t.Errorf("task.Default.Build() returned error: %v", err)
	}
}

// -------------------------------------------------------------------------
// Test 7 (13-01 Task 1): SubDNSTask persists the dnsregs records artefact +
// subdomains_ips.txt AND stages in-scope hostnames harvested from the records.
// -------------------------------------------------------------------------

func TestSubDNSPersistsDnsregsAndIPs(t *testing.T) {
	workDir := t.TempDir()

	// dnsx -recon -json JSONL: two hosts, an in-scope cname, A + AAAA addresses.
	dnsregs := `{"host":"api.example.com","a":["1.2.3.4"],"cname":["cdn.example.com"]}
{"host":"mail.example.com","a":["5.6.7.8"],"aaaa":["2606:4700::1111"]}
`
	mockBe := &mockBackend{result: &backend.Result{Stdout: []byte(dnsregs), ExitCode: 0}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dnsx"})
	runner := backend.NewRunner(mockBe, reg, nil)

	app := newTestApp(workDir, runner, &mockTree{}) // ReverseIP defaults false

	tsk, ok := task.Default.Lookup("subdomains.dns")
	if !ok {
		t.Fatal("subdomains.dns not registered")
	}
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubDNSTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}

	// 1. Records artefact persisted VERBATIM (PAR-01 — previously discarded).
	artefact, err := os.ReadFile(filepath.Join(workDir, "artefacts", "subdomains_dnsregs.json"))
	if err != nil {
		t.Fatalf("artefacts/subdomains_dnsregs.json not written: %v", err)
	}
	if string(artefact) != dnsregs {
		t.Errorf("dnsregs artefact = %q, want verbatim dnsx output", string(artefact))
	}

	// 2. host→IP pairs (A + AAAA) written to subdomains/subdomains_ips.txt.
	ips, err := os.ReadFile(filepath.Join(workDir, "subdomains", "subdomains_ips.txt"))
	if err != nil {
		t.Fatalf("subdomains/subdomains_ips.txt not written: %v", err)
	}
	for _, want := range []string{
		"api.example.com - 1.2.3.4",
		"mail.example.com - 5.6.7.8",
		"mail.example.com - 2606:4700::1111",
	} {
		if !strings.Contains(string(ips), want) {
			t.Errorf("subdomains_ips.txt missing %q; got:\n%s", want, string(ips))
		}
	}

	// 3. In-scope hostnames (host + in-scope cname) reach inputs/resolved.dns.txt.
	staged, err := os.ReadFile(filepath.Join(workDir, "inputs", "resolved.dns.txt"))
	if err != nil {
		t.Fatalf("inputs/resolved.dns.txt not written: %v", err)
	}
	for _, want := range []string{"api.example.com", "mail.example.com", "cdn.example.com"} {
		if !strings.Contains(string(staged), want) {
			t.Errorf("resolved.dns.txt missing %q; got:\n%s", want, string(staged))
		}
	}
}

// -------------------------------------------------------------------------
// Test helpers specific to resolve tests
// -------------------------------------------------------------------------

// newTestApp builds a minimal AppContext for resolve Task tests.
func newTestApp(workDir string, runner *backend.Runner, tree *mockTree) *appctx.AppContext {
	app := &appctx.AppContext{
		Tools: runner,
		Tree:  tree,
		Target: &appctx.Target{
			Domain:  "example.com",
			WorkDir: workDir,
		},
		Cfg: &config.Config{},
	}
	app.Cfg.Subdomains.Passive.Enabled = true
	app.Cfg.Subdomains.Brute.Enabled = true
	app.Cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit = 100
	app.Cfg.Subdomains.DNSResolve.PurednsWildcardbatchLimit = 1000000
	app.Cfg.Subdomains.DNSResolve.PurednsPublicLimit = 5000
	app.Cfg.Subdomains.DNSResolve.DNSXThreads = 100
	app.Cfg.Subdomains.DNSResolve.DNSXRateLimit = 0
	return app
}

// mockStreamBackend simulates Stream returning a set of lines and Exec returning nothing.
type mockStreamBackend struct {
	lines []string
}

func (m *mockStreamBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	return &backend.Result{Stdout: []byte(""), ExitCode: 0}, nil
}

func (m *mockStreamBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event, len(m.lines))
	for _, line := range m.lines {
		ch <- backend.Event{Line: []byte(line), Source: "puredns", IsErr: false}
	}
	close(ch)
	return ch, nil
}

func (m *mockStreamBackend) HealthCheck(_ context.Context) error { return nil }
func (m *mockStreamBackend) Capacity() int                       { return 1 }

// streamTrackingBackend tracks whether Stream vs Exec was called.
type streamTrackingBackend struct {
	lines        []string
	streamCalled bool
	execCalled   bool
}

func (m *streamTrackingBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	m.execCalled = true
	return &backend.Result{Stdout: []byte(""), ExitCode: 0}, nil
}

func (m *streamTrackingBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	m.streamCalled = true
	ch := make(chan backend.Event, len(m.lines))
	for _, line := range m.lines {
		ch <- backend.Event{Line: []byte(line), Source: "puredns", IsErr: false}
	}
	close(ch)
	return ch, nil
}

func (m *streamTrackingBackend) HealthCheck(_ context.Context) error { return nil }
func (m *streamTrackingBackend) Capacity() int                       { return 1 }
