// takeover_test.go — TDD RED tests for TakeoverSubzyTask, TakeoverDNSTakeTask,
// SubBucketsTask, SubASNTask.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-05-PLAN.md
// Task 1 behavior tests.
//
// Test infrastructure reuses mockBackend, mockTree from scope_crosscheck_test.go.
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
// buildEnrichmentApp — minimal AppContext for enrichment task tests.
// -------------------------------------------------------------------------

func buildEnrichmentApp(t *testing.T, toolNames ...string) (*appctx.AppContext, string) {
	t.Helper()
	workDir := t.TempDir()

	// Create required directories.
	for _, dir := range []string{"inputs", "raw"} {
		if err := os.MkdirAll(filepath.Join(workDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	// Write resolved.merged.txt input file.
	mergedFile := filepath.Join(workDir, "inputs", "resolved.merged.txt")
	if err := os.WriteFile(mergedFile, []byte("api.example.com\nmail.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	mockBe := &mockBackend{result: &backend.Result{Stdout: []byte(""), ExitCode: 0}}
	reg := backend.NewToolRegistry()
	for _, name := range toolNames {
		reg.Register(&backend.Tool{Name: name})
	}
	runner := backend.NewRunner(mockBe, reg, nil)

	cfg := &config.Config{}
	cfg.Subdomains.Takeover.Enabled = true
	cfg.Subdomains.S3Buckets.Enabled = true
	cfg.Subdomains.ASN.Enabled = true

	return &appctx.AppContext{
		Tools:  runner,
		Tree:   &mockTree{},
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}, workDir
}

// -------------------------------------------------------------------------
// Test 1: TakeoverSubzyTask.Run writes inputs/takeover.subzy.jsonl staging file
// -------------------------------------------------------------------------

func TestTakeoverSubzyWritesStagingFile(t *testing.T) {
	// subzy returns JSON output; mock returns empty (no takeovers found).
	app, workDir := buildEnrichmentApp(t, "subzy", "httpx")

	tsk, ok := task.Default.Lookup("subdomains.takeover.subzy")
	if !ok {
		t.Fatal("subdomains.takeover.subzy not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("TakeoverSubzyTask.Run: unexpected error: %v", err)
	}
	if res.Status == task.StatusErrored {
		t.Errorf("TakeoverSubzyTask.Run returned StatusErrored")
	}

	// F3 (phase 15): the mock produces NO takeovers, so the write-or-REMOVE
	// contract requires the staging file to be ABSENT. It used to be written as
	// an empty file, which left "subzy found nothing" indistinguishable from
	// "subzy did not run" and, on a stable workspace, let a previous run's
	// takeover survive into this run's merge.
	stagingPath := filepath.Join(workDir, "inputs", "takeover.subzy.jsonl")
	if _, err := os.Stat(stagingPath); !os.IsNotExist(err) {
		t.Errorf("zero-takeover run must REMOVE %s (write-or-remove, F3), stat err = %v",
			stagingPath, err)
	}
}

// TestTakeoverSubzyClearsStaleStagingFile is the other half of F3: a previous
// run's staging file must not survive a run that found nothing.
func TestTakeoverSubzyClearsStaleStagingFile(t *testing.T) {
	app, workDir := buildEnrichmentApp(t, "subzy", "httpx")

	stagingPath := filepath.Join(workDir, "inputs", "takeover.subzy.jsonl")
	stale := []byte(`{"host":"old.example.com","service":"github","status":"vulnerable"}` + "\n")
	if err := os.WriteFile(stagingPath, stale, 0o644); err != nil {
		t.Fatalf("seed stale staging: %v", err)
	}

	tsk, ok := task.Default.Lookup("subdomains.takeover.subzy")
	if !ok {
		t.Fatal("subdomains.takeover.subzy not registered")
	}
	if _, err := tsk.Run(context.Background(), app); err != nil {
		t.Fatalf("TakeoverSubzyTask.Run: unexpected error: %v", err)
	}

	if _, err := os.Stat(stagingPath); !os.IsNotExist(err) {
		t.Errorf("run B found nothing but run A's %s survived — mergeTakeoverFindings "+
			"would republish a takeover this run never observed (F3); stat err = %v",
			stagingPath, err)
	}
}

// -------------------------------------------------------------------------
// Test 2: TakeoverDNSTakeTask.Run writes inputs/takeover.dnstake.jsonl staging file
// -------------------------------------------------------------------------

func TestTakeoverDNSTakeWritesStagingFile(t *testing.T) {
	app, workDir := buildEnrichmentApp(t, "dnstake")

	tsk, ok := task.Default.Lookup("subdomains.takeover.dnstake")
	if !ok {
		t.Fatal("subdomains.takeover.dnstake not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("TakeoverDNSTakeTask.Run: unexpected error: %v", err)
	}
	if res.Status == task.StatusErrored {
		t.Errorf("TakeoverDNSTakeTask.Run returned StatusErrored")
	}

	// F3 (phase 15): zero records ⇒ the staging file is REMOVED, not written
	// empty. See TestTakeoverSubzyWritesStagingFile for the rationale.
	stagingPath := filepath.Join(workDir, "inputs", "takeover.dnstake.jsonl")
	if _, err := os.Stat(stagingPath); !os.IsNotExist(err) {
		t.Errorf("zero-takeover run must REMOVE %s (write-or-remove, F3), stat err = %v",
			stagingPath, err)
	}
}

// -------------------------------------------------------------------------
// Test 3: SubBucketsTask.Run calls app.Tree.Append("buckets", lines) directly
// -------------------------------------------------------------------------

func TestSubBucketsTaskCallsTreeAppend(t *testing.T) {
	// s3scanner returns bucket scan output; mock returns a bucket line.
	mockResult := &backend.Result{
		Stdout:   []byte(`{"bucket":"example-assets","region":"us-east-1","exists":true,"acl":"public-read"}` + "\n"),
		ExitCode: 0,
	}
	workDir := t.TempDir()
	for _, dir := range []string{"inputs"} {
		if err := os.MkdirAll(filepath.Join(workDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "resolved.merged.txt"),
		[]byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write merged: %v", err)
	}

	mockBe := &mockBackend{result: mockResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "s3scanner"})
	runner := backend.NewRunner(mockBe, reg, nil)

	mockTr := &mockTree{}
	cfg := &config.Config{}
	cfg.Subdomains.S3Buckets.Enabled = true

	app := &appctx.AppContext{
		Tools:  runner,
		Tree:   mockTr,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}

	tsk, ok := task.Default.Lookup("subdomains.buckets")
	if !ok {
		t.Fatal("subdomains.buckets not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubBucketsTask.Run: unexpected error: %v", err)
	}
	if res.Status == task.StatusErrored {
		t.Errorf("SubBucketsTask.Run returned StatusErrored")
	}

	// Tree.Append must have been called (single writer — direct Append safe).
	if !mockTr.appendCalled {
		t.Errorf("SubBucketsTask.Run did NOT call Tree.Append — expected single-writer direct Append for buckets artefact")
	}
}

// -------------------------------------------------------------------------
// Test 4: SubASNTask.Run calls app.Tree.Append("asns", lines) directly
// -------------------------------------------------------------------------

func TestSubASNTaskCallsTreeAppend(t *testing.T) {
	mockResult := &backend.Result{
		Stdout:   []byte(`{"asn":"AS12345","org":"Example Corp","cidrs":["192.0.2.0/24"]}` + "\n"),
		ExitCode: 0,
	}
	workDir := t.TempDir()
	for _, dir := range []string{"inputs"} {
		if err := os.MkdirAll(filepath.Join(workDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	mockBe := &mockBackend{result: mockResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "asnmap"})
	runner := backend.NewRunner(mockBe, reg, nil)

	mockTr := &mockTree{}
	cfg := &config.Config{}
	cfg.Subdomains.ASN.Enabled = true

	app := &appctx.AppContext{
		Tools:  runner,
		Tree:   mockTr,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}

	tsk, ok := task.Default.Lookup("subdomains.asn")
	if !ok {
		t.Fatal("subdomains.asn not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubASNTask.Run: unexpected error: %v", err)
	}
	if res.Status == task.StatusErrored {
		t.Errorf("SubASNTask.Run returned StatusErrored")
	}

	// Tree.Append must have been called for asns (single writer — direct Append safe).
	if !mockTr.appendCalled {
		t.Errorf("SubASNTask.Run did NOT call Tree.Append — expected direct Append for asns artefact")
	}
}

// -------------------------------------------------------------------------
// Test 5: All 4 Tasks have DependsOn: nil
// -------------------------------------------------------------------------

func TestEnrichmentTasksDependsOnNil(t *testing.T) {
	names := []string{
		"subdomains.takeover.subzy",
		"subdomains.takeover.dnstake",
		"subdomains.buckets",
		"subdomains.asn",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			tsk, ok := task.Default.Lookup(name)
			if !ok {
				t.Fatalf("task %q not registered", name)
			}
			if deps := tsk.DependsOn(); deps != nil {
				t.Errorf("task %q: DependsOn() = %v, want nil (no barrier tasks)", name, deps)
			}
		})
	}
}

// -------------------------------------------------------------------------
// Test 6: TakeoverSubzyTask.Enabled returns false when Takeover.Enabled == false
// -------------------------------------------------------------------------

func TestTakeoverSubzyEnabledGate(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.takeover.subzy")
	if !ok {
		t.Fatal("subdomains.takeover.subzy not registered")
	}

	cfg := &config.Config{}
	cfg.Subdomains.Takeover.Enabled = false
	if tsk.Enabled(cfg) {
		t.Errorf("TakeoverSubzyTask.Enabled(Takeover.Enabled=false) = true, want false")
	}

	cfg.Subdomains.Takeover.Enabled = true
	if !tsk.Enabled(cfg) {
		t.Errorf("TakeoverSubzyTask.Enabled(Takeover.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 7: TakeoverSubzyTask.Run does NOT call app.Tree.Append (staging contract)
// -------------------------------------------------------------------------

func TestTakeoverSubzyDoesNotCallTreeAppend(t *testing.T) {
	app, _ := buildEnrichmentApp(t, "subzy", "httpx")
	mockTr := &mockTree{}
	app.Tree = mockTr

	tsk, ok := task.Default.Lookup("subdomains.takeover.subzy")
	if !ok {
		t.Fatal("subdomains.takeover.subzy not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("TakeoverSubzyTask.Run: unexpected error: %v", err)
	}

	// Tree.Append must NOT be called — B2 fix: staging files, not direct Append.
	if mockTr.appendCalled {
		t.Errorf("TakeoverSubzyTask.Run called Tree.Append — B2 fix violation: staging file required (findings has two concurrent writers in plan-06)")
	}
}

// -------------------------------------------------------------------------
// Test 8: TakeoverDNSTakeTask.Run does NOT call app.Tree.Append (staging contract)
// -------------------------------------------------------------------------

func TestTakeoverDNSTakeDoesNotCallTreeAppend(t *testing.T) {
	app, _ := buildEnrichmentApp(t, "dnstake")
	mockTr := &mockTree{}
	app.Tree = mockTr

	tsk, ok := task.Default.Lookup("subdomains.takeover.dnstake")
	if !ok {
		t.Fatal("subdomains.takeover.dnstake not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("TakeoverDNSTakeTask.Run: unexpected error: %v", err)
	}

	// Tree.Append must NOT be called — B2 fix: staging files, not direct Append.
	if mockTr.appendCalled {
		t.Errorf("TakeoverDNSTakeTask.Run called Tree.Append — B2 fix violation: staging file required")
	}
}
