// staging_lifecycle_test.go — F3 (phase 15, plan 15-13 Task 1) write-then-clear
// behaviour for the subdomains producers, plus the end-to-end gate-3 experiment
// through MergeAllSubdomains.
//
// The invariant under test, stated once:
//
//	A producer that RAN and found nothing REMOVES its own staging file, so the
//	merge cannot republish a previous run's hostnames. A producer that did NOT
//	run (checkpoint-skipped) never calls the helper at all, so its staging
//	survives and resume still merges its data.
//
// The end-to-end test deliberately drives MergeAllSubdomains rather than a
// direct artefact writer: subdomains has no direct Tree.Append writer for the
// subdomains stage, so the MERGE owns the empty publish here. (For web's hosts,
// fuzz, origins and urls the empty publish belongs to the producer instead —
// see internal/modules/web/artefact_publish_test.go.)
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
	"github.com/six2dez/reconftw/internal/modules/subdomains"
)

// stagingLifecycleApp builds an AppContext whose crt invocation returns the
// supplied stdout, with a real OutputTree so merge assertions are meaningful.
func stagingLifecycleApp(t *testing.T, workDir string, stdout []byte) *appctx.AppContext {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	be := &mockBackend{result: &backend.Result{Stdout: stdout, ExitCode: 0}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "crt"})
	runner := backend.NewRunner(be, reg, nil)

	scope := []string{"*.example.com", "example.com"}
	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{Patterns: scope})
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}

	cfg := &config.Config{}
	cfg.Subdomains.Passive.Enabled = true
	return &appctx.AppContext{
		Tools:  runner,
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: scope},
		Cfg:    cfg,
	}
}

func runCrt(t *testing.T, app *appctx.AppContext) task.Result {
	t.Helper()
	tsk, ok := task.Default.Lookup("subdomains.passive.crt")
	if !ok {
		t.Fatal("subdomains.passive.crt not registered")
	}
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("CrtTask.Run: %v", err)
	}
	return res
}

// nonBlankFileLines counts non-blank lines. A missing file is a FATAL error:
// "present and empty" and "absent" are exactly the two states these tests
// distinguish, so they may never be conflated by a read helper.
func nonBlankFileLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("file must EXIST (present-and-empty, not absent): %v", err)
	}
	n := 0
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Write-then-clear, task 1 of 2 for this package: subdomains.passive.crt
// (.txt staging via output.StageLines).
// ---------------------------------------------------------------------------

// TestPassiveCrtStagingWriteThenClear is the two-run experiment on ONE stable
// workspace: run A stages hostnames, run B on the same workspace finds nothing
// and must REMOVE the file it wrote in run A.
func TestPassiveCrtStagingWriteThenClear(t *testing.T) {
	workDir := t.TempDir()
	staging := filepath.Join(workDir, "inputs", "passive.crt.txt")

	// Run A — crt returns two hostnames.
	appA := stagingLifecycleApp(t, workDir,
		[]byte(`[{"subdomain":"api.example.com"},{"subdomain":"mail.example.com"}]`))
	runCrt(t, appA)

	if got := nonBlankFileLines(t, staging); got != 2 {
		t.Fatalf("run A: staging holds %d hostnames, want 2", got)
	}

	// Run B — SAME workspace, crt now returns nothing.
	appB := stagingLifecycleApp(t, workDir, []byte(`[]`))
	runCrt(t, appB)

	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		body, _ := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		t.Errorf("run B found nothing but %s survived — MergeAllSubdomains would republish "+
			"run A's hostnames (F3); stat err = %v, contents = %q", staging, err, string(body))
	}
}

// TestPassiveCrtDidNotRunPreservesStaging is the other half of the invariant: a
// producer that never runs must not clear. A checkpoint-skipped task never
// reaches writeStagingFile, which is modelled here by simply not invoking it.
func TestPassiveCrtDidNotRunPreservesStaging(t *testing.T) {
	workDir := t.TempDir()
	staging := filepath.Join(workDir, "inputs", "passive.crt.txt")

	appA := stagingLifecycleApp(t, workDir, []byte(`[{"subdomain":"api.example.com"}]`))
	runCrt(t, appA)
	before, err := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("run A staging: %v", err)
	}

	// Run B skips subdomains.passive.crt entirely (checkpoint hit): no Run call,
	// therefore no StageLines call, therefore run A's data must survive so the
	// resumed merge still sees it.
	after, err := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("staging must survive a skipped task: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("skipped task must not touch staging: before %q, after %q", before, after)
	}
}

// ---------------------------------------------------------------------------
// Write-then-clear, task 2 of 2 for this package: subdomains.takeover.subzy
// (JSONL staging via output.StageJSONL) — asserted in takeover_test.go by
// TestTakeoverSubzyWritesStagingFile and TestTakeoverSubzyClearsStaleStagingFile.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// End-to-end gate 3 — MergeAllSubdomains owns the empty publish.
// ---------------------------------------------------------------------------

// TestGate3SubdomainsProducerToMergedArtefact is acceptance gate 3 end to end
// for this package: producer stages a record → merge → artefact has 1 line;
// producer stages nothing → merge → artefact EXISTS with 0 lines.
//
// "subdomains" has no direct Tree.Append writer outside merge.go, so the merge
// is the authoritative publisher and CAN safely empty the artefact. That is why
// this test is written against MergeAllSubdomains and not against a producer.
func TestGate3SubdomainsProducerToMergedArtefact(t *testing.T) {
	workDir := t.TempDir()
	artefact := filepath.Join(workDir, "artefacts", "subdomains.jsonl")

	// Run A — crt finds one in-scope host; merge publishes it.
	appA := stagingLifecycleApp(t, workDir, []byte(`[{"subdomain":"api.example.com"}]`))
	runCrt(t, appA)
	if err := subdomains.MergeAllSubdomains(context.Background(), appA); err != nil {
		t.Fatalf("run A MergeAllSubdomains: %v", err)
	}
	if got := nonBlankFileLines(t, artefact); got != 1 {
		t.Fatalf("run A: artefact holds %d records, want 1", got)
	}

	// Run B — SAME workspace, crt finds nothing. The staging clear must make the
	// glob empty, and the merge must then publish an EMPTY artefact rather than
	// republishing run A's host.
	appB := stagingLifecycleApp(t, workDir, []byte(`[]`))
	runCrt(t, appB)
	if err := subdomains.MergeAllSubdomains(context.Background(), appB); err != nil {
		t.Fatalf("run B MergeAllSubdomains: %v", err)
	}
	if _, err := os.Stat(artefact); err != nil {
		t.Fatalf("artefact must EXIST and be empty, not be deleted: %v", err)
	}
	if got := nonBlankFileLines(t, artefact); got != 0 {
		body, _ := os.ReadFile(artefact) //nolint:gosec // test-controlled temp path
		t.Errorf("run B found nothing but the artefact holds %d records — a previous run's "+
			"subdomains were republished (F3, gate 3): %q", got, string(body))
	}
}
