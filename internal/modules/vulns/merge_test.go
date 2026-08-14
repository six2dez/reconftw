// merge_test.go — F3 (15-03) empty-union behaviour for the vulns merger.
//
// "findings" is a CASE-A stage: artefacts/findings.jsonl has NO direct
// app.Tree.Append writer outside the merge path, so an empty union must publish
// a present, EMPTY artefact. Before 15-03 the merger returned nil and run B
// republished run A's vulnerability — a remediated finding reappeared in every
// later report, SARIF export, store row and notification.
package vulns_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/modules/vulns"
)

func newVulnsMergeApp(t *testing.T) *appctx.AppContext {
	t.Helper()
	workdir := t.TempDir()
	tree, err := output.NewTree(workdir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	return &appctx.AppContext{
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workdir},
	}
}

// TestMergeVulnsFindingsEmptyRunPublishesEmptyArtefact is acceptance gate 3's
// artefact half for the vulns pipeline.
func TestMergeVulnsFindingsEmptyRunPublishesEmptyArtefact(t *testing.T) {
	app := newVulnsMergeApp(t)
	staged := filepath.Join(app.Target.WorkDir, "inputs", "findings.sqli.jsonl")
	artefact := filepath.Join(app.Target.WorkDir, "artefacts", "findings.jsonl")

	// Run A: sqlmap found an injection.
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(staged,
		[]byte("{\"url\":\"https://a.example.com/?id=1\",\"name\":\"sqli\"}\n"), 0o644); err != nil {
		t.Fatalf("write staging: %v", err)
	}
	if err := vulns.MergeVulnsFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run A MergeVulnsFindings: %v", err)
	}
	body, err := os.ReadFile(artefact) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("run A artefact: %v", err)
	}
	if !strings.Contains(string(body), "sqli") {
		t.Fatalf("run A artefact missing the finding:\n%s", body)
	}

	// Run B: the scanner RAN, found nothing, and cleared its staging file.
	if err := os.Remove(staged); err != nil {
		t.Fatalf("remove staging: %v", err)
	}
	if err := vulns.MergeVulnsFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run B MergeVulnsFindings: %v", err)
	}

	info, err := os.Stat(artefact)
	if err != nil {
		t.Fatalf("run B must leave the artefact PRESENT, stat err = %v", err)
	}
	if info.Size() != 0 {
		after, _ := os.ReadFile(artefact) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("run B republished run A's vulnerability (size %d):\n%s", info.Size(), after)
	}
}

// TestMergeAllVulnsArtefactsEmptyRunPublishesEmpty proves the all-level entry
// point no longer short-circuits on an empty pre-glob, which would have left the
// stale artefact in place regardless of what MergeVulnsFindings does.
func TestMergeAllVulnsArtefactsEmptyRunPublishesEmpty(t *testing.T) {
	app := newVulnsMergeApp(t)
	artefact := filepath.Join(app.Target.WorkDir, "artefacts", "findings.jsonl")

	if err := os.MkdirAll(filepath.Dir(artefact), 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	if err := os.WriteFile(artefact,
		[]byte("{\"url\":\"https://a.example.com/?id=1\",\"name\":\"stale\"}\n"), 0o644); err != nil {
		t.Fatalf("seed artefact: %v", err)
	}

	if err := vulns.MergeAllVulnsArtefacts(context.Background(), app); err != nil {
		t.Fatalf("MergeAllVulnsArtefacts: %v", err)
	}
	info, err := os.Stat(artefact)
	if err != nil {
		t.Fatalf("artefact must remain PRESENT: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("pre-glob skip still leaves the stale artefact (%d bytes)", info.Size())
	}
}
