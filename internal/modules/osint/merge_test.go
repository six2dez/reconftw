// merge_test.go — F3 (15-03) empty-union behaviour for the osint merger.
//
// "findings" is a CASE-A stage: artefacts/findings.jsonl has NO direct
// app.Tree.Append writer outside the merge path, so an empty union must publish
// a present, EMPTY artefact instead of leaving the previous run's findings in
// place for the report, SARIF export, store and notifications to re-report.
package osint_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/modules/osint"
)

func newOSINTMergeApp(t *testing.T) *appctx.AppContext {
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

func TestMergeOSINTFindingsEmptyRunPublishesEmptyArtefact(t *testing.T) {
	app := newOSINTMergeApp(t)
	staged := filepath.Join(app.Target.WorkDir, "inputs", "findings.domain_info.jsonl")
	artefact := filepath.Join(app.Target.WorkDir, "artefacts", "findings.jsonl")

	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	// Company-seeded OSINT record (class=="osint", D-O1): no host, no url.
	if err := os.WriteFile(staged,
		[]byte("{\"class\":\"osint\",\"name\":\"whois\",\"value\":\"registrar\"}\n"), 0o644); err != nil {
		t.Fatalf("write staging: %v", err)
	}
	if err := osint.MergeOSINTFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run A MergeOSINTFindings: %v", err)
	}
	body, err := os.ReadFile(artefact) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("run A artefact: %v", err)
	}
	if !strings.Contains(string(body), "whois") {
		t.Fatalf("run A artefact missing the finding:\n%s", body)
	}

	if err := os.Remove(staged); err != nil {
		t.Fatalf("remove staging: %v", err)
	}
	if err := osint.MergeOSINTFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run B MergeOSINTFindings: %v", err)
	}

	info, err := os.Stat(artefact)
	if err != nil {
		t.Fatalf("run B must leave the artefact PRESENT, stat err = %v", err)
	}
	if info.Size() != 0 {
		after, _ := os.ReadFile(artefact) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("run B republished run A's osint finding (size %d):\n%s", info.Size(), after)
	}
}

// TestMergeAllOSINTArtefactsEmptyRunPublishesEmpty proves the all-level entry
// point no longer short-circuits on an empty pre-glob.
func TestMergeAllOSINTArtefactsEmptyRunPublishesEmpty(t *testing.T) {
	app := newOSINTMergeApp(t)
	artefact := filepath.Join(app.Target.WorkDir, "artefacts", "findings.jsonl")

	if err := os.MkdirAll(filepath.Dir(artefact), 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	if err := os.WriteFile(artefact,
		[]byte("{\"class\":\"osint\",\"name\":\"stale\"}\n"), 0o644); err != nil {
		t.Fatalf("seed artefact: %v", err)
	}

	if err := osint.MergeAllOSINTArtefacts(context.Background(), app); err != nil {
		t.Fatalf("MergeAllOSINTArtefacts: %v", err)
	}
	info, err := os.Stat(artefact)
	if err != nil {
		t.Fatalf("artefact must remain PRESENT: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("pre-glob skip still leaves the stale artefact (%d bytes)", info.Size())
	}
}
