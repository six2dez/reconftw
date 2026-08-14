// e2e_takeover_test.go — takeover findings must survive the composite sequence.
//
// Regression for: takeover appeared in `subs` and vanished in recon/all/deep.
// mergeTakeoverFindings wrote straight to artefacts/findings.jsonl during the
// subs stage; a later web.MergeStage("findings") rebuilt that artefact from
// inputs/findings.*.jsonl only, and Append has REPLACE semantics, so the
// takeover records were erased.
//
// The test drives the real sequence — takeover staging → mergeTakeoverFindings
// → a web findings producer → web.MergeStage → final sweep — against a real
// OutputTree. A unit test of either merge alone cannot catch this: each is
// individually correct, and the loss only appears in their ordering.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/modules/subdomains"
	"github.com/six2dez/reconftw/internal/modules/web"
)

func newTakeoverApp(t *testing.T) (*appctx.AppContext, string) {
	t.Helper()
	workDir := t.TempDir()
	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{
		Patterns: []string{"example.com", "*.example.com"},
	})
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	return &appctx.AppContext{Tree: tree, Target: &appctx.Target{WorkDir: workDir}}, workDir
}

func stageLine(t *testing.T, workDir, name, line string) {
	t.Helper()
	p := filepath.Join(workDir, "inputs", name)
	if err := output.WriteJSONL(p, [][]byte{[]byte(line)}); err != nil {
		t.Fatalf("stage %s: %v", name, err)
	}
}

func readFindings(t *testing.T, workDir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(workDir, "artefacts", "findings.jsonl"))
	if err != nil {
		t.Fatalf("artefacts/findings.jsonl unreadable: %v", err)
	}
	return b
}

// TestE2ETakeoverSurvivesCompositeFindingsMerges is the ordering guard.
func TestE2ETakeoverSurvivesCompositeFindingsMerges(t *testing.T) {
	ctx := context.Background()
	app, workDir := newTakeoverApp(t)

	// --- subs / enrichment stage ---
	//
	// These lines are marshalled from the REAL producer struct
	// (subdomains.TakeoverRecord), not hand-written. An earlier version wrote
	// `"vuln_class":"subdomain-takeover"`, a field the producer never emits —
	// so the test passed while every real takeover was being discarded during
	// ingest for having no usable signature.
	subzy, err := json.Marshal(subdomains.TakeoverRecord{
		Type: "subdomain-takeover", Host: "dangling.example.com",
		Service: "github", Confidence: "high", Severity: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	dnstake, err := json.Marshal(subdomains.TakeoverRecord{
		Type: "subdomain-takeover", Host: "ns-orphan.example.com",
		Service: "ns", Confidence: "high", Severity: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	stageLine(t, workDir, "takeover.subzy.jsonl", string(subzy))
	stageLine(t, workDir, "takeover.dnstake.jsonl", string(dnstake))

	if err := mergeTakeoverFindings(ctx, app); err != nil {
		t.Fatalf("mergeTakeoverFindings: %v", err)
	}
	if err := mergeFindingsArtefact(ctx, app); err != nil {
		t.Fatalf("mergeFindingsArtefact: %v", err)
	}
	if got := readFindings(t, workDir); !bytes.Contains(got, []byte("dangling.example.com")) {
		t.Fatalf("takeover missing right after the subs stage: %s", got)
	}

	// --- later web stage: another producer stages a finding, merge runs ---
	stageLine(t, workDir, "findings.nuclei.jsonl",
		`{"host":"api.example.com","vuln_class":"exposed-panel","severity":"low"}`)
	if err := web.MergeStage(ctx, app, "findings"); err != nil {
		t.Fatalf("web.MergeStage(findings): %v", err)
	}

	// --- final sweep, as composite runs it a second time ---
	if err := web.MergeStage(ctx, app, "findings"); err != nil {
		t.Fatalf("web final sweep: %v", err)
	}

	got := readFindings(t, workDir)
	for _, want := range []string{
		"dangling.example.com",  // subzy takeover
		"ns-orphan.example.com", // dnstake takeover
		"api.example.com",       // the web producer
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("%s missing from findings.jsonl after the composite merges: %s", want, got)
		}
	}
}

// TestE2ETakeoverWritesStagingNotArtefact pins the mechanism, not just the
// outcome: mergeTakeoverFindings must leave the artefact alone. If a future
// change reinstates a direct artefact write it will pass the ordering test
// above only until the next merger runs — this one fails immediately.
func TestE2ETakeoverWritesStagingNotArtefact(t *testing.T) {
	ctx := context.Background()
	app, workDir := newTakeoverApp(t)

	rec, merr := json.Marshal(subdomains.TakeoverRecord{
		Type: "subdomain-takeover", Host: "dangling.example.com", Severity: "high",
	})
	if merr != nil {
		t.Fatal(merr)
	}
	stageLine(t, workDir, "takeover.subzy.jsonl", string(rec))

	if err := mergeTakeoverFindings(ctx, app); err != nil {
		t.Fatalf("mergeTakeoverFindings: %v", err)
	}

	staged := filepath.Join(workDir, "inputs", "findings.takeover.jsonl")
	if _, err := os.Stat(staged); err != nil {
		t.Errorf("expected consolidated staging file %s: %v", staged, err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "artefacts", "findings.jsonl")); err == nil {
		t.Error("mergeTakeoverFindings wrote the artefact directly — a later " +
			"findings merge will REPLACE it and the takeover findings will be lost")
	}
}

// TestE2ETakeoverStaleStagingIsCleared covers cross-run contamination: the
// workspace is stable by design, so a run that finds NO takeovers must clear
// the previous run's staging file. Leaving it made the next merge republish a
// stale finding as though this run had observed it — so a remediated takeover
// would keep reappearing forever.
func TestE2ETakeoverStaleStagingIsCleared(t *testing.T) {
	ctx := context.Background()
	app, workDir := newTakeoverApp(t)
	staged := filepath.Join(workDir, "inputs", "findings.takeover.jsonl")

	// Run 1: a takeover exists.
	rec, err := json.Marshal(subdomains.TakeoverRecord{
		Type: "subdomain-takeover", Host: "dangling.example.com", Severity: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	stageLine(t, workDir, "takeover.subzy.jsonl", string(rec))
	if mErr := mergeTakeoverFindings(ctx, app); mErr != nil {
		t.Fatal(mErr)
	}
	if _, sErr := os.Stat(staged); sErr != nil {
		t.Fatalf("run 1 should have staged the takeover: %v", sErr)
	}

	// Run 2: the scanners produce nothing (remediated, or they did not run).
	if rmErr := os.Remove(filepath.Join(workDir, "inputs", "takeover.subzy.jsonl")); rmErr != nil {
		t.Fatal(rmErr)
	}
	if mErr := mergeTakeoverFindings(ctx, app); mErr != nil {
		t.Fatal(mErr)
	}
	if _, sErr := os.Stat(staged); !os.IsNotExist(sErr) {
		t.Error("run 2 found no takeovers but the previous run's staging file " +
			"survived — the next merge will republish a stale finding")
	}
}
