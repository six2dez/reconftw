// composite_passive_merge_test.go — regression guard for the composite recon
// "0 live hosts" bug (found via live bash-vs-Go parity, 2026-08; fix 6990afe).
//
// RunCompositeAsync's per-stage merge dispatcher (compositeStagePostMerge) ran
// MergeStage("passive") under case "subs-enrichment" — but ModeRecon's subs
// pipeline is passive→resolve→discovery with NO enrichment stage. So
// inputs/passive.merged.txt (the file SubActiveTask + web probing consume as
// their host list) was never produced in recon: subdomains were found, yet
// resolve/web ran on empty input → 0 resolved hosts. The fix moved the passive
// merge to case "subs-passive". These tests drive the REAL dispatcher and the
// REAL mode pipelines so BOTH halves of the bug — the merge wired to the wrong
// stage, and that stage being absent from a mode's pipeline — can never
// silently recur. Companion to composite_selection_test.go (which guards the
// task-selection half, the "0 subdomains" bug).
package handlers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// TestCompositePassiveMergeProducesMergedTxt drives the real
// compositeStagePostMerge switch: the "subs-passive" stage MUST invoke
// MergeStage("passive"), which writes inputs/passive.merged.txt — the exact
// downstream input bug #2 starved. Uses a real OutputTree + DefaultScopeFilter
// (no mocks, no live tools), mirroring merge_scope_union_test.go.
func TestCompositePassiveMergeProducesMergedTxt(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	// A passive Task's staging file (what subfinder/crt/hackertarget write).
	if err := os.WriteFile(filepath.Join(inputsDir, "passive.subfinder.txt"),
		[]byte("a.example.com\nb.example.com\n"), 0o644); err != nil {
		t.Fatalf("write staging: %v", err)
	}

	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}})
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	app := &appctx.AppContext{
		Tree: tree,
		Target: &appctx.Target{
			Domain:  "example.com",
			WorkDir: workDir,
			Scope:   []string{"*.example.com"},
		},
	}
	mergedTxt := filepath.Join(inputsDir, "passive.merged.txt")
	if _, err := os.Stat(mergedTxt); !os.IsNotExist(err) {
		t.Fatalf("precondition: passive.merged.txt must not exist before the merge")
	}

	// Drive the REAL dispatcher with the subs-passive stage group.
	compositeStagePostMerge(context.Background(), app,
		compositeStageGroup{name: "subs-passive", module: "subdomains.passive"})

	if _, err := os.Stat(mergedTxt); err != nil {
		t.Fatalf("subs-passive did not produce inputs/passive.merged.txt — the passive "+
			"MergeStage is not wired to the subs-passive stage (0-live-hosts regression): %v", err)
	}
}

// TestReconAndAllPipelinesRunPassiveStage guards the OTHER half of bug #2: since
// the passive merge is wired to "subs-passive", every mode that must resolve
// hosts has to actually RUN a subs-passive stage. Bug #2's root shape was the
// merge living on a stage (enrichment) that ModeRecon's pipeline omits.
func TestReconAndAllPipelinesRunPassiveStage(t *testing.T) {
	for _, mode := range []CompositeMode{ModeRecon, ModeAll, ModePassive, ModeZen, ModeDeep} {
		found := false
		for _, g := range compositePipelineStages(mode) {
			if g.name == "subs-passive" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mode=%d has no subs-passive stage — inputs/passive.merged.txt would "+
				"never be produced (0-live-hosts regression)", mode)
		}
	}
}
