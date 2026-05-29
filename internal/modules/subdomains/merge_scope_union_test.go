// merge_scope_union_test.go — deterministic regression tests for the live-run
// remediation: MergeStage must NOT abort the batch on out-of-scope/garbage
// lines (it filters them), and MergeAllSubdomains must write the cumulative
// UNION of all stage staging files (Append is REPLACE/truncate per stage).
//
// These use a REAL OutputTree + DefaultScopeFilter (not a mock) so the scope
// boundary is exercised end-to-end without any live tools.
package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/modules/subdomains"
)

func writeStaging(t *testing.T, inputsDir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(inputsDir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestMergeStageFiltersScopeAndUnionConsolidates(t *testing.T) {
	workDir := t.TempDir()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}

	// Plain-hostname staging files across three stages. Each in-scope host plus
	// deliberate noise: an out-of-scope domain and a crt-style table-border line.
	writeStaging(t, inputsDir, "passive.subfinder.txt", "a.example.com\nb.example.com\nevil.com\n+----------+\n")
	writeStaging(t, inputsDir, "resolved.active.txt", "c.example.com\n")
	writeStaging(t, inputsDir, "permut.gotator.txt", "d.example.com\n")

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
	ctx := context.Background()

	// Per-stage merges MUST NOT error despite out-of-scope/garbage lines — the
	// pre-Append scope filter drops them instead of the whole-batch reject.
	for _, st := range []string{"passive", "resolved", "permut"} {
		if mErr := subdomains.MergeStage(ctx, app, st); mErr != nil {
			t.Fatalf("MergeStage(%q) errored (batch-abort regression): %v", st, mErr)
		}
	}

	// Final union consolidation.
	if mErr := subdomains.MergeAllSubdomains(ctx, app); mErr != nil {
		t.Fatalf("MergeAllSubdomains errored: %v", mErr)
	}

	data, err := os.ReadFile(filepath.Join(workDir, "artefacts", "subdomains.jsonl"))
	if err != nil {
		t.Fatalf("read subdomains.jsonl: %v", err)
	}
	got := string(data)

	// Union: every in-scope host from every stage must be present.
	for _, want := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("subdomains.jsonl missing %q (union regression)\n--- got ---\n%s", want, got)
		}
	}
	// Out-of-scope + garbage must NOT leak.
	for _, bad := range []string{"evil.com", "+----------+", "+---"} {
		if strings.Contains(got, bad) {
			t.Errorf("out-of-scope/garbage %q leaked into subdomains.jsonl", bad)
		}
	}

	// resolved.merged.txt must exist (downstream stages consume it).
	if _, err := os.Stat(filepath.Join(inputsDir, "resolved.merged.txt")); err != nil {
		t.Errorf("resolved.merged.txt not created (downstream input regression): %v", err)
	}
}
