// merge_hosts_test.go — regression guard for the 13-08 hosts-merge union fix.
//
// web.httpx writes artefacts/hosts.jsonl DIRECTLY via app.Tree.Append (REPLACE
// semantics). The portscan/nerva/wellknown producers stage host records to
// inputs/hosts.*.jsonl, which plan 13-08 consolidates via MergeStage(_, _,
// "hosts"). Without union-preservation, that merge would OVERWRITE httpx's probed
// hosts. These tests assert the merge UNIONS the existing artefact with the
// staging files instead of replacing it.
package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// newHostsMergeApp builds an AppContext with a real OutputTree rooted at a
// per-test WorkDir (nil scope → Append performs field-presence checks but skips
// the in-scope filter, keeping the fixture minimal).
func newHostsMergeApp(t *testing.T) *appctx.AppContext {
	t.Helper()
	workdir := t.TempDir()
	for _, sub := range []string{"artefacts", "inputs"} {
		if err := os.MkdirAll(filepath.Join(workdir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	tree, err := output.NewTree(workdir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	return &appctx.AppContext{
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workdir},
	}
}

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readArtefactHosts(t *testing.T, app *appctx.AppContext) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"))
	if err != nil {
		t.Fatalf("read hosts.jsonl: %v", err)
	}
	return string(b)
}

// TestMergeStageHostsPreservesExistingArtefact is the core anti-regression guard:
// an httpx-written artefacts/hosts.jsonl MUST survive a hosts merge that folds in
// portscan/nerva staging records.
func TestMergeStageHostsPreservesExistingArtefact(t *testing.T) {
	app := newHostsMergeApp(t)

	// httpx wrote two probed hosts directly to the artefact.
	writeLines(t, filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"),
		`{"host":"probe1.example.com","source":"httpx"}`,
		`{"host":"probe2.example.com","source":"httpx"}`)

	// portscan + nerva staged their own host records.
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.portscan.jsonl"),
		`{"host":"scan1.example.com","source":"portscan"}`)
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.nerva.jsonl"),
		`{"host":"scan2.example.com","source":"nerva"}`)

	if err := MergeStage(context.Background(), app, "hosts"); err != nil {
		t.Fatalf("MergeStage(hosts): %v", err)
	}

	got := readArtefactHosts(t, app)
	for _, want := range []string{"probe1.example.com", "probe2.example.com", "scan1.example.com", "scan2.example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("hosts.jsonl missing %q after merge (httpx hosts wiped by REPLACE?)\ngot:\n%s", want, got)
		}
	}
}

// TestMergeStageHostsIdempotent verifies repeated hosts merges (portscan stage +
// web-producers stage both call MergeStage("hosts")) do not duplicate records.
func TestMergeStageHostsIdempotent(t *testing.T) {
	app := newHostsMergeApp(t)

	writeLines(t, filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"),
		`{"host":"probe.example.com","source":"httpx"}`)
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.portscan.jsonl"),
		`{"host":"scan.example.com","source":"portscan"}`)

	for i := 0; i < 3; i++ {
		if err := MergeStage(context.Background(), app, "hosts"); err != nil {
			t.Fatalf("MergeStage(hosts) call %d: %v", i, err)
		}
	}

	got := readArtefactHosts(t, app)
	if n := strings.Count(got, "probe.example.com"); n != 1 {
		t.Errorf("probe.example.com appears %d times after 3 merges, want 1\ngot:\n%s", n, got)
	}
	if n := strings.Count(got, "scan.example.com"); n != 1 {
		t.Errorf("scan.example.com appears %d times after 3 merges, want 1\ngot:\n%s", n, got)
	}
}

// TestMergeStageHostsNoStagingIsNoOp verifies that when no inputs/hosts.*.jsonl
// staging files exist, the merge is a no-op and never touches the httpx artefact.
func TestMergeStageHostsNoStagingIsNoOp(t *testing.T) {
	app := newHostsMergeApp(t)

	original := `{"host":"probe.example.com","source":"httpx"}`
	writeLines(t, filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"), original)

	if err := MergeStage(context.Background(), app, "hosts"); err != nil {
		t.Fatalf("MergeStage(hosts): %v", err)
	}

	got := readArtefactHosts(t, app)
	if !strings.Contains(got, "probe.example.com") {
		t.Errorf("no-staging merge wiped the httpx artefact\ngot:\n%s", got)
	}
}
