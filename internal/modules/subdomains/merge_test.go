// merge_test.go — F3 (15-03) empty-union behaviour for the subdomains merger.
//
// subdomains is CASE C + CASE D and behaves differently from the web/vulns/osint
// mergers on purpose:
//
//	CASE C — MergeStage is NOT the authoritative writer of
//	         artefacts/subdomains.jsonl (MergeAllSubdomains is), and it runs up
//	         to four times per run, so it must never publish an empty artefact.
//	         MergeAllSubdomains owns the empty publish.
//	CASE D — MergeStage DOES write a derived inputs/<stage>.merged.txt that eight
//	         downstream stages open as an input file. It must be refreshed on
//	         EVERY merge, including the empty one, as an EMPTY file (never
//	         removed — subdomains is PolicyFailFast).
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

func newSubsMergeApp(t *testing.T) *appctx.AppContext {
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

func subsArtefact(app *appctx.AppContext) string {
	return filepath.Join(app.Target.WorkDir, "artefacts", "subdomains.jsonl")
}

func subsInput(app *appctx.AppContext, name string) string {
	return filepath.Join(app.Target.WorkDir, "inputs", name)
}

func writeTxtFixture(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func countNonBlank(t *testing.T, path string) int {
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
// CASE A (via MergeAllSubdomains) — the one empty-publish site for subdomains.
// ---------------------------------------------------------------------------

// TestMergeAllSubdomainsEmptyRunPublishesEmptyArtefact is acceptance gate 3's
// artefact half for subdomains: run A resolves two hosts, run B (same
// workspace) resolves none, and the artefact must become PRESENT-and-EMPTY
// rather than keeping run A's hosts.
func TestMergeAllSubdomainsEmptyRunPublishesEmptyArtefact(t *testing.T) {
	app := newSubsMergeApp(t)
	staged := subsInput(app, "passive.subfinder.txt")

	writeTxtFixture(t, staged, "a.example.com", "b.example.com")
	if err := subdomains.MergeAllSubdomains(context.Background(), app); err != nil {
		t.Fatalf("run A MergeAllSubdomains: %v", err)
	}
	if n := countNonBlank(t, subsArtefact(app)); n != 2 {
		t.Fatalf("run A artefact lines = %d, want 2", n)
	}

	// Run B: the producers ran, found nothing, and cleared their staging.
	if err := os.Remove(staged); err != nil {
		t.Fatalf("remove staging: %v", err)
	}
	if err := subdomains.MergeAllSubdomains(context.Background(), app); err != nil {
		t.Fatalf("run B MergeAllSubdomains: %v", err)
	}

	info, err := os.Stat(subsArtefact(app))
	if err != nil {
		t.Fatalf("run B must leave the artefact PRESENT, stat err = %v", err)
	}
	if info.Size() != 0 {
		body, _ := os.ReadFile(subsArtefact(app)) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("run B republished run A's subdomains (size %d):\n%s", info.Size(), body)
	}
}

// ---------------------------------------------------------------------------
// CASE C — the per-stage merge must not truncate the artefact mid-run.
// ---------------------------------------------------------------------------

// TestMergeStageDoesNotTruncateSubdomainsArtefact: composite modes call
// MergeStage four times per run (passive, resolved ×2, permut —
// internal/mcp/handlers/composite.go). A stage that produced nothing must leave
// the artefact alone; emptying it here would show an empty subdomains.jsonl to
// any consumer reading between that call and MergeAllSubdomains.
func TestMergeStageDoesNotTruncateSubdomainsArtefact(t *testing.T) {
	app := newSubsMergeApp(t)

	// An earlier stage already wrote the artefact this run.
	writeTxtFixture(t, subsArtefact(app),
		`{"subdomain":"a.example.com","source":"subfinder"}`,
		`{"subdomain":"b.example.com","source":"crt"}`)

	// permut produced nothing: inputs/permut.*.txt is an empty glob.
	if err := subdomains.MergeStage(context.Background(), app, "permut"); err != nil {
		t.Fatalf("MergeStage(permut): %v", err)
	}

	if n := countNonBlank(t, subsArtefact(app)); n != 2 {
		body, _ := os.ReadFile(subsArtefact(app)) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("MergeStage truncated the artefact mid-run: %d lines, want 2\n%s", n, body)
	}
}

// ---------------------------------------------------------------------------
// CASE D — the derived <stage>.merged.txt intermediate.
// ---------------------------------------------------------------------------

// TestMergeStageRefreshesDerivedMergedTxt: run A resolves two hosts, run B
// resolves none. inputs/resolved.merged.txt must be refreshed to an EMPTY,
// PRESENT file — not left holding run A's hostnames (which the permutation,
// recursive, buckets and takeover stages would then consume), and not REMOVED
// (subdomains is PolicyFailFast, so a missing input file can fail-fast the
// whole spine).
func TestMergeStageRefreshesDerivedMergedTxt(t *testing.T) {
	app := newSubsMergeApp(t)
	staged := subsInput(app, "resolved.puredns.txt")
	merged := subsInput(app, "resolved.merged.txt")

	writeTxtFixture(t, staged, "a.example.com", "b.example.com")
	if err := subdomains.MergeStage(context.Background(), app, "resolved"); err != nil {
		t.Fatalf("run A MergeStage(resolved): %v", err)
	}
	body, err := os.ReadFile(merged) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("run A must produce resolved.merged.txt: %v", err)
	}
	if string(body) != "a.example.com\nb.example.com\n" {
		t.Fatalf("run A merged.txt = %q", body)
	}

	// Run B: no resolved staging at all.
	if err := os.Remove(staged); err != nil {
		t.Fatalf("remove staging: %v", err)
	}
	if err := subdomains.MergeStage(context.Background(), app, "resolved"); err != nil {
		t.Fatalf("run B MergeStage(resolved): %v", err)
	}

	info, err := os.Stat(merged)
	if err != nil {
		t.Fatalf("resolved.merged.txt must remain PRESENT (PolicyFailFast consumers open it): %v", err)
	}
	if info.Size() != 0 {
		after, _ := os.ReadFile(merged) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("run B fed run A's hostnames to downstream stages (%d bytes):\n%s", info.Size(), after)
	}
}

// TestMergeStageMergedTxtRefreshedWhenGlobEmptyFromTheStart proves the refresh
// is unconditional, not merely "on the second call": an empty glob on the FIRST
// call still creates the derived file, so a downstream PolicyFailFast consumer
// can open it.
func TestMergeStageMergedTxtRefreshedWhenGlobEmptyFromTheStart(t *testing.T) {
	app := newSubsMergeApp(t)
	if err := subdomains.MergeStage(context.Background(), app, "permut"); err != nil {
		t.Fatalf("MergeStage(permut): %v", err)
	}
	info, err := os.Stat(subsInput(app, "permut.merged.txt"))
	if err != nil {
		t.Fatalf("permut.merged.txt must be created even on an empty glob: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected zero-byte derived file, got %d bytes", info.Size())
	}
}

// TestMergeAllSubdomainsSkipsDerivedMergedTxt is the reason the derived file
// needs an exemption in the staging-contract guard rather than a StageLines
// call: <stage>.merged.txt DOES match the subdomains merger glob
// <stage>.*.txt, which is why MergeAllSubdomains has to skip it by hand.
func TestMergeAllSubdomainsSkipsDerivedMergedTxt(t *testing.T) {
	app := newSubsMergeApp(t)

	// A derived file left by an earlier stage, with a host no producer staged.
	writeTxtFixture(t, subsInput(app, "passive.merged.txt"), "ghost.example.com")
	writeTxtFixture(t, subsInput(app, "passive.subfinder.txt"), "real.example.com")

	if err := subdomains.MergeAllSubdomains(context.Background(), app); err != nil {
		t.Fatalf("MergeAllSubdomains: %v", err)
	}
	body, err := os.ReadFile(subsArtefact(app)) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read artefact: %v", err)
	}
	if strings.Contains(string(body), "ghost.example.com") {
		t.Errorf("derived merged.txt was consumed as a merge source:\n%s", body)
	}
	if !strings.Contains(string(body), "real.example.com") {
		t.Errorf("real staging host missing:\n%s", body)
	}
}
