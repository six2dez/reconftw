// merge_test.go — F3 (15-03) empty-union behaviour for the web merger.
//
// Run A finds a result, run B on the SAME workspace finds nothing. Workspaces
// are stable across runs by design, so before 15-03 run B republished run A's
// artefact. These tests drive the STAGE-LEVEL entry point (web.MergeStage)
// because that is what production calls — MergeAllWebArtefacts is reached only
// from tests and doc comments (internal/mcp/handlers/web.go,
// internal/mcp/handlers/composite.go call MergeStage directly).
package web_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/modules/web"
)

func newMergeApp(t *testing.T) *appctx.AppContext {
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

func writeJSONLFixture(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func artefactPath(app *appctx.AppContext, stage string) string {
	return filepath.Join(app.Target.WorkDir, "artefacts", stage+".jsonl")
}

func stagingPath(app *appctx.AppContext, name string) string {
	return filepath.Join(app.Target.WorkDir, "inputs", name)
}

// nonBlankLines counts the non-blank lines of a file. A missing file is an
// error, because "present and empty" and "absent" are exactly the two states
// these tests must distinguish.
func nonBlankLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("artefact must EXIST (present-and-empty, not absent): %v", err)
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
// CASE A — stages with no direct artefact writer publish an EMPTY artefact.
// ---------------------------------------------------------------------------

// TestMergeStageFindingsEmptyRunPublishesEmptyArtefact is acceptance gate 3's
// artefact half for the "findings" stage: run A with a finding, then run B with
// nothing, must leave a PRESENT, EMPTY artefact — not run A's finding.
func TestMergeStageFindingsEmptyRunPublishesEmptyArtefact(t *testing.T) {
	app := newMergeApp(t)
	staged := stagingPath(app, "findings.x.jsonl")

	// Run A: one finding.
	writeJSONLFixture(t, staged, `{"host":"a.example.com","name":"cve-2020-1234"}`)
	if err := web.MergeStage(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run A MergeStage(findings): %v", err)
	}
	if n := nonBlankLines(t, artefactPath(app, "findings")); n != 1 {
		t.Fatalf("run A artefact lines = %d, want 1", n)
	}

	// Run B: the producer ran, found nothing, and cleared its staging file.
	if err := os.Remove(staged); err != nil {
		t.Fatalf("remove staging: %v", err)
	}
	if err := web.MergeStage(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run B MergeStage(findings): %v", err)
	}

	info, err := os.Stat(artefactPath(app, "findings"))
	if err != nil {
		t.Fatalf("run B must leave the artefact PRESENT, stat err = %v", err)
	}
	if info.Size() != 0 {
		body, _ := os.ReadFile(artefactPath(app, "findings")) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("run B republished run A's finding (size %d):\n%s", info.Size(), body)
	}
}

// TestMergeStageWafEmptyRunPublishesEmptyArtefact — same two-step experiment for
// the other Case-A web stage.
func TestMergeStageWafEmptyRunPublishesEmptyArtefact(t *testing.T) {
	app := newMergeApp(t)
	staged := stagingPath(app, "waf.wafw00f.jsonl")

	writeJSONLFixture(t, staged, `{"host":"a.example.com","waf":"cloudflare"}`)
	if err := web.MergeStage(context.Background(), app, "waf"); err != nil {
		t.Fatalf("run A MergeStage(waf): %v", err)
	}
	if n := nonBlankLines(t, artefactPath(app, "waf")); n != 1 {
		t.Fatalf("run A artefact lines = %d, want 1", n)
	}

	if err := os.Remove(staged); err != nil {
		t.Fatalf("remove staging: %v", err)
	}
	if err := web.MergeStage(context.Background(), app, "waf"); err != nil {
		t.Fatalf("run B MergeStage(waf): %v", err)
	}
	if n := nonBlankLines(t, artefactPath(app, "waf")); n != 0 {
		t.Fatalf("run B artefact lines = %d, want 0 (stale waf republished)", n)
	}
}

// TestMergeStageEmptyStagingFilePublishesEmpty covers the second empty path: the
// staging file EXISTS but holds no records (glob non-empty, union empty).
func TestMergeStageEmptyStagingFilePublishesEmpty(t *testing.T) {
	app := newMergeApp(t)
	staged := stagingPath(app, "findings.x.jsonl")

	writeJSONLFixture(t, staged, `{"host":"a.example.com","name":"stale"}`)
	if err := web.MergeStage(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run A: %v", err)
	}

	// Producer truncated its staging file rather than removing it.
	if err := os.WriteFile(staged, nil, 0o644); err != nil {
		t.Fatalf("truncate staging: %v", err)
	}
	if err := web.MergeStage(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run B: %v", err)
	}
	if n := nonBlankLines(t, artefactPath(app, "findings")); n != 0 {
		t.Fatalf("artefact lines = %d, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// CASE B — the merge must never TRUNCATE an artefact it does not own.
//
// These four tests prove ONE THING ONLY: that THE MERGE does not truncate.
// They are deliberately NOT named "…ArtefactPreserved", because these four
// artefacts MUST be emptied when their own direct writer runs and finds
// nothing. That producer-side empty-publish is plan 15-13 Task 3 at
// web/ffuf.go, web/hakoriginfinder.go, web/urldedup.go and web/httpx.go.
// ---------------------------------------------------------------------------

func assertMergeDoesNotTruncate(t *testing.T, stage, seed string) {
	t.Helper()
	app := newMergeApp(t)
	// The stage's DIRECT writer (ffuf / hakoriginfinder / urldedup / httpx)
	// produced this artefact in THIS run.
	writeJSONLFixture(t, artefactPath(app, stage), seed)

	// The staging glob is empty — for fuzz and origins it is permanently empty
	// (no staging producer exists at all).
	if err := web.MergeStage(context.Background(), app, stage); err != nil {
		t.Fatalf("MergeStage(%s): %v", stage, err)
	}

	got, err := os.ReadFile(artefactPath(app, stage)) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("MergeStage(%s) removed the artefact its direct writer produced: %v", stage, err)
	}
	if strings.TrimSpace(string(got)) != seed {
		t.Fatalf("MergeStage(%s) did not preserve the direct writer's record byte-for-byte\n got %q\nwant %q",
			stage, got, seed)
	}
}

// TestMergeStageDoesNotTruncateFuzz — artefacts/fuzz.jsonl is written directly
// by web/ffuf.go:203 and has NO staging producer, so the glob is permanently
// empty. An unconditional empty publish would zero it in the same run ffuf
// produced it, and web/nomore403.go, vulns/bypass4xx.go and web/portscan.go
// would then read an empty file.
// Emptying fuzz when ffuf RUNS and finds nothing is plan 15-13 Task 3.
func TestMergeStageDoesNotTruncateFuzz(t *testing.T) {
	assertMergeDoesNotTruncate(t, "fuzz", `{"url":"https://a.example.com/admin","status":200}`)
}

// TestMergeStageDoesNotTruncateOrigins — artefacts/origins.jsonl is written
// directly by web/hakoriginfinder.go:146 and likewise has NO staging producer.
// Emptying origins when hakoriginfinder RUNS and finds nothing is 15-13 Task 3.
func TestMergeStageDoesNotTruncateOrigins(t *testing.T) {
	assertMergeDoesNotTruncate(t, "origins", `{"host":"a.example.com","origin":"192.0.2.10"}`)
}

// TestMergeStageDoesNotTruncateHosts — artefacts/hosts.jsonl is written
// directly by web/httpx.go:228 AND subdomains/geo.go:196.
// Emptying hosts when httpx RUNS and finds nothing is 15-13 Task 3.
func TestMergeStageDoesNotTruncateHosts(t *testing.T) {
	assertMergeDoesNotTruncate(t, "hosts", `{"host":"a.example.com","source":"httpx"}`)
}

// TestMergeStageDoesNotTruncateUrls — artefacts/urls.jsonl is written directly
// by web/urldedup.go:230, the sole semantic-dedup writer (WEB-14).
// Emptying urls when urldedup RUNS and finds nothing is 15-13 Task 3.
func TestMergeStageDoesNotTruncateUrls(t *testing.T) {
	assertMergeDoesNotTruncate(t, "urls", `{"url":"https://a.example.com/one"}`)
}

// TestMergeStageUrlsStillUnionsRawStaging pins the OTHER half of the urls rule:
// the never-truncate guard must NOT have turned into a seed-and-union for
// "urls". Only "hosts" seeds the existing artefact (artefactSeedStages); seeding
// urls would re-import the pre-dedup staging URLs on top of urldedup's
// deduplicated artefact and undo WEB-14. The intermediate merge at
// internal/mcp/handlers/web.go:143 must keep publishing the raw union.
func TestMergeStageUrlsStillUnionsRawStaging(t *testing.T) {
	app := newMergeApp(t)

	// urldedup's deduplicated artefact from an earlier point in the run.
	writeJSONLFixture(t, artefactPath(app, "urls"),
		`{"url":"https://a.example.com/keep1"}`,
		`{"url":"https://a.example.com/keep2"}`)

	// katana staged 3 raw records, one of them a duplicate of another.
	writeJSONLFixture(t, stagingPath(app, "urls.katana.jsonl"),
		`{"url":"https://a.example.com/raw1"}`,
		`{"url":"https://a.example.com/raw2"}`,
		`{"url":"https://a.example.com/raw1"}`)

	if err := web.MergeStage(context.Background(), app, "urls"); err != nil {
		t.Fatalf("MergeStage(urls): %v", err)
	}

	body, err := os.ReadFile(artefactPath(app, "urls")) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read urls artefact: %v", err)
	}
	got := string(body)
	if n := nonBlankLines(t, artefactPath(app, "urls")); n != 2 {
		t.Fatalf("urls artefact has %d lines, want 2 (raw union, byte-deduped)\ngot:\n%s", n, got)
	}
	for _, want := range []string{"/raw1", "/raw2"} {
		if !strings.Contains(got, want) {
			t.Errorf("raw union missing %q\ngot:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"/keep1", "/keep2"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("urls merge SEEDED the existing artefact (%q survived) — WEB-14 undone\ngot:\n%s",
				unwanted, got)
		}
	}
}
