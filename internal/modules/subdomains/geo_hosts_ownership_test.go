// geo_hosts_ownership_test.go — the subdomains half of plan 15-13 Task 3's
// "hosts" ownership decision.
//
// artefacts/hosts.jsonl has TWO direct writers: web/httpx.go and this package's
// SubGeoTask. The F3 empty publish is assigned to httpx ALONE, on ordering
// evidence verified in internal/mcp/handlers/composite.go — subdomains.geo sits
// in "subs-enrichment", the LAST subdomains stage group, and web.httpx sits in
// "web-probe", the FIRST web group, with the web groups appended after the subs
// groups. geo therefore always runs BEFORE httpx.
//
// geo must NOT empty-publish, because in a subs-only or passive run httpx never
// runs at all, and an empty publish from geo would erase a previous web run's
// hosts that no producer in this run ever examined. That is strictly worse than
// the staleness it would remove.
//
// This file pins that decision so a later "let's make geo consistent with the
// other producers" change fails loudly.
package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"
)

// TestGeoDoesNotEmptyPublishHostsArtefact runs SubGeoTask against a workspace
// whose hosts artefact already holds a previous web run's records, with geo
// producing ZERO records of its own, and asserts the artefact is UNCHANGED.
func TestGeoDoesNotEmptyPublishHostsArtefact(t *testing.T) {
	// No ipinfo server: every lookup fails, so geo builds no records.
	app, workDir := buildGeoApp(t, "")

	// A previous web run's hosts.jsonl, which geo must not touch.
	artefactsDir := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	artefact := filepath.Join(artefactsDir, "hosts.jsonl")
	seed := `{"host":"www.example.com","url":"https://www.example.com","status_code":200}` + "\n"
	if err := os.WriteFile(artefact, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed hosts.jsonl: %v", err)
	}

	// Remove the resolved input so geo has nothing to enrich and produces no
	// records on any path.
	if err := os.Remove(filepath.Join(workDir, "inputs", "resolved.merged.txt")); err != nil &&
		!os.IsNotExist(err) {
		t.Fatalf("remove resolved.merged.txt: %v", err)
	}

	tsk, ok := task.Default.Lookup("subdomains.geo")
	if !ok {
		t.Fatal("subdomains.geo not registered")
	}
	if _, err := tsk.Run(context.Background(), app); err != nil {
		t.Fatalf("SubGeoTask.Run: %v", err)
	}

	got, err := os.ReadFile(artefact) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("geo must not delete artefacts/hosts.jsonl: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(seed) {
		t.Errorf("geo produced no records and must leave artefacts/hosts.jsonl UNCHANGED — "+
			"httpx (web/httpx.go) owns the hosts empty publish, because in a subs-only run "+
			"httpx never runs and an empty publish here would erase a previous web run's "+
			"hosts that nothing in this run examined.\n got: %q\nwant: %q",
			string(got), seed)
	}
}

// TestGeoSoleWriterCommentReplacedNotDeleted pins the corrected comment.
//
// The original comment asserted SubGeoTask was the only "hosts" writer. That was
// false, and deleting it outright is how the error would be reintroduced — the
// next reader would have no reason to think about httpx at all. The replacement
// must name httpx and the ordering.
func TestGeoSoleWriterCommentReplacedNotDeleted(t *testing.T) {
	src, err := os.ReadFile("geo.go") //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read geo.go: %v", err)
	}
	body := string(src)
	if strings.Contains(body, "SubGeoTask is the only") {
		t.Error("geo.go still claims SubGeoTask is the only \"hosts\" writer — " +
			"web/httpx.go is the other, and the authoritative one")
	}
	if !strings.Contains(body, "httpx") {
		t.Error("geo.go must name httpx as the authoritative hosts writer and " +
			"empty-publish owner — a wrong comment replaced by NO comment is how this " +
			"was missed the first time")
	}
}
