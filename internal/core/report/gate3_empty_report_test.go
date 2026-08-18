// gate3_empty_report_test.go — the owning test for the SECOND clause of
// acceptance gate 3.
//
// Gate 3, verbatim from 15-CONTEXT.md:
//
//	"Run A with findings followed by an empty run B produces an empty artefact
//	 and an empty report."
//
// Plans 15-03, 15-13 and 15-14 prove the ARTEFACT half. Plan 15-11 Task 1
// proves a scan with zero observations renders zero rows FROM A DIRECTLY SEEDED
// STORE. Neither runs the real sequence, so before this file the "and an empty
// report" clause had no owning test: nothing drove artefact → ingest → render
// for a run that found nothing.
//
// This file does, using ONLY the exported ingest.ScanIntoStore and
// report.RenderAll, so it does not break when plan 15-10 reshapes ingest
// internals in the same wave. Every assertion is made against the PARSED
// RENDERED FILE taken from RenderResult.Files — not a store query, not a
// counter, not an intermediate slice.
package report_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/findings"
	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/report"
)

// fileFromManifest returns the path with base name from a render's manifest,
// failing if this render did not write it. Reading a path the manifest does not
// list would test the filesystem, not the report.
func fileFromManifest(t *testing.T, res report.RenderResult, base string) string {
	t.Helper()
	for _, p := range res.Files {
		if filepath.Base(p) == base {
			return p
		}
	}
	t.Fatalf("this render did not write %s; it wrote %v", base, res.Files)
	return ""
}

// sarifResultCount parses a rendered findings.sarif and returns the number of
// results across its runs — the findings collection of the rendered file.
func sarifResultCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the render manifest
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc findings.SarifLog
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	n := 0
	for _, run := range doc.Runs {
		n += len(run.Results)
	}
	return n
}

// mustBeZeroBytes asserts the artefact EXISTS and is empty. "the file is
// absent" and "the file is empty" are different states and the empty-publish
// path produces the second (web.publishEmptyStage → output.PublishArtefact with
// nil lines); asserting the wrong one would test a state the pipeline never
// reaches.
func mustBeZeroBytes(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("run B's artefact must exist and be empty, but stat failed: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("run B's artefact is %d bytes; want a zero-byte file", info.Size())
	}
}

func gate3Renderer(t *testing.T, dataDir string) *report.ReportRenderer {
	t.Helper()
	r, err := report.NewReportRenderer(dataDir, config.Defaults(), quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// TestGate3EmptyRunRendersEmptyReport drives the real sequence twice: once for
// the findings record class (artefacts/findings.jsonl, as web.MergeStage emits
// it) and once for the subdomains class (artefacts/subdomains.jsonl, as
// subdomains.MergeAllSubdomains emits it — the authoritative writer of that
// artefact after plan 15-03, not the per-stage MergeStage).
func TestGate3EmptyRunRendersEmptyReport(t *testing.T) {
	t.Run("findings", func(t *testing.T) {
		const target = "gate3findings.example"
		dataDir := t.TempDir()
		workDir := filepath.Join(dataDir, "ws")
		artefacts := filepath.Join(workDir, "artefacts")
		if err := os.MkdirAll(artefacts, 0o755); err != nil {
			t.Fatalf("mkdir artefacts: %v", err)
		}
		findingsPath := filepath.Join(artefacts, "findings.jsonl")

		// Step 2: ONE finding, in web.FindingRecord's shape.
		record := `{"type":"http","host":"api.` + target + `","template_id":"exposed-panel",` +
			`"severity":"high","matched_at":"https://api.` + target + `/admin",` +
			`"confidence":"high","refs":[]}` + "\n"
		if err := os.WriteFile(findingsPath, []byte(record), 0o644); err != nil {
			t.Fatalf("write findings.jsonl: %v", err)
		}

		// Step 3: run A.
		resA, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", quietLogger())
		if err != nil {
			t.Fatalf("run A ScanIntoStore: %v", err)
		}
		if resA.Findings != 1 {
			t.Fatalf("run A ingested %d findings; want 1", resA.Findings)
		}

		// Step 4: the artefact goes EMPTY, not away.
		if err := os.WriteFile(findingsPath, nil, 0o644); err != nil {
			t.Fatalf("empty findings.jsonl: %v", err)
		}
		mustBeZeroBytes(t, findingsPath)

		// Step 5: run B.
		resB, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", quietLogger())
		if err != nil {
			t.Fatalf("run B ScanIntoStore: %v", err)
		}
		if resB.ScanID == resA.ScanID {
			t.Fatalf("run B reused run A's scan id %s", resA.ScanID)
		}

		// Steps 6-7: render run B and assert on the RENDERED FILE.
		r := gate3Renderer(t, dataDir)
		renderedB, err := r.RenderAll(context.Background(), target, resB.ScanID, false, false)
		if err != nil {
			t.Fatalf("RenderAll(run B): %v", err)
		}
		if got := sarifResultCount(t, fileFromManifest(t, renderedB, "findings.sarif")); got != 0 {
			t.Errorf("run B's RENDERED report contains %d findings; want 0 — an empty run "+
				"resurrected run A's finding through the store", got)
		}
		if rows := csvRows(t, fileFromManifest(t, renderedB, "findings.csv")); len(rows) != 0 {
			t.Errorf("run B's rendered findings.csv has %d rows; want 0: %v", len(rows), rows)
		}

		// Step 8: the control. Without it a renderer that emits nothing for
		// every scan would pass every assertion above.
		renderedA, err := r.RenderAll(context.Background(), target, resA.ScanID, false, false)
		if err != nil {
			t.Fatalf("RenderAll(run A): %v", err)
		}
		if got := sarifResultCount(t, fileFromManifest(t, renderedA, "findings.sarif")); got != 1 {
			t.Errorf("run A's rendered report contains %d findings; want 1 — the renderer "+
				"is emitting nothing for every scan, so the run-B assertion proves nothing", got)
		}
	})

	t.Run("subdomains", func(t *testing.T) {
		const target = "gate3subs.example"
		dataDir := t.TempDir()
		workDir := filepath.Join(dataDir, "ws")
		artefacts := filepath.Join(workDir, "artefacts")
		if err := os.MkdirAll(artefacts, 0o755); err != nil {
			t.Fatalf("mkdir artefacts: %v", err)
		}
		subsPath := filepath.Join(artefacts, "subdomains.jsonl")

		// subdomains.SubdomainRecord: {"subdomain","source","first_seen"}.
		record := `{"subdomain":"api.` + target + `","source":"subfinder",` +
			`"first_seen":"2026-01-01T00:00:00Z"}` + "\n"
		if err := os.WriteFile(subsPath, []byte(record), 0o644); err != nil {
			t.Fatalf("write subdomains.jsonl: %v", err)
		}

		resA, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "subs", quietLogger())
		if err != nil {
			t.Fatalf("run A ScanIntoStore: %v", err)
		}
		if resA.Hosts != 1 {
			t.Fatalf("run A ingested %d hosts; want 1", resA.Hosts)
		}

		if err := os.WriteFile(subsPath, nil, 0o644); err != nil {
			t.Fatalf("empty subdomains.jsonl: %v", err)
		}
		mustBeZeroBytes(t, subsPath)

		resB, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "subs", quietLogger())
		if err != nil {
			t.Fatalf("run B ScanIntoStore: %v", err)
		}

		r := gate3Renderer(t, dataDir)
		renderedB, err := r.RenderAll(context.Background(), target, resB.ScanID, false, false)
		if err != nil {
			t.Fatalf("RenderAll(run B): %v", err)
		}
		if rows := csvRows(t, fileFromManifest(t, renderedB, "hosts.csv")); len(rows) != 0 {
			t.Errorf("run B's RENDERED hosts.csv has %d rows; want 0 — an empty subdomains "+
				"run resurrected run A's host: %v", len(rows), rows)
		}

		renderedA, err := r.RenderAll(context.Background(), target, resA.ScanID, false, false)
		if err != nil {
			t.Fatalf("RenderAll(run A): %v", err)
		}
		if rows := csvRows(t, fileFromManifest(t, renderedA, "hosts.csv")); len(rows) != 1 {
			t.Errorf("run A's rendered hosts.csv has %d rows; want 1 (control)", len(rows))
		}
	})
}
