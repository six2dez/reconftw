// report_manifest_test.go — plan 15-11 Task 2.
//
// RenderReportsForTarget used to answer with os.ReadDir(reportsDir): every file
// in the shared reports directory, whoever wrote it and whenever. A file
// dropped there by another engagement, or left by a previous run with different
// integrations enabled, was handed to whichever MCP client asked for a report
// (T-15-11-02). The handler now answers from the renderer's own manifest.
package handlers_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// seedReportStore ingests one scan for target into dataDir/store.db.
func seedReportStore(t *testing.T, dataDir, target string) {
	t.Helper()
	workDir := filepath.Join(dataDir, "ws")
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(artefacts, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("hosts.jsonl", `{"host":"api.`+target+`","ip":"1.1.1.1"}`+"\n")
	write("findings.jsonl",
		`{"type":"http","host":"api.`+target+`","template_id":"panel","severity":"high",`+
			`"matched_at":"https://api.`+target+`/a"}`+"\n")

	if _, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", nil); err != nil {
		t.Fatalf("seed ScanIntoStore: %v", err)
	}
}

// TestRenderReportsForTargetReturnsOnlyThisRendersFiles plants an unrelated file
// in the reports tree and asserts it is absent from the response, while every
// path that IS returned exists and lives in this render's directory.
func TestRenderReportsForTargetReturnsOnlyThisRendersFiles(t *testing.T) {
	const target = "mcpreport.example"
	dataDir := t.TempDir()
	seedReportStore(t, dataDir, target)

	// A foreign file in the shared reports root — the exact thing the old
	// directory listing would have handed to the caller.
	reportsRoot := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(reportsRoot, 0o755); err != nil {
		t.Fatalf("mkdir reports root: %v", err)
	}
	foreign := filepath.Join(reportsRoot, "another-engagement-export.json")
	if err := os.WriteFile(foreign, []byte(`{"leak":true}`), 0o644); err != nil {
		t.Fatalf("plant foreign file: %v", err)
	}

	cfg := config.Defaults()
	cfg.Paths.DataDir = dataDir

	res, err := handlers.RenderReportsForTarget(context.Background(), cfg, &log.Redactor{}, target, "", false)
	if err != nil {
		t.Fatalf("RenderReportsForTarget: %v", err)
	}

	if len(res.Files) == 0 {
		t.Fatal("the report tool returned no files at all")
	}
	for _, p := range res.Files {
		if p == foreign {
			t.Error("the response contains a file this render did not write")
		}
		if filepath.Dir(p) != res.Dir {
			t.Errorf("returned path %s is outside this render's directory %s", p, res.Dir)
		}
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("returned path %s does not exist: %v", p, statErr)
		}
	}
	if res.ScanID == "" {
		t.Error("the response does not identify the scan it rendered")
	}

	// The render honoured cfg.Paths.DataDir rather than a freshly loaded
	// default — the F7 half of this change.
	ident, err := output.CanonicalTargetID(target)
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	wantDir := filepath.Join(dataDir, "reports", ident.Slug, res.ScanID)
	if res.Dir != wantDir {
		t.Errorf("render dir = %s; want %s — the caller's config was not honoured", res.Dir, wantDir)
	}
}
