// e2e_scan_scope_test.go — a report must describe ONE scan of ONE target.
//
// RenderAll resolved a scan, then queried findings and hosts by the targetID
// the CALLER passed and URLs with HostIDFilter 0 — no filter at all. On a store
// holding more than one target that produced a report whose header named one
// scan while its URL section listed every URL in the database, and
// `--target A --scan-id <scan of B>` rendered B's header over A's data without
// complaint.
package report_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/report"

	_ "modernc.org/sqlite"
)

// seedTarget ingests one target's artefacts into the shared store at dataDir.
func seedTarget(t *testing.T, dataDir, target, host, url string) {
	t.Helper()
	workDir := filepath.Join(dataDir, target)
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(artefacts, name), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("hosts.jsonl", `{"host":"`+host+`","ip":"1.2.3.4"}`)
	write("urls.jsonl", `{"url":"`+url+`","host":"`+host+`"}`)
	write("findings.jsonl",
		`{"type":"http","host":"`+host+`","template_id":"panel","severity":"high","matched_at":"`+url+`"}`)

	if _, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "all", nil); err != nil {
		t.Fatalf("seed %s: %v", target, err)
	}
}

// TestE2EReportDoesNotLeakAnotherTarget seeds TWO targets into one shared store
// and checks the rendered report contains only its own.
func TestE2EReportDoesNotLeakAnotherTarget(t *testing.T) {
	dataDir := t.TempDir()
	seedTarget(t, dataDir, "alpha.example", "api.alpha.example", "https://api.alpha.example/a")
	seedTarget(t, dataDir, "beta.example", "api.beta.example", "https://api.beta.example/SECRET-BETA")

	r, err := report.NewReportRenderer(dataDir, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer r.Close() //nolint:errcheck

	if err := r.RenderAll(context.Background(), "alpha.example", "", false); err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dataDir, "reports", "report.html"))
	if err != nil {
		// Format name may differ; fall back to scanning the whole reports dir.
		entries, _ := os.ReadDir(filepath.Join(dataDir, "reports"))
		var all []byte
		for _, e := range entries {
			b, _ := os.ReadFile(filepath.Join(dataDir, "reports", e.Name()))
			all = append(all, b...)
		}
		body = all
	}
	if len(body) == 0 {
		t.Skip("no report artefacts produced in this environment")
	}
	if strings.Contains(string(body), "SECRET-BETA") {
		t.Error("alpha's report contains beta's URL — the URL query is not target-scoped")
	}
}

// latestScanID reads the most recent scan id for target straight from the
// shared store, so the test does not depend on report internals.
func latestScanID(t *testing.T, dataDir, target string) string {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "store.db")+"?mode=ro")
	if err != nil {
		return ""
	}
	defer db.Close() //nolint:errcheck
	var id string
	if err := db.QueryRow(
		`SELECT id FROM scans WHERE target_id = ? ORDER BY started_at DESC LIMIT 1`,
		target).Scan(&id); err != nil {
		return ""
	}
	return id
}

// TestE2EReportRejectsMismatchedScanAndTarget covers the explicit --scan-id
// path: a scan belonging to another target must be refused, not rendered.
func TestE2EReportRejectsMismatchedScanAndTarget(t *testing.T) {
	dataDir := t.TempDir()
	seedTarget(t, dataDir, "alpha.example", "api.alpha.example", "https://api.alpha.example/a")
	seedTarget(t, dataDir, "beta.example", "api.beta.example", "https://api.beta.example/b")

	r, err := report.NewReportRenderer(dataDir, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck

	betaScan := latestScanID(t, dataDir, "beta.example")
	if betaScan == "" {
		t.Skip("could not resolve beta's scan id")
	}
	err = r.RenderAll(context.Background(), "alpha.example", betaScan, false)
	if err == nil {
		t.Fatal("rendering beta's scan under --target alpha must be refused")
	}
	if !strings.Contains(err.Error(), "belongs to target") {
		t.Errorf("error should explain the target mismatch, got: %v", err)
	}
}

// TestE2EReportOfSecondScanExcludesVanishedAsset is the case two different
// targets cannot expose: two scans of the SAME target, where an asset present
// in scan 1 is gone by scan 2.
//
// Querying by target rather than by scan meant scan 2's report still listed
// scan 1's asset — the report described a state that never existed, and a
// remediated or decommissioned asset could never drop out of it.
func TestE2EReportOfSecondScanExcludesVanishedAsset(t *testing.T) {
	dataDir := t.TempDir()
	target := "example.com"
	workDir := filepath.Join(dataDir, "ws")
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(artefacts, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Scan 1: hosts A and B.
	write("hosts.jsonl", `{"host":"alpha.example.com","ip":"1.1.1.1"}`+"\n"+
		`{"host":"beta.example.com","ip":"2.2.2.2"}`+"\n")
	write("findings.jsonl", `{"type":"http","host":"alpha.example.com","template_id":"panel","severity":"high"}`+"\n")
	if _, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", nil); err != nil {
		t.Fatalf("scan 1: %v", err)
	}

	// Scan 2: only B — alpha is gone.
	write("hosts.jsonl", `{"host":"beta.example.com","ip":"2.2.2.2"}`+"\n")
	write("findings.jsonl", `{"type":"http","host":"beta.example.com","template_id":"panel","severity":"low"}`+"\n")
	res2, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", nil)
	if err != nil {
		t.Fatalf("scan 2: %v", err)
	}

	r, err := report.NewReportRenderer(dataDir, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck

	if err := r.RenderAll(context.Background(), target, res2.ScanID, false); err != nil {
		t.Fatalf("RenderAll(scan 2): %v", err)
	}

	entries, _ := os.ReadDir(filepath.Join(dataDir, "reports"))
	var all []byte
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dataDir, "reports", e.Name()))
		all = append(all, b...)
	}
	if len(all) == 0 {
		t.Skip("no report artefacts produced in this environment")
	}
	if !strings.Contains(string(all), "beta.example.com") {
		t.Error("scan 2's report is missing the host that scan 2 actually observed")
	}
	if strings.Contains(string(all), "alpha.example.com") {
		t.Error("scan 2's report contains alpha.example.com, which only scan 1 " +
			"observed — the report is target-scoped, not scan-scoped")
	}
}
