// e2e_takeover_ingest_test.go — real takeover records must reach the store.
//
// subdomains.TakeoverRecord emits {type, host, service, confidence, severity,
// refs}. The finding signature was built from template_id / vuln_class /
// source+category / matcher_name — none of which that producer writes — so
// every real takeover hit `sig == ""` and was dropped during ingest. The
// pipeline found it, merged it and wrote it to artefacts/findings.jsonl, and
// then the store never heard about it, so report/monitor/SARIF could not.
//
// The record here is marshalled from the production struct on purpose: writing
// the JSON by hand is exactly how the gap survived.
package ingest_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/modules/subdomains"

	_ "modernc.org/sqlite"
)

func TestE2ETakeoverRecordReachesStore(t *testing.T) {
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatal(err)
	}

	rec, err := json.Marshal(subdomains.TakeoverRecord{
		Type:       "subdomain-takeover",
		Host:       "dangling.example.com",
		Service:    "github",
		Confidence: "high",
		Severity:   "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artefacts, "findings.jsonl"), append(rec, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artefacts, "hosts.jsonl"),
		[]byte(`{"host":"dangling.example.com","ip":"1.2.3.4"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir,
		"example.com", "recon", nil)
	if err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}
	if res.Findings != 1 {
		t.Fatalf("ingested %d findings, want 1 — the takeover record was discarded "+
			"for having no usable signature", res.Findings)
	}

	db, err := sql.Open("sqlite", filepath.Join(dataDir, "store.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck

	var sig, severity string
	if err := db.QueryRow(
		`SELECT template_signature, severity FROM findings LIMIT 1`).Scan(&sig, &severity); err != nil {
		t.Fatalf("takeover finding absent from the store: %v", err)
	}
	if sig != "subdomain-takeover" {
		t.Errorf("template_signature = %q, want the record's type", sig)
	}
	if severity != "high" {
		t.Errorf("severity = %q, want high", severity)
	}
}
