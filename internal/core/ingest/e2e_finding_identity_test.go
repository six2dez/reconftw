// e2e_finding_identity_test.go — distinct endpoints are distinct findings.
//
// The findings unique key is (template_signature, tool, host_id, port_id,
// path), and ingest passed path = "" for every record. So two SQL injections
// on two different endpoints of the same host collapsed into ONE row: the
// scanner found both, the merge wrote both, and the store kept one. A report
// built from that store under-counts real vulnerabilities.
package ingest_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/ingest"

	_ "modernc.org/sqlite"
)

func countFindings(t *testing.T, dataDir string) int {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "store.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestE2EDistinctEndpointsStayDistinctFindings(t *testing.T) {
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(artefacts, "hosts.jsonl"),
		[]byte(`{"host":"shop.example.com","ip":"1.2.3.4"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Same class, same tool, same host — three genuinely different locations:
	// two distinct paths, and two distinct parameters on one path.
	body := `{"vuln_class":"sqli","engine":"sqlmap","host":"shop.example.com","severity":"critical","url":"https://shop.example.com/product?id=1"}
{"vuln_class":"sqli","engine":"sqlmap","host":"shop.example.com","severity":"critical","url":"https://shop.example.com/search?q=x"}
{"vuln_class":"sqli","engine":"sqlmap","host":"shop.example.com","severity":"critical","url":"https://shop.example.com/product?ref=2"}
`
	if err := os.WriteFile(filepath.Join(artefacts, "findings.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir,
		"example.com", "all", nil); err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}

	if got := countFindings(t, dataDir); got != 3 {
		t.Errorf("store holds %d findings, want 3 — distinct endpoints collapsed "+
			"into one row because the finding identity carries no path", got)
	}
}

// TestE2ESameEndpointStillDedups is the other half of the contract: identity
// must be narrow enough to separate real findings, and wide enough that
// re-observing the SAME one does not duplicate it.
func TestE2ESameEndpointStillDedups(t *testing.T) {
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artefacts, "hosts.jsonl"),
		[]byte(`{"host":"shop.example.com","ip":"1.2.3.4"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Same finding twice, once with the query parameters in the other order —
	// the normaliser sorts query keys, so this is still one finding.
	body := `{"vuln_class":"sqli","engine":"sqlmap","host":"shop.example.com","severity":"critical","url":"https://shop.example.com/p?a=1&b=2"}
{"vuln_class":"sqli","engine":"sqlmap","host":"shop.example.com","severity":"critical","url":"https://shop.example.com/p?b=9&a=8"}
`
	if err := os.WriteFile(filepath.Join(artefacts, "findings.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir,
		"example.com", "all", nil); err != nil {
		t.Fatal(err)
	}
	if got := countFindings(t, dataDir); got != 1 {
		t.Errorf("store holds %d findings, want 1 — the same endpoint must not "+
			"duplicate just because query values or ordering differ", got)
	}
}
