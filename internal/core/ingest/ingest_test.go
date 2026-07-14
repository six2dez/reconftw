package ingest

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// writeArtefact writes lines to <workDir>/artefacts/<name>.
func writeArtefact(t *testing.T, workDir, name string, lines ...string) {
	t.Helper()
	dir := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestScanIntoStore_EndToEnd is the correctness proof for the hand-authored
// schema: it ingests one record of each of the three heterogeneous finding
// shapes plus hosts/urls, then reads them back through the EXACT queries the
// report renderer uses. If the DDL or column mapping were wrong, these reads
// would fail or return nothing.
func TestScanIntoStore_EndToEnd(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	workDir := filepath.Join(tmp, "ws")
	target := "example.com"
	ctx := context.Background()

	// web.FindingRecord, vulns.VulnFindingRecord, osint.OSINTFindingRecord shapes.
	writeArtefact(t, workDir, "findings.jsonl",
		`{"type":"http","host":"api.example.com","template_id":"exposed-panel","severity":"high","matched_at":"https://api.example.com/admin"}`,
		`{"severity":"medium","vuln_class":"xss","matched_param":"q","engine":"dalfox"}`,
		`{"severity":"info","class":"osint","source":"github_leaks","category":"leaked-secret"}`,
	)
	writeArtefact(t, workDir, "hosts.jsonl",
		`{"host":"api.example.com","ip":"1.2.3.4","cdn":"cloudflare"}`,
	)
	writeArtefact(t, workDir, "subdomains.jsonl",
		`{"host":"www.example.com","ip":"5.6.7.8"}`,
	)
	writeArtefact(t, workDir, "urls.jsonl",
		`{"url":"https://api.example.com/admin?q=1","host":"api.example.com"}`,
	)

	res, err := ScanIntoStore(ctx, dataDir, workDir, target, "all", quietLogger())
	if err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}
	if res.Findings != 3 {
		t.Errorf("findings = %d, want 3", res.Findings)
	}
	if res.Hosts != 2 {
		t.Errorf("hosts = %d, want 2", res.Hosts)
	}
	if res.URLs != 1 {
		t.Errorf("urls = %d, want 1", res.URLs)
	}

	// Re-open the store and query it exactly as report.RenderAll does.
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "store.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	q := sqlcgen.New(db)

	scan, err := q.GetLatestCompletedScanForTarget(ctx, target)
	if err != nil {
		t.Fatalf("GetLatestCompletedScanForTarget: %v", err)
	}
	if scan.Status != "completed" {
		t.Errorf("scan status = %q, want completed", scan.Status)
	}
	if scan.FindingsCount != 3 {
		t.Errorf("scan.FindingsCount = %d, want 3", scan.FindingsCount)
	}
	if scan.FinishedAt == nil {
		t.Error("scan.FinishedAt is nil, want a timestamp")
	}

	findings, err := q.ListFindingsForTarget(ctx, sqlcgen.ListFindingsForTargetParams{
		TargetID: target, Limit: 100, Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListFindingsForTarget: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("ListFindingsForTarget returned %d, want 3", len(findings))
	}
	// Every finding must carry a signature, tool and normalized severity.
	for _, f := range findings {
		if f.TemplateSignature == "" || f.Tool == "" || f.Severity == "" {
			t.Errorf("finding under-populated: sig=%q tool=%q sev=%q", f.TemplateSignature, f.Tool, f.Severity)
		}
	}

	// NOTE: the *Cursor params are interface{} — leaving CdnFilter/CursorSeenAt
	// unset passes SQL NULL, and "NULL = ''"/"NULL = 0" are falsy, so the
	// no-filter branches never fire and every row is excluded. Pass the same
	// explicit "" / 0 sentinels the report renderer uses (renderer.go).
	hosts, err := q.ListHostsCursor(ctx, sqlcgen.ListHostsCursorParams{
		TargetID: target, CdnFilter: "", CursorSeenAt: 0, CursorLastID: 0, RowLimit: 100,
	})
	if err != nil {
		t.Fatalf("ListHostsCursor: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("ListHostsCursor returned %d hosts, want 2", len(hosts))
	}

	urls, err := q.ListURLsCursor(ctx, sqlcgen.ListURLsCursorParams{
		HostIDFilter: 0, StatusCodeFilter: 0, ContentTypeFilter: "", CursorSeenAt: 0, CursorLastID: 0, RowLimit: 100,
	})
	if err != nil {
		t.Fatalf("ListURLsCursor: %v", err)
	}
	if len(urls) != 1 {
		t.Errorf("ListURLsCursor returned %d urls, want 1", len(urls))
	}
}

// TestScanIntoStore_Idempotent verifies a second run against the shared store
// dedups findings (UpsertFinding ON CONFLICT) while recording a fresh scan row,
// and that missing artefact files are non-fatal.
func TestScanIntoStore_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	workDir := filepath.Join(tmp, "ws")
	target := "acme.test"
	ctx := context.Background()

	writeArtefact(t, workDir, "findings.jsonl",
		`{"severity":"high","vuln_class":"sqli","engine":"sqlmap"}`,
	)
	// No hosts.jsonl / urls.jsonl on purpose — must not error.

	if _, err := ScanIntoStore(ctx, dataDir, workDir, target, "vulns", quietLogger()); err != nil {
		t.Fatalf("first ScanIntoStore: %v", err)
	}
	if _, err := ScanIntoStore(ctx, dataDir, workDir, target, "vulns", quietLogger()); err != nil {
		t.Fatalf("second ScanIntoStore: %v", err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dataDir, "store.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	q := sqlcgen.New(db)

	findings, err := q.ListFindingsForTarget(ctx, sqlcgen.ListFindingsForTargetParams{
		TargetID: target, Limit: 100, Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListFindingsForTarget: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("after two runs, findings = %d, want 1 (deduped)", len(findings))
	}
}
