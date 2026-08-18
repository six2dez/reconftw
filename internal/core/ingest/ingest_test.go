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
	// subdomains.MergeStage writes {"subdomain","source","first_seen"} — NOT
	// {"host"}. This fixture previously used the host shape, which no producer
	// emits, so it validated a decoder that silently dropped every real
	// subdomain line.
	writeArtefact(t, workDir, "subdomains.jsonl",
		`{"subdomain":"www.example.com","source":"subfinder","first_seen":"2026-08-13T00:00:00Z"}`,
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
	defer db.Close() //nolint:errcheck
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
	defer db.Close() //nolint:errcheck // read/cleanup path
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

// -------------------------------------------------------------------------
// F10 — atomic ingest, truthful terminal states, honest counters.
// -------------------------------------------------------------------------

// openStore opens the store for read-back assertions. Every test below reads a
// real on-disk database rather than a mock: the property under test is what
// SURVIVED a commit or a rollback, which a mock cannot express.
func openStore(t *testing.T, dataDir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "store.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// scalar runs a single-value query.
func scalar(t *testing.T, db *sql.DB, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

// countObservations counts what a scan actually committed, straight from the
// table — the independent check that the stored counters are not derived from
// the same number they claim to verify.
func countObservations(t *testing.T, db *sql.DB, scanID, kind string) int64 {
	t.Helper()
	return scalar(t, db,
		`SELECT count(*) FROM scan_observation WHERE scan_id = ? AND asset_kind = ?`, scanID, kind)
}

// TestScanIntoStoreCountersCountCommittedRowsNotInputLines feeds artefacts whose
// LINE counts are deliberately higher than the row counts they produce: repeated
// URLs and two finding lines that share one identity. A counter derived from
// input lines would report 3/3/4; the store holds 2/2/3.
//
// The difference matters beyond tidiness — a scan row claiming more findings
// than the store holds produces a report that cannot be reconciled against the
// store it was built from.
func TestScanIntoStoreCountersCountCommittedRowsNotInputLines(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	workDir := filepath.Join(tmp, "ws")
	target := "counts.test"
	ctx := context.Background()

	// 3 lines, 2 distinct hosts (one repeats across the two artefacts).
	writeArtefact(t, workDir, "hosts.jsonl",
		`{"host":"a.counts.test","ip":"1.2.3.4","cdn":""}`,
	)
	writeArtefact(t, workDir, "subdomains.jsonl",
		`{"subdomain":"a.counts.test","source":"subfinder","first_seen":"2026-08-18T00:00:00Z"}`,
		`{"subdomain":"b.counts.test","source":"crtsh","first_seen":"2026-08-18T00:00:00Z"}`,
	)
	// 3 lines, 2 distinct URLs.
	writeArtefact(t, workDir, "urls.jsonl",
		`{"url":"https://a.counts.test/one","source":"katana","host":"a.counts.test"}`,
		`{"url":"https://a.counts.test/one","source":"waymore","host":"a.counts.test"}`,
		`{"url":"https://a.counts.test/two","source":"katana","host":"a.counts.test"}`,
	)
	// 4 lines, 3 distinct findings — the last two share (sig, tool, host, path).
	writeArtefact(t, workDir, "findings.jsonl",
		`{"type":"http","host":"a.counts.test","template_id":"exposed-panel","severity":"high","matched_at":"https://a.counts.test/admin"}`,
		`{"severity":"info","class":"osint","source":"github_leaks","category":"leaked-secret"}`,
		`{"vuln_class":"sqli","engine":"sqlmap","host":"a.counts.test","severity":"critical","url":"https://a.counts.test/p?id=1"}`,
		`{"vuln_class":"sqli","engine":"sqlmap","host":"a.counts.test","severity":"critical","url":"https://a.counts.test/p?id=9"}`,
	)

	res, err := ScanIntoStore(ctx, dataDir, workDir, target, "all", quietLogger())
	if err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}

	db := openStore(t, dataDir)

	wantHosts := countObservations(t, db, res.ScanID, "host")
	wantURLs := countObservations(t, db, res.ScanID, "url")
	wantFindings := countObservations(t, db, res.ScanID, "finding")

	if wantHosts != 2 || wantURLs != 2 || wantFindings != 3 {
		t.Fatalf("committed rows = %d hosts / %d urls / %d findings, want 2/2/3 — "+
			"fixture no longer exercises the line-count vs row-count gap",
			wantHosts, wantURLs, wantFindings)
	}

	if int64(res.Hosts) != wantHosts || int64(res.URLs) != wantURLs || int64(res.Findings) != wantFindings {
		t.Errorf("Result = %d hosts / %d urls / %d findings, want %d/%d/%d — "+
			"the returned counters were derived from input lines, not committed rows",
			res.Hosts, res.URLs, res.Findings, wantHosts, wantURLs, wantFindings)
	}

	var status string
	var storedFindings, storedSubdomains, storedURLs int64
	if err := db.QueryRow(
		`SELECT status, findings_count, subdomain_count, url_count FROM scans WHERE id = ?`, res.ScanID,
	).Scan(&status, &storedFindings, &storedSubdomains, &storedURLs); err != nil {
		t.Fatalf("read scan row: %v", err)
	}
	if status != "completed" {
		t.Errorf("scan status = %q, want completed", status)
	}
	if storedFindings != wantFindings || storedSubdomains != wantHosts || storedURLs != wantURLs {
		t.Errorf("stored counters = %d findings / %d subdomains / %d urls, want %d/%d/%d",
			storedFindings, storedSubdomains, storedURLs, wantFindings, wantHosts, wantURLs)
	}
}

// TestScanIntoStoreMalformedLinesAreStillBestEffort is the counterweight to the
// atomicity work: a junk line in one artefact must NOT fail an otherwise good
// scan. Bad input is skipped; only a rejected database write degrades the run.
func TestScanIntoStoreMalformedLinesAreStillBestEffort(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	workDir := filepath.Join(tmp, "ws")
	target := "junk.test"
	ctx := context.Background()

	writeArtefact(t, workDir, "findings.jsonl",
		`{"vuln_class":"sqli","engine":"sqlmap","host":"junk.test","severity":"high","url":"https://junk.test/a"}`,
		`this is not json at all`,
		`{"vuln_class":"xss","engine":"dalfox","host":"junk.test","severity":"medium","url":"https://junk.test/b"}`,
		`{"vuln_class":"lfi","engine":`, // truncated mid-object
		`{"vuln_class":"crlf","engine":"crlfuzz","host":"junk.test","severity":"low","url":"https://junk.test/c"}`,
	)

	res, err := ScanIntoStore(ctx, dataDir, workDir, target, "vulns", quietLogger())
	if err != nil {
		t.Fatalf("ScanIntoStore returned an error for MALFORMED INPUT: %v — "+
			"bad input must stay best-effort; only rejected writes degrade a scan", err)
	}
	if res.Findings != 3 {
		t.Errorf("findings = %d, want 3 (the 3 well-formed lines)", res.Findings)
	}

	db := openStore(t, dataDir)
	var status string
	if err := db.QueryRow(`SELECT status FROM scans WHERE id = ?`, res.ScanID).Scan(&status); err != nil {
		t.Fatalf("read scan row: %v", err)
	}
	if status != "completed" {
		t.Errorf("scan status = %q, want completed — two junk lines must not "+
			"downgrade a scan whose every WRITE succeeded", status)
	}
}

// TestScanIntoStoreReconDirTracksCurrentRun: recon_dir named the FIRST run's
// workspace forever, because it was only written when the target row was
// created. Every reader resolving artefacts through targets.recon_dir was then
// pointed at an older engagement's directory.
func TestScanIntoStoreReconDirTracksCurrentRun(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	first := filepath.Join(tmp, "run-1")
	second := filepath.Join(tmp, "run-2")
	target := "recondir.test"
	ctx := context.Background()

	writeArtefact(t, first, "subdomains.jsonl",
		`{"subdomain":"a.recondir.test","source":"subfinder","first_seen":"2026-08-18T00:00:00Z"}`)
	writeArtefact(t, second, "subdomains.jsonl",
		`{"subdomain":"b.recondir.test","source":"subfinder","first_seen":"2026-08-18T00:00:00Z"}`)

	if _, err := ScanIntoStore(ctx, dataDir, first, target, "recon", quietLogger()); err != nil {
		t.Fatalf("first ScanIntoStore: %v", err)
	}
	if _, err := ScanIntoStore(ctx, dataDir, second, target, "recon", quietLogger()); err != nil {
		t.Fatalf("second ScanIntoStore: %v", err)
	}

	db := openStore(t, dataDir)
	var reconDir string
	if err := db.QueryRow(`SELECT recon_dir FROM targets WHERE id = ?`, target).Scan(&reconDir); err != nil {
		t.Fatalf("read target row: %v", err)
	}
	if reconDir != second {
		t.Errorf("recon_dir = %q, want %q — the target still points at the first "+
			"run's workspace", reconDir, second)
	}
}

// TestScanIntoStoreRepairsStaleReconDirAfterWorkspaceRename is the assertion
// plan 15-01's MIGRATION.md note points at.
//
// 15-01 renames every existing workspace directory onto the new canonical slug,
// which leaves the recon_dir values already in store.db naming paths that no
// longer exist on disk. Nothing back-fills them: the repair is exactly this
// unconditional refresh, applied one scan per target.
func TestScanIntoStoreRepairsStaleReconDirAfterWorkspaceRename(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	renamed := filepath.Join(tmp, "example.com-20260818")
	target := "rename.test"
	ctx := context.Background()

	// Seed the pre-rename state: a target whose recon_dir is a path that no
	// longer exists, exactly as 15-01 leaves it.
	stale := filepath.Join(tmp, "old-name-before-15-01")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seed := openStore(t, dataDir)
	if err := sqlcgen.EnsureSchema(ctx, seed); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	if _, err := sqlcgen.New(seed).CreateTarget(ctx, sqlcgen.CreateTargetParams{
		ID: target, Name: target, ReconDir: stale, TagsJson: "[]", Now: 1,
	}); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("fixture broken: %q must not exist for this to model the rename", stale)
	}

	writeArtefact(t, renamed, "subdomains.jsonl",
		`{"subdomain":"a.rename.test","source":"subfinder","first_seen":"2026-08-18T00:00:00Z"}`)
	if _, err := ScanIntoStore(ctx, dataDir, renamed, target, "recon", quietLogger()); err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}

	var reconDir string
	if err := seed.QueryRow(`SELECT recon_dir FROM targets WHERE id = ?`, target).Scan(&reconDir); err != nil {
		t.Fatalf("read target row: %v", err)
	}
	if reconDir != renamed {
		t.Errorf("recon_dir = %q, want %q — a target that pre-dates the 15-01 "+
			"workspace rename was left pointing at a directory that does not exist",
			reconDir, renamed)
	}
}

// TestScanIntoStoreFindingsCarryTargetID guards the field that 15-18 made part
// of the finding dedup key. An empty target_id would put every engagement's
// findings back into one shared row.
func TestScanIntoStoreFindingsCarryTargetID(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	workDir := filepath.Join(tmp, "ws")
	target := "tid.test"
	ctx := context.Background()

	writeArtefact(t, workDir, "findings.jsonl",
		`{"type":"http","host":"a.tid.test","template_id":"exposed-panel","severity":"high","matched_at":"https://a.tid.test/admin"}`,
		`{"severity":"medium","vuln_class":"xss","matched_param":"q","engine":"dalfox"}`,
	)
	if _, err := ScanIntoStore(ctx, dataDir, workDir, target, "all", quietLogger()); err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}

	db := openStore(t, dataDir)
	if got := scalar(t, db, `SELECT count(*) FROM findings`); got != 2 {
		t.Fatalf("findings = %d, want 2", got)
	}
	if got := scalar(t, db, `SELECT count(*) FROM findings WHERE target_id = ?`, target); got != 2 {
		t.Errorf("%d of 2 findings carry target_id = %q — an empty target_id "+
			"re-shares one findings row across every engagement", got, target)
	}
}
