package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/extract/urls"
	"github.com/six2dez/reconftw/internal/modules/osint"
	"github.com/six2dez/reconftw/internal/modules/subdomains"
	"github.com/six2dez/reconftw/internal/modules/vulns"
	"github.com/six2dez/reconftw/internal/modules/web"
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

// -------------------------------------------------------------------------
// The failure-injection seam.
//
// Test-only: failingDBTX lives in this file, is never referenced by ingest.go,
// and reaches the ingest through the unexported scanIntoStoreWithDB's wrapTx
// PARAMETER — not through an exported hook and not through package-level state
// that production code reads. Production always passes nil.
// -------------------------------------------------------------------------

// errInjected is the failure the tests inject. Deliberately not a driver error:
// the point is a store that REJECTS a write, not a connection that died, and a
// rejected statement leaves the transaction usable (which is what separates
// "incomplete" from "no scan row at all").
var errInjected = errors.New("injected store failure")

// failingDBTX wraps a real DBTX and rejects ExecContext calls chosen by fail.
//
// Only ExecContext is intercepted. That is enough to reach every terminal
// state: the attach / observe / update-scan statements are all :exec, so the
// seam can fail one record's write (leaving the transaction usable) or every
// write from a point onwards (which also fails the counts and status updates,
// so nothing is ever committed).
type failingDBTX struct {
	inner sqlcgen.DBTX

	mu       sync.Mutex
	calls    int
	failures int

	// fail receives the 1-based ExecContext index and the statement text and
	// reports whether this call should be rejected.
	fail func(n int, query string) bool
}

// failOnce rejects the first ExecContext whose statement contains substr and
// lets everything else through — one rejected record on a healthy transaction.
func failOnce(substr string) func(inner sqlcgen.DBTX) sqlcgen.DBTX {
	return func(inner sqlcgen.DBTX) sqlcgen.DBTX {
		fired := false
		return &failingDBTX{inner: inner, fail: func(_ int, query string) bool {
			if fired || !strings.Contains(query, substr) {
				return false
			}
			fired = true
			return true
		}}
	}
}

// failFrom rejects the first ExecContext whose statement contains substr and
// every ExecContext after it — a store that goes away part-way through, which
// also fails the counts and status updates and therefore the whole ingest.
func failFrom(substr string) func(inner sqlcgen.DBTX) sqlcgen.DBTX {
	return func(inner sqlcgen.DBTX) sqlcgen.DBTX {
		tripped := false
		return &failingDBTX{inner: inner, fail: func(_ int, query string) bool {
			if !tripped && strings.Contains(query, substr) {
				tripped = true
			}
			return tripped
		}}
	}
}

func (f *failingDBTX) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	reject := f.fail != nil && f.fail(n, query)
	if reject {
		f.failures++
	}
	f.mu.Unlock()
	if reject {
		return nil, errInjected
	}
	return f.inner.ExecContext(ctx, query, args...)
}

func (f *failingDBTX) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return f.inner.PrepareContext(ctx, query)
}

func (f *failingDBTX) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return f.inner.QueryContext(ctx, query, args...)
}

func (f *failingDBTX) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return f.inner.QueryRowContext(ctx, query, args...)
}

// openIngestStore opens and migrates a store the way ScanIntoStore does, so a
// test driving scanIntoStoreWithDB directly exercises the same DSN.
func openIngestStore(t *testing.T, dataDir string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	path := filepath.Join(dataDir, "store.db")
	db, err := sql.Open("sqlite",
		path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlcgen.EnsureSchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return db
}

// writeGateFixture lays down one host, one url and one finding — enough for the
// ingest to reach every phase, small enough that a failure's blast radius is
// unambiguous.
func writeGateFixture(t *testing.T, workDir, host string) {
	t.Helper()
	writeArtefact(t, workDir, "hosts.jsonl",
		`{"host":"`+host+`","ip":"1.2.3.4","cdn":"cloudflare"}`)
	writeArtefact(t, workDir, "urls.jsonl",
		`{"url":"https://`+host+`/admin","source":"katana","host":"`+host+`"}`)
	writeArtefact(t, workDir, "findings.jsonl",
		`{"vuln_class":"sqli","engine":"sqlmap","host":"`+host+`","severity":"critical","url":"https://`+host+`/p?id=1"}`)
}

// TestScanIntoStoreInjectedFailureLeavesNoCompletedScanAndNoPartialData is
// acceptance gate 7, asserted against a real on-disk database.
//
// The store starts rejecting writes at the first scan_observation insert — part
// way through, after hosts have already been upserted. Before this plan those
// upserts autocommitted one by one and the run still ended with
// UpdateScanStatus("completed"), so the store held a scan that ADVERTISED
// itself as whole while holding a fraction of the data. An operator reading
// that report sees a short findings list and concludes the target is clean.
func TestScanIntoStoreInjectedFailureLeavesNoCompletedScanAndNoPartialData(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	workDir := filepath.Join(tmp, "ws")
	target := "gate7.test"
	ctx := context.Background()

	writeGateFixture(t, workDir, "a.gate7.test")
	db := openIngestStore(t, dataDir)

	res, err := scanIntoStoreWithDB(ctx, db, failFrom("INSERT INTO scan_observation"),
		filepath.Join(dataDir, "store.db"), workDir, target, "all", quietLogger())
	if err == nil {
		t.Fatal("ScanIntoStore returned nil error after an injected mid-ingest failure")
	}
	if !errors.Is(err, errInjected) {
		t.Errorf("error = %v, want it to wrap the injected failure", err)
	}
	if res.ScanID != "" {
		t.Errorf("Result carries scan id %q for a scan that was never committed", res.ScanID)
	}

	if got := scalar(t, db, `SELECT count(*) FROM scans WHERE status = 'completed'`); got != 0 {
		t.Errorf("completed scans = %d, want 0 — a failed ingest advertised itself as whole", got)
	}
	if got := scalar(t, db, `SELECT count(*) FROM scans`); got != 0 {
		t.Errorf("scan rows = %d, want 0 — the doomed transaction left a scan row behind", got)
	}
	for _, table := range []string{"hosts", "urls", "findings", "scan_observation", "targets"} {
		if got := scalar(t, db, `SELECT count(*) FROM `+table); got != 0 {
			t.Errorf("%s rows = %d, want 0 — the rollback did not discard partial data", table, got)
		}
	}
}

// TestScanIntoStoreTerminalStates walks the whole state machine as a unit. Each
// row asserts a DIFFERENT observable outcome, so a regression that collapses two
// states into one cannot pass.
func TestScanIntoStoreTerminalStates(t *testing.T) {
	tests := []struct {
		name string
		wrap func(sqlcgen.DBTX) sqlcgen.DBTX
		// wantScans is how many scan rows survive.
		wantScans int64
		// wantStatus is the surviving row's status ("" when none survives).
		wantStatus string
		wantErr    bool
		// wantAssets is whether any asset rows survive.
		wantAssets bool
	}{
		{
			name:       "completed: every write landed",
			wrap:       nil,
			wantScans:  1,
			wantStatus: "completed",
			wantErr:    false,
			wantAssets: true,
		},
		{
			// One rejected record on a transaction that stays usable: the rows
			// that did land are committed, and the scan says so honestly.
			// GetLatestCompletedScanForTarget filters on 'completed', so this
			// scan can never become a report or monitor-diff baseline.
			name:       "incomplete: one record rejected, transaction still usable",
			wrap:       failOnce("INSERT INTO target_finding"),
			wantScans:  1,
			wantStatus: "incomplete",
			wantErr:    true,
			wantAssets: true,
		},
		{
			// The transaction cannot be completed, so nothing is committed —
			// not even a 'failed' marker, because the row that would carry it
			// was created inside the transaction being discarded.
			name:       "no scan row: the transaction never commits",
			wrap:       failFrom("INSERT INTO scan_observation"),
			wantScans:  0,
			wantStatus: "",
			wantErr:    true,
			wantAssets: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			dataDir := filepath.Join(tmp, "data")
			workDir := filepath.Join(tmp, "ws")
			target := "states.test"
			ctx := context.Background()

			writeGateFixture(t, workDir, "a.states.test")
			db := openIngestStore(t, dataDir)

			_, err := scanIntoStoreWithDB(ctx, db, tc.wrap,
				filepath.Join(dataDir, "store.db"), workDir, target, "all", quietLogger())
			if tc.wantErr && err == nil {
				t.Fatal("want a non-nil error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil error, got %v", err)
			}

			if got := scalar(t, db, `SELECT count(*) FROM scans`); got != tc.wantScans {
				t.Fatalf("scan rows = %d, want %d", got, tc.wantScans)
			}
			if tc.wantStatus != "" {
				var status string
				if err := db.QueryRow(`SELECT status FROM scans`).Scan(&status); err != nil {
					t.Fatalf("read scan status: %v", err)
				}
				if status != tc.wantStatus {
					t.Errorf("scan status = %q, want %q", status, tc.wantStatus)
				}
			}
			gotAssets := scalar(t, db, `SELECT count(*) FROM hosts`) > 0
			if gotAssets != tc.wantAssets {
				t.Errorf("asset rows present = %v, want %v", gotAssets, tc.wantAssets)
			}
			// 'failed' is never written from ingest — see the terminal-state
			// constants. A doomed transaction leaves no row to mark.
			if got := scalar(t, db, `SELECT count(*) FROM scans WHERE status = 'failed'`); got != 0 {
				t.Errorf("scans with status 'failed' = %d, want 0", got)
			}
		})
	}
}

// TestFixturesMatchProducerShapes is the audit the earlier subdomains.jsonl
// incident demands. A fixture written by hand can encode the bug instead of
// catching it: this package once fed itself a subdomains.jsonl full of
// {"host":…} lines, a shape no producer emits, so a decoder that dropped every
// real subdomain line looked correct.
//
// Here each artefact line is MARSHALLED FROM THE PRODUCING STRUCT, so the
// fixtures cannot drift from the producers without this test failing to
// compile or failing to ingest.
func TestFixturesMatchProducerShapes(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	workDir := filepath.Join(tmp, "ws")
	target := "producers.test"
	ctx := context.Background()

	marshal := func(v any) string {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		return string(b)
	}

	// artefacts/subdomains.jsonl — subdomains.MergeStage.
	writeArtefact(t, workDir, "subdomains.jsonl",
		marshal(subdomains.SubdomainRecord{
			Subdomain: "sub.producers.test", Source: "subfinder", FirstSeen: "2026-08-18T00:00:00Z",
		}),
	)
	// artefacts/hosts.jsonl — web.HTTPXTask.Run and subdomains' geo enrichment.
	writeArtefact(t, workDir, "hosts.jsonl",
		marshal(web.HostRecord{
			Host: "www.producers.test", URL: "https://www.producers.test",
			Scheme: "https", Port: "443", Status: 200, IP: "1.2.3.4", CDN: "cloudflare",
		}),
		marshal(subdomains.HostRecord{
			Host: "geo.producers.test", IP: "5.6.7.8", ASN: "AS64500", Country: "ES",
		}),
	)
	// artefacts/urls.jsonl — urls.ExtractURLs.
	writeArtefact(t, workDir, "urls.jsonl",
		marshal(urls.URLRecord{
			URL: "https://www.producers.test/admin", Source: "katana", Host: "www.producers.test",
		}),
	)
	// artefacts/findings.jsonl — the four producing shapes.
	writeArtefact(t, workDir, "findings.jsonl",
		marshal(web.FindingRecord{
			Type: "http", Host: "www.producers.test", TemplateID: "exposed-panel",
			Severity: "high", MatchedAt: "https://www.producers.test/admin",
		}),
		marshal(vulns.VulnFindingRecord{
			Host: "www.producers.test", URL: "https://www.producers.test/p?id=1",
			Severity: "critical", VulnClass: "sqli", MatchedParam: "id", Engine: "sqlmap",
		}),
		marshal(osint.OSINTFindingRecord{
			Severity: "info", Class: "osint", Source: "github_leaks", Category: "leaked-secret",
		}),
		marshal(subdomains.TakeoverRecord{
			Type: "subdomain-takeover", Host: "sub.producers.test", Service: "github",
			Confidence: "high", Severity: "high",
		}),
	)

	res, err := ScanIntoStore(ctx, dataDir, workDir, target, "all", quietLogger())
	if err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}
	if res.Hosts != 3 {
		t.Errorf("hosts = %d, want 3 (one per producer shape) — a hosts/subdomains "+
			"line from a real producer was decoded to nothing", res.Hosts)
	}
	if res.URLs != 1 {
		t.Errorf("urls = %d, want 1", res.URLs)
	}
	if res.Findings != 4 {
		t.Errorf("findings = %d, want 4 (one per producing shape) — a real "+
			"producer's record was dropped during ingest", res.Findings)
	}
}
