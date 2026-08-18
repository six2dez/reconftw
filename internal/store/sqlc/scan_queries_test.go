// Hand-written tests for the per-scan asset queries and the latest-scan
// tie-break — Phase 15, Plan 18.
//
// Every query here is proven against seeded data rather than by compilation:
// this package has no generator, so a SELECT list and its row.Scan target list
// only disagree at runtime.
package sqlcgen

import (
	"context"
	"fmt"
	"testing"

	_ "modernc.org/sqlite"
)

func seedHost(t *testing.T, q *Queries, fqdn string) int64 {
	t.Helper()
	res, err := q.db.ExecContext(context.Background(),
		`INSERT INTO hosts (fqdn, first_seen_at, last_seen_at) VALUES (?, 1700000000, 1700000000)`, fqdn)
	if err != nil {
		t.Fatalf("seed host %s: %v", fqdn, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed host id: %v", err)
	}
	return id
}

func seedURL(t *testing.T, q *Queries, url string) int64 {
	t.Helper()
	res, err := q.db.ExecContext(context.Background(),
		`INSERT INTO urls (url, url_hash, scheme, first_seen_at, last_seen_at)
		 VALUES (?, ?, 'https', 1700000000, 1700000000)`, url, []byte(url))
	if err != nil {
		t.Fatalf("seed url %s: %v", url, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed url id: %v", err)
	}
	return id
}

func observe(t *testing.T, q *Queries, scanID, target, kind string, assetID int64) {
	t.Helper()
	if err := insertObs(t, q, scanID, target, kind, assetID); err != nil {
		t.Fatalf("observe %s %d in %s: %v", kind, assetID, scanID, err)
	}
}

// TestListHostsForScanIsScanScoped: scan A observed three hosts, scan B one.
// A target-wide query would return four for both.
func TestListHostsForScanIsScanScoped(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)
	const target = "a.example.com"

	for i := 1; i <= 3; i++ {
		observe(t, q, "scan-a", target, "host", seedHost(t, q, fmt.Sprintf("h%d.example.com", i)))
	}
	observe(t, q, "scan-b", target, "host", seedHost(t, q, "only-b.example.com"))

	a, err := q.ListHostsForScan(ctx, ListHostsForScanParams{ScanID: "scan-a", Limit: 100})
	if err != nil {
		t.Fatalf("ListHostsForScan(a): %v", err)
	}
	if len(a) != 3 {
		t.Errorf("scan-a hosts = %d, want 3", len(a))
	}
	b, err := q.ListHostsForScan(ctx, ListHostsForScanParams{ScanID: "scan-b", Limit: 100})
	if err != nil {
		t.Fatalf("ListHostsForScan(b): %v", err)
	}
	if len(b) != 1 {
		t.Fatalf("scan-b hosts = %d, want 1", len(b))
	}
	if b[0].FQDN != "only-b.example.com" {
		t.Errorf("scan-b host = %q, want only-b.example.com", b[0].FQDN)
	}
}

func TestListURLsForScanIsScanScoped(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)
	const target = "a.example.com"

	for i := 1; i <= 3; i++ {
		observe(t, q, "scan-a", target, "url", seedURL(t, q, fmt.Sprintf("https://a.example.com/%d", i)))
	}
	observe(t, q, "scan-b", target, "url", seedURL(t, q, "https://a.example.com/only-b"))

	a, err := q.ListURLsForScan(ctx, ListURLsForScanParams{ScanID: "scan-a", Limit: 100})
	if err != nil {
		t.Fatalf("ListURLsForScan(a): %v", err)
	}
	if len(a) != 3 {
		t.Errorf("scan-a urls = %d, want 3", len(a))
	}
	b, err := q.ListURLsForScan(ctx, ListURLsForScanParams{ScanID: "scan-b", Limit: 100})
	if err != nil {
		t.Fatalf("ListURLsForScan(b): %v", err)
	}
	if len(b) != 1 {
		t.Fatalf("scan-b urls = %d, want 1", len(b))
	}
	if b[0].URL != "https://a.example.com/only-b" {
		t.Errorf("scan-b url = %q", b[0].URL)
	}
}

func TestListFindingsForScanIsScanScopedAndCarriesTargetID(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)
	const target = "a.example.com"

	for i := 1; i <= 3; i++ {
		f := upsertFindingFor(t, q, target, fmt.Sprintf("nuclei/high/sig-%d", i))
		observe(t, q, "scan-a", target, "finding", f.ID)
	}
	only := upsertFindingFor(t, q, target, "nuclei/high/only-b")
	observe(t, q, "scan-b", target, "finding", only.ID)

	a, err := q.ListFindingsForScan(ctx, ListFindingsForScanParams{ScanID: "scan-a", Limit: 100})
	if err != nil {
		t.Fatalf("ListFindingsForScan(a): %v", err)
	}
	if len(a) != 3 {
		t.Fatalf("scan-a findings = %d, want 3", len(a))
	}
	for _, f := range a {
		if f.TargetID != target {
			t.Errorf("finding %d has target_id %q, want %q — the new column is missing from the "+
				"SELECT list or the Scan targets disagree", f.ID, f.TargetID, target)
		}
	}

	b, err := q.ListFindingsForScan(ctx, ListFindingsForScanParams{ScanID: "scan-b", Limit: 100})
	if err != nil {
		t.Fatalf("ListFindingsForScan(b): %v", err)
	}
	if len(b) != 1 || b[0].ID != only.ID {
		t.Errorf("scan-b findings = %+v, want only %d", b, only.ID)
	}
}

// TestListFindingsForScanPaginates proves the LIMIT/OFFSET contract plan 15-11
// pages with, instead of fetching a fixed target-wide window.
func TestListFindingsForScanPaginates(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)
	const target = "a.example.com"

	var ids []int64
	for i := 1; i <= 5; i++ {
		f := upsertFindingFor(t, q, target, fmt.Sprintf("nuclei/high/sig-%d", i))
		observe(t, q, "scan-a", target, "finding", f.ID)
		ids = append(ids, f.ID)
	}

	page, err := q.ListFindingsForScan(ctx, ListFindingsForScanParams{
		ScanID: "scan-a", Limit: 2, Offset: 2,
	})
	if err != nil {
		t.Fatalf("ListFindingsForScan: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("page size = %d, want 2", len(page))
	}
	if page[0].ID != ids[2] || page[1].ID != ids[3] {
		t.Errorf("page = [%d %d], want the 3rd and 4th by id [%d %d]",
			page[0].ID, page[1].ID, ids[2], ids[3])
	}
}

func TestCountObservationsForScanByKind(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)
	const target = "a.example.com"

	for i := 1; i <= 3; i++ {
		observe(t, q, "scan-a", target, "host", seedHost(t, q, fmt.Sprintf("h%d.example.com", i)))
	}

	got, err := q.CountObservationsForScanByKind(ctx, CountObservationsForScanByKindParams{
		ScanID: "scan-a", AssetKind: "host",
	})
	if err != nil {
		t.Fatalf("CountObservationsForScanByKind(host): %v", err)
	}
	if got != 3 {
		t.Errorf("host observations = %d, want 3", got)
	}

	got, err = q.CountObservationsForScanByKind(ctx, CountObservationsForScanByKindParams{
		ScanID: "scan-a", AssetKind: "url",
	})
	if err != nil {
		t.Fatalf("CountObservationsForScanByKind(url): %v", err)
	}
	if got != 0 {
		t.Errorf("url observations = %d, want 0", got)
	}
}

func TestUpdateTargetReconDir(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)

	if _, err := q.CreateTarget(ctx, CreateTargetParams{
		ID: "a.example.com", Name: "a.example.com", ReconDir: "/old/recon/a.example.com",
		TagsJson: "[]", Now: 1700000000,
	}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	if err := q.UpdateTargetReconDir(ctx, UpdateTargetReconDirParams{
		ReconDir: "/new/recon/a.example.com", Now: 1700000100, ID: "a.example.com",
	}); err != nil {
		t.Fatalf("UpdateTargetReconDir: %v", err)
	}

	got, err := q.GetTarget(ctx, "a.example.com")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if got.ReconDir != "/new/recon/a.example.com" {
		t.Errorf("recon_dir = %q, want /new/recon/a.example.com", got.ReconDir)
	}
	if got.UpdatedAt != 1700000100 {
		t.Errorf("updated_at = %d, want 1700000100", got.UpdatedAt)
	}
}

// TestGetLatestCompletedScanForTargetTieBreak: two completed scans of one target
// with the SAME started_at second must resolve to the one inserted second.
//
// started_at is INTEGER seconds, so this tie is not hypothetical — a monitor
// loop and a manual re-run in the same second produce it. Run this with
// -count=5 to distinguish a deterministic answer from an incidentally ordered
// one.
func TestGetLatestCompletedScanForTargetTieBreak(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)
	const target = "a.example.com"
	const sameSecond = int64(1700000000)

	for _, id := range []string{"scan-first", "scan-second"} {
		if _, err := q.CreateScan(ctx, CreateScanParams{
			ID: id, TargetID: target, Mode: "recon", Status: "completed",
			StartedAt: sameSecond, RawArgsJson: "{}", ConfigOverridesJson: "{}",
		}); err != nil {
			t.Fatalf("CreateScan %s: %v", id, err)
		}
	}

	got, err := q.GetLatestCompletedScanForTarget(ctx, target)
	if err != nil {
		t.Fatalf("GetLatestCompletedScanForTarget: %v", err)
	}
	if got.ID != "scan-second" {
		t.Errorf("latest completed scan = %q, want scan-second — the started_at tie is "+
			"resolved arbitrarily without the rowid tie-break", got.ID)
	}
}
