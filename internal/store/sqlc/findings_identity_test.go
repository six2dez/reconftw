// Hand-written tests for the target-scoped finding identity (F11) and the
// scan_observation uniqueness constraint (F10) — Phase 15, Plan 18.
//
// No sqlc.yaml is present in this repo; every file in this package is
// hand-maintained, so a SELECT list and its row.Scan target list can drift apart
// without the compiler noticing. These tests exist to turn that runtime hazard
// into a test failure.
package sqlcgen

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// freshDB returns a brand-new store.db at SchemaVersion, created from schema.sql.
func freshDB(t *testing.T) (*sql.DB, *Queries) {
	t.Helper()
	db := openFileDB(t, t.TempDir())
	if err := EnsureSchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return db, New(db)
}

func upsertFindingFor(t *testing.T, q *Queries, targetID, sig string) Finding {
	t.Helper()
	f, err := q.UpsertFinding(context.Background(), UpsertFindingParams{
		TargetID:          targetID,
		TemplateSignature: sig,
		Tool:              "nuclei",
		Path:              "/admin",
		Severity:          "high",
		Title:             "example",
		Description:       "d",
		Evidence:          "e",
		MatchedAt:         "https://" + targetID + "/admin",
		Now:               1700000000,
	})
	if err != nil {
		t.Fatalf("UpsertFinding(%s): %v", targetID, err)
	}
	return f
}

// --- F11: target-scoped finding identity ----------------------------------

// TestFindingIdentityIsTargetScoped is the acceptance-gate-8 experiment: the
// same hostless finding signature observed on two targets must occupy two rows
// with INDEPENDENT triage state. Before plan 15-18 ux_findings_dedup had no
// target component, so the second upsert collided with the first and marking one
// "triaged" marked the other too.
func TestFindingIdentityIsTargetScoped(t *testing.T) {
	ctx := context.Background()
	_, q := freshDB(t)

	a := upsertFindingFor(t, q, "a.example.com", "nuclei/high/exposed-panel")
	b := upsertFindingFor(t, q, "b.example.com", "nuclei/high/exposed-panel")

	if a.ID == b.ID {
		t.Fatalf("the same signature on two targets collapsed into one row (id=%d) — "+
			"target_id is not part of ux_findings_dedup", a.ID)
	}
	if a.TargetID != "a.example.com" || b.TargetID != "b.example.com" {
		t.Fatalf("target_id not round-tripped: a=%q b=%q", a.TargetID, b.TargetID)
	}

	if err := q.UpdateFindingStatus(ctx, UpdateFindingStatusParams{
		Status: "triaged", TagsJson: "[]", Notes: "", ID: a.ID,
	}); err != nil {
		t.Fatalf("UpdateFindingStatus: %v", err)
	}

	gotB, err := q.GetFinding(ctx, b.ID)
	if err != nil {
		t.Fatalf("GetFinding(b): %v", err)
	}
	if gotB.Status != "open" {
		t.Errorf("triaging target a's finding changed target b's status to %q; want open", gotB.Status)
	}
	gotA, err := q.GetFinding(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetFinding(a): %v", err)
	}
	if gotA.Status != "triaged" {
		t.Errorf("target a status = %q, want triaged", gotA.Status)
	}
}

// TestUpsertFindingReDedupesWithinOneTarget guards the other direction: the
// target component must not defeat deduplication INSIDE one engagement.
func TestUpsertFindingReDedupesWithinOneTarget(t *testing.T) {
	_, q := freshDB(t)
	first := upsertFindingFor(t, q, "a.example.com", "nuclei/high/exposed-panel")
	again := upsertFindingFor(t, q, "a.example.com", "nuclei/high/exposed-panel")
	if first.ID != again.ID {
		t.Fatalf("re-observing the same finding on the same target created a second row (%d != %d)",
			first.ID, again.ID)
	}
}

// TestUpsertFindingConflictMatchesDedupIndex compares the ON CONFLICT target in
// findings.sql.go with the ux_findings_dedup column list in schema.sql. SQLite
// resolves an upsert conflict target by matching an index EXPRESSION, so a
// silent divergence here does not error — it just stops deduplicating.
func TestUpsertFindingConflictMatchesDedupIndex(t *testing.T) {
	idx := parenGroupAfter(t, schemaSQL,
		"CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_dedup\n    ON findings")
	conflict := parenGroupAfter(t, upsertFinding, "ON CONFLICT")

	if normalizeSQL(idx) != normalizeSQL(conflict) {
		t.Fatalf("ON CONFLICT target does not match ux_findings_dedup\n index: %s\nupsert: %s", idx, conflict)
	}
	if !strings.HasPrefix(normalizeSQL(idx), "(target_id,") {
		t.Fatalf("ux_findings_dedup is not target-scoped: %s", idx)
	}
}

// --- F10: scan_observation uniqueness -------------------------------------

func insertObs(t *testing.T, q *Queries, scanID, targetID, kind string, assetID int64) error {
	t.Helper()
	return q.InsertObservation(context.Background(), InsertObservationParams{
		ScanID: scanID, TargetID: targetID, AssetKind: kind, AssetID: assetID,
		ObservedAt: 1700000000,
	})
}

func countObs(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM scan_observation`).Scan(&n); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	return n
}

// TestInsertObservationIsIdempotent asserts the re-observation path is a no-op
// success, not an error: two artefact lines resolving to one upserted row is
// normal and must never fail an ingest.
func TestInsertObservationIsIdempotent(t *testing.T) {
	db, q := freshDB(t)
	if err := insertObs(t, q, "scan-1", "a.example.com", "finding", 7); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insertObs(t, q, "scan-1", "a.example.com", "finding", 7); err != nil {
		t.Fatalf("duplicate insert must be a no-op success, got: %v", err)
	}
	if got := countObs(t, db); got != 1 {
		t.Errorf("scan_observation rows = %d, want 1 — the four-column uniqueness is not enforced", got)
	}
}

// TestInsertObservationUniquenessIsFourColumns asserts the key includes
// target_id: two targets observing the same asset id in one scan is legitimate
// and both rows must survive.
func TestInsertObservationUniquenessIsFourColumns(t *testing.T) {
	db, q := freshDB(t)
	if err := insertObs(t, q, "scan-1", "a.example.com", "finding", 7); err != nil {
		t.Fatalf("insert a: %v", err)
	}
	if err := insertObs(t, q, "scan-1", "b.example.com", "finding", 7); err != nil {
		t.Fatalf("insert b: %v", err)
	}
	if got := countObs(t, db); got != 2 {
		t.Errorf("scan_observation rows = %d, want 2 — uniqueness collapsed a legitimate second target", got)
	}
}

func TestFreshSchemaHasObservationIndexes(t *testing.T) {
	db, _ := freshDB(t)
	for _, name := range []string{
		"ux_scan_observation_dedup", "ix_scan_observation_scan_kind", "ix_scan_observation_asset",
	} {
		var got string
		err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, name,
		).Scan(&got)
		if err != nil {
			t.Errorf("index %s missing from a fresh database: %v", name, err)
		}
	}
}

// --- Every whole-Finding reader carries target_id -------------------------

// TestTargetIDSurvivesEveryWholeRowReader is the SELECT-list/row.Scan agreement
// gate. Adding a column to a hand-maintained sqlc package is a RUNTIME hazard,
// not a compile-time one: a query whose SELECT list gained the column while its
// Scan list did not (or the reverse) fails only when executed.
func TestTargetIDSurvivesEveryWholeRowReader(t *testing.T) {
	ctx := context.Background()
	db, q := freshDB(t)
	const target = "a.example.com"

	f := upsertFindingFor(t, q, target, "nuclei/high/exposed-panel")
	if f.TargetID != target {
		t.Fatalf("UpsertFinding RETURNING dropped target_id: %q", f.TargetID)
	}
	if err := q.AttachFindingToTarget(ctx, AttachFindingToTargetParams{
		TargetID: target, FindingID: f.ID,
	}); err != nil {
		t.Fatalf("AttachFindingToTarget: %v", err)
	}

	got, err := q.GetFinding(ctx, f.ID)
	if err != nil || got.TargetID != target {
		t.Errorf("GetFinding: target_id=%q err=%v", got.TargetID, err)
	}

	list, err := q.ListFindingsForTarget(ctx, ListFindingsForTargetParams{
		TargetID: target, Limit: 10, Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListFindingsForTarget: %v", err)
	}
	if len(list) != 1 || list[0].TargetID != target {
		t.Errorf("ListFindingsForTarget: %+v", list)
	}

	cursor, err := q.ListFindingsCursor(ctx, ListFindingsCursorParams{
		TargetID: "", HostIDFilter: 0, Severity: "", StatusFilter: "",
		CursorLastID: 0, RowLimit: 10,
	})
	if err != nil {
		t.Fatalf("ListFindingsCursor: %v", err)
	}
	if len(cursor) != 1 || cursor[0].TargetID != target {
		t.Errorf("ListFindingsCursor: %+v", cursor)
	}

	triaged := "triaged"
	patched, err := q.PatchFinding(ctx, PatchFindingParams{NewStatus: &triaged, ID: f.ID})
	if err != nil || patched.TargetID != target {
		t.Errorf("PatchFinding: target_id=%q err=%v", patched.TargetID, err)
	}

	// DiffScansFindings resolves a finding through scan_observation.asset_id and
	// returns a named subset row (no target_id column — see the SUMMARY verdict
	// table). Exercised here so its SELECT list and Scan list are still proven to
	// agree after the findings table gained a column.
	if err := insertObs(t, q, "scan-new", target, "finding", f.ID); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
	diff, err := q.DiffScansFindings(ctx, DiffScansFindingsParams{ScanA: "scan-new", ScanB: "scan-old"})
	if err != nil {
		t.Fatalf("DiffScansFindings: %v", err)
	}
	if len(diff) != 1 || diff[0].FindingID != f.ID {
		t.Errorf("DiffScansFindings = %+v, want the one finding %d", diff, f.ID)
	}

	// SearchFindings is NOT exercised: it joins findings_fts, a virtual table
	// schema.sql deliberately omits, so it cannot run against a real store.db at
	// all. Its verdict (six-column subset, no change required) is recorded in the
	// plan SUMMARY.
	var ftsTables int
	if err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE name = 'findings_fts'`,
	).Scan(&ftsTables); err != nil {
		t.Fatalf("probe findings_fts: %v", err)
	}
	if ftsTables != 0 {
		t.Errorf("findings_fts unexpectedly exists; the SearchFindings verdict needs revisiting")
	}
}

// --- helpers ---------------------------------------------------------------

// parenGroupAfter returns the balanced parenthesised group that follows marker
// in s, brackets included. Depth-counted because the dedup key contains nested
// COALESCE(...) calls that a naive IndexByte(')') would truncate.
func parenGroupAfter(t *testing.T, s, marker string) string {
	t.Helper()
	i := strings.Index(s, marker)
	if i < 0 {
		t.Fatalf("marker %q not found", marker)
	}
	rest := s[i+len(marker):]
	open := strings.IndexByte(rest, '(')
	if open < 0 {
		t.Fatalf("no '(' after marker %q", marker)
	}
	depth := 0
	for j := open; j < len(rest); j++ {
		switch rest[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return rest[open : j+1]
			}
		}
	}
	t.Fatalf("unbalanced parentheses after marker %q", marker)
	return ""
}

// normalizeSQL collapses whitespace runs to a single space and then removes the
// spaces adjacent to punctuation, so DDL that differs only in layout compares
// equal. It deliberately does NOT strip all whitespace: `NOT NULL` and `NOTNULL`
// must stay distinguishable.
func normalizeSQL(s string) string {
	out := strings.Join(strings.Fields(s), " ")
	for _, p := range []string{",", "(", ")"} {
		out = strings.ReplaceAll(out, " "+p, p)
		out = strings.ReplaceAll(out, p+" ", p)
	}
	return out
}
