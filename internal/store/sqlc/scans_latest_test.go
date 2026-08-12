// Hand-written test for GetLatestCompletedScanForTarget (Phase 10, Plan 01).
// No sqlc.yaml is present in this repo; generated files are hand-maintained.

package sqlcgen

import (
	"context"
	"database/sql"
	stderrors "errors"
	"testing"

	_ "modernc.org/sqlite"
)

// openTestDB opens an in-memory SQLite database, registers the "sqlite" driver,
// creates the minimal scans schema, and returns *sql.DB.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() }) //nolint:errcheck // read/cleanup path

	schema := `
CREATE TABLE IF NOT EXISTS scans (
    id                   TEXT PRIMARY KEY NOT NULL,
    target_id            TEXT NOT NULL,
    mode                 TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'queued',
    started_at           INTEGER NOT NULL,
    finished_at          INTEGER,
    exit_code            INTEGER,
    reconftw_version     TEXT,
    tool_versions_json   TEXT,
    raw_args_json        TEXT NOT NULL DEFAULT '{}',
    config_overrides_json TEXT NOT NULL DEFAULT '{}',
    output_dir           TEXT NOT NULL DEFAULT '',
    cancelled_by         TEXT,
    findings_count       INTEGER NOT NULL DEFAULT 0,
    subdomain_count      INTEGER NOT NULL DEFAULT 0,
    url_count            INTEGER NOT NULL DEFAULT 0
);`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return db
}

func insertTestScan(t *testing.T, db *sql.DB, id, targetID, status string, startedAt int64) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO scans (id, target_id, status, started_at) VALUES (?, ?, ?, ?)`,
		id, targetID, status, startedAt,
	)
	if err != nil {
		t.Fatalf("insert scan %s: %v", id, err)
	}
}

// TestGetLatestCompletedScanForTarget verifies that with two completed scans
// for target "t1" and one failed scan, the function returns the scan with
// the most recent started_at (id="scan3").
func TestGetLatestCompletedScanForTarget(t *testing.T) {
	db := openTestDB(t)
	q := New(db)

	// older completed scan
	insertTestScan(t, db, "scan1", "t1", "completed", 1000)
	// newer completed scan — this is the one we expect back
	insertTestScan(t, db, "scan3", "t1", "completed", 3000)
	// failed scan — must NOT be returned
	insertTestScan(t, db, "scan2", "t1", "failed", 2000)

	got, err := q.GetLatestCompletedScanForTarget(context.Background(), "t1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "scan3" {
		t.Errorf("expected scan3 (newest completed), got %q", got.ID)
	}
	if got.Status != "completed" {
		t.Errorf("expected status=completed, got %q", got.Status)
	}
	if got.TargetID != "t1" {
		t.Errorf("expected target_id=t1, got %q", got.TargetID)
	}
}

// TestGetLatestCompletedScanForTarget_NoRows verifies that sql.ErrNoRows is
// returned when no completed scan exists for the target.
func TestGetLatestCompletedScanForTarget_NoRows(t *testing.T) {
	db := openTestDB(t)
	q := New(db)

	// Insert a failed scan only — no completed scan
	insertTestScan(t, db, "scan_fail", "t2", "failed", 1000)

	_, err := q.GetLatestCompletedScanForTarget(context.Background(), "t2")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !stderrors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows, got: %v", err)
	}
}

// TestGetLatestCompletedScanForTarget_NoRows_NoTarget verifies sql.ErrNoRows
// when the target has no scans at all.
func TestGetLatestCompletedScanForTarget_NoRows_NoTarget(t *testing.T) {
	db := openTestDB(t)
	q := New(db)

	_, err := q.GetLatestCompletedScanForTarget(context.Background(), "nonexistent")
	if !stderrors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows, got: %v", err)
	}
}
