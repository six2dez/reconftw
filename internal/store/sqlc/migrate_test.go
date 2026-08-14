// Hand-written tests for the store.db migration runner (Phase 15, Plan 04).
// No sqlc.yaml is present in this repo; files in this package are hand-maintained.
//
// Every test here uses a t.TempDir() FILE database, never ":memory:". PRAGMA
// user_version lives in the database header, and "does the stamp survive a close
// and re-open" is precisely what is under test — an in-memory database would make
// the persistence half of that assertion vacuous.
package sqlcgen

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// storeDSN mirrors the DSN internal/core/ingest/ingest.go opens store.db with, so
// these tests exercise the same pragma set production does.
func storeDSN(path string) string {
	return path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
}

// openFileDB opens (creating if absent) a file-backed store database under dir.
func openFileDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", storeDSN(filepath.Join(dir, "store.db")))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping sqlite: %v", err)
	}
	return db
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return v
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name,
	).Scan(&n); err != nil {
		t.Fatalf("probe sqlite_master for %q: %v", name, err)
	}
	return n > 0
}

// schemaTables is every table schema.sql creates. Asserted explicitly rather than
// counted so a dropped table shows up by name.
var schemaTables = []string{
	"companies", "targets", "target_roots", "scans", "hosts", "target_host",
	"ports", "target_port", "urls", "target_url", "findings", "target_finding",
	"js_files", "target_j", "settings", "scan_observation",
}

// legacySchemaSQL is a copy of the pre-versioning DDL — the shape a store.db
// created by a build with no migration runner actually has on disk. It is
// deliberately a frozen copy and NOT a reference to schemaSQL: the whole point of
// the legacy path is to be exercised against DDL that has since moved on, so
// wiring it to the live constant would make the test pass by definition forever.
const legacySchemaSQL = `
CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    name        TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT '',
    company_id  TEXT,
    recon_dir   TEXT    NOT NULL DEFAULT '',
    tags_json   TEXT    NOT NULL DEFAULT '[]',
    notes       TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id                    TEXT PRIMARY KEY,
    target_id             TEXT    NOT NULL,
    mode                  TEXT    NOT NULL,
    status                TEXT    NOT NULL,
    started_at            INTEGER NOT NULL,
    finished_at           INTEGER,
    exit_code             INTEGER,
    reconftw_version      TEXT,
    tool_versions_json    TEXT,
    raw_args_json         TEXT    NOT NULL DEFAULT '{}',
    config_overrides_json TEXT    NOT NULL DEFAULT '{}',
    output_dir            TEXT    NOT NULL DEFAULT '',
    cancelled_by          TEXT,
    findings_count        INTEGER NOT NULL DEFAULT 0,
    subdomain_count       INTEGER NOT NULL DEFAULT 0,
    url_count             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn          TEXT    NOT NULL UNIQUE,
    ip_current    TEXT,
    asn           INTEGER,
    asn_org       TEXT,
    cdn           TEXT,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'new',
    tags_json     TEXT    NOT NULL DEFAULT '[]',
    notes         TEXT    NOT NULL DEFAULT '',
    raw_json      TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    template_signature TEXT    NOT NULL,
    tool               TEXT    NOT NULL,
    host_id            INTEGER,
    port_id            INTEGER,
    url_id             INTEGER,
    path               TEXT    NOT NULL DEFAULT '',
    severity           TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'open',
    title              TEXT    NOT NULL DEFAULT '',
    description        TEXT    NOT NULL DEFAULT '',
    evidence           TEXT    NOT NULL DEFAULT '',
    matched_at         TEXT    NOT NULL DEFAULT '',
    cvss_score         REAL,
    tags_json          TEXT    NOT NULL DEFAULT '[]',
    notes              TEXT    NOT NULL DEFAULT '',
    raw_json           TEXT,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_dedup
    ON findings(template_signature, tool, COALESCE(host_id, 0), COALESCE(port_id, 0), path);

CREATE TABLE IF NOT EXISTS scan_observation (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL,
    target_id   TEXT    NOT NULL,
    asset_kind  TEXT    NOT NULL,
    asset_id    INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    raw_json    TEXT
);
`

// seedLegacyDB creates a database in the pre-versioning shape with one scans row,
// left at user_version = 0 exactly as a real legacy store.db would be.
func seedLegacyDB(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(legacySchemaSQL); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO scans (id, target_id, mode, status, started_at) VALUES (?, ?, ?, ?, ?)`,
		"legacy-scan-1", "example.com", "recon", "completed", 1700000000,
	); err != nil {
		t.Fatalf("seed legacy scans row: %v", err)
	}
	if got := userVersion(t, db); got != 0 {
		t.Fatalf("seeded legacy db should be at user_version 0, got %d", got)
	}
}

// --- Fresh database -------------------------------------------------------

func TestMigrateFreshDatabaseCreatesSchemaAndStamps(t *testing.T) {
	db := openFileDB(t, t.TempDir())

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate on fresh db: %v", err)
	}

	for _, tbl := range schemaTables {
		if !tableExists(t, db, tbl) {
			t.Errorf("fresh Migrate did not create table %q", tbl)
		}
	}
	if got := userVersion(t, db); got != SchemaVersion {
		t.Errorf("user_version = %d, want %d", got, SchemaVersion)
	}
}

// TestMigrateStampSurvivesReopen is why these tests use a file database: an
// in-memory one would drop the header the pragma lives in.
func TestMigrateStampSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	db := openFileDB(t, dir)
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := openFileDB(t, dir)
	if got := userVersion(t, reopened); got != SchemaVersion {
		t.Errorf("user_version after reopen = %d, want %d", got, SchemaVersion)
	}
}

func TestMigrateTwiceIsNoOp(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	ctx := context.Background()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	first := userVersion(t, db)

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if second := userVersion(t, db); second != first {
		t.Errorf("user_version changed on repeat Migrate: %d -> %d", first, second)
	}
}

// --- Legacy database ------------------------------------------------------

func TestMigrateDetectsLegacyDatabaseAndPreservesRows(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate on legacy db: %v", err)
	}

	if got := userVersion(t, db); got != SchemaVersion {
		t.Errorf("user_version = %d, want %d", got, SchemaVersion)
	}

	var id string
	if err := db.QueryRow(`SELECT id FROM scans WHERE id = ?`, "legacy-scan-1").Scan(&id); err != nil {
		t.Fatalf("pre-existing legacy row did not survive migration: %v", err)
	}
	if id != "legacy-scan-1" {
		t.Errorf("legacy row id = %q, want %q", id, "legacy-scan-1")
	}
}

// TestMigrateLegacyStampsV1BeforeReplaying pins the fork that makes the legacy
// path work at all: a pre-versioning database must be stamped v1 and REPLAYED,
// not mistaken for a fresh one and stamped straight to SchemaVersion (which would
// skip every step it has never seen).
func TestMigrateLegacyStampsV1BeforeReplaying(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)

	var sawFrom int
	steps := []migrationStep{{
		To:   2,
		Name: "observer",
		Apply: func(ctx context.Context, tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&sawFrom)
		},
	}}

	if err := migrateWithSteps(context.Background(), db, steps); err != nil {
		t.Fatalf("migrateWithSteps: %v", err)
	}
	if sawFrom != legacyVersion {
		t.Errorf("step ran with user_version = %d, want %d (legacy stamp)", sawFrom, legacyVersion)
	}
}

// --- Refusal to downgrade -------------------------------------------------

func TestMigrateRefusesNewerSchemaVersion(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	newer := SchemaVersion + 1
	if _, err := db.ExecContext(ctx, "PRAGMA user_version = 3"); err != nil {
		t.Fatalf("bump user_version: %v", err)
	}

	err := Migrate(ctx, db)
	if err == nil {
		t.Fatal("Migrate accepted a database written by a newer binary; want an error")
	}
	msg := err.Error()
	for _, want := range []string{"3", "2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name version %s", msg, want)
		}
	}
	if got := userVersion(t, db); got != newer {
		t.Errorf("refused Migrate changed user_version to %d, want %d", got, newer)
	}
}

// --- Failed step ----------------------------------------------------------

// TestMigrateFailedStepAdvancesNothing is the transactionality assertion: a step
// that creates a table and then blows up must leave BOTH the pragma and
// sqlite_master exactly as it found them.
func TestMigrateFailedStepAdvancesNothing(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	ctx := context.Background()

	steps := []migrationStep{{
		To:   2,
		Name: "deliberately broken step",
		Apply: func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `CREATE TABLE half_applied (x INTEGER)`); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `THIS IS NOT SQL`)
			return err
		},
	}}

	err := migrateWithSteps(ctx, db, steps)
	if err == nil {
		t.Fatal("migrateWithSteps returned nil for a step that failed")
	}
	if !strings.Contains(err.Error(), "deliberately broken step") {
		t.Errorf("error %q does not name the failing step", err.Error())
	}
	if !strings.Contains(err.Error(), "v1->v2") {
		t.Errorf("error %q does not name the version transition", err.Error())
	}

	if got := userVersion(t, db); got != legacyVersion {
		t.Errorf("failed step advanced user_version to %d, want %d", got, legacyVersion)
	}
	if tableExists(t, db, "half_applied") {
		t.Error("failed step left partial DDL behind: table half_applied exists")
	}
}

// TestMigrateFailedStepRetriesWholeStep proves the point of leaving the version
// untouched: the next run must replay the step from the beginning.
func TestMigrateFailedStepRetriesWholeStep(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	ctx := context.Background()

	attempts := 0
	failFirst := []migrationStep{{
		To:   2,
		Name: "flaky step",
		Apply: func(_ context.Context, _ *sql.Tx) error {
			attempts++
			if attempts == 1 {
				return errors.New("boom")
			}
			return nil
		},
	}}

	if err := migrateWithSteps(ctx, db, failFirst); err == nil {
		t.Fatal("first migrateWithSteps should have failed")
	}
	if err := migrateWithSteps(ctx, db, failFirst); err != nil {
		t.Fatalf("retry migrateWithSteps: %v", err)
	}
	if attempts != 2 {
		t.Errorf("step applied %d times, want 2 (fail then retry)", attempts)
	}
	if got := userVersion(t, db); got != 2 {
		t.Errorf("user_version after successful retry = %d, want 2", got)
	}
}

// --- Registry invariants --------------------------------------------------

// TestSchemaVersionMatchesStepRegistry keeps SchemaVersion honest. schema.sql is
// applied verbatim to a fresh database and stamped straight to SchemaVersion, so
// a step registered above SchemaVersion would run on legacy databases and never
// on new ones — the two would silently diverge.
func TestSchemaVersionMatchesStepRegistry(t *testing.T) {
	highest := legacyVersion
	prev := 0
	for _, s := range migrationSteps {
		if s.To <= prev {
			t.Errorf("migrationSteps is not in ascending To order: %d after %d", s.To, prev)
		}
		prev = s.To
		if s.To > highest {
			highest = s.To
		}
		if s.Name == "" {
			t.Errorf("migration step To=%d has no Name; errors would not identify it", s.To)
		}
	}
	if highest != SchemaVersion {
		t.Errorf("highest migration step is v%d but SchemaVersion is %d", highest, SchemaVersion)
	}
}

// TestEnsureSchemaDelegatesToMigrate guards the seam the single production caller
// (internal/core/ingest/ingest.go) actually uses.
func TestEnsureSchemaDelegatesToMigrate(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	if err := EnsureSchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	if got := userVersion(t, db); got != SchemaVersion {
		t.Errorf("EnsureSchema left user_version at %d, want %d — it is not delegating to Migrate",
			got, SchemaVersion)
	}
	for _, tbl := range schemaTables {
		if !tableExists(t, db, tbl) {
			t.Errorf("EnsureSchema did not create table %q", tbl)
		}
	}
}

// TestEnsureSchemaOnLegacyDatabase is the regression this whole plan exists for:
// the old EnsureSchema re-ran CREATE IF NOT EXISTS DDL and left a pre-existing
// database completely unversioned.
func TestEnsureSchemaOnLegacyDatabase(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	if err := EnsureSchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureSchema on legacy db: %v", err)
	}
	if got := userVersion(t, db); got != SchemaVersion {
		t.Errorf("legacy db left at user_version %d, want %d", got, SchemaVersion)
	}
}
