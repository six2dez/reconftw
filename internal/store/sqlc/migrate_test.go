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
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
//
// Plan 15-18 added the target_finding table to this copy. Its absence was an
// omission, not a property of a real v1 database: v1 schema.sql created it, so
// every legacy store.db on disk has it, and the v1->v2 finding split reads it.
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

CREATE TABLE IF NOT EXISTS target_finding (
    target_id  TEXT    NOT NULL,
    finding_id INTEGER NOT NULL,
    PRIMARY KEY (target_id, finding_id)
);

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
		Apply: func(ctx context.Context, tx DBTX) error {
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
		Apply: func(ctx context.Context, tx DBTX) error {
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
		Apply: func(_ context.Context, _ DBTX) error {
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
// the old EnsureSchema re-ran conditional-CREATE DDL and left a pre-existing
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

// --- Concurrency ----------------------------------------------------------

// countingStep returns a step that records how many times its body actually ran.
// A DDL statement with no IF NOT EXISTS is deliberate: it reproduces the real
// failure mode (the second application blowing up on "table already exists"),
// so a broken runner fails loudly rather than passing by idempotence.
func countingStep(applied *atomic.Int64) []migrationStep {
	return []migrationStep{{
		To:   2,
		Name: "counted step",
		Apply: func(ctx context.Context, tx DBTX) error {
			applied.Add(1)
			_, err := tx.ExecContext(ctx, `CREATE TABLE counted_step (x INTEGER)`)
			return err
		},
	}}
}

// TestMigrateConcurrentOverlappingAppliesStepExactlyOnce is the load-bearing
// concurrency test.
//
// Releasing two goroutines from a barrier (see the test below) is NOT sufficient:
// the migration takes about a millisecond, so in practice one goroutine finishes
// the whole thing before the other reads the version, the second then sees
// user_version already at SchemaVersion, skips the step in the OUTER loop, and the
// in-transaction guard is never exercised. That test passes even with the guard
// deleted — a false green of exactly the kind this phase exists to remove.
//
// So this one forces the overlap instead of hoping for it. The step body parks
// mid-migration while holding the write transaction, and the second goroutine is
// started only once the first is provably inside it. The second therefore reads
// the PRE-migration version outside the transaction, blocks at BEGIN IMMEDIATE,
// and can only avoid re-applying the step by re-reading user_version after it
// acquires the lock.
//
// The assertion that matters is the application COUNT, not that both calls
// returned nil: a runner that applied the step twice with idempotent DDL would
// also produce two nils, and the real v1->v2 step is not idempotent.
func TestMigrateConcurrentOverlappingAppliesStepExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	dbA := openFileDB(t, dir)
	dbB := openFileDB(t, dir)
	ctx := context.Background()

	// Put the database in the legacy state and stamp it to v1 with an empty
	// registry, so both goroutines below start from "v1, step 2 pending" and
	// neither has to win the bootstrap race first.
	seedLegacyDB(t, dbA)
	if err := migrateWithSteps(ctx, dbA, nil); err != nil {
		t.Fatalf("bootstrap to legacy version: %v", err)
	}
	if got := userVersion(t, dbA); got != legacyVersion {
		t.Fatalf("setup left user_version at %d, want %d", got, legacyVersion)
	}

	var applied atomic.Int64
	entered := make(chan struct{}) // closed once a step body is executing
	proceed := make(chan struct{}) // closed to let that step body finish
	var enterOnce sync.Once

	steps := []migrationStep{{
		To:   2,
		Name: "parked step",
		Apply: func(ctx context.Context, tx DBTX) error {
			applied.Add(1)
			enterOnce.Do(func() { close(entered) })
			<-proceed
			// No IF NOT EXISTS: a second application must fail loudly rather than
			// pass by idempotence, mirroring the real "duplicate column" /
			// "index already exists" failure.
			_, err := tx.ExecContext(ctx, `CREATE TABLE counted_step (x INTEGER)`)
			return err
		},
	}}

	firstDone := make(chan error, 1)
	go func() { firstDone <- migrateWithSteps(ctx, dbA, steps) }()

	select {
	case <-entered:
	case err := <-firstDone:
		t.Fatalf("first Migrate finished without entering the step: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("first Migrate never entered the step body")
	}

	// The first goroutine now holds the write lock with the v2 stamp uncommitted.
	secondDone := make(chan error, 1)
	go func() { secondDone <- migrateWithSteps(ctx, dbB, steps) }()

	// Give the second goroutine time to read the version and block at
	// BEGIN IMMEDIATE. It must NOT have completed by now.
	select {
	case err := <-secondDone:
		t.Fatalf("second Migrate completed (%v) while the first held the write lock", err)
	case <-time.After(300 * time.Millisecond):
	}

	close(proceed)

	for i, ch := range []chan error{firstDone, secondDone} {
		select {
		case err := <-ch:
			if err != nil {
				t.Errorf("concurrent Migrate %d returned %v; the loser of the race must succeed, not error", i, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("concurrent Migrate %d never returned", i)
		}
	}

	if got := applied.Load(); got != 1 {
		t.Errorf("step body ran %d times, want exactly 1", got)
	}
	if got := userVersion(t, dbA); got != SchemaVersion {
		t.Errorf("user_version = %d, want %d", got, SchemaVersion)
	}
	if !tableExists(t, dbA, "counted_step") {
		t.Error("step never applied: table counted_step is missing")
	}
}

// TestMigrateConcurrentAppliesStepExactlyOnce releases two goroutines from a
// barrier against the same file. See the note on the overlapping test above for
// why this one is a smoke test rather than the real gate: it usually does not
// overlap, so it cannot be relied on to catch a missing in-transaction guard.
func TestMigrateConcurrentAppliesStepExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	dbA := openFileDB(t, dir)
	dbB := openFileDB(t, dir)

	// Seed the legacy shape so BOTH goroutines face a real v1->v2 advance. A
	// fresh database would be stamped straight to SchemaVersion and skip the step
	// entirely, making the count trivially 0.
	seedLegacyDB(t, dbA)

	var applied atomic.Int64
	steps := countingStep(&applied)

	handles := []*sql.DB{dbA, dbB}
	errs := make([]error, len(handles))

	// A closed channel releases both goroutines at the same instant; the
	// WaitGroup collects them.
	release := make(chan struct{})
	var ready, done sync.WaitGroup
	for i, db := range handles {
		ready.Add(1)
		done.Add(1)
		go func(i int, db *sql.DB) {
			defer done.Done()
			ready.Done()
			<-release
			errs[i] = migrateWithSteps(context.Background(), db, steps)
		}(i, db)
	}
	ready.Wait()
	close(release)
	done.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Migrate %d returned %v; the loser of the race must succeed, not error", i, err)
		}
	}
	if got := applied.Load(); got != 1 {
		t.Errorf("step body ran %d times, want exactly 1", got)
	}
	if got := userVersion(t, dbA); got != SchemaVersion {
		t.Errorf("user_version = %d, want %d", got, SchemaVersion)
	}
	if !tableExists(t, dbA, "counted_step") {
		t.Error("step never applied: table counted_step is missing")
	}
}

// TestMigrateOnCurrentDatabaseDoesNotReapply covers the cheap path every ingest
// after the first one takes.
func TestMigrateOnCurrentDatabaseDoesNotReapply(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	ctx := context.Background()

	var applied atomic.Int64
	steps := countingStep(&applied)

	if err := migrateWithSteps(ctx, db, steps); err != nil {
		t.Fatalf("first migrateWithSteps: %v", err)
	}
	if got := applied.Load(); got != 1 {
		t.Fatalf("first run applied step %d times, want 1", got)
	}
	first := userVersion(t, db)

	if err := migrateWithSteps(ctx, db, steps); err != nil {
		t.Fatalf("second migrateWithSteps: %v", err)
	}
	if got := applied.Load(); got != 1 {
		t.Errorf("second run re-applied the step (count %d, want 1)", got)
	}
	if second := userVersion(t, db); second != first {
		t.Errorf("second run changed user_version: %d -> %d", first, second)
	}
}

// TestMigrateWaitsForAnotherWriter proves migrateBusyTimeoutMS is load-bearing
// rather than decorative: with no busy timeout, BEGIN IMMEDIATE against a locked
// database returns SQLITE_BUSY immediately instead of waiting.
//
// The migrating handle is opened with a BARE DSN — no pragmas at all. Migrate is
// handed a *sql.DB it did not open and cannot change the DSN of, so relying on the
// caller having set busy_timeout would be an unverifiable assumption. This test
// fails unless Migrate sets the timeout on the connection it owns.
func TestMigrateWaitsForAnotherWriter(t *testing.T) {
	dir := t.TempDir()
	dbA := openFileDB(t, dir)
	ctx := context.Background()

	dbB, err := sql.Open("sqlite", filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatalf("open bare-DSN sqlite: %v", err)
	}
	t.Cleanup(func() { _ = dbB.Close() })

	seedLegacyDB(t, dbA)

	// Hold the write lock on a connection of dbA.
	connA, err := dbA.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire conn: %v", err)
	}
	if _, err := connA.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("begin immediate: %v", err)
	}
	if _, err := connA.ExecContext(ctx,
		`UPDATE scans SET status = 'held' WHERE id = 'legacy-scan-1'`); err != nil {
		t.Fatalf("write under held lock: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- Migrate(ctx, dbB) }()

	select {
	case err := <-done:
		t.Fatalf("Migrate returned (%v) while another writer held the lock; "+
			"busy_timeout is not in effect on the migration connection", err)
	case <-time.After(200 * time.Millisecond):
		// Still waiting, as it should be.
	}

	if _, err := connA.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	if err := connA.Close(); err != nil {
		t.Fatalf("close conn: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate after the lock was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Migrate never completed after the write lock was released")
	}

	if got := userVersion(t, dbB); got != SchemaVersion {
		t.Errorf("user_version = %d, want %d", got, SchemaVersion)
	}
}

// TestMigrateFailedStepReleasesWriteLock guards the rollback defer: a step that
// errors must not leave the transaction open on the pooled connection, or the
// next writer blocks until busy_timeout and the store wedges.
func TestMigrateFailedStepReleasesWriteLock(t *testing.T) {
	dir := t.TempDir()
	db := openFileDB(t, dir)
	seedLegacyDB(t, db)
	ctx := context.Background()

	broken := []migrationStep{{
		To:   2,
		Name: "broken step",
		Apply: func(_ context.Context, _ DBTX) error {
			return errors.New("boom")
		},
	}}
	if err := migrateWithSteps(ctx, db, broken); err == nil {
		t.Fatal("migrateWithSteps should have failed")
	}

	// If the failed step leaked its transaction, this write blocks for
	// migrateBusyTimeoutMS and then fails.
	other := openFileDB(t, dir)
	writeDone := make(chan error, 1)
	go func() {
		_, err := other.ExecContext(ctx,
			`UPDATE scans SET status = 'after' WHERE id = 'legacy-scan-1'`)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write after failed migration: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write after a failed migration blocked: the rollback did not release the write lock")
	}
}

// --- v1 -> v2: the finding split, the repointing and the dedupe -----------
//
// Plan 15-18. These tests seed a database in the v1 shape (legacySchemaSQL, left
// at user_version 0) and drive the real Migrate, so they exercise the same code
// path an operator's existing store.db takes on first run after the upgrade.

// seedV1Finding inserts one findings row in the v1 shape (no target_id column)
// and returns its id.
func seedV1Finding(t *testing.T, db *sql.DB, sig string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO findings (template_signature, tool, path, severity, first_seen_at, last_seen_at)
		 VALUES (?, 'nuclei', '/admin', 'high', 1700000000, 1700000000)`, sig)
	if err != nil {
		t.Fatalf("seed v1 finding: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed v1 finding id: %v", err)
	}
	return id
}

func seedV1Link(t *testing.T, db *sql.DB, targetID string, findingID int64) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO target_finding (target_id, finding_id) VALUES (?, ?)`, targetID, findingID,
	); err != nil {
		t.Fatalf("seed target_finding(%s, %d): %v", targetID, findingID, err)
	}
}

// seedV1Observation inserts one scan_observation row and returns its id.
func seedV1Observation(t *testing.T, db *sql.DB, scanID, targetID, kind string, assetID int64) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO scan_observation (scan_id, target_id, asset_kind, asset_id, observed_at)
		 VALUES (?, ?, ?, ?, 1700000000)`, scanID, targetID, kind, assetID)
	if err != nil {
		t.Fatalf("seed observation: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed observation id: %v", err)
	}
	return id
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

// TestMigrateV1SplitsSharedFindingPerTarget: one v1 findings row linked to two
// targets must become two rows, each owned by one target, with target_finding
// pointing at the two distinct ids.
func TestMigrateV1SplitsSharedFindingPerTarget(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	shared := seedV1Finding(t, db, "nuclei/high/exposed-panel")
	seedV1Link(t, db, "a.example.com", shared)
	seedV1Link(t, db, "b.example.com", shared)

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if got := countRows(t, db, `SELECT count(*) FROM findings`); got != 2 {
		t.Fatalf("findings rows = %d, want 2 (one per target)", got)
	}
	rows, err := db.Query(`SELECT id, target_id FROM findings ORDER BY target_id`)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	defer rows.Close() //nolint:errcheck // read path
	seenTargets := map[string]int64{}
	for rows.Next() {
		var id int64
		var target string
		if err := rows.Scan(&id, &target); err != nil {
			t.Fatalf("scan findings row: %v", err)
		}
		if target == "" {
			t.Errorf("finding %d still has an empty target_id after the split", id)
		}
		if prev, dup := seenTargets[target]; dup {
			t.Errorf("target %s owns two rows (%d and %d); the split duplicated instead of partitioning",
				target, prev, id)
		}
		seenTargets[target] = id
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate findings: %v", err)
	}
	if len(seenTargets) != 2 {
		t.Fatalf("distinct target_ids = %d, want 2: %v", len(seenTargets), seenTargets)
	}

	for target, wantID := range seenTargets {
		got := countRows(t, db,
			`SELECT count(*) FROM target_finding WHERE target_id = ? AND finding_id = ?`, target, wantID)
		if got != 1 {
			t.Errorf("target_finding(%s) does not point at that target's own finding %d", target, wantID)
		}
	}
}

// TestMigrateV1RepointsObservationsToOwnTarget is the B3 gate.
//
// A migration that performs the split but SKIPS the scan_observation repointing
// passes every other test in this plan and fails only this one: the second
// target's historical observation still resolves, through the production join,
// to the FIRST target's finding row.
func TestMigrateV1RepointsObservationsToOwnTarget(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	shared := seedV1Finding(t, db, "nuclei/high/exposed-panel")
	seedV1Link(t, db, "a.example.com", shared)
	seedV1Link(t, db, "b.example.com", shared)
	obsA := seedV1Observation(t, db, "scan-a", "a.example.com", "finding", shared)
	obsB := seedV1Observation(t, db, "scan-b", "b.example.com", "finding", shared)

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Both observations must SURVIVE. Asserted separately from the resolution
	// check below because a migration that skips step 5 leaves target b's
	// observation pointing at target a's row, which step 6 then deletes as
	// unresolvable — the loss and the mixing are two distinct failure modes of
	// the same missing statement, and the test names both.
	if got := countRows(t, db, `SELECT count(*) FROM scan_observation`); got != 2 {
		t.Errorf("scan_observation rows = %d, want 2 — an observation was lost, "+
			"which means it did not resolve to its own target's finding after the split", got)
	}

	for _, obsID := range []int64{obsA, obsB} {
		var findingTarget, obsTarget string
		err := db.QueryRow(
			`SELECT f.target_id, so.target_id
			 FROM scan_observation so
			 JOIN findings f ON f.id = so.asset_id
			 WHERE so.id = ?`, obsID,
		).Scan(&findingTarget, &obsTarget)
		if err != nil {
			t.Fatalf("resolve observation %d: %v", obsID, err)
		}
		if findingTarget != obsTarget {
			t.Errorf("observation %d resolves to target %q's finding but belongs to target %q — "+
				"the split did not repoint scan_observation.asset_id",
				obsID, findingTarget, obsTarget)
		}
	}
}

// TestMigrateV1LeavesNoDanglingObservations: after the split, no finding
// observation may point at an asset_id that no longer resolves.
func TestMigrateV1LeavesNoDanglingObservations(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	shared := seedV1Finding(t, db, "nuclei/high/exposed-panel")
	seedV1Link(t, db, "a.example.com", shared)
	seedV1Link(t, db, "b.example.com", shared)
	seedV1Observation(t, db, "scan-a", "a.example.com", "finding", shared)
	seedV1Observation(t, db, "scan-b", "b.example.com", "finding", shared)
	// An orphan finding (never linked to a target) plus an observation of it:
	// step 6 must remove both rather than leave a broken join behind.
	orphan := seedV1Finding(t, db, "nuclei/info/orphan")
	seedV1Observation(t, db, "scan-a", "a.example.com", "finding", orphan)

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	dangling := countRows(t, db,
		`SELECT count(*) FROM scan_observation so
		 WHERE so.asset_kind = 'finding'
		   AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.id = so.asset_id)`)
	if dangling != 0 {
		t.Errorf("dangling finding observations = %d, want 0", dangling)
	}
	if got := countRows(t, db, `SELECT count(*) FROM findings WHERE target_id = ''`); got != 0 {
		t.Errorf("findings with an empty target_id = %d, want 0 (orphans must be dropped)", got)
	}
}

// TestMigrateV1DedupesObservations: pre-existing duplicate tuples must be
// collapsed BEFORE ux_scan_observation_dedup is built, or index creation fails
// and the whole migration rolls back on exactly the databases that need it.
func TestMigrateV1DedupesObservations(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	f := seedV1Finding(t, db, "nuclei/high/exposed-panel")
	seedV1Link(t, db, "a.example.com", f)
	first := seedV1Observation(t, db, "scan-a", "a.example.com", "finding", f)
	seedV1Observation(t, db, "scan-a", "a.example.com", "finding", f)
	// A host observation duplicated too — the dedupe is not finding-specific.
	seedV1Observation(t, db, "scan-a", "a.example.com", "host", 1)
	seedV1Observation(t, db, "scan-a", "a.example.com", "host", 1)

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if got := countRows(t, db,
		`SELECT count(*) FROM scan_observation WHERE asset_kind = 'finding'`); got != 1 {
		t.Errorf("finding observations = %d, want 1 after dedupe", got)
	}
	if got := countRows(t, db,
		`SELECT count(*) FROM scan_observation WHERE asset_kind = 'host'`); got != 1 {
		t.Errorf("host observations = %d, want 1 after dedupe", got)
	}
	if got := countRows(t, db,
		`SELECT count(*) FROM scan_observation WHERE id = ?`, first); got != 1 {
		t.Errorf("dedupe kept a row other than the lowest id (%d)", first)
	}

	var name string
	if err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'ux_scan_observation_dedup'`,
	).Scan(&name); err != nil {
		t.Errorf("ux_scan_observation_dedup missing after migration: %v", err)
	}
}

// TestMigrateV1SingleTargetFindingIsUpdatedInPlace: the common case must not
// churn. Its id is stable, so nothing that references it needs rewriting.
func TestMigrateV1SingleTargetFindingIsUpdatedInPlace(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	f := seedV1Finding(t, db, "nuclei/high/exposed-panel")
	seedV1Link(t, db, "a.example.com", f)
	obs := seedV1Observation(t, db, "scan-a", "a.example.com", "finding", f)

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var id int64
	var target string
	if err := db.QueryRow(`SELECT id, target_id FROM findings`).Scan(&id, &target); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	if id != f {
		t.Errorf("single-target finding id changed from %d to %d; it must be updated in place", f, id)
	}
	if target != "a.example.com" {
		t.Errorf("target_id = %q, want a.example.com", target)
	}

	var resolved int64
	if err := db.QueryRow(
		`SELECT f.id FROM scan_observation so JOIN findings f ON f.id = so.asset_id WHERE so.id = ?`, obs,
	).Scan(&resolved); err != nil {
		t.Fatalf("resolve observation: %v", err)
	}
	if resolved != f {
		t.Errorf("observation resolves to finding %d, want %d", resolved, f)
	}
}

// TestMigratedSchemaMatchesFreshSchema: a database brought forward by the step
// and one created from schema.sql must have the SAME DDL. Divergence means two
// schema realities in the field, and every future migration would have to cope
// with both.
func TestMigratedSchemaMatchesFreshSchema(t *testing.T) {
	migrated := openFileDB(t, t.TempDir())
	seedLegacyDB(t, migrated)
	f := seedV1Finding(t, migrated, "nuclei/high/exposed-panel")
	seedV1Link(t, migrated, "a.example.com", f)
	if err := Migrate(context.Background(), migrated); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	fresh := openFileDB(t, t.TempDir())
	if err := Migrate(context.Background(), fresh); err != nil {
		t.Fatalf("Migrate fresh: %v", err)
	}

	for _, object := range []string{
		"findings", "scan_observation",
		"ux_findings_dedup", "ux_scan_observation_dedup",
		"ix_scan_observation_scan_kind", "ix_scan_observation_asset",
	} {
		got := objectDDL(t, migrated, object)
		want := objectDDL(t, fresh, object)
		if got != want {
			t.Errorf("DDL for %s diverges\nmigrated: %s\n   fresh: %s", object, got, want)
		}
	}
}

// objectDDL returns the normalised sqlite_master DDL for one object.
func objectDDL(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var ddl sql.NullString
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = ?`, name).Scan(&ddl); err != nil {
		t.Fatalf("read DDL for %s: %v", name, err)
	}
	if !ddl.Valid {
		t.Fatalf("no DDL recorded for %s", name)
	}
	return normalizeSQL(ddl.String)
}

// TestMigrateV1RollsBackAfterTheDestructiveSteps drives exactly steps 1-5 and
// then fails. Nothing may survive: not the new column, not the split, and not
// the version advance.
func TestMigrateV1RollsBackAfterTheDestructiveSteps(t *testing.T) {
	db := openFileDB(t, t.TempDir())
	seedLegacyDB(t, db)
	shared := seedV1Finding(t, db, "nuclei/high/exposed-panel")
	seedV1Link(t, db, "a.example.com", shared)
	seedV1Link(t, db, "b.example.com", shared)

	boom := errors.New("boom after step 5")
	steps := []migrationStep{{
		To:   2,
		Name: "target-scoped finding identity (fails after step 5)",
		Apply: func(ctx context.Context, tx DBTX) error {
			if err := splitAndRepointFindings(ctx, tx); err != nil {
				return err
			}
			return boom
		},
	}}

	err := migrateWithSteps(context.Background(), db, steps)
	if !errors.Is(err, boom) {
		t.Fatalf("migrateWithSteps error = %v, want %v", err, boom)
	}

	if got := userVersion(t, db); got != legacyVersion {
		t.Errorf("user_version = %d after a failed step, want %d", got, legacyVersion)
	}
	if got := countRows(t, db, `SELECT count(*) FROM findings`); got != 1 {
		t.Errorf("findings rows = %d after rollback, want 1 (the split must not survive)", got)
	}
	// The column itself is rolled back with everything else, so querying it must
	// fail — the strongest possible assertion that step 1 did not survive.
	var target string
	err = db.QueryRow(`SELECT target_id FROM findings`).Scan(&target)
	if err == nil {
		t.Errorf("findings.target_id still exists after rollback (value %q)", target)
	} else if !strings.Contains(err.Error(), "target_id") {
		t.Errorf("unexpected error reading rolled-back findings: %v", err)
	}
}
