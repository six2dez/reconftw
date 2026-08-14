// migrate.go — hand-authored (NOT sqlc-generated) migration runner for store.db.
//
// WHY THIS FILE EXISTS: every statement in schema.sql is `CREATE ... IF NOT
// EXISTS`, so applying it to a database that already has the tables is a no-op by
// construction. That is fine for bringing a NEW store up, and useless for changing
// an EXISTING one: a new column, a new index or a changed uniqueness constraint
// would apply on a fresh CI database and silently do nothing on every real
// operator's store.db. This runner closes that gap with SQLite's built-in
// `PRAGMA user_version` — an integer in the database header, so there is no
// bootstrap problem (no version table that itself needs creating before it can be
// read).
//
// This is deliberately NOT a mirror of internal/core/checkpoint/migrations.go.
// That file is a different database (checkpoints.db) and is idempotent-DDL-only —
// it has the same blind spot this file exists to remove.
package sqlcgen

import (
	"context"
	"database/sql"
	"fmt"
)

// SchemaVersion is the store.db schema version this binary understands.
//
// Bump it in the same commit that adds a migrationStep producing it. The
// embedded schema.sql must always describe the schema AT SchemaVersion, because
// a brand-new database is created from schema.sql and stamped straight to
// SchemaVersion without replaying any step.
const SchemaVersion = 2

// legacyVersion is the version stamped onto a database that already had tables
// when this runner first saw it — i.e. a store.db created before versioning
// existed. Such a database reads user_version = 0, exactly like an empty one, so
// the two cases are told apart by probing sqlite_master rather than by the pragma.
const legacyVersion = 1

// migrationStep is one forward-only schema change.
//
// Apply runs inside a transaction that also carries the user_version advance, so a
// step either lands completely or not at all. A step must be written to run against
// the schema its predecessor produced — never against schema.sql, which describes
// only the newest version.
type migrationStep struct {
	// To is the user_version this step produces.
	To int
	// Name identifies the step in error messages, so an operator can tell which
	// migration failed without reading the source.
	Name string
	// Apply performs all DDL and data movement for this step.
	Apply func(ctx context.Context, tx *sql.Tx) error
}

// migrationSteps is the ordered forward-only registry. Steps must be listed in
// ascending To order; the runner relies on that to advance monotonically.
var migrationSteps = []migrationStep{
	{To: 2, Name: "target-scoped finding identity", Apply: migrateV1ToV2},
}

// migrateV1ToV2 is a deliberate placeholder. Plan 15-18 fills in the body: the
// target-scoped finding identity split (ux_findings_dedup gains a target
// component) and the scan_observation uniqueness constraint.
//
// It is registered but empty on purpose. Landing the runner and the data
// migration together would put a destructive one-way data step and the mechanism
// that decides whether to run it in the same review and the same blast radius.
func migrateV1ToV2(_ context.Context, _ *sql.Tx) error {
	return nil
}

// Migrate brings db up to SchemaVersion.
//
// Behaviour:
//   - user_version == 0 and no tables  → apply schema.sql, stamp SchemaVersion.
//   - user_version == 0 and tables     → a pre-versioning database: stamp
//     legacyVersion and replay every step above it.
//   - user_version  > SchemaVersion    → refuse. The store was written by a newer
//     binary and must not be silently downgraded.
//
// Each step runs in its own transaction together with its version advance, so a
// step that fails part-way leaves user_version untouched and the next run retries
// the whole step instead of resuming mid-way.
func Migrate(ctx context.Context, db *sql.DB) error {
	return migrateWithSteps(ctx, db, migrationSteps)
}

// migrateWithSteps is Migrate with an injectable registry. Tests drive it with
// their own steps so they never mutate the production registry — mutating a
// package-level slice would race under `go test -race` the moment two tests or two
// goroutines run concurrently.
func migrateWithSteps(ctx context.Context, db *sql.DB, steps []migrationStep) error {
	current, err := readUserVersion(ctx, db)
	if err != nil {
		return err
	}

	if current > SchemaVersion {
		return fmt.Errorf(
			"sqlcgen: store.db schema version %d is newer than this binary supports (version %d): "+
				"upgrade reconftw or point --output at a different data dir",
			current, SchemaVersion)
	}

	if current == 0 {
		current, err = bootstrap(ctx, db)
		if err != nil {
			return err
		}
	}

	for _, step := range steps {
		if step.To <= current {
			continue
		}
		if err := applyStep(ctx, db, step, current); err != nil {
			return err
		}
		current = step.To
	}
	return nil
}

// bootstrap handles the user_version == 0 fork and returns the version the
// database is left at.
func bootstrap(ctx context.Context, db *sql.DB) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sqlcgen: migrate bootstrap: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// A pre-versioning store.db is indistinguishable from an empty one by the
	// pragma alone — both read 0. Probing for a table schema.sql creates is the
	// only way to tell them apart, and getting it wrong means re-running every
	// migration against a database that already has them.
	var tables int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'scans'`,
	).Scan(&tables); err != nil {
		return 0, fmt.Errorf("sqlcgen: migrate bootstrap: probe sqlite_master: %w", err)
	}

	to := legacyVersion
	if tables == 0 {
		if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
			return 0, fmt.Errorf("sqlcgen: migrate bootstrap: apply schema: %w", err)
		}
		to = SchemaVersion
	}

	if err := setUserVersion(ctx, tx, to); err != nil {
		return 0, fmt.Errorf("sqlcgen: migrate bootstrap: stamp v%d: %w", to, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sqlcgen: migrate bootstrap: commit: %w", err)
	}
	return to, nil
}

// applyStep runs one step and its version advance in a single transaction.
func applyStep(ctx context.Context, db *sql.DB, step migrationStep, from int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlcgen: migrate v%d->v%d (%s): begin: %w", from, step.To, step.Name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if step.Apply != nil {
		if err := step.Apply(ctx, tx); err != nil {
			return fmt.Errorf("sqlcgen: migrate v%d->v%d (%s): %w", from, step.To, step.Name, err)
		}
	}

	// The version advance rides in the SAME transaction as the step body. Setting
	// it afterwards would let a crash between the two leave a migrated schema
	// stamped at the old version, and the next run would replay the step against
	// a database that already has it.
	if err := setUserVersion(ctx, tx, step.To); err != nil {
		return fmt.Errorf("sqlcgen: migrate v%d->v%d (%s): stamp: %w", from, step.To, step.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlcgen: migrate v%d->v%d (%s): commit: %w", from, step.To, step.Name, err)
	}
	return nil
}

// readUserVersion reads PRAGMA user_version from db.
func readUserVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("sqlcgen: migrate: read user_version: %w", err)
	}
	return v, nil
}

// setUserVersion writes PRAGMA user_version.
//
// SQLite does not accept a bound parameter in a PRAGMA, so the value is
// formatted in. It is an int drawn from this package's own registry and can never
// carry caller input.
func setUserVersion(ctx context.Context, tx *sql.Tx, v int) error {
	//nolint:gosec // v is an int constant from migrationSteps, never user input.
	_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v))
	return err
}
