// migrate.go — hand-authored (NOT sqlc-generated) migration runner for store.db.
//
// WHY THIS FILE EXISTS: every statement in schema.sql is a conditional CREATE, so
// applying it to a database that already has the tables is a no-op by
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
//
// CONCURRENCY. EnsureSchema -> Migrate runs on EVERY ingest against one shared
// <dataDir>/store.db, while the workspace lock is per-TARGET. Two scans of two
// different targets, both the first run after an upgrade, therefore reach this
// code at the same moment against the same file. With an ordinary deferred
// transaction both would read the old user_version before either wrote, and the
// loser would fail on "duplicate column" / "index already exists" — which under
// the run-outcome rules means that scan records no `completed` row. A legitimate
// run destroyed by the mechanism meant to protect it. Every version advance here
// is therefore taken on a dedicated connection, under BEGIN IMMEDIATE, with the
// version re-read INSIDE the transaction so the loser becomes a no-op success
// rather than an error.
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

// migrateBusyTimeoutMS is how long a blocked migration waits for another
// process's write lock before giving up.
//
// Migrate is handed a *sql.DB it did not open and cannot change the DSN of, so it
// must not assume the caller set a busy timeout — it sets one on the connection it
// owns. 5000ms deliberately matches the busy_timeout(5000) in the checkpoint
// store's DSN (internal/core/checkpoint/store.go) and in the store.db DSN that
// internal/core/ingest/ingest.go opens, so a blocked writer behaves the same
// everywhere. Bounded on purpose: a migration that cannot get the lock should
// fail loudly, not hang forever.
const migrateBusyTimeoutMS = 5000

// migrationStep is one forward-only schema change.
//
// Apply runs inside a BEGIN IMMEDIATE transaction that also carries the
// user_version advance, so a step either lands completely or not at all. A step
// must be written to run against the schema its predecessor produced — never
// against schema.sql, which describes only the newest version.
type migrationStep struct {
	// To is the user_version this step produces.
	To int
	// Name identifies the step in error messages, so an operator can tell which
	// migration failed without reading the source.
	Name string
	// Apply performs all DDL and data movement for this step.
	//
	// tx is the migration's dedicated connection with an open write transaction.
	// It is typed as DBTX (rather than *sql.Tx) because the transaction is begun
	// with an explicit BEGIN IMMEDIATE rather than by database/sql — see the
	// package comment. DBTX is the same interface New() takes, so a step needing
	// the generated queries can simply call New(tx).
	Apply func(ctx context.Context, tx DBTX) error
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
func migrateV1ToV2(_ context.Context, _ DBTX) error {
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
// the whole step instead of resuming mid-way. One transaction per step rather than
// one for the whole runner, so a future multi-step migration cannot hold the
// store's write lock for an unbounded time.
//
// Safe to call concurrently from multiple processes against the same file: at most
// one applies each step, and the others return nil.
func Migrate(ctx context.Context, db *sql.DB) error {
	return migrateWithSteps(ctx, db, migrationSteps)
}

// migrateWithSteps is Migrate with an injectable registry. Tests drive it with
// their own steps so they never mutate the production registry — mutating a
// package-level slice would race under `go test -race` the moment two tests or two
// goroutines run concurrently.
func migrateWithSteps(ctx context.Context, db *sql.DB, steps []migrationStep) error {
	// One dedicated connection for the whole migration. Pragmas are per-connection
	// session state, and the explicit BEGIN IMMEDIATE below is too: issuing them
	// against the pool could land them on different connections and silently
	// detach the transaction from the statements meant to be inside it.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlcgen: migrate: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := setBusyTimeout(ctx, conn); err != nil {
		return err
	}

	current, err := readUserVersion(ctx, conn)
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
		current, err = bootstrap(ctx, conn)
		if err != nil {
			return err
		}
	}

	for _, step := range steps {
		if step.To <= current {
			continue
		}
		if err := applyStep(ctx, conn, step, current); err != nil {
			return err
		}
		current = step.To
	}
	return nil
}

// bootstrap handles the user_version == 0 fork and returns the version the
// database is left at.
func bootstrap(ctx context.Context, conn *sql.Conn) (int, error) {
	var result int
	err := inImmediateTx(ctx, conn, func() error {
		// Re-read under the write lock. Another process may have bootstrapped
		// between our read and our BEGIN, in which case its result is the truth
		// and this call must do nothing rather than re-create the schema.
		v, err := readUserVersion(ctx, conn)
		if err != nil {
			return err
		}
		if v != 0 {
			result = v
			return nil
		}

		// A pre-versioning store.db is indistinguishable from an empty one by the
		// pragma alone — both read 0. Probing for a table schema.sql creates is
		// the only way to tell them apart, and getting it wrong means replaying
		// every migration against a database that already has them.
		var tables int
		if err := conn.QueryRowContext(ctx,
			`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'scans'`,
		).Scan(&tables); err != nil {
			return fmt.Errorf("probe sqlite_master: %w", err)
		}

		to := legacyVersion
		if tables == 0 {
			if _, err := conn.ExecContext(ctx, schemaSQL); err != nil {
				return fmt.Errorf("apply schema: %w", err)
			}
			to = SchemaVersion
		}

		if err := setUserVersion(ctx, conn, to); err != nil {
			return fmt.Errorf("stamp v%d: %w", to, err)
		}
		result = to
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("sqlcgen: migrate bootstrap: %w", err)
	}
	return result, nil
}

// applyStep runs one step and its version advance in a single write transaction.
func applyStep(ctx context.Context, conn *sql.Conn, step migrationStep, from int) error {
	err := inImmediateTx(ctx, conn, func() error {
		// Belt to the BEGIN IMMEDIATE braces. If another process applied this step
		// while this one waited for the write lock, re-running Apply would fail on
		// "duplicate column" / "index already exists" and turn a perfectly good
		// run into a failed one. Observing the advanced version is a success.
		v, err := readUserVersion(ctx, conn)
		if err != nil {
			return err
		}
		if v >= step.To {
			return nil
		}

		if step.Apply != nil {
			if err := step.Apply(ctx, conn); err != nil {
				return err
			}
		}

		// The version advance rides in the SAME transaction as the step body.
		// Setting it afterwards would let a crash between the two leave a migrated
		// schema stamped at the old version, and the next run would replay the
		// step against a database that already has it.
		if err := setUserVersion(ctx, conn, step.To); err != nil {
			return fmt.Errorf("stamp: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("sqlcgen: migrate v%d->v%d (%s): %w", from, step.To, step.Name, err)
	}
	return nil
}

// inImmediateTx runs fn inside an explicit BEGIN IMMEDIATE transaction on conn.
//
// BEGIN IMMEDIATE rather than database/sql's BeginTx (which issues a deferred
// BEGIN): IMMEDIATE takes the write lock at BEGIN, so a second process blocks
// there — for up to migrateBusyTimeoutMS — instead of racing to be first to write
// and losing with SQLITE_BUSY halfway through a migration.
//
// The transaction is rolled back unless fn succeeded AND the COMMIT succeeded,
// mirroring the `defer tx.Rollback()` shape of internal/core/checkpoint/store.go.
func inImmediateTx(ctx context.Context, conn *sql.Conn, fn func() error) error {
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin immediate: %w", err)
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		// WithoutCancel: if ctx was cancelled mid-step, the rollback still has to
		// run or the connection returns to the pool holding the write lock.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
	}()

	if err := fn(); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// setBusyTimeout sets the blocked-writer wait on the migration's own connection.
func setBusyTimeout(ctx context.Context, conn *sql.Conn) error {
	//nolint:gosec // migrateBusyTimeoutMS is a compile-time int, never user input.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", migrateBusyTimeoutMS)); err != nil {
		return fmt.Errorf("sqlcgen: migrate: set busy_timeout: %w", err)
	}
	return nil
}

// readUserVersion reads PRAGMA user_version from q, which may be a pool, a
// connection or an open transaction.
func readUserVersion(ctx context.Context, q DBTX) (int, error) {
	var v int
	if err := q.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("sqlcgen: migrate: read user_version: %w", err)
	}
	return v, nil
}

// setUserVersion writes PRAGMA user_version.
//
// SQLite does not accept a bound parameter in a PRAGMA, so the value is
// formatted in. It is an int drawn from this package's own registry and can never
// carry caller input.
func setUserVersion(ctx context.Context, q DBTX, v int) error {
	//nolint:gosec // v is an int constant from migrationSteps, never user input.
	_, err := q.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v))
	return err
}
