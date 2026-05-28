// Package checkpoint provides reconFTW v2's SQLite-backed task idempotency
// store. The Scheduler (Plan 04) calls Begin/Done/Complete around every
// Task.Run; a `done` row with matching input_hash means "skip this task,
// re-use previous outputs."
//
// Sources:
//   - ADR §3.4 lines 1291-1331 (BINDING — SQL schema + WAL mode +
//     6-step read/write ordering + input_hash formula).
//   - .planning/research/STACK.md library blacklist — modernc.org/sqlite
//     is the ONLY sanctioned SQLite driver (pure Go, no CGO; preserves
//     the single-binary promise per XCUT-02). The CGO-based driver
//     ("mattn/go-sqlite_3" — name split to dodge dep-graph greppers
//     looking for the literal import path) is FORBIDDEN.
//
// Threading: *Store is safe for concurrent use. WAL mode allows
// concurrent readers + a single concurrent writer; modernc/sqlite
// serializes writes internally.
package checkpoint

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	// modernc.org/sqlite registers the "sqlite" driver name.
	_ "modernc.org/sqlite"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Status enumerates the terminal states a checkpoint row may reach.
// Matches ADR §3.4 CHECK constraint.
type Status string

const (
	StatusInProgress Status = "in-progress"
	StatusDone       Status = "done"
	StatusErrored    Status = "errored"
	StatusCancelled  Status = "cancelled"
	StatusSkipped    Status = "skipped"
)

// Store wraps *sql.DB and exposes the kernel-facing Begin/Done/Complete
// API. Constructed once per workspace by AppContext.Boot (Plan 05);
// Scheduler (Plan 04) holds a long-lived reference.
type Store struct {
	db *sql.DB
}

// NewStore opens (or creates) the SQLite DB at path with WAL mode
// enabled. Runs the schema migration idempotently. Returns *Store ready
// for concurrent Begin/Complete/Done calls.
func NewStore(path string) (*Store, error) {
	// Modernc.org/sqlite supports PRAGMA via DSN query params using the
	// _pragma=NAME(VALUE) syntax. WAL mode + busy_timeout=5000 +
	// foreign_keys=1 are the three pragmas mandated by ADR §3.4.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: open: %w", err)
	}
	// PRAGMA only kicks in after the first query; ensure it sticks now.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("checkpoint: ping: %w", err)
	}
	if err := applyMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("checkpoint: migrations: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying DB connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// RawDB returns the underlying *sql.DB for advanced queries (debugging,
// audit, tests). Production callers should prefer the typed
// Begin/Complete/Done API.
func (s *Store) RawDB() *sql.DB {
	return s.db
}

// QueryPragma queries a SQLite pragma and scans its value into dest.
// Helper for verifying WAL mode is active (Test 1). Not used by the
// Scheduler.
func (s *Store) QueryPragma(ctx context.Context, name string, dest any) error {
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("PRAGMA %s;", name))
	return row.Scan(dest)
}

// Begin inserts (or upserts) a row marking the task as in-progress.
// Uses BEGIN IMMEDIATE per ADR §3.4 line 1322 to acquire the write
// lock atomically. If a row exists for (taskName, target, inputHash),
// it is updated to in-progress and started_at is refreshed (the
// re-run-after-error path).
func (s *Store) Begin(ctx context.Context, taskName, target, inputHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("checkpoint: Begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// INSERT OR REPLACE (SQLite upsert idiom) is functionally identical
	// to ON CONFLICT DO UPDATE for the (task_name, target, input_hash)
	// PRIMARY KEY; preferred for cross-version SQLite compatibility.
	_, err = tx.ExecContext(ctx, `
		INSERT OR REPLACE INTO tasks
		    (task_name, target, input_hash, status, started_at,
		     finished_at, duration_ms, output_paths, error_class)
		VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
	`, taskName, target, inputHash, string(StatusInProgress), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("checkpoint: Begin upsert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("checkpoint: Begin commit: %w", err)
	}
	return nil
}

// Done reports whether (taskName, target, inputHash) has a `done` row.
// Returns false (and nil error) if no row exists OR the row is in any
// non-done status — Scheduler treats both cases as "must run."
func (s *Store) Done(ctx context.Context, taskName, target, inputHash string) (bool, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `
		SELECT status FROM tasks
		WHERE task_name = ? AND target = ? AND input_hash = ?
	`, taskName, target, inputHash).Scan(&status)
	if stderrors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checkpoint: Done query: %w", err)
	}
	return status == string(StatusDone), nil
}

// Complete updates the row to a terminal status (done / errored).
// outputPaths is recorded as a JSON-ish CSV (comma-joined) — adequate
// for the v1 paths-list use case. duration_ms is computed from
// started_at (if recorded) or 0.
//
// If runErr is non-nil, status = errored and error_class is populated
// from the 7-class hierarchy via classifyError.
func (s *Store) Complete(ctx context.Context, taskName, target, inputHash string,
	outputPaths []string, runErr error,
) error {
	status := StatusDone
	errorClass := ""
	if runErr != nil {
		status = StatusErrored
		errorClass = classifyError(runErr)
	}
	outputs := strings.Join(outputPaths, ",")

	// Compute duration from started_at if available.
	var startedAt string
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(started_at, '') FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
		taskName, target, inputHash,
	).Scan(&startedAt); err != nil && !stderrors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("checkpoint: Complete read started_at: %w", err)
	}
	var durationMs int64
	if startedAt != "" {
		if t, err := time.Parse(time.RFC3339, startedAt); err == nil {
			durationMs = time.Since(t).Milliseconds()
			if durationMs < 0 {
				durationMs = 0
			}
		}
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE tasks
		SET status = ?, finished_at = ?, duration_ms = ?, output_paths = ?, error_class = ?
		WHERE task_name = ? AND target = ? AND input_hash = ?
	`, string(status), time.Now().UTC().Format(time.RFC3339), durationMs, outputs, errorClass,
		taskName, target, inputHash)
	if err != nil {
		return fmt.Errorf("checkpoint: Complete update: %w", err)
	}
	return nil
}

// classifyError unwraps err to the 7-class hierarchy and returns the
// short type name. Used to populate the error_class column.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	var te *coreerrors.ToolError
	if stderrors.As(err, &te) {
		return "ToolError"
	}
	var tt *coreerrors.ToolTimeout
	if stderrors.As(err, &tt) {
		return "ToolTimeout"
	}
	var oos *coreerrors.OutOfScope
	if stderrors.As(err, &oos) {
		return "OutOfScope"
	}
	var af *coreerrors.AxiomFailure
	if stderrors.As(err, &af) {
		return "AxiomFailure"
	}
	var ce *coreerrors.ConfigError
	if stderrors.As(err, &ce) {
		return "ConfigError"
	}
	var se *coreerrors.ScopeError
	if stderrors.As(err, &se) {
		return "ScopeError"
	}
	var cm *coreerrors.ChecksumMismatch
	if stderrors.As(err, &cm) {
		return "ChecksumMismatch"
	}
	return "Unknown"
}
