// Source: ADR §3.4 lines 1294-1310 — checkpoints.db schema (BINDING).
// PRIMARY KEY (task_name, target, input_hash) per ADR.
//
// SQLite-specific notes:
//   - status CHECK constraint mirrors ADR §3.4 status enumeration
//     (in-progress / done / errored / cancelled / skipped).
//   - idx_status + idx_target speed up the Scheduler's "find resumable"
//     query during workspace re-open.
package checkpoint

import "database/sql"

const createTableSQL = `
CREATE TABLE IF NOT EXISTS tasks (
    task_name    TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    input_hash   TEXT    NOT NULL,
    status       TEXT    NOT NULL CHECK (status IN ('in-progress','done','errored','cancelled','skipped')),
    started_at   TEXT,
    finished_at  TEXT,
    duration_ms  INTEGER,
    output_paths TEXT,
    error_class  TEXT,
    PRIMARY KEY (task_name, target, input_hash)
);

CREATE INDEX IF NOT EXISTS idx_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_target ON tasks(target);
`

// applyMigrations creates the schema if it does not already exist.
// Idempotent — safe to call on every NewStore invocation.
func applyMigrations(db *sql.DB) error {
	_, err := db.Exec(createTableSQL)
	return err
}
