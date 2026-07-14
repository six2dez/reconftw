// schema.go — hand-authored (NOT sqlc-generated) schema bootstrap for store.db.
//
// The generated query layer in this package targets tables whose CREATE
// statements were never checked in. EnsureSchema applies the embedded schema.sql
// so any process that opens store.db (ingest, quick-rescan, report, monitor) can
// rely on the tables existing. All DDL is idempotent (CREATE ... IF NOT EXISTS),
// so calling this on every open is safe and cheap.
package sqlcgen

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
)

//go:embed schema.sql
var schemaSQL string

// EnsureSchema applies the embedded store schema to db. It is idempotent: every
// statement is IF NOT EXISTS, so repeated calls against an already-initialised
// database are no-ops. Callers should invoke it once immediately after opening a
// writable *sql.DB and before issuing any query.
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("sqlcgen: apply schema: %w", err)
	}
	return nil
}
