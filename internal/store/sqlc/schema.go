// schema.go — hand-authored (NOT sqlc-generated) schema bootstrap for store.db.
//
// The generated query layer in this package targets tables whose CREATE
// statements were never checked in. schema.sql is the authoritative DDL for the
// CURRENT schema version, and is applied verbatim only when creating a brand-new
// database. Existing databases are brought forward by the versioned steps in
// migrate.go — see the note on EnsureSchema below.
package sqlcgen

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed schema.sql
var schemaSQL string

// EnsureSchema brings db up to SchemaVersion. Callers should invoke it once
// immediately after opening a writable *sql.DB and before issuing any query.
//
// It is NOT "apply idempotent DDL". schema.sql creates every object
// conditionally — each statement is skipped when the object already exists — so
// re-running it against a database that already has the tables changes nothing.
// That made it impossible to alter an existing store.db at all: a new index or
// column would apply on a fresh database and silently do nothing on every real
// operator's. EnsureSchema therefore delegates to Migrate, which tracks
// PRAGMA user_version and replays only the steps a given database has not yet
// seen. Repeated calls on an already-current database read the pragma and return
// without writing.
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	return Migrate(ctx, db)
}
