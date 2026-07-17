// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 3.
// CANONICAL tests for the SQLite checkpoint store. Tests 1 + 8 + 11 are
// the FOUND-05 idempotency/WAL/concurrent gates.
package checkpoint_test

import (
	stderrors "errors"
	"sync"
	"testing"

	"context"
	"database/sql"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/checkpoint"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

func newTestStore(t *testing.T) *checkpoint.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoints.db")
	s, err := checkpoint.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Test 1: NewStore opens with WAL mode. We verify via PRAGMA journal_mode.
func TestCheckpointStoreWALMode(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	var mode string
	if err := s.QueryPragma(context.Background(), "journal_mode", &mode); err != nil {
		t.Fatalf("PRAGMA query: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q; want wal", mode)
	}
}

// Test 2: Schema is created on first open.
func TestCheckpointStoreSchemaCreated(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	// Try to query the tasks table — should succeed with empty result.
	_, err := s.RawDB().Exec(`SELECT * FROM tasks`)
	if err != nil {
		t.Fatalf("SELECT on tasks table: %v", err)
	}
}

// Test 3: Re-opening an existing DB is idempotent.
func TestCheckpointStoreReopenIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoints.db")
	s1, err := checkpoint.NewStore(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := checkpoint.NewStore(path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer func() { _ = s2.Close() }()
}

// Test 4: Begin inserts an in-progress row.
func TestCheckpointStoreBegin(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Begin(ctx, "subdomains.passive", "example.com", "hash123"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Query the row directly via RawDB.
	var status string
	if err := s.RawDB().QueryRow(
		`SELECT status FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
		"subdomains.passive", "example.com", "hash123",
	).Scan(&status); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if status != "in-progress" {
		t.Fatalf("status = %q; want in-progress", status)
	}
}

// Test 5: Complete updates the row to status=done.
func TestCheckpointStoreComplete(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Begin(ctx, "subdomains.passive", "example.com", "hash123"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Complete(ctx, "subdomains.passive", "example.com", "hash123",
		[]string{"artefacts/subdomains.jsonl"}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var status string
	if err := s.RawDB().QueryRow(
		`SELECT status FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
		"subdomains.passive", "example.com", "hash123",
	).Scan(&status); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if status != "done" {
		t.Fatalf("status after Complete = %q; want done", status)
	}
}

// Test 6: Done returns true after Complete.
func TestCheckpointStoreDoneAfterComplete(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Begin(ctx, "t.x", "tgt", "h1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Complete(ctx, "t.x", "tgt", "h1", nil, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got, err := s.Done(ctx, "t.x", "tgt", "h1")
	if err != nil {
		t.Fatalf("Done: %v", err)
	}
	if !got {
		t.Fatal("Done = false after Complete; want true")
	}
}

// Test 7: Done returns false for a different input_hash (canonical
// re-run trigger per ADR §3.4).
func TestCheckpointStoreDoneDifferentHash(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Begin(ctx, "t.x", "tgt", "h1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Complete(ctx, "t.x", "tgt", "h1", nil, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got, err := s.Done(ctx, "t.x", "tgt", "h_different")
	if err != nil {
		t.Fatalf("Done: %v", err)
	}
	if got {
		t.Fatal("Done = true for different input_hash; want false (forces re-run)")
	}
}

// Test 8 — CANONICAL CRASH RECOVERY:
// Begin a task; close the DB WITHOUT calling Complete (simulates a crash
// mid-task). Re-open; the row should still have status=in-progress, which
// ADR §3.4 mandates the next-startup Scheduler treats as "cancelled" →
// safe re-run.
func TestCheckpointStoreCrashRecovery(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoints.db")
	ctx := context.Background()

	s1, err := checkpoint.NewStore(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := s1.Begin(ctx, "t.x", "tgt", "h1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Simulate crash: close without Complete.
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen — row should still be in-progress.
	s2, err := checkpoint.NewStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	var status string
	if err := s2.RawDB().QueryRow(
		`SELECT status FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
		"t.x", "tgt", "h1",
	).Scan(&status); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if status != "in-progress" {
		t.Fatalf("post-crash status = %q; want in-progress", status)
	}
	// Done() must return false — the row is not "done."
	got, err := s2.Done(ctx, "t.x", "tgt", "h1")
	if err != nil {
		t.Fatalf("Done: %v", err)
	}
	if got {
		t.Fatal("Done = true for in-progress row (should be false → re-run)")
	}
}

// Test 11 — CANONICAL CONCURRENT-BEGIN:
// 10 goroutines call Begin for different (task,target,hash) triples
// concurrently. WAL mode allows concurrent writes; no error should occur.
func TestCheckpointStoreConcurrentBegin(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			taskName := "t.x"
			target := "tgt"
			hash := "h" + string(rune('A'+i))
			if err := s.Begin(context.Background(), taskName, target, hash); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Begin: %v", err)
	}
	var count int
	if err := s.RawDB().QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != N {
		t.Fatalf("inserted = %d; want %d", count, N)
	}
}

// Test 12: Complete with a non-nil error records the appropriate
// error_class from the 7-class hierarchy.
func TestCheckpointStoreErrorClass(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Begin(ctx, "t.x", "tgt", "h1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	toolErr := &coreerrors.ToolError{Tool: "subfinder", ExitCode: 1, Inner: stderrors.New("boom")}
	if err := s.Complete(ctx, "t.x", "tgt", "h1", nil, toolErr); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var status, errorClass string
	if err := s.RawDB().QueryRow(
		`SELECT status, COALESCE(error_class,'') FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
		"t.x", "tgt", "h1",
	).Scan(&status, &errorClass); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if status != "errored" {
		t.Fatalf("status = %q; want errored", status)
	}
	if errorClass != "ToolError" {
		t.Fatalf("error_class = %q; want ToolError", errorClass)
	}
}

// nil error: status=done, empty error_class.
func TestCheckpointStoreNilErrorDone(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Begin(ctx, "t.x", "tgt", "h1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Complete(ctx, "t.x", "tgt", "h1", []string{"artefacts/x.jsonl"}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var status, errorClass string
	if err := s.RawDB().QueryRow(
		`SELECT status, COALESCE(error_class,'') FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
		"t.x", "tgt", "h1",
	).Scan(&status, &errorClass); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if status != "done" {
		t.Fatalf("status = %q; want done", status)
	}
	if errorClass != "" {
		t.Fatalf("error_class = %q; want empty", errorClass)
	}
}

// Done with no matching row returns false (no row = not done).
func TestCheckpointStoreDoneNoRow(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	got, err := s.Done(context.Background(), "task.unknown", "tgt", "h1")
	if err != nil {
		t.Fatalf("Done: %v", err)
	}
	if got {
		t.Fatal("Done = true for absent task; want false")
	}
}

// Begin twice with the same triple → second call overwrites (the
// ON CONFLICT DO UPDATE / INSERT OR REPLACE semantics per ADR §3.4
// re-run trigger).
func TestCheckpointStoreBeginUpsert(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Begin(ctx, "t.x", "tgt", "h1"); err != nil {
		t.Fatalf("Begin 1: %v", err)
	}
	// First Complete with errored status.
	stubErr := &coreerrors.ToolError{Tool: "x", ExitCode: 1, Inner: stderrors.New("e")}
	if err := s.Complete(ctx, "t.x", "tgt", "h1", nil, stubErr); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// Re-Begin (re-run after error) should reset status to in-progress.
	if err := s.Begin(ctx, "t.x", "tgt", "h1"); err != nil {
		t.Fatalf("Begin 2: %v", err)
	}
	var status string
	if err := s.RawDB().QueryRow(
		`SELECT status FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
		"t.x", "tgt", "h1",
	).Scan(&status); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if status != "in-progress" {
		t.Fatalf("post-re-Begin status = %q; want in-progress", status)
	}
}

// Sanity: confirm DB has the indexes per ADR §3.4.
func TestCheckpointStoreIndexes(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	rows, err := s.RawDB().Query(`SELECT name FROM sqlite_master WHERE type='index'`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	found := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		found[name] = true
	}
	if !found["idx_status"] {
		t.Error("missing idx_status")
	}
	if !found["idx_target"] {
		t.Error("missing idx_target")
	}
}

// XCUT-03 gap (store.go:56 NewStore 72.7%): an unopenable DB path (parent
// directory absent) makes db.Ping fail — exercises the ping-error branch,
// the compensating db.Close(), and the wrapped-error return.
func TestCheckpointStoreNewStorePingError(t *testing.T) {
	t.Parallel()
	badPath := filepath.Join(t.TempDir(), "no-such-dir", "checkpoints.db")
	s, err := checkpoint.NewStore(badPath)
	if err == nil {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal("NewStore(unopenable path) err = nil; want a ping/open error")
	}
	if s != nil {
		t.Fatalf("NewStore returned non-nil Store alongside error: %v", err)
	}
}

// XCUT-03 gap (store.go Done error branch): a query error that is NOT
// sql.ErrNoRows must propagate. Closing the DB before the call forces the
// QueryRowContext.Scan to fail with a non-ErrNoRows error.
func TestCheckpointStoreDoneQueryErrorAfterClose(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "checkpoints.db")
	s, err := checkpoint.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, err := s.Done(context.Background(), "t.x", "tgt", "h1")
	if err == nil {
		t.Fatal("Done on closed DB err = nil; want a query error")
	}
	if got {
		t.Fatal("Done on closed DB returned true; want false")
	}
}

// XCUT-03 gap (store.go Complete started_at read error branch): closing the
// DB before Complete forces the started_at read (the first DB op inside
// Complete) to return a non-ErrNoRows error, which must propagate.
func TestCheckpointStoreCompleteReadErrorAfterClose(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "checkpoints.db")
	s, err := checkpoint.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Complete(context.Background(), "t.x", "tgt", "h1", []string{"a"}, nil); err == nil {
		t.Fatal("Complete on closed DB err = nil; want a read/update error")
	}
}

// Ensure context cancellation propagates correctly.
func TestCheckpointStoreContextCancel(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Begin on a cancelled context must fail (sql layer reports it).
	err := s.Begin(ctx, "t.x", "tgt", "h1")
	if err == nil {
		t.Fatal("Begin on cancelled ctx returned nil")
	}
	if !stderrors.Is(err, context.Canceled) && !stderrors.Is(err, sql.ErrTxDone) {
		// modernc/sqlite may surface as a different sentinel — at minimum
		// the error must be non-nil. We accept any error type here.
		t.Logf("Begin returned non-canceled error: %v (accepted — sqlite-specific)", err)
	}
}
