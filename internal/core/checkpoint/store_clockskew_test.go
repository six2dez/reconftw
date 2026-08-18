// Regression test for the duration clamp in Store.Complete. Added to close
// the XCUT-03 statement-weighted coverage gate for
// internal/core/checkpoint/store.go after 15-07 replaced the unweighted
// per-function mean that had been reporting this file above 90%.
package checkpoint_test

import (
	"context"
	"testing"
	"time"
)

// A started_at in the future — which happens on clock skew, on a resumed
// workspace copied from another machine, or when NTP steps the clock
// backwards mid-run — must clamp duration_ms to 0 rather than persisting a
// negative duration. A negative duration_ms would flow into the timing
// summary and any downstream report that sums task durations.
func TestCompleteClampsNegativeDurationFromFutureStartedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const (
		taskName = "subdomains.passive"
		target   = "example.com"
		hash     = "deadbeef"
	)

	if err := s.Begin(ctx, taskName, target, hash); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// Rewrite started_at into the future, behind Complete's back. This is
	// the state a skewed clock leaves on disk.
	future := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	if _, err := s.RawDB().ExecContext(ctx,
		`UPDATE tasks SET started_at = ? WHERE task_name = ? AND target = ? AND input_hash = ?`,
		future, taskName, target, hash,
	); err != nil {
		t.Fatalf("seed future started_at: %v", err)
	}

	if err := s.Complete(ctx, taskName, target, hash, []string{"out.jsonl"}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	var durationMs int64
	if err := s.RawDB().QueryRowContext(ctx,
		`SELECT COALESCE(duration_ms, -1) FROM tasks WHERE task_name = ? AND target = ? AND input_hash = ?`,
		taskName, target, hash,
	).Scan(&durationMs); err != nil {
		t.Fatalf("read duration_ms: %v", err)
	}

	if durationMs < 0 {
		t.Fatalf("duration_ms = %d; a future started_at must clamp to 0, never persist a negative duration", durationMs)
	}
	if durationMs != 0 {
		t.Fatalf("duration_ms = %d; want exactly 0 for a future started_at", durationMs)
	}
}
