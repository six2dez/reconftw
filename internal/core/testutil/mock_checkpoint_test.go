// Source: .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 1.
//
// MockCheckpoint test suite (Tests 10-15).
package testutil_test

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/checkpoint"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/testutil"
)

// Test 10 (interface satisfaction): MockCheckpoint satisfies checkpoint.Interface.
var _ checkpoint.Interface = (*testutil.MockCheckpoint)(nil)

// Test 11/12: Begin → Done false, Begin + Complete (nil err) → Done true.
func TestMockCheckpoint_BeginCompleteDone(t *testing.T) {
	t.Parallel()
	mc := testutil.NewMockCheckpoint()
	ctx := context.Background()
	if err := mc.Begin(ctx, "task.a", "example.com", "hash1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	done, err := mc.Done(ctx, "task.a", "example.com", "hash1")
	if err != nil {
		t.Fatalf("Done: %v", err)
	}
	if done {
		t.Error("Done should be false before Complete")
	}
	if err := mc.Complete(ctx, "task.a", "example.com", "hash1", []string{"out.jsonl"}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	done, err = mc.Done(ctx, "task.a", "example.com", "hash1")
	if err != nil {
		t.Fatalf("Done(2): %v", err)
	}
	if !done {
		t.Error("Done should be true after Complete(nil err)")
	}
}

// Test 13: Different inputHash → different rows → Done returns false.
func TestMockCheckpoint_DifferentHashDifferentRow(t *testing.T) {
	t.Parallel()
	mc := testutil.NewMockCheckpoint()
	ctx := context.Background()
	_ = mc.Begin(ctx, "task.a", "example.com", "hash1")
	_ = mc.Complete(ctx, "task.a", "example.com", "hash1", nil, nil)
	done, err := mc.Done(ctx, "task.a", "example.com", "hash2-different")
	if err != nil {
		t.Fatalf("Done: %v", err)
	}
	if done {
		t.Error("Done with different hash must be false (idempotency-by-hash)")
	}
}

// Test 14: AllRecords returns sorted slice.
func TestMockCheckpoint_AllRecordsSorted(t *testing.T) {
	t.Parallel()
	mc := testutil.NewMockCheckpoint()
	ctx := context.Background()
	_ = mc.Begin(ctx, "task.b", "x.com", "h1")
	_ = mc.Begin(ctx, "task.a", "x.com", "h2")
	_ = mc.Begin(ctx, "task.c", "x.com", "h3")
	records := mc.AllRecords()
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
	for i := 1; i < len(records); i++ {
		if records[i].TaskName < records[i-1].TaskName {
			t.Errorf("AllRecords not sorted: %s < %s", records[i].TaskName, records[i-1].TaskName)
		}
	}
}

// Test 15: Race-clean — concurrent Begin/Complete/Done.
func TestMockCheckpoint_RaceClean(t *testing.T) {
	t.Parallel()
	mc := testutil.NewMockCheckpoint()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = mc.Begin(ctx, "task.a", "example.com", "hash")
			_ = mc.Complete(ctx, "task.a", "example.com", "hash", nil, nil)
			_, _ = mc.Done(ctx, "task.a", "example.com", "hash")
		}(i)
	}
	wg.Wait()
}

// Bonus: Complete with non-nil err records errored status, not done.
func TestMockCheckpoint_CompleteWithErrorIsNotDone(t *testing.T) {
	t.Parallel()
	mc := testutil.NewMockCheckpoint()
	ctx := context.Background()
	_ = mc.Begin(ctx, "task.a", "example.com", "hash")
	_ = mc.Complete(ctx, "task.a", "example.com", "hash", nil,
		&coreerrors.ToolError{Tool: "x", ExitCode: 1, Inner: stderrors.New("boom")})
	done, err := mc.Done(ctx, "task.a", "example.com", "hash")
	if err != nil {
		t.Fatalf("Done: %v", err)
	}
	if done {
		t.Error("Done must be false after Complete with non-nil err (status=errored)")
	}
}

// Bonus: Reset clears state.
func TestMockCheckpoint_Reset(t *testing.T) {
	t.Parallel()
	mc := testutil.NewMockCheckpoint()
	ctx := context.Background()
	_ = mc.Begin(ctx, "task.a", "example.com", "hash")
	_ = mc.Complete(ctx, "task.a", "example.com", "hash", nil, nil)
	mc.Reset()
	done, _ := mc.Done(ctx, "task.a", "example.com", "hash")
	if done {
		t.Error("Done should be false after Reset")
	}
	if len(mc.AllRecords()) != 0 {
		t.Errorf("AllRecords should be empty after Reset, got %d", len(mc.AllRecords()))
	}
}
