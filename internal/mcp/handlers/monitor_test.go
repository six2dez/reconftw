// Tests for internal/mcp/handlers monitor loop helpers.
package handlers_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/notifier"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// TestRunMonitorLoop_StopsAtMaxCycles verifies that runMonitorLoop calls
// runCycle exactly maxCycles times and then returns nil.
func TestRunMonitorLoop_StopsAtMaxCycles(t *testing.T) {
	t.Parallel()

	const maxCycles = 2
	callCount := 0

	err := handlers.ExportedRunMonitorLoop(
		context.Background(),
		0, // zero interval — don't wait
		maxCycles,
		func(_ context.Context, _ int) error {
			callCount++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runMonitorLoop returned non-nil error: %v", err)
	}
	if callCount != maxCycles {
		t.Errorf("expected %d calls, got %d", maxCycles, callCount)
	}
}

// TestRunMonitorLoop_StopsOnContextCancel verifies that a cancelled context
// causes runMonitorLoop to return nil without running additional cycles.
func TestRunMonitorLoop_StopsOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	callCount := 0
	err := handlers.ExportedRunMonitorLoop(
		ctx,
		1*time.Hour, // long interval — should not be reached
		0,           // infinite; cancelled context must stop it
		func(cycleCtx context.Context, _ int) error {
			callCount++
			cancel() // cancel after first cycle
			return nil
		},
	)
	if err != nil {
		t.Fatalf("expected nil error on context cancel, got: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 cycle before cancel, got %d", callCount)
	}
}

// TestRunMonitorLoop_StopsOnCanceledError verifies that returning
// context.Canceled from runCycle causes runMonitorLoop to return nil (clean exit).
func TestRunMonitorLoop_StopsOnCanceledError(t *testing.T) {
	t.Parallel()

	err := handlers.ExportedRunMonitorLoop(
		context.Background(),
		0,
		5, // would run 5 cycles if not cancelled
		func(_ context.Context, _ int) error {
			return context.Canceled
		},
	)
	if err != nil {
		t.Fatalf("expected nil on context.Canceled, got: %v", err)
	}
}

// TestFindingContentHash_Stable verifies that findingContentHash is deterministic.
func TestFindingContentHash_Stable(t *testing.T) {
	t.Parallel()

	h1 := handlers.ExportedFindingContentHash("nuclei:xss-reflected", "high", "https://example.com/path")
	h2 := handlers.ExportedFindingContentHash("nuclei:xss-reflected", "high", "https://example.com/path")
	if h1 != h2 {
		t.Errorf("hash not stable: %q != %q", h1, h2)
	}
	if len(h1) != 32 {
		t.Errorf("expected 32-char hex string, got len=%d: %q", len(h1), h1)
	}
	// Verify different inputs produce different hashes.
	h3 := handlers.ExportedFindingContentHash("nuclei:sqli", "critical", "https://example.com/api")
	if h1 == h3 {
		t.Error("different inputs produced the same hash")
	}
}

// TestNoReNotify_SameHash verifies that a finding with a hash already in
// notifiedHashes is not re-notified (D-02 content-hash dedup).
func TestNoReNotify_SameHash(t *testing.T) {
	t.Parallel()

	notifyCount := 0
	stub := &countingNotifier{notify: func() { notifyCount++ }}
	events := []string{string(notifier.EventCriticalFinding)}
	ef := notifier.NewEventFilter(stub, events)

	// Simulate the dedup map pre-populated with the finding's hash.
	notifiedHashes := make(map[string]struct{})
	hash := handlers.ExportedFindingContentHash("nuclei:xss-reflected", "high", "https://example.com")
	notifiedHashes[hash] = struct{}{}

	// Apply the dedup check exactly as the monitor loop does.
	handlers.ApplyDedup(context.Background(), ef, notifiedHashes,
		"nuclei:xss-reflected", "high", "https://example.com", 0)

	if notifyCount != 0 {
		t.Errorf("expected 0 notifications for already-seen hash, got %d", notifyCount)
	}
}

// TestNoReNotify_NewHash verifies that a finding with a NEW hash IS notified.
func TestNoReNotify_NewHash(t *testing.T) {
	t.Parallel()

	notifyCount := 0
	stub := &countingNotifier{notify: func() { notifyCount++ }}
	events := []string{string(notifier.EventCriticalFinding)}
	ef := notifier.NewEventFilter(stub, events)

	notifiedHashes := make(map[string]struct{}) // empty — no prior notifications

	handlers.ApplyDedup(context.Background(), ef, notifiedHashes,
		"nuclei:xss-reflected", "high", "https://example.com", 0)

	if notifyCount != 1 {
		t.Errorf("expected 1 notification for new hash, got %d", notifyCount)
	}
}

// TestIncrementalSeedFile_Written verifies that writeNewAssetSeedFile creates
// the expected file with 3 FQDNs and returns the correct path.
func TestIncrementalSeedFile_Written(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()
	newFQDNs := []string{"api.example.com", "staging.example.com", "dev.example.com"}
	cycleNum := 2

	seedPath, err := handlers.ExportedWriteNewAssetSeedFile(workDir, cycleNum, newFQDNs)
	if err != nil {
		t.Fatalf("writeNewAssetSeedFile returned error: %v", err)
	}

	// Verify path structure.
	expectedPath := filepath.Join(workDir, "monitor", fmt.Sprintf("newassets-cycle-%d.txt", cycleNum))
	if seedPath != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, seedPath)
	}

	// Verify file exists and contains 3 lines.
	data, err := os.ReadFile(seedPath) //nolint:gosec
	if err != nil {
		t.Fatalf("cannot read seed file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines in seed file, got %d: %q", len(lines), string(data))
	}
	for i, want := range newFQDNs {
		if lines[i] != want {
			t.Errorf("line %d: want %q, got %q", i, want, lines[i])
		}
	}
}

// TestFlusherAssertion_Succeeds is a compile-time + runtime proof that
// *notifier.Multi implements notifier.Flusher (BLOCKER-2 fix).
func TestFlusherAssertion_Succeeds(t *testing.T) {
	t.Parallel()

	// Compile-time check.
	var _ notifier.Flusher = (*notifier.Multi)(nil)

	// Runtime check: wrapping a DigestCoalescer inside Multi.
	inner := &noopNotifier{}
	coalescer := notifier.NewDigestCoalescer(inner, nil, "")
	multi := notifier.NewMulti(coalescer)

	var i interface{} = multi
	if _, ok := i.(notifier.Flusher); !ok {
		t.Fatal("*notifier.Multi does not satisfy notifier.Flusher at runtime")
	}
}

// TestRunMonitorAsync_NilSchedulerReturnsError mirrors the nil-Scheduler guard
// pattern from other RunXxxAsync functions.
func TestRunMonitorAsync_NilSchedulerReturnsError(t *testing.T) {
	t.Parallel()

	err := handlers.RunMonitorAsync(context.Background(), handlers.RunOptions{
		Target:    "example.com",
		Scheduler: nil,
	}, handlers.MonitorOptions{})
	if err == nil {
		t.Fatal("expected non-nil error for nil Scheduler")
	}
	if !strings.Contains(err.Error(), "Scheduler must not be nil") {
		t.Errorf("error %q does not mention 'Scheduler must not be nil'", err.Error())
	}
}

// --- helpers ---

// countingNotifier counts Notify calls for dedup tests.
type countingNotifier struct {
	notify func()
}

func (c *countingNotifier) Notify(_ context.Context, _ notifier.Level, _ string, _ ...any) error {
	c.notify()
	return nil
}

// noopNotifier discards all Notify calls.
type noopNotifier struct{}

func (n *noopNotifier) Notify(_ context.Context, _ notifier.Level, _ string, _ ...any) error {
	return nil
}

// --- verify error wrapping works correctly ---

func TestRunMonitorLoop_NonCanceledError_Continues(t *testing.T) {
	t.Parallel()

	const maxCycles = 3
	callCount := 0

	err := handlers.ExportedRunMonitorLoop(
		context.Background(),
		0,
		maxCycles,
		func(_ context.Context, _ int) error {
			callCount++
			return errors.New("some transient error") // best-effort: should continue
		},
	)
	// Non-canceled errors are best-effort; runMonitorLoop should complete all cycles.
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if callCount != maxCycles {
		t.Errorf("expected %d calls despite errors, got %d", maxCycles, callCount)
	}
}
