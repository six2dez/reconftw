// Tests for internal/mcp/handlers monitor loop helpers.
package handlers_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // driver registration for the diff-store test

	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/notifier"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
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

// writeStoreArtefact writes newline-joined JSONL lines to <workDir>/artefacts/<name>.
func writeStoreArtefact(t *testing.T, workDir, name string, lines ...string) {
	t.Helper()
	dir := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestMonitorDiff_RealCrossCycleDeltas is the INTEG-04 behavioral proof: it
// simulates two monitor cycles by ingesting two scans for the SAME target into
// the SAME shared <dataDir>/store.db (the store the monitor now reads), where the
// second cycle's artefacts add one new host and one new finding. It then opens the
// store exactly as RunMonitorAsync does and asserts the real diff queries surface
// the new host + new finding — NOT an empty diff. The old <workDir>/store.db path
// (and the missing scan_observation rows) would both make this diff silently empty,
// which build/vet cannot catch — hence a data-backed test.
func TestMonitorDiff_RealCrossCycleDeltas(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data") // the SHARED store lives here
	const target = "example.com"
	ctx := context.Background()

	// Cycle 1 workspace: one host (alpha), one finding (exposed-panel).
	ws1 := filepath.Join(tmp, "ws1")
	writeStoreArtefact(t, ws1, "subdomains.jsonl", `{"host":"alpha.example.com"}`)
	writeStoreArtefact(t, ws1, "findings.jsonl",
		`{"template_id":"exposed-panel","host":"alpha.example.com","severity":"high"}`)
	resA, err := ingest.ScanIntoStore(ctx, dataDir, ws1, target, "recon", discardLogger())
	if err != nil {
		t.Fatalf("cycle 1 ScanIntoStore: %v", err)
	}

	// Cycle 2 workspace: alpha carried forward + NEW host bravo + NEW finding
	// open-redirect (exposed-panel repeats and must NOT appear in the diff).
	ws2 := filepath.Join(tmp, "ws2")
	writeStoreArtefact(t, ws2, "subdomains.jsonl",
		`{"host":"alpha.example.com"}`,
		`{"host":"bravo.example.com"}`)
	writeStoreArtefact(t, ws2, "findings.jsonl",
		`{"template_id":"exposed-panel","host":"alpha.example.com","severity":"high"}`,
		`{"template_id":"open-redirect","host":"bravo.example.com","severity":"medium"}`)
	resB, err := ingest.ScanIntoStore(ctx, dataDir, ws2, target, "recon", discardLogger())
	if err != nil {
		t.Fatalf("cycle 2 ScanIntoStore: %v", err)
	}
	if resA.ScanID == resB.ScanID {
		t.Fatalf("two cycles produced the same scan id %q", resA.ScanID)
	}

	// Open the shared store exactly as RunMonitorAsync now does: plain open (no
	// "?mode=ro") against <dataDir>/store.db.
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "store.db"))
	if err != nil {
		t.Fatalf("open shared store: %v", err)
	}
	defer db.Close() //nolint:errcheck
	q := sqlcgen.New(db)

	// Both ingests may share the same started_at second; push cycle 1 back so
	// GetLatestCompletedScanForTarget deterministically resolves cycle 2 as latest
	// (mirrors real cycles minutes apart).
	if _, err := db.ExecContext(ctx, "UPDATE scans SET started_at = started_at - 1000 WHERE id = ?", resA.ScanID); err != nil {
		t.Fatalf("age cycle-1 scan: %v", err)
	}

	latest, err := q.GetLatestCompletedScanForTarget(ctx, target)
	if err != nil {
		t.Fatalf("GetLatestCompletedScanForTarget: %v", err)
	}
	if latest.ID != resB.ScanID {
		t.Fatalf("latest scan = %q, want cycle-2 %q", latest.ID, resB.ScanID)
	}

	// Host diff: cycle 2 (latest) minus cycle 1 (prev) → bravo only.
	hostRows, err := q.DiffScansHosts(ctx, sqlcgen.DiffScansHostsParams{ScanA: latest.ID, ScanB: resA.ScanID})
	if err != nil {
		t.Fatalf("DiffScansHosts: %v", err)
	}
	hostSet := map[string]bool{}
	for _, h := range hostRows {
		hostSet[h.FQDN] = true
	}
	if !hostSet["bravo.example.com"] {
		t.Errorf("host diff missing new host bravo.example.com; got %v", hostSet)
	}
	if hostSet["alpha.example.com"] {
		t.Errorf("host diff wrongly includes carried-forward alpha.example.com; got %v", hostSet)
	}
	if len(hostRows) != 1 {
		t.Errorf("host diff = %d rows, want exactly 1 (the new host)", len(hostRows))
	}

	// Finding diff: cycle 2 (latest) minus cycle 1 (prev) → open-redirect only.
	findingRows, err := q.DiffScansFindings(ctx, sqlcgen.DiffScansFindingsParams{ScanA: latest.ID, ScanB: resA.ScanID})
	if err != nil {
		t.Fatalf("DiffScansFindings: %v", err)
	}
	sigSet := map[string]bool{}
	for _, f := range findingRows {
		sigSet[f.TemplateSignature] = true
	}
	if !sigSet["open-redirect"] {
		t.Errorf("finding diff missing new finding open-redirect; got %v", sigSet)
	}
	if sigSet["exposed-panel"] {
		t.Errorf("finding diff wrongly includes carried-forward exposed-panel; got %v", sigSet)
	}
	if len(findingRows) != 1 {
		t.Errorf("finding diff = %d rows, want exactly 1 (the new finding)", len(findingRows))
	}

	// Reverse diff (prev minus latest) must be empty — nothing was removed.
	removed, err := q.DiffScansHosts(ctx, sqlcgen.DiffScansHostsParams{ScanA: resA.ScanID, ScanB: latest.ID})
	if err != nil {
		t.Fatalf("reverse DiffScansHosts: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("reverse host diff = %d rows, want 0 (nothing removed)", len(removed))
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
