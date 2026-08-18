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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite" // driver registration for the diff-store test

	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/notifier"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// instantWait is the loop's wait replaced by a no-op, so tests never sleep for a
// real (floored) monitor interval.
func instantWait(ctx context.Context, _ time.Duration) bool {
	return handlers.InstantMonitorWaiter(ctx, 0)
}

// TestRunMonitorLoop_StopsAtMaxCycles verifies that runMonitorLoop calls
// runCycle exactly maxCycles times and then returns nil.
func TestRunMonitorLoop_StopsAtMaxCycles(t *testing.T) {
	t.Parallel()

	const maxCycles = 2
	callCount := 0

	err := handlers.ExportedRunMonitorLoop(
		context.Background(),
		time.Minute,
		maxCycles,
		instantWait,
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

// TestRunMonitorLoop_ZeroIntervalDoesNotBusyLoop is the T-15-16-01 guard.
//
// A zero interval used to reach `case <-time.After(0)`, i.e. a continuous scan
// loop with no pause against third-party infrastructure. The assertion is on the
// duration the loop REQUESTS from its wait function (an injected fake clock) —
// asserting on elapsed wall time would mean actually waiting the floor, and
// asserting only that the loop terminated would pass against the defect.
func TestRunMonitorLoop_ZeroIntervalDoesNotBusyLoop(t *testing.T) {
	t.Parallel()

	_, minInterval, _, _ := handlers.ExportedMonitorConstants()

	var requested []time.Duration
	err := handlers.ExportedRunMonitorLoop(
		context.Background(),
		0, // the defect's input: "no interval configured"
		3,
		func(ctx context.Context, d time.Duration) bool {
			requested = append(requested, d)
			return handlers.InstantMonitorWaiter(ctx, d)
		},
		func(_ context.Context, _ int) error { return nil },
	)
	if err != nil {
		t.Fatalf("runMonitorLoop: %v", err)
	}
	if len(requested) != 2 { // 3 cycles → 2 inter-cycle waits
		t.Fatalf("expected 2 inter-cycle waits, got %d", len(requested))
	}
	for i, d := range requested {
		if d < minInterval {
			t.Fatalf("wait %d requested %s, want at least the floor %s — a zero "+
				"interval produced a no-wait scan loop", i, d, minInterval)
		}
	}
}

// TestRealMonitorWait covers the production waiter: every other test injects an
// instant fake, so without this the one code path that actually sleeps between
// cycles is never executed.
func TestRealMonitorWait(t *testing.T) {
	t.Parallel()

	// Completes normally for a short positive duration.
	start := time.Now()
	if !handlers.ExportedRealMonitorWait(context.Background(), 5*time.Millisecond) {
		t.Fatal("realMonitorWait reported an incomplete wait on a live context")
	}
	if time.Since(start) < 5*time.Millisecond {
		t.Fatal("realMonitorWait returned before its duration elapsed")
	}

	// Returns false promptly when the context is already done, rather than
	// sleeping out the (floored) interval.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if handlers.ExportedRealMonitorWait(ctx, time.Hour) {
		t.Fatal("realMonitorWait reported a completed wait on a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancelled wait took %s — cancellation is not short-circuiting", elapsed)
	}

	// A non-positive duration must never become a busy wait, even here.
	start = time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if handlers.ExportedRealMonitorWait(ctx2, 0) {
		t.Fatal("a zero duration completed instantly — realMonitorWait must clamp it")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("a zero duration waited only %s — that is a busy loop", elapsed)
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
		nil,         // the REAL waiter: the test must not hang, so this also
		//              proves cancellation short-circuits the wait
		func(_ context.Context, _ int) error {
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
		time.Minute,
		5, // would run 5 cycles if not cancelled
		instantWait,
		func(_ context.Context, _ int) error {
			return context.Canceled
		},
	)
	if err != nil {
		t.Fatalf("expected nil on context.Canceled, got: %v", err)
	}
}

func TestRunMonitorLoop_NonCanceledError_Continues(t *testing.T) {
	t.Parallel()

	const maxCycles = 3
	callCount := 0

	err := handlers.ExportedRunMonitorLoop(
		context.Background(),
		time.Minute,
		maxCycles,
		instantWait,
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

// TestResolveMonitorInterval is the interval precedence + floor table.
func TestResolveMonitorInterval(t *testing.T) {
	t.Parallel()

	defInterval, minInterval, _, _ := handlers.ExportedMonitorConstants()

	cases := []struct {
		name     string
		explicit time.Duration
		cfgMin   int
		want     time.Duration
	}{
		{"explicit wins over config", 30 * time.Minute, 45, 30 * time.Minute},
		{"config used when no flag", 0, 45, 45 * time.Minute},
		{"package default when neither", 0, 0, defInterval},
		{"negative treated as unset", -time.Hour, 45, 45 * time.Minute},
		{"explicit below the floor is raised", time.Millisecond, 0, minInterval},
		{"config below the floor is raised", 0, 0, defInterval},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := handlers.ResolveMonitorInterval(c.explicit, c.cfgMin); got != c.want {
				t.Errorf("ResolveMonitorInterval(%s, %d) = %s, want %s",
					c.explicit, c.cfgMin, got, c.want)
			}
		})
	}

	// The floor is a safety limit, so it must be unreachable from any input.
	for _, d := range []time.Duration{-1, 0, time.Nanosecond, time.Second} {
		if got := handlers.ResolveMonitorInterval(d, 0); got < minInterval {
			t.Fatalf("ResolveMonitorInterval(%s, 0) = %s, below the floor %s", d, got, minInterval)
		}
	}
}

// TestMonitorRetryBudgetStaysBelowIntervalFloor documents the argument recorded
// in the SUMMARY as an executable assertion: a failing notifier can never stall
// the loop past its own cadence.
func TestMonitorRetryBudgetStaysBelowIntervalFloor(t *testing.T) {
	t.Parallel()

	_, minInterval, base, attempts := handlers.ExportedMonitorConstants()
	// Worst case: base + 2*base + 4*base ... for (attempts-1) waits.
	var total time.Duration
	d := base
	for i := 0; i < attempts-1; i++ {
		total += d
		d *= 2
	}
	if total >= minInterval {
		t.Fatalf("worst-case retry sleep %s >= interval floor %s — a failing "+
			"notifier could stall the monitor past its cadence", total, minInterval)
	}
}

// TestMonitorMinSeverityFilter — cfg.Monitor.MinSeverity is actually applied.
func TestMonitorMinSeverityFilter(t *testing.T) {
	t.Parallel()

	if handlers.ExportedSeverityMeetsMin("medium", "high") {
		t.Error("medium passed a MinSeverity of high")
	}
	if !handlers.ExportedSeverityMeetsMin("critical", "high") {
		t.Error("critical was filtered by a MinSeverity of high")
	}
	if !handlers.ExportedSeverityMeetsMin("high", "high") {
		t.Error("high was filtered by a MinSeverity of high (must be inclusive)")
	}
	if !handlers.ExportedSeverityMeetsMin("LOW", "low") {
		t.Error("severity comparison is case-sensitive")
	}
	if !handlers.ExportedSeverityMeetsMin("medium", "") {
		t.Error("an empty MinSeverity must disable the filter, not drop everything")
	}
	// Fail-open: an unrecognised severity is dispatched rather than dropped.
	if !handlers.ExportedSeverityMeetsMin("unclassified", "critical") {
		t.Error("an unknown severity was silently dropped — it must fail open")
	}
}

// TestMonitorEventKindFollowsSeverity — findings are no longer all emitted as
// EventCriticalFinding.
func TestMonitorEventKindFollowsSeverity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		sev  string
		kind notifier.EventKind
		lvl  notifier.Level
	}{
		{"critical", notifier.EventCriticalFinding, notifier.LevelError},
		{"high", notifier.EventCriticalFinding, notifier.LevelWarn},
		{"medium", notifier.EventScanComplete, notifier.LevelWarn},
		{"low", notifier.EventScanComplete, notifier.LevelInfo},
		{"info", notifier.EventScanComplete, notifier.LevelInfo},
		{"", notifier.EventScanComplete, notifier.LevelInfo},
	}
	for _, c := range cases {
		kind, lvl := handlers.ExportedMonitorEventForSeverity(c.sev)
		if kind != c.kind || lvl != c.lvl {
			t.Errorf("severity %q → (%v, %v), want (%v, %v)", c.sev, kind, lvl, c.kind, c.lvl)
		}
	}
	// The regression this replaces: everything mapping to one kind.
	if k1, _ := handlers.ExportedMonitorEventForSeverity("critical"); k1 == mustKind(t, "low") {
		t.Error("critical and low map to the same event kind — severity is not being honoured")
	}
}

func mustKind(t *testing.T, sev string) notifier.EventKind {
	t.Helper()
	k, _ := handlers.ExportedMonitorEventForSeverity(sev)
	return k
}

// TestNotifyWithRetry_SucceedsAfterTransientFailure — a transient notifier
// error must not lose the alert.
func TestNotifyWithRetry_SucceedsAfterTransientFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	stub := &flakyNotifier{failUntil: 1, calls: &calls}
	ef := notifier.NewEventFilter(stub, []string{string(notifier.EventCriticalFinding)})

	err := handlers.ExportedNotifyWithRetry(context.Background(), ef,
		notifier.EventCriticalFinding, notifier.LevelWarn, "msg", instantWait)
	if err != nil {
		t.Fatalf("notifyWithRetry: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("notifier called %d times, want 2 (one failure then one success)", got)
	}
}

// TestNotifyWithRetry_GivesUpAfterBudget — the retry is bounded.
func TestNotifyWithRetry_GivesUpAfterBudget(t *testing.T) {
	t.Parallel()

	_, _, _, attempts := handlers.ExportedMonitorConstants()

	var calls atomic.Int32
	stub := &flakyNotifier{failUntil: 1 << 30, calls: &calls}
	ef := notifier.NewEventFilter(stub, []string{string(notifier.EventCriticalFinding)})

	err := handlers.ExportedNotifyWithRetry(context.Background(), ef,
		notifier.EventCriticalFinding, notifier.LevelWarn, "msg", instantWait)
	if err == nil {
		t.Fatal("notifyWithRetry returned nil against an always-failing notifier")
	}
	if got := int(calls.Load()); got != attempts {
		t.Fatalf("notifier called %d times, want exactly %d", got, attempts)
	}
}

// TestDispatchFindingAlert_MarkOrdering is the T-15-16-03 guard: the finding is
// recorded as notified ONLY after a notification actually succeeded.
//
// The previous code inserted the hash and then discarded Notify's error, so a
// transient outage suppressed a critical finding permanently.
func TestDispatchFindingAlert_MarkOrdering(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const target = "example.com"
	alert := handlers.FindingAlert{
		Fingerprint: "fp-1",
		Severity:    "critical",
		Message:     "new finding: boom",
	}

	t.Run("not marked when every attempt fails", func(t *testing.T) {
		t.Parallel()
		st := openState(t, t.TempDir())
		var calls atomic.Int32
		ef := notifier.NewEventFilter(&flakyNotifier{failUntil: 1 << 30, calls: &calls},
			[]string{string(notifier.EventCriticalFinding)})

		sent, err := handlers.ExportedDispatchFindingAlert(ctx, ef, st, target, alert, true, instantWait)
		if err == nil {
			t.Fatal("expected an error from an always-failing notifier")
		}
		if sent {
			t.Fatal("reported a dispatch that never succeeded")
		}
		if seen, _ := st.WasNotified(ctx, target, alert.Fingerprint); seen {
			t.Fatal("finding was marked notified despite a failed dispatch — the " +
				"next cycle would never retry it")
		}
	})

	t.Run("marked after a retry succeeds", func(t *testing.T) {
		t.Parallel()
		st := openState(t, t.TempDir())
		var calls atomic.Int32
		ef := notifier.NewEventFilter(&flakyNotifier{failUntil: 1, calls: &calls},
			[]string{string(notifier.EventCriticalFinding)})

		sent, err := handlers.ExportedDispatchFindingAlert(ctx, ef, st, target, alert, true, instantWait)
		if err != nil {
			t.Fatalf("dispatchFindingAlert: %v", err)
		}
		if !sent {
			t.Fatal("dispatch reported not-sent after a successful retry")
		}
		if seen, _ := st.WasNotified(ctx, target, alert.Fingerprint); !seen {
			t.Fatal("finding was not marked notified after a successful dispatch")
		}
	})
}

// TestDispatchFindingAlert_SuppressionSwitch — AlertSuppression is actually the
// switch that enables the WasNotified/MarkNotified path.
func TestDispatchFindingAlert_SuppressionSwitch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const target = "example.com"
	alert := handlers.FindingAlert{Fingerprint: "fp-x", Severity: "critical", Message: "m"}

	t.Run("true suppresses a repeat", func(t *testing.T) {
		t.Parallel()
		st := openState(t, t.TempDir())
		var calls atomic.Int32
		ef := notifier.NewEventFilter(&flakyNotifier{calls: &calls},
			[]string{string(notifier.EventCriticalFinding)})

		for i := 0; i < 3; i++ {
			if _, err := handlers.ExportedDispatchFindingAlert(ctx, ef, st, target, alert, true, instantWait); err != nil {
				t.Fatalf("dispatch %d: %v", i, err)
			}
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("notifier called %d times with suppression ON, want 1", got)
		}
	})

	t.Run("false re-notifies", func(t *testing.T) {
		t.Parallel()
		st := openState(t, t.TempDir())
		var calls atomic.Int32
		ef := notifier.NewEventFilter(&flakyNotifier{calls: &calls},
			[]string{string(notifier.EventCriticalFinding)})

		for i := 0; i < 3; i++ {
			if _, err := handlers.ExportedDispatchFindingAlert(ctx, ef, st, target, alert, false, instantWait); err != nil {
				t.Fatalf("dispatch %d: %v", i, err)
			}
		}
		if got := calls.Load(); got != 3 {
			t.Fatalf("notifier called %d times with suppression OFF, want 3", got)
		}
		if n, _ := st.CountNotified(ctx, target); n != 0 {
			t.Fatalf("suppression OFF wrote %d rows to the suppression table, want 0", n)
		}
	})
}

// TestIncrementalSeedFile_Written verifies that writeNewAssetSeedFile creates
// the expected file with 3 FQDNs and returns the correct path. The filename is
// keyed on the persistent GENERATION, not the loop index, so a restarted monitor
// does not overwrite the previous run's seed (and so the seed path — which feeds
// checkpoint.InputHash — is unique per re-feed).
func TestIncrementalSeedFile_Written(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()
	newFQDNs := []string{"api.example.com", "staging.example.com", "dev.example.com"}
	const generation = uint64(7)

	seedPath, err := handlers.ExportedWriteNewAssetSeedFile(workDir, generation, newFQDNs)
	if err != nil {
		t.Fatalf("writeNewAssetSeedFile returned error: %v", err)
	}

	expectedPath := filepath.Join(workDir, "monitor", fmt.Sprintf("newassets-gen-%d.txt", generation))
	if seedPath != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, seedPath)
	}

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

	// A different generation must produce a DIFFERENT file, not overwrite.
	other, err := handlers.ExportedWriteNewAssetSeedFile(workDir, generation+1, newFQDNs)
	if err != nil {
		t.Fatalf("second writeNewAssetSeedFile: %v", err)
	}
	if other == seedPath {
		t.Fatal("two generations wrote the same seed path")
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

// TestMonitorDryRunCreatesNoState is the T-15-16-08 guard: the monitor state
// store is a new mutation and must sit behind plan 15-05's dry-run gate.
func TestMonitorDryRunCreatesNoState(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	dataDir := filepath.Join(root, "data") // deliberately not created
	cfgPath := lockTestConfigPath(t, dataDir)

	var booted atomic.Int32
	err := handlers.RunMonitorAsync(context.Background(), handlers.RunOptions{
		Target:     "example.com",
		ConfigPath: cfgPath,
		OutputDir:  dataDir,
		DryRun:     true,
		Scheduler:  lockTestScheduler(nil),
		AfterBoot:  func(handlers.AppBoot) { booted.Add(1) },
	}, handlers.MonitorOptions{Mode: handlers.ModeRecon, MaxCycles: 2})
	if err != nil {
		t.Fatalf("dry-run RunMonitorAsync: %v", err)
	}
	if booted.Load() != 1 {
		t.Fatalf("dry run reported %d boots, want exactly 1 (the plan preview)", booted.Load())
	}

	// Nothing at all may exist under the data dir — no workspace, no monitor/,
	// no state.db.
	if entries, rerr := os.ReadDir(dataDir); rerr == nil && len(entries) > 0 {
		t.Fatalf("dry run created %d entries under %s", len(entries), dataDir)
	}
	var found []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() && info.Name() == "state.db" {
			found = append(found, p)
		}
		return nil
	})
	if len(found) > 0 {
		t.Fatalf("dry run created monitor state databases: %v", found)
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
	// subdomains.MergeStage writes {"subdomain",...}, not {"host"} — using the
	// host shape here made the fixture agree with a decoder that ignored every
	// real subdomain line.
	writeStoreArtefact(t, ws1, "subdomains.jsonl", `{"subdomain":"alpha.example.com","source":"subfinder"}`)
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
		`{"subdomain":"alpha.example.com","source":"subfinder"}`,
		`{"subdomain":"bravo.example.com","source":"subfinder"}`)
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

// flakyNotifier fails its first failUntil calls and then succeeds, counting
// every call. failUntil = 0 means "always succeed".
type flakyNotifier struct {
	failUntil int32
	calls     *atomic.Int32
}

func (f *flakyNotifier) Notify(_ context.Context, _ notifier.Level, _ string, _ ...any) error {
	n := f.calls.Add(1)
	if n <= f.failUntil {
		return errors.New("notifier: transient failure")
	}
	return nil
}

// noopNotifier discards all Notify calls.
type noopNotifier struct{}

func (n *noopNotifier) Notify(_ context.Context, _ notifier.Level, _ string, _ ...any) error {
	return nil
}

// countingLogHandler counts log records whose message contains substr. The
// monitor's finding alerts reach the default LogSink (appctx wires
// notifier.NewLogSink(logger) whenever no webhook is configured), so a capturing
// logger is a real observation of DISPATCH, not of the monitor's bookkeeping.
type countingLogHandler struct {
	mu     *sync.Mutex
	substr string
	count  *int
	msgs   *[]string
}

func (h countingLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h countingLogHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.substr) {
		h.mu.Lock()
		*h.count++
		*h.msgs = append(*h.msgs, r.Message)
		h.mu.Unlock()
	}
	return nil
}

func (h countingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingLogHandler) WithGroup(string) slog.Handler      { return h }

// alertCounter observes monitor finding dispatches through the LogSink.
type alertCounter struct {
	mu    sync.Mutex
	count int
	msgs  []string
}

func (a *alertCounter) logger() *slog.Logger {
	return slog.New(countingLogHandler{mu: &a.mu, substr: "new finding:", count: &a.count, msgs: &a.msgs})
}

func (a *alertCounter) snapshot() (int, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.count, append([]string(nil), a.msgs...)
}

// stageFindings writes findings staging lines for the current cycle.
//
// It writes inputs/findings.monitortest.jsonl rather than
// artefacts/findings.jsonl: web.MergeStage("findings") has REPLACE semantics over
// the staging glob and would erase a direct artefact write (merge.go documents
// this as the takeover bug it fixed). Staging is the sanctioned seam.
func stageFindings(t *testing.T, workDir string, lines []string) {
	t.Helper()
	dir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "findings.monitortest.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatalf("write findings staging: %v", err)
	}
}

func findingLine(template, host, severity string) string {
	return fmt.Sprintf(`{"template_id":%q,"host":%q,"severity":%q,"matched_at":"https://%s/panel","type":"nuclei"}`,
		template, host, severity, host)
}

// countDistinctInputHashes reports how many DISTINCT checkpoint input_hash
// values exist for the busiest task in the workspace's checkpoints.db.
//
// This is the behavioural observation of RunGeneration: the generation is folded
// into checkpoint.InputHash (common.go), so N cycles with distinct generations
// leave N distinct hashes per task. A restarted monitor that replayed
// "cycle-0"/"cycle-1" would add ZERO new hashes — and, worse, every task would
// find a done row and skip.
func countDistinctInputHashes(t *testing.T, workspace string) int {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(workspace, "checkpoints.db"))
	if err != nil {
		t.Fatalf("open checkpoints.db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	var taskName string
	if err := db.QueryRow(
		`SELECT task_name FROM tasks GROUP BY task_name ORDER BY COUNT(*) DESC, task_name LIMIT 1`,
	).Scan(&taskName); err != nil {
		t.Fatalf("pick a task_name from checkpoints.db: %v", err)
	}
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(DISTINCT input_hash) FROM tasks WHERE task_name = ?`, taskName,
	).Scan(&n); err != nil {
		t.Fatalf("count distinct input_hash: %v", err)
	}
	return n
}

// TestMonitorRestartPreservesBaselineSuppressionAndGeneration is ACCEPTANCE
// GATE 10, end to end, across a real process/state boundary: two separate
// RunMonitorAsync invocations, each opening and closing its own MonitorState
// over one on-disk state.db, exactly as a restarted monitor does.
//
// The three assertions, in one test:
//
//	(a) generation — run 2's cycles use generations strictly greater than run 1's,
//	    proven both from the state store AND behaviourally from the distinct
//	    checkpoint input_hash count (a replayed generation adds none and makes
//	    every task a no-op).
//	(b) baseline   — run 2's FIRST cycle diffs against the scan run 1 finished on.
//	    Observable: it alerts on the one finding that is new relative to that
//	    baseline. A lost baseline means no diff at all and zero alerts.
//	(c) suppression — a finding alerted in run 1, which disappears and then
//	    reappears (so it re-enters a diff), is NOT alerted again in run 2.
//
// The cycle artefacts are staged through inputs/findings.*.jsonl so the real
// merge + ingest path produces the scans; nothing is written straight into the
// store.
func TestMonitorRestartPreservesBaselineSuppressionAndGeneration(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	cfgPath := lockTestConfigPath(t, dataDir)
	const target = "example.com"
	ctx := context.Background()

	const (
		panelFinding    = "exposed-panel"
		redirectFinding = "open-redirect"
		injectFinding   = "sqli"
	)
	// Per-cycle finding sets, consumed in order across BOTH runs.
	cycleFindings := [][]string{
		// run 1, cycle 0 — establishes the baseline (no diff yet).
		{findingLine(panelFinding, "alpha.example.com", "critical")},
		// run 1, cycle 1 — open-redirect is NEW → alerted, fingerprint stored.
		{
			findingLine(panelFinding, "alpha.example.com", "critical"),
			findingLine(redirectFinding, "bravo.example.com", "critical"),
		},
		// run 2, cycle 0 — open-redirect DISAPPEARS, sqli is NEW. Alerting on
		// sqli is only possible if the baseline carried over from run 1.
		{
			findingLine(panelFinding, "alpha.example.com", "critical"),
			findingLine(injectFinding, "charlie.example.com", "critical"),
		},
		// run 2, cycle 1 — open-redirect REAPPEARS, so it is new relative to the
		// previous cycle's scan and re-enters the diff. Persistent suppression
		// must keep it silent; an in-memory set would alert it again.
		{
			findingLine(panelFinding, "alpha.example.com", "critical"),
			findingLine(injectFinding, "charlie.example.com", "critical"),
			findingLine(redirectFinding, "bravo.example.com", "critical"),
		},
	}

	var cycleIdx atomic.Int32
	alerts := &alertCounter{}

	runMonitor := func(t *testing.T, maxCycles int) {
		t.Helper()
		err := handlers.RunMonitorAsync(ctx, handlers.RunOptions{
			Target:     target,
			ConfigPath: cfgPath,
			OutputDir:  dataDir,
			Scheduler:  lockTestScheduler(nil),
			Logger:     alerts.logger(),
			AfterBoot: func(b handlers.AppBoot) {
				i := int(cycleIdx.Add(1)) - 1
				if i < len(cycleFindings) {
					stageFindings(t, b.WorkDir, cycleFindings[i])
				}
			},
		}, handlers.WithMonitorWaiter(handlers.MonitorOptions{
			Mode:      handlers.ModeRecon,
			MaxCycles: maxCycles,
		}, instantWait))
		if err != nil {
			t.Fatalf("RunMonitorAsync: %v", err)
		}
	}

	// ---- run 1 -------------------------------------------------------------
	runMonitor(t, 2)

	workspace, err := output.WorkspaceInit(dataDir, target)
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}

	st1, err := handlers.OpenMonitorState(workspace)
	if err != nil {
		t.Fatalf("OpenMonitorState after run 1: %v", err)
	}
	genAfterRun1, err := st1.Generation(ctx, target)
	if err != nil {
		t.Fatalf("Generation after run 1: %v", err)
	}
	baselineAfterRun1, err := st1.Baseline(ctx, target)
	if err != nil {
		t.Fatalf("Baseline after run 1: %v", err)
	}
	notifiedAfterRun1, err := st1.CountNotified(ctx, target)
	if err != nil {
		t.Fatalf("CountNotified after run 1: %v", err)
	}
	_ = st1.Close()

	if genAfterRun1 != 2 {
		t.Fatalf("generation after 2 cycles = %d, want 2", genAfterRun1)
	}
	if baselineAfterRun1 == "" {
		t.Fatal("run 1 finished with no baseline recorded — the next run cannot diff")
	}
	alertsRun1, msgsRun1 := alerts.snapshot()
	if alertsRun1 != 1 {
		t.Fatalf("run 1 dispatched %d finding alerts, want exactly 1 (%v)", alertsRun1, msgsRun1)
	}
	if !strings.Contains(msgsRun1[0], redirectFinding) {
		t.Fatalf("run 1 alert was %q, want the new %s finding", msgsRun1[0], redirectFinding)
	}
	if notifiedAfterRun1 != 1 {
		t.Fatalf("run 1 recorded %d suppression fingerprints, want 1", notifiedAfterRun1)
	}
	hashesAfterRun1 := countDistinctInputHashes(t, workspace)
	if hashesAfterRun1 != 2 {
		t.Fatalf("run 1 left %d distinct checkpoint input hashes, want 2 (one per generation)",
			hashesAfterRun1)
	}

	// ---- run 2: a fresh RunMonitorAsync over the SAME on-disk state ---------
	runMonitor(t, 2)

	st2, err := handlers.OpenMonitorState(workspace)
	if err != nil {
		t.Fatalf("OpenMonitorState after run 2: %v", err)
	}
	defer st2.Close() //nolint:errcheck
	genAfterRun2, err := st2.Generation(ctx, target)
	if err != nil {
		t.Fatalf("Generation after run 2: %v", err)
	}
	baselineAfterRun2, err := st2.Baseline(ctx, target)
	if err != nil {
		t.Fatalf("Baseline after run 2: %v", err)
	}

	// (a) generation strictly greater, and behaviourally distinct.
	if genAfterRun2 <= genAfterRun1 {
		t.Fatalf("generation after restart = %d, want > %d — a restarted monitor "+
			"replayed generations, which makes every task's checkpoint.InputHash "+
			"match the previous run's and the whole cycle a silent no-op",
			genAfterRun2, genAfterRun1)
	}
	if genAfterRun2 != 4 {
		t.Fatalf("generation after 2+2 cycles = %d, want 4", genAfterRun2)
	}
	hashesAfterRun2 := countDistinctInputHashes(t, workspace)
	if hashesAfterRun2 != 4 {
		t.Fatalf("run 2 left %d distinct checkpoint input hashes, want 4 — the "+
			"restarted cycles reused the first run's generations", hashesAfterRun2)
	}

	// (b) the baseline carried over: run 2's first cycle diffed against run 1's
	// last scan and alerted on the finding that was new relative to it.
	alertsTotal, msgsTotal := alerts.snapshot()
	run2Msgs := msgsTotal[alertsRun1:]
	if len(run2Msgs) != 1 {
		t.Fatalf("run 2 dispatched %d finding alerts, want exactly 1 (%v)", len(run2Msgs), run2Msgs)
	}
	if !strings.Contains(run2Msgs[0], injectFinding) {
		t.Fatalf("run 2 alert was %q, want the new %s finding — a lost baseline "+
			"would have produced no diff and no alert at all", run2Msgs[0], injectFinding)
	}
	// The alert carries the finding's resolved LOCATION. That location comes from
	// the same resolveFindingLocation call that feeds the fingerprint, so an
	// alert that named no host would mean the fingerprint was built without one —
	// which is the collision F13 lists (one template on N hosts = one identity).
	if !strings.Contains(run2Msgs[0], "charlie.example.com") {
		t.Fatalf("run 2 alert %q does not name the finding's host — the locator "+
			"lookup that also feeds the fingerprint is not resolving", run2Msgs[0])
	}

	// (c) suppression survived: the finding alerted in run 1 re-entered a diff in
	// run 2's second cycle and was NOT alerted again.
	for _, m := range run2Msgs {
		if strings.Contains(m, redirectFinding) {
			t.Fatalf("run 2 re-alerted %s (%q) — the suppression set did not "+
				"survive the restart", redirectFinding, m)
		}
	}
	if alertsTotal != 2 {
		t.Fatalf("total finding alerts across both runs = %d, want 2", alertsTotal)
	}
	if baselineAfterRun2 == baselineAfterRun1 {
		t.Fatal("the baseline did not advance during run 2")
	}
}

// monitorTestConfigPath writes a reconftw.toml pinning data_dir plus an
// arbitrary extra section (used here for [monitor]).
func monitorTestConfigPath(t *testing.T, dataDir, extra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "reconftw.toml")
	body := fmt.Sprintf("[paths]\ndata_dir = %q\n\n%s\n", dataDir, extra)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// runMonitorWithStagedFindings drives RunMonitorAsync for len(cycles) cycles,
// staging cycles[i] into the workspace at the start of cycle i, and returns the
// finding-alert messages the notifier actually received.
func runMonitorWithStagedFindings(t *testing.T, cfgPath, dataDir, target string, cycles [][]string) []string {
	t.Helper()
	var idx atomic.Int32
	alerts := &alertCounter{}
	err := handlers.RunMonitorAsync(context.Background(), handlers.RunOptions{
		Target:     target,
		ConfigPath: cfgPath,
		OutputDir:  dataDir,
		Scheduler:  lockTestScheduler(nil),
		Logger:     alerts.logger(),
		AfterBoot: func(b handlers.AppBoot) {
			i := int(idx.Add(1)) - 1
			if i < len(cycles) {
				stageFindings(t, b.WorkDir, cycles[i])
			}
		},
	}, handlers.WithMonitorWaiter(handlers.MonitorOptions{
		Mode:      handlers.ModeRecon,
		MaxCycles: len(cycles),
	}, instantWait))
	if err != nil {
		t.Fatalf("RunMonitorAsync: %v", err)
	}
	_, msgs := alerts.snapshot()
	return msgs
}

// TestMonitorAppliesConfiguredMinSeverity proves cfg.Monitor.MinSeverity reaches
// the dispatch decision — not merely that the comparison function works.
//
// Both severities would otherwise be dispatched: the default
// notifications.events set allows on-critical-finding AND on-scan-complete, and
// the severity-to-event-kind map routes medium to the latter. So a medium
// finding going missing here can only be the MinSeverity gate.
func TestMonitorAppliesConfiguredMinSeverity(t *testing.T) {
	t.Parallel()

	const target = "example.com"
	cycles := func() [][]string {
		return [][]string{
			{findingLine("baseline-only", "alpha.example.com", "critical")},
			{
				findingLine("baseline-only", "alpha.example.com", "critical"),
				findingLine("medium-thing", "bravo.example.com", "medium"),
				findingLine("critical-thing", "charlie.example.com", "critical"),
			},
		}
	}

	t.Run("min_severity=high drops the medium finding", func(t *testing.T) {
		t.Parallel()
		dataDir := t.TempDir()
		cfg := monitorTestConfigPath(t, dataDir, "[monitor]\nmin_severity = \"high\"")
		msgs := runMonitorWithStagedFindings(t, cfg, dataDir, target, cycles())
		if len(msgs) != 1 {
			t.Fatalf("dispatched %d alerts, want 1 (%v)", len(msgs), msgs)
		}
		if !strings.Contains(msgs[0], "critical-thing") {
			t.Fatalf("alert was %q, want the critical finding", msgs[0])
		}
		for _, m := range msgs {
			if strings.Contains(m, "medium-thing") {
				t.Fatalf("a medium finding passed a min_severity of high: %q", m)
			}
		}
	})

	t.Run("min_severity=info passes both", func(t *testing.T) {
		t.Parallel()
		dataDir := t.TempDir()
		cfg := monitorTestConfigPath(t, dataDir, "[monitor]\nmin_severity = \"info\"")
		msgs := runMonitorWithStagedFindings(t, cfg, dataDir, target, cycles())
		if len(msgs) != 2 {
			t.Fatalf("dispatched %d alerts, want 2 with min_severity=info (%v)", len(msgs), msgs)
		}
	})
}

// TestMonitorAppliesConfiguredAlertSuppression proves cfg.Monitor.alert_suppression
// is the switch on the already-notified path, at loop level.
//
// The four cycles make one finding FLAP: present, absent, present. The
// reappearance is new relative to the previous cycle's scan, so it re-enters the
// diff — which is the only way a suppression decision becomes observable.
func TestMonitorAppliesConfiguredAlertSuppression(t *testing.T) {
	t.Parallel()

	const target = "example.com"
	base := findingLine("steady", "alpha.example.com", "critical")
	flap := findingLine("flapping", "bravo.example.com", "critical")
	cycles := func() [][]string {
		return [][]string{
			{base},       // baseline
			{base, flap}, // flapping appears -> alert
			{base},       // flapping disappears
			{base, flap}, // flapping returns -> back in the diff
		}
	}

	t.Run("suppression on silences the repeat", func(t *testing.T) {
		t.Parallel()
		dataDir := t.TempDir()
		cfg := monitorTestConfigPath(t, dataDir, "[monitor]\nalert_suppression = true")
		msgs := runMonitorWithStagedFindings(t, cfg, dataDir, target, cycles())
		if len(msgs) != 1 {
			t.Fatalf("dispatched %d alerts with suppression ON, want 1 (%v)", len(msgs), msgs)
		}
	})

	t.Run("suppression off re-alerts", func(t *testing.T) {
		t.Parallel()
		dataDir := t.TempDir()
		cfg := monitorTestConfigPath(t, dataDir, "[monitor]\nalert_suppression = false")
		msgs := runMonitorWithStagedFindings(t, cfg, dataDir, target, cycles())
		if len(msgs) != 2 {
			t.Fatalf("dispatched %d alerts with suppression OFF, want 2 (%v)", len(msgs), msgs)
		}
	})
}

// TestMonitorTwoCyclesDoNotSelfDeadlock is the F4 monitor guard (plan 15-09).
//
// THIS TEST MUST SURVIVE ANY REWRITE OF monitor.go. What it protects:
//
// RunMonitorAsync pre-boots ONCE to obtain workDir, cfg and the notifier, and
// then each cycle calls RunCompositeAsync, which boots AGAIN. Both boots take
// the SAME per-target workspace lock. If the pre-boot keeps its lock for the
// monitor's lifetime, every cycle is rejected by its own process with "target
// already running" and the monitor polls forever while executing nothing — a
// silent failure that no build, vet or -race run can detect. The resolution is
// that the pre-boot releases its lock (via boot.Close()) immediately after the
// pre-boot checkpoint is closed, so only the current cycle ever holds it.
//
// The assertion is cycle-count-based on purpose: AfterBoot fires exactly once
// per cycle (RunCompositeAsync calls it; the pre-boot does not), so a
// self-deadlocked monitor yields 0 and a working one yields MaxCycles. A test
// that only asserted "RunMonitorAsync returned nil" would pass against the
// deadlock, because the loop swallows per-cycle errors and continues.
//
// Plan 15-16 note: the assertion below is UNCHANGED. The only edit this plan
// made was replacing MonitorOptions.Interval=0 with an injected instant waiter —
// interval 0 now resolves to the safety floor, so the old form would have made
// this test wait a real minute between cycles. The wait is not what the test
// observes; the executed-cycle count is.
func TestMonitorTwoCyclesDoNotSelfDeadlock(t *testing.T) {
	t.Parallel()

	const wantCycles = 2

	dataDir := t.TempDir()
	cfgPath := lockTestConfigPath(t, dataDir)

	var cycleBoots atomic.Int32

	err := handlers.RunMonitorAsync(context.Background(), handlers.RunOptions{
		Target:     "example.com",
		ConfigPath: cfgPath,
		OutputDir:  dataDir,
		Scheduler:  lockTestScheduler(nil),
		AfterBoot:  func(handlers.AppBoot) { cycleBoots.Add(1) },
	}, handlers.WithMonitorWaiter(handlers.MonitorOptions{
		Mode:      handlers.ModeRecon,
		MaxCycles: wantCycles,
	}, instantWait))
	if err != nil {
		t.Fatalf("RunMonitorAsync: %v", err)
	}

	if got := int(cycleBoots.Load()); got != wantCycles {
		t.Fatalf("%d of %d monitor cycles executed — the monitor deadlocked against "+
			"its own pre-boot (the pre-boot must release the workspace lock before "+
			"the cycle loop starts)", got, wantCycles)
	}
	// Belt and braces: after the monitor returns, the workspace is free.
	ws, err := output.WorkspaceInit(dataDir, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	l, err := output.AcquireWorkspaceLock(ws)
	if err != nil {
		t.Fatalf("workspace still locked after the monitor exited: %v", err)
	}
	_ = l.Release()
}
