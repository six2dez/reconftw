// Tests for MonitorState — the persistent monitor generation / baseline /
// suppression store (F13, acceptance gate 10).
//
// Every persistence assertion CLOSES and REOPENS the store. An in-process
// assertion would pass against the in-memory map this store replaces, which is
// exactly the defect the plan exists to fix.
package handlers_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

const stateTestTarget = "example.com"

func openState(t *testing.T, workDir string) *handlers.MonitorState {
	t.Helper()
	st, err := handlers.OpenMonitorState(workDir)
	if err != nil {
		t.Fatalf("OpenMonitorState(%q): %v", workDir, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestMonitorStateGenerationSurvivesRestart is the core gate-10 assertion: the
// generation counter is monotonic ACROSS a close/reopen. A counter that reset
// here would make a restarted monitor replay generation 1, which makes every
// task's checkpoint.InputHash match the previous run's, Done() true, and the
// whole cycle a silent no-op.
func TestMonitorStateGenerationSurvivesRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()

	st := openState(t, dir)
	for want := uint64(1); want <= 3; want++ {
		got, err := st.NextGeneration(ctx, stateTestTarget)
		if err != nil {
			t.Fatalf("NextGeneration: %v", err)
		}
		if got != want {
			t.Fatalf("NextGeneration #%d = %d, want %d", want, got, want)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// RESTART: a brand-new handle over the same file.
	st2 := openState(t, dir)
	got, err := st2.NextGeneration(ctx, stateTestTarget)
	if err != nil {
		t.Fatalf("NextGeneration after reopen: %v", err)
	}
	if got != 4 {
		t.Fatalf("NextGeneration after reopen = %d, want 4 — the generation counter "+
			"did not survive a restart, so a restarted monitor replays generations "+
			"and every task short-circuits on an unchanged InputHash", got)
	}
	if cur, err := st2.Generation(ctx, stateTestTarget); err != nil || cur != 4 {
		t.Fatalf("Generation = %d (err %v), want 4", cur, err)
	}
}

// TestMonitorStateGenerationIsPerTarget proves one state file can serve several
// targets without their counters interfering.
func TestMonitorStateGenerationIsPerTarget(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := openState(t, t.TempDir())

	for i := 0; i < 3; i++ {
		if _, err := st.NextGeneration(ctx, "a.example.com"); err != nil {
			t.Fatalf("NextGeneration(a): %v", err)
		}
	}
	got, err := st.NextGeneration(ctx, "b.example.com")
	if err != nil {
		t.Fatalf("NextGeneration(b): %v", err)
	}
	if got != 1 {
		t.Fatalf("second target's first generation = %d, want 1", got)
	}
}

// TestMonitorStateGenerationConcurrent asserts 20 concurrent callers receive 20
// DISTINCT values with no gaps and no duplicates. A SELECT-then-UPDATE
// implementation loses updates here and hands two cycles the same generation.
func TestMonitorStateGenerationConcurrent(t *testing.T) {
	t.Parallel()

	const n = 20
	ctx := context.Background()
	st := openState(t, t.TempDir())

	var (
		mu   sync.Mutex
		seen = make(map[uint64]int, n)
		wg   sync.WaitGroup
	)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gen, err := st.NextGeneration(ctx, stateTestTarget)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			seen[gen]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent NextGeneration: %v", err)
	}

	if len(seen) != n {
		t.Fatalf("got %d distinct generations from %d calls — duplicates: %v", len(seen), n, seen)
	}
	for want := uint64(1); want <= n; want++ {
		if seen[want] != 1 {
			t.Fatalf("generation %d observed %d times, want exactly 1 (gap or duplicate)", want, seen[want])
		}
	}
}

// TestMonitorStateBaselineSurvivesRestart — the baseline scan id is durable.
func TestMonitorStateBaselineSurvivesRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()

	st := openState(t, dir)
	if got, err := st.Baseline(ctx, stateTestTarget); err != nil || got != "" {
		t.Fatalf("fresh Baseline = %q (err %v), want empty", got, err)
	}
	if err := st.SetBaseline(ctx, stateTestTarget, "scan-abc"); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2 := openState(t, dir)
	got, err := st2.Baseline(ctx, stateTestTarget)
	if err != nil {
		t.Fatalf("Baseline after reopen: %v", err)
	}
	if got != "scan-abc" {
		t.Fatalf("Baseline after reopen = %q, want %q", got, "scan-abc")
	}
}

// TestMonitorStateSetBaselineDoesNotResetGeneration guards the two counters
// against each other: they advance at different points in a cycle (generation at
// the start, baseline only after the diff and notifications complete).
func TestMonitorStateSetBaselineDoesNotResetGeneration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := openState(t, t.TempDir())

	if _, err := st.NextGeneration(ctx, stateTestTarget); err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if _, err := st.NextGeneration(ctx, stateTestTarget); err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if err := st.SetBaseline(ctx, stateTestTarget, "scan-xyz"); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}
	gen, err := st.Generation(ctx, stateTestTarget)
	if err != nil {
		t.Fatalf("Generation: %v", err)
	}
	if gen != 2 {
		t.Fatalf("Generation after SetBaseline = %d, want 2 (SetBaseline must not touch it)", gen)
	}
}

// TestMonitorStateSetBaselineBeforeAnyGeneration covers the insert branch of the
// baseline upsert (no monitor_run row exists yet).
func TestMonitorStateSetBaselineBeforeAnyGeneration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := openState(t, t.TempDir())

	if err := st.SetBaseline(ctx, stateTestTarget, "scan-first"); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}
	if got, _ := st.Baseline(ctx, stateTestTarget); got != "scan-first" {
		t.Fatalf("Baseline = %q, want scan-first", got)
	}
	gen, err := st.NextGeneration(ctx, stateTestTarget)
	if err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if gen != 1 {
		t.Fatalf("first generation after a baseline-only row = %d, want 1", gen)
	}
	if got, _ := st.Baseline(ctx, stateTestTarget); got != "scan-first" {
		t.Fatalf("NextGeneration clobbered the baseline: %q", got)
	}
}

// TestMonitorStateNotifiedSurvivesRestart — the suppression set is durable.
func TestMonitorStateNotifiedSurvivesRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	const fp = "0123456789abcdef0123456789abcdef"

	st := openState(t, dir)
	if seen, err := st.WasNotified(ctx, stateTestTarget, fp); err != nil || seen {
		t.Fatalf("fresh WasNotified = %v (err %v), want false", seen, err)
	}
	if err := st.MarkNotified(ctx, stateTestTarget, fp); err != nil {
		t.Fatalf("MarkNotified: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2 := openState(t, dir)
	seen, err := st2.WasNotified(ctx, stateTestTarget, fp)
	if err != nil {
		t.Fatalf("WasNotified after reopen: %v", err)
	}
	if !seen {
		t.Fatal("WasNotified after reopen = false — the suppression set did not survive a restart")
	}
	if other, err := st2.WasNotified(ctx, stateTestTarget, "ffffffffffffffffffffffffffffffff"); err != nil || other {
		t.Fatalf("unmarked fingerprint reported notified (err %v)", err)
	}
	// Suppression must not leak across targets.
	if other, err := st2.WasNotified(ctx, "other.example.com", fp); err != nil || other {
		t.Fatalf("fingerprint leaked to another target (err %v)", err)
	}
	// MarkNotified is idempotent — a second mark must not create a second row.
	if err := st2.MarkNotified(ctx, stateTestTarget, fp); err != nil {
		t.Fatalf("second MarkNotified: %v", err)
	}
	if n, err := st2.CountNotified(ctx, stateTestTarget); err != nil || n != 1 {
		t.Fatalf("CountNotified = %d (err %v), want 1", n, err)
	}
}

// TestMonitorStatePruneNotified — old entries go, recent entries stay.
func TestMonitorStatePruneNotified(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := openState(t, t.TempDir())

	if err := st.MarkNotified(ctx, stateTestTarget, "old"); err != nil {
		t.Fatalf("MarkNotified(old): %v", err)
	}
	// Prune with a cutoff in the future: "old" is older than it.
	if err := st.PruneNotified(ctx, stateTestTarget, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("PruneNotified: %v", err)
	}
	if seen, _ := st.WasNotified(ctx, stateTestTarget, "old"); seen {
		t.Fatal("PruneNotified did not remove an entry older than the cutoff")
	}

	if err := st.MarkNotified(ctx, stateTestTarget, "new"); err != nil {
		t.Fatalf("MarkNotified(new): %v", err)
	}
	// Prune with a cutoff in the past: nothing qualifies.
	if err := st.PruneNotified(ctx, stateTestTarget, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("PruneNotified: %v", err)
	}
	if seen, _ := st.WasNotified(ctx, stateTestTarget, "new"); !seen {
		t.Fatal("PruneNotified removed an entry newer than the cutoff")
	}
}

// TestOpenMonitorStateErrors covers the two argument/IO failure branches.
func TestOpenMonitorStateErrors(t *testing.T) {
	t.Parallel()

	if _, err := handlers.OpenMonitorState(""); err == nil {
		t.Fatal("OpenMonitorState(\"\") returned nil error")
	}

	// A regular FILE where the monitor/ directory must go: MkdirAll fails.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "monitor"), []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	if _, err := handlers.OpenMonitorState(dir); err == nil {
		t.Fatal("OpenMonitorState over a file-blocked monitor/ path returned nil error")
	}
}

// TestMonitorStateNilReceiverIsSafe — every method tolerates a nil store, which
// is what the monitor holds if OpenMonitorState ever fails on a degraded path.
func TestMonitorStateNilReceiverIsSafe(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var st *handlers.MonitorState

	if err := st.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
	if st.Path() != "" {
		t.Fatal("nil Path is not empty")
	}
	if _, err := st.NextGeneration(ctx, stateTestTarget); err == nil {
		t.Fatal("nil NextGeneration returned nil error")
	}
	if _, err := st.Generation(ctx, stateTestTarget); err == nil {
		t.Fatal("nil Generation returned nil error")
	}
	if _, err := st.Baseline(ctx, stateTestTarget); err == nil {
		t.Fatal("nil Baseline returned nil error")
	}
	if err := st.SetBaseline(ctx, stateTestTarget, "x"); err == nil {
		t.Fatal("nil SetBaseline returned nil error")
	}
	if _, err := st.WasNotified(ctx, stateTestTarget, "x"); err == nil {
		t.Fatal("nil WasNotified returned nil error")
	}
	if err := st.MarkNotified(ctx, stateTestTarget, "x"); err == nil {
		t.Fatal("nil MarkNotified returned nil error")
	}
	if err := st.PruneNotified(ctx, stateTestTarget, time.Now()); err == nil {
		t.Fatal("nil PruneNotified returned nil error")
	}
	if _, err := st.CountNotified(ctx, stateTestTarget); err == nil {
		t.Fatal("nil CountNotified returned nil error")
	}
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

// TestMonitorStateFingerprintStableAndWide — determinism + unchanged width.
func TestMonitorStateFingerprintStableAndWide(t *testing.T) {
	t.Parallel()

	a := handlers.ExportedFindingFingerprint("nuclei:xss", "high", "a.example.com", "https://a.example.com/p")
	b := handlers.ExportedFindingFingerprint("nuclei:xss", "high", "a.example.com", "https://a.example.com/p")
	if a != b {
		t.Fatalf("fingerprint not stable: %q != %q", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("fingerprint width = %d, want 32", len(a))
	}
}

// TestMonitorStateFingerprintDistinguishesHost is the collision the previous
// three-input hash allowed: one template at one severity on two hosts collapsed
// into a single fingerprint, so the second host's finding was suppressed forever.
func TestMonitorStateFingerprintDistinguishesHost(t *testing.T) {
	t.Parallel()

	a := handlers.ExportedFindingFingerprint("nuclei:exposed-panel", "high", "a.example.com", "https://a.example.com/admin")
	b := handlers.ExportedFindingFingerprint("nuclei:exposed-panel", "high", "b.example.com", "https://b.example.com/admin")
	if a == b {
		t.Fatal("same template+severity on DIFFERENT hosts produced one fingerprint — " +
			"the second host's finding would be suppressed forever")
	}
}

// TestMonitorStateFingerprintDistinguishesPath — the same for two endpoints on
// one host.
func TestMonitorStateFingerprintDistinguishesPath(t *testing.T) {
	t.Parallel()

	a := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "https://a.example.com/one")
	b := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "https://a.example.com/two")
	if a == b {
		t.Fatal("two paths on one host produced one fingerprint")
	}

	// Query KEYS are part of the identity; ?id= and ?user= are different findings.
	q1 := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "https://a.example.com/x?id=1")
	q2 := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "https://a.example.com/x?user=1")
	if q1 == q2 {
		t.Fatal("different query keys produced one fingerprint")
	}
	// Query VALUES are NOT: they carry payloads and would defeat suppression
	// entirely (every payload variant would look like a new finding).
	v1 := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "https://a.example.com/x?id=1")
	v2 := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "https://a.example.com/x?id=2%27OR1%3D1")
	if v1 != v2 {
		t.Fatal("query VALUES changed the fingerprint — payload variants would each re-alert")
	}
	// Scheme and fragment are not part of the location either.
	s1 := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "https://a.example.com/x")
	s2 := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "http://a.example.com/x#frag")
	if s1 != s2 {
		t.Fatal("scheme/fragment changed the fingerprint")
	}
}

// TestMonitorStateFingerprintDistinguishesTemplateAndSeverity keeps the two
// original inputs load-bearing.
func TestMonitorStateFingerprintDistinguishesTemplateAndSeverity(t *testing.T) {
	t.Parallel()

	base := handlers.ExportedFindingFingerprint("nuclei:sqli", "critical", "a.example.com", "/x")
	if base == handlers.ExportedFindingFingerprint("nuclei:xss", "critical", "a.example.com", "/x") {
		t.Fatal("template signature is not part of the fingerprint")
	}
	if base == handlers.ExportedFindingFingerprint("nuclei:sqli", "high", "a.example.com", "/x") {
		t.Fatal("severity is not part of the fingerprint")
	}
}

// TestMonitorStateHostFromLocator covers the bare-host shape that made plan
// 15-14's F19 fix inert (url.Parse reports a bare hostname as a PATH, so
// u.Host is empty).
func TestMonitorStateHostFromLocator(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"https://Alpha.Example.com/admin?x=1", "alpha.example.com"},
		{"http://a.example.com:8443/x", "a.example.com"},
		{"alpha.example.com", "alpha.example.com"},
		{"alpha.example.com/admin", "alpha.example.com"},
		{"alpha.example.com:8080/admin", "alpha.example.com"},
		{"/just/a/path", ""},
		{"", ""},
		{"notahost", ""},
	}
	for _, c := range cases {
		if got := handlers.ExportedFindingHostFromLocator(c.in); got != c.want {
			t.Errorf("host(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
