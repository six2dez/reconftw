// notify_test.go — in-scan notification seam tests (INTEG-02).
//
// White-box (package handlers) so the tests can call the unexported
// notifyScanStart/notifyScanComplete/notifyScanFailure helpers directly and
// construct an AppBoot with a seeded workspace + recording spy sink — no live
// HTTP. Covers: EventScanStart routing, config Events oneof, enabled/soft
// gating, event routing, critical read-from-findings.jsonl + de-dup, best-effort
// (an erroring sink never aborts), and monitor SuppressScanNotify suppression.
package handlers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/notifier"
)

// recordingNotifier is a spy sink that records every dispatched message and can
// be configured to return an error from Notify (best-effort test).
type recordingNotifier struct {
	mu   sync.Mutex
	msgs []string
	err  error
}

func (r *recordingNotifier) Notify(_ context.Context, _ notifier.Level, msg string, _ ...any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, msg)
	return r.err
}

func (r *recordingNotifier) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}

func (r *recordingNotifier) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.msgs))
	copy(out, r.msgs)
	return out
}

// notifyCfg builds a Defaults() config with notifications toggled. When events
// is non-empty it overrides the default routed event set.
func notifyCfg(enabled, soft bool, events ...string) *config.Config {
	cfg := config.Defaults()
	cfg.Notifications.Enabled = enabled
	cfg.Notifications.SoftEnabled = soft
	if len(events) > 0 {
		cfg.Notifications.Events = events
	}
	return cfg
}

// newNotifyBoot wires a spy notifier + config + workDir into an AppBoot as the
// real BootReconApp would (minus the pipeline).
func newNotifyBoot(spy notifier.Notifier, cfg *config.Config, workDir string) AppBoot {
	app := &appctx.AppContext{
		Notify: spy,
		Cfg:    cfg,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return AppBoot{App: app, WorkDir: workDir, Cfg: cfg}
}

// seedFindings writes <workDir>/artefacts/findings.jsonl (mirrors the ingest
// test seeding pattern) so notifyCriticalFindings reads via the real path.
func seedFindings(t *testing.T, workDir string, lines ...string) {
	t.Helper()
	dir := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "findings.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatalf("write findings.jsonl: %v", err)
	}
}

// TestEventScanStartRouting proves the new EventScanStart kind routes through
// NewEventFilter when listed and is dropped when not.
func TestEventScanStartRouting(t *testing.T) {
	t.Parallel()

	spy := &recordingNotifier{}
	ef := notifier.NewEventFilter(spy, []string{string(notifier.EventScanStart)})
	if err := ef.NotifyEvent(context.Background(), notifier.EventScanStart, notifier.LevelInfo, "start"); err != nil {
		t.Fatalf("NotifyEvent: %v", err)
	}
	if spy.count() != 1 {
		t.Fatalf("EventScanStart routed: want 1 dispatch, got %d", spy.count())
	}

	spy2 := &recordingNotifier{}
	ef2 := notifier.NewEventFilter(spy2, []string{string(notifier.EventScanComplete)})
	_ = ef2.NotifyEvent(context.Background(), notifier.EventScanStart, notifier.LevelInfo, "start")
	if spy2.count() != 0 {
		t.Fatalf("unlisted EventScanStart: want 0 dispatch, got %d", spy2.count())
	}
}

// TestConfigEventsOneOfAllowsScanStart proves the config oneof accepts
// on-scan-start and still rejects an unknown event string.
func TestConfigEventsOneOfAllowsScanStart(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Notifications.Events = []string{"on-scan-start", "on-critical-finding", "on-scan-complete", "on-failure"}
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("valid Events including on-scan-start rejected: %v", err)
	}

	cfg.Notifications.Events = []string{"on-bogus-event"}
	if err := config.Validate(cfg); err == nil {
		t.Fatal("unknown event string should fail validation, got nil")
	}
}

// TestNotifyScanStartGating proves scan-start is a soft event: it fires only
// when Enabled AND SoftEnabled.
func TestNotifyScanStartGating(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	opts := RunOptions{Target: "example.com"}

	spy := &recordingNotifier{}
	notifyScanStart(context.Background(), newNotifyBoot(spy, notifyCfg(true, true), work), opts, "subs")
	if spy.count() != 1 {
		t.Fatalf("enabled+soft: want 1 scan-start, got %d", spy.count())
	}

	spySoftOff := &recordingNotifier{}
	notifyScanStart(context.Background(), newNotifyBoot(spySoftOff, notifyCfg(true, false), work), opts, "subs")
	if spySoftOff.count() != 0 {
		t.Fatalf("soft off: want 0 scan-start, got %d", spySoftOff.count())
	}

	spyDisabled := &recordingNotifier{}
	notifyScanStart(context.Background(), newNotifyBoot(spyDisabled, notifyCfg(false, true), work), opts, "subs")
	if spyDisabled.count() != 0 {
		t.Fatalf("disabled: want 0 scan-start, got %d", spyDisabled.count())
	}
}

// TestNotifyScanCompleteCountsAndCriticals proves the shared finalization seam
// fires one on-scan-complete (with ingest counts) plus one on-critical-finding
// for the high finding — and NOT for the info finding.
func TestNotifyScanCompleteCountsAndCriticals(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	seedFindings(t, work,
		`{"type":"http","template_id":"exposed-panel","severity":"high","matched_at":"https://api.example.com/admin"}`,
		`{"severity":"info","class":"osint","source":"github_leaks","category":"leaked-secret"}`,
	)
	spy := &recordingNotifier{}
	boot := newNotifyBoot(spy, notifyCfg(true, true), work)
	notifyScanComplete(context.Background(), boot, RunOptions{Target: "example.com"}, "web",
		ingest.Result{Findings: 2, Hosts: 3, URLs: 5})

	msgs := spy.snapshot()
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages (scan-complete + 1 critical), got %d: %v", len(msgs), msgs)
	}
	var completeSeen, criticalSeen bool
	for _, m := range msgs {
		if strings.Contains(m, "scan complete") &&
			strings.Contains(m, "findings=2") && strings.Contains(m, "hosts=3") && strings.Contains(m, "urls=5") {
			completeSeen = true
		}
		if strings.Contains(m, "critical") && strings.Contains(m, "exposed-panel") {
			criticalSeen = true
		}
	}
	if !completeSeen {
		t.Errorf("scan-complete with counts not found in %v", msgs)
	}
	if !criticalSeen {
		t.Errorf("on-critical-finding for the high finding not found in %v", msgs)
	}
}

// TestNotifyScanCompleteDedupCriticals proves a repeated identical critical
// (same title+severity) is de-duped within a single call.
func TestNotifyScanCompleteDedupCriticals(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	seedFindings(t, work,
		`{"template_id":"exposed-panel","severity":"high"}`,
		`{"template_id":"exposed-panel","severity":"high"}`,
	)
	spy := &recordingNotifier{}
	// soft off → only criticals count.
	boot := newNotifyBoot(spy, notifyCfg(true, false), work)
	notifyScanComplete(context.Background(), boot, RunOptions{Target: "example.com"}, "web", ingest.Result{})
	if spy.count() != 1 {
		t.Fatalf("dedup: want 1 critical for repeated finding, got %d: %v", spy.count(), spy.snapshot())
	}
}

// TestNotifyBestEffortNeverAborts proves an always-erroring sink never causes a
// helper to panic or propagate — the scan-simulating caller proceeds (T-12-04-02).
func TestNotifyBestEffortNeverAborts(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	seedFindings(t, work, `{"template_id":"exposed-panel","severity":"critical"}`)
	spy := &recordingNotifier{err: errors.New("webhook 500")}
	boot := newNotifyBoot(spy, notifyCfg(true, true), work)
	opts := RunOptions{Target: "example.com"}

	// None of these return an error (void) and none must panic despite the sink error.
	notifyScanStart(context.Background(), boot, opts, "web")
	notifyScanComplete(context.Background(), boot, opts, "web", ingest.Result{Findings: 1})
	notifyScanFailure(context.Background(), boot, opts, "web", errors.New("pipeline boom"))

	// Dispatch was attempted (proves the seam ran) but every error was swallowed;
	// reaching this assertion proves the caller proceeded past all three helpers.
	if spy.count() == 0 {
		t.Fatal("expected dispatch attempts despite erroring sink")
	}
}

// TestNotifyScanFailureRouted proves on-failure fires when routed + enabled
// (not gated by soft), and does nothing for a nil cause.
func TestNotifyScanFailureRouted(t *testing.T) {
	t.Parallel()

	spy := &recordingNotifier{}
	// soft off — failure is not a soft event, so it must still fire.
	boot := newNotifyBoot(spy, notifyCfg(true, false), t.TempDir())
	notifyScanFailure(context.Background(), boot, RunOptions{Target: "example.com"}, "vulns", errors.New("boom"))
	if spy.count() != 1 {
		t.Fatalf("want 1 on-failure, got %d", spy.count())
	}
	if !strings.Contains(spy.snapshot()[0], "scan failed") {
		t.Errorf("failure message unexpected: %q", spy.snapshot()[0])
	}

	spyNil := &recordingNotifier{}
	notifyScanFailure(context.Background(), newNotifyBoot(spyNil, notifyCfg(true, false), t.TempDir()),
		RunOptions{Target: "x"}, "vulns", nil)
	if spyNil.count() != 0 {
		t.Fatalf("nil cause: want 0 dispatch, got %d", spyNil.count())
	}
}

// TestNotifyScanCompleteSoftOffStillCriticals proves that with SoftEnabled=false
// no on-scan-complete fires but on-critical-finding STILL does.
func TestNotifyScanCompleteSoftOffStillCriticals(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	seedFindings(t, work, `{"vuln_class":"sqli","severity":"critical","engine":"dalfox"}`)
	spy := &recordingNotifier{}
	boot := newNotifyBoot(spy, notifyCfg(true, false), work) // soft OFF
	notifyScanComplete(context.Background(), boot, RunOptions{Target: "example.com"}, "vulns",
		ingest.Result{Findings: 1})

	msgs := spy.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("soft off: want exactly 1 message (critical only), got %d: %v", len(msgs), msgs)
	}
	if strings.Contains(msgs[0], "scan complete") {
		t.Errorf("scan-complete soft event should be suppressed when soft off: %q", msgs[0])
	}
	if !strings.Contains(msgs[0], "sqli") {
		t.Errorf("expected critical for sqli, got %q", msgs[0])
	}
}

// TestNotifyRoutingGatesCriticals proves EventFilter routing gates criticals:
// when on-critical-finding is not in Events, a critical finding does NOT dispatch.
func TestNotifyRoutingGatesCriticals(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	seedFindings(t, work, `{"template_id":"exposed-panel","severity":"critical"}`)
	spy := &recordingNotifier{}
	cfg := notifyCfg(true, false, "on-scan-complete", "on-failure", "on-scan-start") // no on-critical-finding
	boot := newNotifyBoot(spy, cfg, work)
	notifyScanComplete(context.Background(), boot, RunOptions{Target: "example.com"}, "web", ingest.Result{})
	if spy.count() != 0 {
		t.Fatalf("routing without on-critical-finding: want 0 dispatch, got %d: %v", spy.count(), spy.snapshot())
	}
}

// TestNotifySuppressScanNotify proves the monitor's SuppressScanNotify flag
// silences all three helpers (no per-cycle double-notify).
func TestNotifySuppressScanNotify(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	seedFindings(t, work, `{"template_id":"exposed-panel","severity":"critical"}`)
	spy := &recordingNotifier{}
	boot := newNotifyBoot(spy, notifyCfg(true, true), work)
	opts := RunOptions{Target: "example.com", SuppressScanNotify: true}

	notifyScanStart(context.Background(), boot, opts, "recon")
	notifyScanComplete(context.Background(), boot, opts, "recon", ingest.Result{Findings: 1})
	notifyScanFailure(context.Background(), boot, opts, "recon", errors.New("boom"))
	if spy.count() != 0 {
		t.Fatalf("SuppressScanNotify: want 0 dispatch across all helpers, got %d: %v", spy.count(), spy.snapshot())
	}
}

// TestNotifyDisabledEmitsNothing proves notifications.enabled=false suppresses
// every in-scan event.
func TestNotifyDisabledEmitsNothing(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	seedFindings(t, work, `{"template_id":"exposed-panel","severity":"critical"}`)
	spy := &recordingNotifier{}
	boot := newNotifyBoot(spy, notifyCfg(false, true), work) // disabled
	opts := RunOptions{Target: "example.com"}

	notifyScanStart(context.Background(), boot, opts, "all")
	notifyScanComplete(context.Background(), boot, opts, "all", ingest.Result{Findings: 1})
	notifyScanFailure(context.Background(), boot, opts, "all", errors.New("boom"))
	if spy.count() != 0 {
		t.Fatalf("disabled: want 0 dispatch, got %d: %v", spy.count(), spy.snapshot())
	}
}

// TestNotifyNilSafety proves the helpers no-op (no panic) when the app or its
// notifier is unwired.
func TestNotifyNilSafety(t *testing.T) {
	t.Parallel()
	opts := RunOptions{Target: "x"}

	// nil App entirely.
	notifyScanComplete(context.Background(), AppBoot{}, opts, "web", ingest.Result{})

	// App present but Notify nil.
	boot := AppBoot{App: &appctx.AppContext{Cfg: config.Defaults()}}
	notifyScanStart(context.Background(), boot, opts, "web")
	notifyScanFailure(context.Background(), boot, opts, "web", errors.New("x"))
	// Reaching here without a panic is the assertion.
}
