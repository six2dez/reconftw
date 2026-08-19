// lifecycle_test.go — F9: the MCP server must own the lifetime of what it starts.
//
// Four defects, all of which looked fine from the outside:
//
//   - scanCtx derived from context.Background() and nothing cancelled it at
//     shutdown, so scans outlived the server that started them and kept
//     spawning external tool processes (T-15-15-06).
//   - status errors went to the client verbatim behind a comment claiming the
//     server-wide redactor scrubbed them; RegisterTools had discarded the
//     redactor, so nothing did (T-15-15-02).
//   - there was no way to cancel one scan (T-15-15-03 covers doing it safely).
//   - the registry grew for as long as the server ran (T-15-15-05).
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	corelog "github.com/six2dez/reconftw/internal/core/log"

	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// setTerminalAtForTest backdates an entry's terminal timestamp so eviction
// order is deterministic without sleeping.
func (r *SessionRegistry) setTerminalAtForTest(runID string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[runID]; ok {
		entry.TerminalAt = at
	}
}

// blockingRun returns a run function that reports when it started and then
// blocks until its context is cancelled. It is the stand-in for a real scan,
// which is exactly a long-running context-respecting operation.
func blockingRun(started chan<- struct{}, cancelled chan<- error) func(context.Context, handlers.RunOptions) error {
	return func(ctx context.Context, _ handlers.RunOptions) error {
		close(started)
		<-ctx.Done()
		cancelled <- ctx.Err()
		return ctx.Err()
	}
}

// awaitCancel waits for a scan to report its cancellation, failing on timeout
// rather than blocking the suite forever.
func awaitCancel(t *testing.T, cancelled <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-cancelled:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: the scan was never cancelled", what)
		return nil
	}
}

func awaitStart(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the scan never started")
	}
}

// newLifecycleServer builds a server whose scan root is a context the test can
// cancel, mirroring the entrypoint (cobra's cmd.Context()).
func newLifecycleServer(t *testing.T) (*MCPServer, context.CancelFunc) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	cfgPath := writeTestConfig(t, dataDir, "")
	cfg := mustLoadConfig(t, cfgPath)

	ctx, cancel := context.WithCancel(context.Background())
	srv := NewMCPServer(ctx, cfg, cfgPath, "", testSchedFactory(), &corelog.Redactor{}, "test")
	t.Cleanup(srv.Cancel)
	t.Cleanup(cancel)
	return srv, cancel
}

// TestShutdownCancelsInFlightScans is acceptance gate 6, third clause: the scan
// root is the entrypoint's context, so cancelling it (SIGINT) stops the scans.
func TestShutdownCancelsInFlightScans(t *testing.T) {
	srv, cancelRoot := newLifecycleServer(t)

	started := make(chan struct{})
	cancelled := make(chan error, 1)
	res, _, err := srv.tools.launch("sess-shutdown", "shutdown.example", true, "", blockingRun(started, cancelled))
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if res.IsError {
		t.Fatalf("launch returned a tool error: %s", toolText(res))
	}
	awaitStart(t, started)

	cancelRoot()

	if err := awaitCancel(t, cancelled, "root cancellation"); !errors.Is(err, context.Canceled) {
		t.Errorf("scan context error = %v; want context.Canceled", err)
	}
}

// TestStartLinksItsContextToInFlightScans covers the other half of the shutdown
// contract: a server constructed with one context and STARTED with another must
// react to the one Start was given, because that is the transport's lifetime.
//
// linkShutdown is what Start calls; asserting it directly avoids standing up a
// transport that would read os.Stdin or bind a port inside the test suite.
func TestStartLinksItsContextToInFlightScans(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cfgPath := writeTestConfig(t, dataDir, "")
	cfg := mustLoadConfig(t, cfgPath)

	// Constructed with a context the test never cancels.
	srv := NewMCPServer(context.Background(), cfg, cfgPath, "", testSchedFactory(), &corelog.Redactor{}, "test")
	t.Cleanup(srv.Cancel)

	started := make(chan struct{})
	cancelled := make(chan error, 1)
	if _, _, err := srv.tools.launch("sess-start", "start.example", true, "", blockingRun(started, cancelled)); err != nil {
		t.Fatalf("launch: %v", err)
	}
	awaitStart(t, started)

	transportCtx, shutdown := context.WithCancel(context.Background())
	stop := srv.linkShutdown(transportCtx)
	defer stop()

	shutdown() // the transport goes away

	if err := awaitCancel(t, cancelled, "transport shutdown"); !errors.Is(err, context.Canceled) {
		t.Errorf("scan context error = %v; want context.Canceled", err)
	}
}

// TestCancelScanStopsTheOwningSessionsRun — the happy path.
func TestCancelScanStopsTheOwningSessionsRun(t *testing.T) {
	srv, _ := newLifecycleServer(t)

	started := make(chan struct{})
	cancelled := make(chan error, 1)
	res, _, err := srv.tools.launch("sess-owner", "cancel.example", true, "", blockingRun(started, cancelled))
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	runID := runIDFromLaunch(t, res)
	awaitStart(t, started)

	got, _, err := srv.tools.cancelScan("sess-owner", CancelScanInput{RunID: runID})
	if err != nil {
		t.Fatalf("cancel_scan: %v", err)
	}
	if got.IsError {
		t.Fatalf("cancel_scan on an owned run was refused: %s", toolText(got))
	}
	if err := awaitCancel(t, cancelled, "cancel_scan"); !errors.Is(err, context.Canceled) {
		t.Errorf("scan context error = %v; want context.Canceled", err)
	}

	// The registry records the operator's intent, not a failure.
	deadline := time.Now().Add(5 * time.Second)
	for {
		entry, ok := srv.registry.Lookup(runID)
		if ok && entry.Status == SessionStatusCancelled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run status = %q; want %q", entry.Status, SessionStatusCancelled)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCancelScanRefusesOtherSessionsAndDoesNotLeakRunIDs is T-15-15-03: the
// refusal for a run owned by someone else must be byte-identical to the refusal
// for a run that does not exist, or cancel_scan becomes a run-id oracle.
func TestCancelScanRefusesOtherSessionsAndDoesNotLeakRunIDs(t *testing.T) {
	srv, _ := newLifecycleServer(t)

	started := make(chan struct{})
	cancelled := make(chan error, 1)
	res, _, err := srv.tools.launch("sess-a", "owned.example", true, "", blockingRun(started, cancelled))
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	runID := runIDFromLaunch(t, res)
	awaitStart(t, started)

	foreign, _, err := srv.tools.cancelScan("sess-b", CancelScanInput{RunID: runID})
	if err != nil {
		t.Fatalf("cancel_scan (foreign): %v", err)
	}
	if !foreign.IsError {
		t.Fatal("a session cancelled a run it did not start")
	}

	unknown, _, err := srv.tools.cancelScan("sess-b", CancelScanInput{RunID: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("cancel_scan (unknown): %v", err)
	}
	if !unknown.IsError {
		t.Fatal("cancel_scan accepted an unknown run id")
	}

	if toolText(foreign) != toolText(unknown) {
		t.Errorf("the refusals differ, so cancel_scan reveals which run ids exist:\n"+
			" not-yours: %s\n unknown:   %s", toolText(foreign), toolText(unknown))
	}

	// The victim's run is untouched: still running, still cancellable by its owner.
	entry, ok := srv.registry.Lookup(runID)
	if !ok || entry.Status != SessionStatusRunning {
		t.Errorf("the refused call changed the run's state (status=%q)", entry.Status)
	}
	srv.Cancel()
	if err := awaitCancel(t, cancelled, "cleanup"); !errors.Is(err, context.Canceled) {
		t.Errorf("cleanup cancellation = %v; want context.Canceled", err)
	}
}

// TestCancelScanCannotDestroyASessionScopeEntry: a session-scope entry lives in
// the same map as the runs, keyed by the session id, and carries no owner. If
// cancel_scan accepted it, naming another session's id would mark that entry
// cancelled and hand it to the sweeper — quietly destroying a live session's
// captured scope, which is its authorisation state.
func TestCancelScanCannotDestroyASessionScopeEntry(t *testing.T) {
	srv, _ := newLifecycleServer(t)

	const victim = "victim-session"
	if _, err := srv.registry.CaptureScopeIfUnset(victim, "victim.example"); err != nil {
		t.Fatalf("CaptureScopeIfUnset: %v", err)
	}

	res, _, err := srv.tools.cancelScan("attacker-session", CancelScanInput{RunID: victim})
	if err != nil {
		t.Fatalf("cancel_scan: %v", err)
	}
	if !res.IsError {
		t.Fatal("cancel_scan accepted a SESSION id as a run id")
	}

	entry, ok := srv.registry.Lookup(victim)
	if !ok {
		t.Fatal("the victim session entry was removed")
	}
	if entry.Status == SessionStatusCancelled {
		t.Error("a session-scope entry was marked cancelled and is now sweeper-eligible")
	}
	if !entry.Scope.Contains("victim.example") {
		t.Error("the victim session lost its captured scope")
	}
}

// TestStatusResourceRedactsSecretsInErrors is T-15-15-02. A pipeline error can
// embed an API key; the status resource hands it to the client.
func TestStatusResourceRedactsSecretsInErrors(t *testing.T) {
	const secret = "s3cr3t-api-key-value-31-chars--"

	rdct := &corelog.Redactor{}
	rdct.Register(secret)

	reg := NewSessionRegistry()
	reg.RegisterRun("run-secret", "sess")
	reg.MarkFailed("run-secret", fmt.Errorf("nuclei: exit 1: request to https://api.example/?key=%s failed", secret))

	entry, ok := reg.Lookup("run-secret")
	if !ok {
		t.Fatal("run missing")
	}
	body, err := statusPayload(entry, rdct)
	if err != nil {
		t.Fatalf("statusPayload: %v", err)
	}
	if strings.Contains(string(body), secret) {
		t.Errorf("the status payload sent to the client contains a registered secret: %s", body)
	}
	if !strings.Contains(string(body), "***") {
		t.Errorf("the secret was not replaced by the redaction marker: %s", body)
	}

	// A nil redactor must not panic — several call sites tolerate one.
	if _, err := statusPayload(entry, nil); err != nil {
		t.Errorf("statusPayload with a nil redactor: %v", err)
	}
}

// TestRegistryReclaimsTerminalEntries is T-15-15-05. Time is a parameter, not a
// sleep: the production TTL is an hour.
func TestRegistryReclaimsTerminalEntries(t *testing.T) {
	t.Run("ttl", func(t *testing.T) {
		reg := NewSessionRegistry()
		reg.Register("live-session", "", NewSessionScope([]string{"keep.example"}))
		reg.RegisterRun("still-running", "live-session")
		for i := range 5 {
			id := fmt.Sprintf("done-%d", i)
			reg.RegisterRun(id, "live-session")
			reg.MarkComplete(id)
		}
		if got := reg.Len(); got != 7 {
			t.Fatalf("registry holds %d entries before the sweep, want 7", got)
		}

		removed := reg.SweepTerminal(time.Now().Add(time.Minute)) // everything terminal is now "old"
		if removed != 5 {
			t.Errorf("sweep removed %d entries, want 5", removed)
		}
		if got := reg.Len(); got != 2 {
			t.Errorf("registry holds %d entries after the sweep, want 2 "+
				"(the live session and the running scan)", got)
		}
		if _, ok := reg.Lookup("live-session"); !ok {
			t.Error("the sweeper reclaimed a live session's scope — that silently revokes its authorisation")
		}
		if _, ok := reg.Lookup("still-running"); !ok {
			t.Error("the sweeper reclaimed a RUNNING scan")
		}
	})

	t.Run("size cap", func(t *testing.T) {
		reg := NewSessionRegistry()
		base := time.Now()
		for i := range maxTerminalEntries + 10 {
			id := fmt.Sprintf("burst-%04d", i)
			reg.RegisterRun(id, "sess")
			reg.MarkComplete(id)
			// Make the ages deterministic so oldest-first eviction is checkable.
			reg.setTerminalAtForTest(id, base.Add(time.Duration(i)*time.Second))
		}

		// A cutoff before every entry: nothing expires, so only the cap can act.
		reg.SweepTerminal(base.Add(-time.Hour))
		if got := reg.Len(); got != maxTerminalEntries {
			t.Fatalf("registry holds %d terminal entries; the cap is %d", got, maxTerminalEntries)
		}
		if _, ok := reg.Lookup("burst-0000"); ok {
			t.Error("the oldest terminal entry survived the cap; eviction is not oldest-first")
		}
		if _, ok := reg.Lookup(fmt.Sprintf("burst-%04d", maxTerminalEntries+9)); !ok {
			t.Error("the newest terminal entry was evicted")
		}
	})
}

// TestSweeperGoroutineExitsOnCancel — the reclamation goroutine must not
// outlive the server it belongs to. Without this the fix for one leak
// introduces another.
func TestSweeperGoroutineExitsOnCancel(t *testing.T) {
	srv, _ := newLifecycleServer(t)

	select {
	case <-srv.sweeperDone:
		t.Fatal("the sweeper exited before the server was cancelled")
	default:
	}

	srv.Cancel()

	select {
	case <-srv.sweeperDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweeper goroutine did not exit after Cancel()")
	}
}

// TestFindingsResourceIsOwnershipGated re-asserts the guard the audit flagged:
// a findings resource must not be served to a session that did not start the
// run, however it learned the run id. This was ALREADY enforced by OwnedBy; the
// test pins it so the lifecycle work cannot regress it.
func TestFindingsResourceIsOwnershipGated(t *testing.T) {
	reg := NewSessionRegistry()
	reg.RegisterRun("run-owned", "sess-a")
	reg.SetWorkDir("run-owned", t.TempDir())

	if !reg.OwnedBy("run-owned", "sess-a") {
		t.Error("the owning session cannot read its own findings")
	}
	if reg.OwnedBy("run-owned", "sess-b") {
		t.Error("a foreign session can read another run's findings: registering a WorkDir " +
			"would expose the target's whole findings history")
	}
	if reg.OwnedBy("no-such-run", "sess-a") {
		t.Error("an unknown run id was authorised")
	}
}

// runIDFromLaunch pulls the run_id out of a scanning tool's response.
func runIDFromLaunch(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var payload struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(toolText(res)), &payload); err != nil {
		t.Fatalf("decode launch response %q: %v", toolText(res), err)
	}
	if payload.RunID == "" {
		t.Fatalf("launch response carries no run_id: %s", toolText(res))
	}
	return payload.RunID
}
