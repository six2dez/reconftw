// scope_capture_test.go — F8: scope capture is the MCP server's authorisation
// boundary, so it must be atomic and it must be the SAME path for every tool.
//
// Two defects, one fix:
//
//   - the report tool captured only when the session did not exist. HTTP
//     sessions are pre-registered by InitializedHandler with a nil scope, so
//     they DO exist, nothing captured, and CheckScope rejected the first
//     ordinary report call for an empty scope (acceptance gate 6, clause 1).
//   - the scanning tools captured with Lookup → Register → SetScope, releasing
//     the lock between steps, so two concurrent first calls could capture two
//     different targets (T-15-15-01).
package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// TestFirstReportCallOnAPreRegisteredSessionSucceeds is acceptance gate 6,
// first clause. The session is registered exactly as InitializedHandler
// registers an HTTP session — existing, with a nil scope — and report is its
// FIRST call.
func TestFirstReportCallOnAPreRegisteredSessionSucceeds(t *testing.T) {
	const (
		target = "firstreport.example"
		sessID = "http-session-uuid"
	)
	dataDir := filepath.Join(t.TempDir(), "data")
	seedStoreForTarget(t, dataDir, target)
	cfgPath := writeTestConfig(t, dataDir, "")
	srv := newTestServer(t, cfgPath, "")

	// Exactly what InitializedHandler does for an HTTP session.
	srv.registry.Register(sessID, "", nil)

	res, _, err := srv.tools.report(context.Background(), sessID, ReportInput{Target: target})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if res.IsError {
		t.Fatalf("the FIRST report call on a pre-registered session was rejected: %s\n"+
			"acceptance gate 6 requires it to succeed", toolText(res))
	}
	if !strings.Contains(toolText(res), `"scan_id"`) {
		t.Errorf("report answered without a scan id: %s", toolText(res))
	}

	// The call captured the scope, so the session is now scoped to that target.
	entry, ok := srv.registry.Lookup(sessID)
	if !ok {
		t.Fatal("the session vanished from the registry")
	}
	if entry.Scope.isEmpty() {
		t.Error("the report call did not capture the session scope")
	}
	if !entry.Scope.Contains(target) {
		t.Errorf("the captured scope does not contain %q", target)
	}
}

// TestPreChangeReportCaptureWouldRejectTheFirstCall pins the failure the fix
// removes, so the regression cannot come back silently. It reproduces the OLD
// capture sequence verbatim against a pre-registered session and asserts
// CheckScope rejects — the exact observed pre-change behaviour:
//
//	mcp: session "http-session-uuid" scope not initialized: out of scope
func TestPreChangeReportCaptureWouldRejectTheFirstCall(t *testing.T) {
	const (
		target = "prechange.example"
		sessID = "http-session-uuid"
	)
	reg := NewSessionRegistry()
	reg.Register(sessID, "", nil) // InitializedHandler

	// The pre-change capture, verbatim: capture ONLY when the session is absent.
	if _, exists := reg.Lookup(sessID); !exists {
		reg.Register(sessID, "", nil)
		reg.SetScope(sessID, NewSessionScope([]string{target}))
	}

	err := CheckScope(sessID, target, reg)
	if err == nil {
		t.Fatal("the pre-change sequence is expected to REJECT the first report call; " +
			"if it now succeeds, this test no longer pins anything")
	}
	if !strings.Contains(err.Error(), "scope not initialized") {
		t.Errorf("pre-change rejection = %v; want a 'scope not initialized' rejection", err)
	}

	// The fix: one atomic capture, and the same call now passes.
	captured, capErr := reg.CaptureScopeIfUnset(sessID, target)
	if capErr != nil {
		t.Fatalf("CaptureScopeIfUnset: %v", capErr)
	}
	if !captured {
		t.Error("CaptureScopeIfUnset reported no capture on a nil-scope session")
	}
	if err := CheckScope(sessID, target, reg); err != nil {
		t.Errorf("after capture the call must pass, got: %v", err)
	}
}

// TestCaptureScopeIfUnsetIsAtomicUnderConcurrency launches 50 goroutines with 50
// DIFFERENT targets against one session. Exactly one may capture, and the final
// scope must admit exactly that one target — anything else is an authorisation
// bypass: a client could scan a target the session was never scoped to.
//
// Run with -race -count=5.
func TestCaptureScopeIfUnsetIsAtomicUnderConcurrency(t *testing.T) {
	const (
		n      = 50
		sessID = "concurrent-session"
	)
	reg := NewSessionRegistry()
	reg.Register(sessID, "", nil) // the HTTP shape: exists, nil scope

	targets := make([]string, n)
	for i := range targets {
		targets[i] = fmt.Sprintf("t%02d.example", i)
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		captures []string
		errs     []error
	)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			<-start
			captured, err := reg.CaptureScopeIfUnset(sessID, target)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if captured {
				captures = append(captures, target)
			}
		}(targets[i])
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Errorf("unexpected error: %v", err)
	}
	if len(captures) != 1 {
		t.Fatalf("%d goroutines reported a capture; exactly 1 may. Two concurrent first calls "+
			"capturing different targets is an authorisation bypass (T-15-15-01)", len(captures))
	}

	entry, ok := reg.Lookup(sessID)
	if !ok {
		t.Fatal("session missing after concurrent capture")
	}
	inScope := make([]string, 0, 2)
	for _, target := range targets {
		if entry.Scope.Contains(target) {
			inScope = append(inScope, target)
		}
	}
	if len(inScope) != 1 {
		t.Fatalf("the final scope admits %d targets (%v); it must admit exactly the one that "+
			"was captured", len(inScope), inScope)
	}
	if inScope[0] != captures[0] {
		t.Errorf("the scope admits %q but %q reported the capture", inScope[0], captures[0])
	}
}

// TestCaptureScopeIfUnsetLeavesAnExistingScopeAlone — the second and every later
// call must be a no-op, or a client could re-scope a session mid-stream.
func TestCaptureScopeIfUnsetLeavesAnExistingScopeAlone(t *testing.T) {
	const sessID = "scoped-session"
	reg := NewSessionRegistry()
	reg.Register(sessID, "", NewSessionScope([]string{"first.example"}))

	captured, err := reg.CaptureScopeIfUnset(sessID, "second.example")
	if err != nil {
		t.Fatalf("CaptureScopeIfUnset: %v", err)
	}
	if captured {
		t.Error("captured = true on a session that already had a scope")
	}

	entry, _ := reg.Lookup(sessID)
	if !entry.Scope.Contains("first.example") {
		t.Error("the original scope was lost")
	}
	if entry.Scope.Contains("second.example") {
		t.Error("the second call widened the session scope — D-06 forbids scope widening " +
			"from tool arguments (T-08-02-03)")
	}
}

// TestCaptureScopeIfUnsetRegistersAnUnknownSession covers the in-memory
// transport shape, where the session ID is "" and nothing pre-registered it.
func TestCaptureScopeIfUnsetRegistersAnUnknownSession(t *testing.T) {
	reg := NewSessionRegistry()
	captured, err := reg.CaptureScopeIfUnset("", "inmemory.example")
	if err != nil {
		t.Fatalf("CaptureScopeIfUnset: %v", err)
	}
	if !captured {
		t.Error("the first call on an unregistered session must capture")
	}
	if err := CheckScope("", "inmemory.example", reg); err != nil {
		t.Errorf("CheckScope after capture: %v", err)
	}
}

// TestCaptureScopeIfUnsetRejectsAnEmptyTarget — capturing "" would install a
// fail-closed scope that rejects every target including the one that set it.
func TestCaptureScopeIfUnsetRejectsAnEmptyTarget(t *testing.T) {
	reg := NewSessionRegistry()
	for _, target := range []string{"", "   "} {
		captured, err := reg.CaptureScopeIfUnset("sess", target)
		if err == nil {
			t.Errorf("CaptureScopeIfUnset(%q) returned no error", target)
		}
		if captured {
			t.Errorf("CaptureScopeIfUnset(%q) reported a capture", target)
		}
	}
	if _, ok := reg.Lookup("sess"); ok {
		if entry, _ := reg.Lookup("sess"); !entry.Scope.isEmpty() {
			t.Error("an empty target installed a scope")
		}
	}
}

// TestScanToolAndReportToolShareOneCapturePath asserts the two entry points
// agree: whichever runs first captures, and the other is then bound by it.
func TestScanToolAndReportToolShareOneCapturePath(t *testing.T) {
	const (
		target = "shared.example"
		other  = "elsewhere.example"
		sessID = "shared-session"
	)
	dataDir := filepath.Join(t.TempDir(), "data")
	cfgPath := writeTestConfig(t, dataDir, "")
	srv := newTestServer(t, cfgPath, "")
	srv.registry.Register(sessID, "", nil)

	// A scan captures first…
	noop := func(ctx context.Context, opts handlers.RunOptions) error { return nil }
	res, _, err := srv.tools.launch(sessID, target, true, "", noop)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if res.IsError {
		t.Fatalf("the scan tool was rejected: %s", toolText(res))
	}

	// …so a report for a DIFFERENT target on the same session is refused.
	rep, _, err := srv.tools.report(context.Background(), sessID, ReportInput{Target: other})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !rep.IsError {
		t.Fatalf("report for an out-of-scope target succeeded: %s", toolText(rep))
	}
	if !strings.Contains(toolText(rep), "out_of_scope") {
		t.Errorf("report rejection = %s; want an out_of_scope rejection", toolText(rep))
	}
}
