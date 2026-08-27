// ssrf_lifecycle_test.go — THE ADJUDICATION OF vulns/ssrf.go, decided by running
// something rather than by reading something (18-05 Task 3).
//
// THE QUESTION. ssrf.go's declared bypass reason is `process_lifecycle`, not
// stdin: it assigns no standard input anywhere. It runs interactsh-client as a
// LONG-LIVED out-of-band callback server — SysProcAttr{Setpgid:true}, a
// persistent stdout pipe read line by line for the whole task, and a
// process-group SIGTERM on cleanup. 18-03 established that this is the one
// manifest reason 18-01 did NOT make obsolete, because ExecOptions has no
// caller-managed background-process mode.
//
// But "no background-process MODE" is not the same as "cannot serve that
// lifecycle". backend.Runner.StreamOpts already returns a channel that outlives
// the call, and LocalBackend.StreamOpts already sets the process-group attribute,
// SIGTERMs the group on ctx cancellation, and escalates to a group SIGKILL
// KillGrace+500ms later specifically to reap GRANDCHILDREN the stdlib does not.
// Whether those add up to what ssrf.go needs is EMPIRICAL, and this file answers
// it by dispatching a real process and cancelling it.
//
// THE FIXTURE SPAWNS A GRANDCHILD ON PURPOSE. A test that only checks the direct
// child would pass on the stdlib's own WaitDelay/SIGKILL and prove nothing about
// the kill-TREE property the process-group code exists for. The grandchild
// records that it is alive, then — if it is ever allowed to finish sleeping —
// writes a SURVIVED marker. The marker's absence is what "the tree died" means
// here, and it is checked alongside a direct kill(pid, 0) liveness probe.
package vulns

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

// writeInteractshFixture writes a script that behaves like interactsh-client:
// it prints a registered callback domain on stdout, forks a background child,
// and then sleeps for the rest of the task's life.
//
//   - <dir>/domain.txt  — written by the PARENT once it has "registered"
//   - <dir>/grandchild.pid — the background child's pid
//   - <dir>/SURVIVED   — written by the grandchild ONLY if it outlives the kill
func writeInteractshFixture(t *testing.T, dir, domain string) string {
	t.Helper()
	script := filepath.Join(dir, "fake-interactsh-client")
	body := "#!/bin/sh\n" +
		"PATH=/bin:/usr/bin; export PATH\n" +
		// The grandchild: record its pid, IGNORE SIGTERM, sleep well past the
		// kill grace, then leave a marker.
		//
		// `trap '' TERM` IS LOAD-BEARING AND WAS ADDED BY MUTATION 5. Without it
		// this fixture proved nothing about the kill-TREE: LocalBackend's
		// cmd.Cancel already sends SIGTERM to the whole process group, a plain
		// `sleep` dies on SIGTERM, and the test passed with the supplementary
		// group-SIGKILL escalation goroutine DISABLED — a green light for the
		// exact code path it exists to pin. A child that survives SIGTERM is also
		// the realistic case: it is precisely the child that needs escalating on.
		"( trap '' TERM\n" +
		"  echo $$ > '" + filepath.Join(dir, "grandchild.pid") + "'\n" +
		"  sleep 30\n" +
		"  echo alive > '" + filepath.Join(dir, "SURVIVED") + "' ) &\n" +
		// The parent: emit the callback domain the way interactsh-client does,
		// then hold the session open.
		"printf '%s\\n' '" + domain + "'\n" +
		"echo '" + domain + "' > '" + filepath.Join(dir, "domain.txt") + "'\n" +
		"sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write fixture: %v", err)
	}
	return script
}

// pidAlive reports whether pid exists. signal 0 performs error checking only.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// TestInteractshLifecycleThroughStreamOpts is the adjudication.
//
// THREE LEGS, and the verdict needs all three:
//
//	(a) the registered callback domain reaches the consumer on the event channel
//	    — PRESENCE first, before anything is asserted about absence;
//	(b) cancelling the context terminates the process AND the grandchild it
//	    spawned, within the kill-grace window;
//	(c) the channel closes, so a consumer ranging over it is not left hanging.
func TestInteractshLifecycleThroughStreamOpts(t *testing.T) {
	dir := t.TempDir()
	const domain = "abcdef123456.oast.fun"
	script := writeInteractshFixture(t, dir, domain)

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "interactsh-client", Path: script})
	// KillGrace kept short so the whole test stays well inside `go test`'s budget.
	runner := backend.NewRunner(&backend.LocalBackend{KillGrace: 500 * time.Millisecond}, reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	events, err := runner.StreamOpts(ctx, "interactsh-client", nil, backend.ExecOptions{})
	if err != nil {
		cancel()
		t.Fatalf("StreamOpts: %v", err)
	}

	// (a) PRESENCE: the callback domain arrives on the channel while the process
	//     is still running — the persistent-stdout-pipe property ssrf.go needs.
	var gotDomain string
	domainDeadline := time.After(10 * time.Second)
readLoop:
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				break readLoop
			}
			if strings.Contains(string(ev.Line), domain) {
				gotDomain = string(ev.Line)
				break readLoop
			}
		case <-domainDeadline:
			break readLoop
		}
	}
	if gotDomain == "" {
		cancel()
		t.Fatalf("the callback domain %q never arrived on the event channel — StreamOpts "+
			"cannot serve a long-lived OOB session, and ssrf.go's process_lifecycle bypass "+
			"is therefore NOT obsolete", domain)
	}

	// The grandchild must exist before cancellation, or leg (b) proves nothing:
	// asserting a process is dead when it was never alive is a trivially passing
	// test, and this file exists to avoid exactly that.
	var grandchild int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		data, readErr := os.ReadFile(filepath.Join(dir, "grandchild.pid")) //nolint:gosec // test-owned temp path
		if readErr == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil && pidAlive(pid) {
				grandchild = pid
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if grandchild == 0 {
		cancel()
		t.Fatal("the fixture's grandchild never came up — the kill-tree leg would pass " +
			"vacuously, so the verdict cannot rest on it")
	}
	t.Logf("grandchild %d is alive before cancellation", grandchild)

	// (b) Cancel and require the WHOLE TREE to die.
	cancel()

	// (c) The channel must close. Drain until it does, bounded.
	closed := make(chan struct{})
	go func() {
		for range events { //nolint:revive // intentional drain
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(15 * time.Second):
		t.Fatal("the event channel never closed after cancellation — a consumer ranging " +
			"over it would hang forever, and the SSRF task ranges over it for the whole run")
	}

	// The escalation fires at WaitDelay+500ms; allow generous slack.
	var died bool
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if !pidAlive(grandchild) {
			died = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !died {
		_ = syscall.Kill(grandchild, syscall.SIGKILL) // do not leak it into wave 6
		t.Fatalf("the GRANDCHILD (pid %d) survived cancellation — StreamOpts did not kill "+
			"the process tree, so it cannot replace ssrf.go's hand-rolled process-group "+
			"teardown", grandchild)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "SURVIVED")); statErr == nil {
		t.Fatal("the grandchild wrote its SURVIVED marker — it outlived the kill window")
	}
	t.Logf("grandchild %d is gone and left no SURVIVED marker: StreamOpts kills the TREE", grandchild)
}

// TestStartInteractshClientThroughTheSeam drives the REAL startInteractshClient
// (not the package-var override) against a fake interactsh-client resolved from
// the registry.
//
// The lifecycle test above proves StreamOpts CAN serve the shape. This proves
// ssrf.go actually USES it: the callback domain is parsed off the event channel,
// the invocation lands in logs/tools.jsonl — which it never did while this file
// dispatched directly — and cleanup() kills the tree and returns only once the
// process has been reaped.
func TestStartInteractshClientThroughTheSeam(t *testing.T) {
	dir := t.TempDir()
	const domain = "c0ffee1234.oast.fun"
	script := writeInteractshFixture(t, dir, domain)

	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "logs"), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	logPath := filepath.Join(workDir, "logs", "tools.jsonl")

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: ssrfInteractshTool, Path: script})
	runner := backend.NewRunner(&backend.LocalBackend{KillGrace: 500 * time.Millisecond}, reg, nil)
	runner.Recorder = backend.NewToolRecorder(logPath, nil)

	app := &appctx.AppContext{
		Tools:  runner,
		Cfg:    config.Defaults(),
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}

	sess, ok := startInteractshClient(context.Background(), app)
	if !ok {
		t.Fatal("startInteractshClient returned false against a fixture that DOES print a " +
			"callback domain — OOB SSRF would degrade to in-band silently")
	}
	if sess.callbackDomain != domain {
		t.Fatalf("callbackDomain = %q, want %q", sess.callbackDomain, domain)
	}

	// Grab the grandchild before teardown so the kill-tree claim is not vacuous.
	var grandchild int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		data, readErr := os.ReadFile(filepath.Join(dir, "grandchild.pid")) //nolint:gosec // test-owned temp path
		if readErr == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil && pidAlive(pid) {
				grandchild = pid
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	sess.cleanup()

	if grandchild != 0 {
		var died bool
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
			if !pidAlive(grandchild) {
				died = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !died {
			_ = syscall.Kill(grandchild, syscall.SIGKILL)
			t.Fatalf("cleanup() left the grandchild (pid %d) alive — a leaked OOB callback "+
				"server outlives its task and holds a session open (T-18-05-03)", grandchild)
		}
	}

	if err := runner.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}
	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — the OOB session was NOT recorded: %v", err)
	}
	if !strings.Contains(string(data), `"tool":"`+ssrfInteractshTool+`"`) {
		t.Fatalf("no record naming %q:\n%s", ssrfInteractshTool, data)
	}
	// XCUT-07: the callback domain is a SESSION SECRET. It reaches this process on
	// the tool's stdout, and stdout is not argv — but assert it at this call site
	// rather than assuming the property survived the move.
	if strings.Contains(string(data), domain) {
		t.Errorf("THE OOB CALLBACK DOMAIN LEAKED INTO logs/tools.jsonl (XCUT-07) — %q is a "+
			"session secret and must never appear in a file operators paste into issue "+
			"reports:\n%s", domain, data)
	}
}

// TestStartInteractshClientFallsBackWhenUnresolvable pins the failure policy: an
// interactsh-client the registry cannot resolve must yield (nil, false) so the
// SSRF task falls through to in-band checks, exactly as the exec.LookPath gate
// used to make it.
func TestStartInteractshClientFallsBackWhenUnresolvable(t *testing.T) {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: ssrfInteractshTool}) // registered, Path empty
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{KillGrace: 500 * time.Millisecond}, reg, nil),
		Cfg:    config.Defaults(),
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
	}

	sess, ok := startInteractshClient(context.Background(), app)
	if ok || sess != nil {
		t.Fatalf("startInteractshClient returned (%v, %v) for an unresolvable tool — the SSRF "+
			"task must fall through to in-band checks, not proceed with a dead session", sess, ok)
	}
}
