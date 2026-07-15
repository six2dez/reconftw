// ssrf_test.go — behavior tests for the BOUNDED interactsh-client auto-start
// that restores SSRF OOB detection (13-07 Task 2).
//
// Internal (package vulns) so the tests override the unexported
// startInteractshClient seam and drive resolveSSRFCollabSession / SSRFTask.Run
// directly. The seam is stubbed via a package var — no real interactsh-client
// binary is spawned, so the tests are hermetic and fast.
//
// Coverage (plan 13-07 Task 2 behavior spec):
//   - CollabServer set  → configured server used, NO subprocess (regression guard)
//   - CollabServer unset + interactsh present → bounded auto-start, OOB payloads
//   - CollabServer unset + interactsh absent  → in-band only (no crash)
//   - bounded: a stub that never emits a callback does NOT hang past the task timeout
//   - XCUT-07: the callback domain NEVER appears in any log line
package vulns

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// swapInteractshStarter replaces the startInteractshClient package var and
// returns a restore fn.
func swapInteractshStarter(fn func(context.Context, *appctx.AppContext) (*interactshSession, bool)) func() {
	prev := startInteractshClient
	startInteractshClient = fn
	return func() { startInteractshClient = prev }
}

// newSSRFTestApp builds a minimal AppContext with ffuf registered and a
// buffer-backed logger (so XCUT-07 log assertions can inspect emitted lines).
func newSSRFTestApp(t *testing.T, buf *bytes.Buffer, cfg *config.Config) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "ffuf"})
	be := newSprayFakeBackend() // reused: Stream returns an immediately-closed channel
	var logger *slog.Logger
	if buf != nil {
		logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
		Cfg:    cfg,
		Log:    logger,
	}
}

// writeSSRFBucket writes a single param URL into inputs/gf/ssrf.txt so Run
// proceeds past the empty-bucket skip.
func writeSSRFBucket(t *testing.T, app *appctx.AppContext) {
	t.Helper()
	gfDir := filepath.Join(app.Target.WorkDir, "inputs", "gf")
	if err := os.MkdirAll(gfDir, 0o755); err != nil {
		t.Fatalf("mkdir gf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gfDir, "ssrf.txt"),
		[]byte("http://target.example.com/api?url=value\n"), 0o644); err != nil {
		t.Fatalf("write ssrf.txt: %v", err)
	}
}

// -------------------------------------------------------------------------
// resolveSSRFCollabSession precedence (hermetic, no Run)
// -------------------------------------------------------------------------

// TestSSRFCollabServerSetRegression — an explicit COLLAB_SERVER is used directly
// and the interactsh auto-start seam is NEVER consulted (behavior unchanged).
func TestSSRFCollabServerSetRegression(t *testing.T) {
	cfg := &config.Config{}
	cfg.APIKeys.CollabServer = "https://oob.example.com"
	app := newSSRFTestApp(t, nil, cfg)

	seamCalled := false
	restore := swapInteractshStarter(func(context.Context, *appctx.AppContext) (*interactshSession, bool) {
		seamCalled = true
		return nil, false
	})
	defer restore()

	token, url, usingOOB, cleanup := resolveSSRFCollabSession(context.Background(), cfg, app)
	if seamCalled {
		t.Error("interactsh auto-start seam consulted despite an explicit COLLAB_SERVER (regression)")
	}
	if !usingOOB {
		t.Error("usingInteractsh=false with COLLAB_SERVER set")
	}
	if cleanup != nil {
		t.Error("cleanup non-nil with a configured server (no subprocess should exist)")
	}
	if !strings.Contains(token, "oob.example.com") || !strings.Contains(url, "oob.example.com") {
		t.Errorf("token/url not derived from COLLAB_SERVER: token=%q url=%q", token, url)
	}
}

// TestSSRFAutoStartOOB — CollabServer unset + interactsh present → OOB token
// derived from the callback domain; cleanup wired to the subprocess teardown.
func TestSSRFAutoStartOOB(t *testing.T) {
	cfg := &config.Config{} // no CollabServer
	app := newSSRFTestApp(t, nil, cfg)

	cleanupCalled := false
	restore := swapInteractshStarter(func(context.Context, *appctx.AppContext) (*interactshSession, bool) {
		return &interactshSession{
			callbackDomain: "abcd1234.oast.example",
			cleanup:        func() { cleanupCalled = true },
		}, true
	})
	defer restore()

	token, url, usingOOB, cleanup := resolveSSRFCollabSession(context.Background(), cfg, app)
	if !usingOOB {
		t.Error("usingInteractsh=false despite a started interactsh session")
	}
	if !strings.Contains(token, "abcd1234.oast.example") || !strings.Contains(url, "abcd1234.oast.example") {
		t.Errorf("OOB token/url not derived from callback domain: token=%q url=%q", token, url)
	}
	if cleanup == nil {
		t.Fatal("cleanup nil for an auto-started subprocess (leak risk)")
	}
	cleanup()
	if !cleanupCalled {
		t.Error("cleanup did not invoke the session teardown (process would leak)")
	}
}

// TestSSRFInteractshAbsentInBand — CollabServer unset + interactsh absent →
// in-band only, placeholder token, no subprocess.
func TestSSRFInteractshAbsentInBand(t *testing.T) {
	cfg := &config.Config{}
	app := newSSRFTestApp(t, nil, cfg)

	restore := swapInteractshStarter(func(context.Context, *appctx.AppContext) (*interactshSession, bool) {
		return nil, false // not installed
	})
	defer restore()

	token, _, usingOOB, cleanup := resolveSSRFCollabSession(context.Background(), cfg, app)
	if usingOOB {
		t.Error("usingInteractsh=true when interactsh-client is absent")
	}
	if token != "SSRFCHECK" {
		t.Errorf("in-band token = %q, want SSRFCHECK", token)
	}
	if cleanup != nil {
		t.Error("cleanup non-nil in the in-band path (no subprocess)")
	}
}

// TestSSRFXCUT07NoCallbackURLInLogs — the callback domain NEVER appears in any
// log line; only the oob_enabled marker is surfaced.
func TestSSRFXCUT07NoCallbackURLInLogs(t *testing.T) {
	const secretDomain = "secretcallback9999.oast.example"
	buf := &bytes.Buffer{}
	cfg := &config.Config{}
	app := newSSRFTestApp(t, buf, cfg)

	restore := swapInteractshStarter(func(context.Context, *appctx.AppContext) (*interactshSession, bool) {
		return &interactshSession{callbackDomain: secretDomain, cleanup: func() {}}, true
	})
	defer restore()

	_, _, _, _ = resolveSSRFCollabSession(context.Background(), cfg, app)

	logs := buf.String()
	if strings.Contains(strings.ToLower(logs), secretDomain) {
		t.Errorf("XCUT-07 VIOLATION: callback domain leaked into logs:\n%s", logs)
	}
	if !strings.Contains(logs, "oob_enabled") {
		t.Errorf("expected oob_enabled marker in logs; got:\n%s", logs)
	}
}

// -------------------------------------------------------------------------
// SSRFTask.Run — bounded auto-start + OOB payload wiring
// -------------------------------------------------------------------------

// TestSSRFRunBoundedNoHang is the DoD-2 regression guard: a stubbed interactsh
// that never emits a callback (it blocks until ctx is cancelled) must NOT hang
// the task past cfg.Vulns.SSRF.TimeoutSeconds — the overall task WithTimeout
// cancels it and Run falls through to in-band.
func TestSSRFRunBoundedNoHang(t *testing.T) {
	cfg := &config.Config{}
	cfg.Vulns.SSRF.Enabled = true
	cfg.Vulns.SSRF.TimeoutSeconds = 1 // tiny overall budget
	app := newSSRFTestApp(t, nil, cfg)
	writeSSRFBucket(t, app)

	// Stub blocks until the task ctx is cancelled — exactly the never-emits-a-
	// callback case that caused the DoD-2 unbounded wait. It relies on taskCtx.
	restore := swapInteractshStarter(func(ctx context.Context, _ *appctx.AppContext) (*interactshSession, bool) {
		<-ctx.Done() // released only by the overall task WithTimeout
		return nil, false
	})
	defer restore()

	done := make(chan task.Result, 1)
	start := time.Now()
	go func() {
		res, _ := (&SSRFTask{}).Run(context.Background(), app)
		done <- res
	}()

	select {
	case res := <-done:
		elapsed := time.Since(start)
		if elapsed > 15*time.Second {
			t.Fatalf("Run took %s — auto-start not bounded by the task timeout (DoD-2 regression)", elapsed)
		}
		if res.Status == task.StatusErrored {
			t.Errorf("Run errored; a never-emitting interactsh must degrade to in-band, not error")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run HUNG — interactsh auto-start is NOT bounded (DoD-2 unbounded-wait regression reintroduced)")
	}
}

// TestSSRFRunUsesOOBPayloads — with interactsh auto-started, the generated
// payloads target the OOB callback domain (NOT the in-band placeholder) and the
// subprocess is torn down (cleanup called) when Run completes.
func TestSSRFRunUsesOOBPayloads(t *testing.T) {
	const cbDomain = "oobcallback.oast.example"
	cfg := &config.Config{}
	cfg.Vulns.SSRF.Enabled = true
	cfg.Vulns.SSRF.TimeoutSeconds = 1 // bound the 5s OOB wait so the test stays fast
	app := newSSRFTestApp(t, nil, cfg)
	writeSSRFBucket(t, app)

	cleanupCalled := false
	restore := swapInteractshStarter(func(context.Context, *appctx.AppContext) (*interactshSession, bool) {
		return &interactshSession{callbackDomain: cbDomain, cleanup: func() { cleanupCalled = true }}, true
	})
	defer restore()

	res, err := (&SSRFTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("Status = %q, want done", res.Status)
	}

	// The OOB callback domain must appear in the generated payloads (proves the
	// in-band-only path was NOT taken).
	tmp, rErr := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "tmp_ssrf.txt"))
	if rErr != nil {
		t.Fatalf("read tmp_ssrf.txt: %v", rErr)
	}
	if !strings.Contains(string(tmp), cbDomain) {
		t.Errorf("OOB payloads do not target the callback domain %q:\n%s", cbDomain, tmp)
	}
	if strings.Contains(string(tmp), "SSRFCHECK") {
		t.Errorf("in-band placeholder used despite an active OOB session:\n%s", tmp)
	}
	if !cleanupCalled {
		t.Error("interactsh subprocess NOT torn down on task completion (process-group leak)")
	}
}

// -------------------------------------------------------------------------
// parseInteractshDomain unit tests
// -------------------------------------------------------------------------

func TestParseInteractshDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"c6a3b2c9d0e1f2.oast.fun", "c6a3b2c9d0e1f2.oast.fun"},
		{"[INF] abcdef123.oast.site", "abcdef123.oast.site"},
		{"  UPPER.Example.COM  ", "upper.example.com"},
		{"[INF] Listing 1 payload for OOB Testing", ""}, // sentence, last token has no dot
		{"https://scheme.example.com/path", ""},         // scheme/path rejected
		{"host:8080", ""},                               // port rejected
		{"nodothostname", ""},                           // no dot
		{"", ""},
	}
	for _, c := range cases {
		if got := parseInteractshDomain(c.in); got != c.want {
			t.Errorf("parseInteractshDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
