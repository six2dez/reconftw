// wellknown_test.go — behavior tests for WebWellKnownTask (13-04 Task 2).
//
// Internal (package web) to reach the unexported helpers. An httptest server
// stands in for the real .well-known endpoints; scope + userinfo guards are
// asserted by pointing targets at (or around) that server and checking which
// requests actually fire.
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
)

// wellknownTestServer returns an httptest server serving security.txt +
// openid-configuration bodies, plus a hit counter for guard assertions.
func wellknownTestServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		// In-scope hostnames (login/policy.example.com) + one off-scope (evil.com).
		_, _ = w.Write([]byte("Contact: mailto:security@login.example.com\n" +
			"Policy: https://policy.example.com/policy\n" +
			"Acknowledgments: https://evil.com/thanks\n"))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://auth.example.com",` +
			`"jwks_uri":"https://keys.example.com/jwks"}`))
	})
	// Everything else (e.g. /security.txt, oauth-authorization-server) counts as a
	// hit but returns empty so the guard tests can still observe request volume.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

// newWellknownApp builds an AppContext with WellKnown enabled and a scope that
// admits both the local httptest host and *.example.com discoveries.
func newWellknownApp(t *testing.T, enabled bool) *appctx.AppContext {
	t.Helper()
	cfg := &config.Config{}
	cfg.Web.WellKnown = config.WebWellKnown{Enabled: enabled, MaxTargets: 200}
	return &appctx.AppContext{
		Cfg: cfg,
		Target: &appctx.Target{
			Domain:  "example.com",
			WorkDir: t.TempDir(),
			Scope:   []string{"127.0.0.1", "*.example.com"},
		},
	}
}

// writeWellknownTargets writes artefacts/hosts.jsonl from the given target URLs.
func writeWellknownTargets(t *testing.T, app *appctx.AppContext, urls ...string) {
	t.Helper()
	dir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	var b strings.Builder
	for _, u := range urls {
		b.WriteString(`{"url":"` + u + `","host":"127.0.0.1"}` + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write hosts.jsonl: %v", err)
	}
}

func TestWebWellKnownTaskIdentity(t *testing.T) {
	tsk := &WebWellKnownTask{}
	if tsk.Name() != "web.wellknown" {
		t.Errorf("Name() = %q, want web.wellknown", tsk.Name())
	}
	if tsk.Module() != "web" {
		t.Errorf("Module() = %q, want web", tsk.Module())
	}
	if tsk.DependsOn() != nil {
		t.Errorf("DependsOn() = %v, want nil", tsk.DependsOn())
	}
	cfg := &config.Config{}
	cfg.Web.WellKnown.Enabled = false
	if tsk.Enabled(cfg) {
		t.Error("Enabled should be false by default (bash parity)")
	}
	cfg.Web.WellKnown.Enabled = true
	if !tsk.Enabled(cfg) {
		t.Error("Enabled should be true when cfg.Web.WellKnown.Enabled=true")
	}
}

// TestWebWellKnownExtractsInScopeHosts is the happy path: security.txt +
// openid-configuration bodies yield in-scope hostnames (staged) while an
// off-scope hostname in the response is filtered out.
func TestWebWellKnownExtractsInScopeHosts(t *testing.T) {
	srv, _ := wellknownTestServer(t)
	app := newWellknownApp(t, true)
	writeWellknownTargets(t, app, srv.URL)

	res, err := (&WebWellKnownTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("status = %v, want done", res.Status)
	}

	staged, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "hosts.wellknown.jsonl"))
	if err != nil {
		t.Fatalf("read hosts.wellknown.jsonl: %v", err)
	}
	out := string(staged)
	for _, want := range []string{
		"login.example.com",  // security.txt Contact
		"policy.example.com", // security.txt Policy URL
		"auth.example.com",   // OIDC issuer
		"keys.example.com",   // OIDC jwks_uri
	} {
		if !strings.Contains(out, want) {
			t.Errorf("hosts.wellknown.jsonl missing in-scope host %q; got:\n%s", want, out)
		}
	}
	// Off-scope hostname from the response body must be filtered out.
	if strings.Contains(out, "evil.com") {
		t.Errorf("off-scope host evil.com leaked into staging; got:\n%s", out)
	}
}

// TestWebWellKnownScopeAndUserinfoGuard proves off-scope + userinfo targets are
// NEVER fetched (SSRF/scope guard, T-13-04-01).
func TestWebWellKnownScopeAndUserinfoGuard(t *testing.T) {
	srv, hits := wellknownTestServer(t)
	app := newWellknownApp(t, true)

	// userinfo target (must be rejected) built from the real server host.
	userinfoURL := strings.Replace(srv.URL, "http://", "http://user:pass@", 1)
	writeWellknownTargets(t, app, userinfoURL, "http://8.8.8.8")

	res, err := (&WebWellKnownTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// No in-scope target → no fetch, no discoveries.
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Errorf("guarded targets triggered %d fetch(es); want 0 (userinfo + off-scope must be rejected)", got)
	}
	if res.Status != "done" && res.Status != "skipped" {
		t.Errorf("status = %v, want done/skipped", res.Status)
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "inputs", "hosts.wellknown.jsonl")); err == nil {
		t.Error("staging file written despite all targets being guarded")
	}
}

// TestWebWellKnownMaxTargetsCap proves MaxTargets bounds the probed targets.
func TestWebWellKnownMaxTargetsCap(t *testing.T) {
	srv, hits := wellknownTestServer(t)
	app := newWellknownApp(t, true)
	app.Cfg.Web.WellKnown.MaxTargets = 1
	// Three in-scope targets; only the first must be probed.
	writeWellknownTargets(t, app, srv.URL, srv.URL, srv.URL)

	if _, err := (&WebWellKnownTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Exactly one target probed → one GET per wellknownPaths entry.
	if got, want := int(atomic.LoadInt32(hits)), len(wellknownPaths); got != want {
		t.Errorf("MaxTargets=1 produced %d fetches; want %d (one probed target × %d paths)",
			got, want, len(wellknownPaths))
	}
}

func TestWebWellKnownDisabledSkips(t *testing.T) {
	srv, hits := wellknownTestServer(t)
	app := newWellknownApp(t, false) // Enabled=false
	writeWellknownTargets(t, app, srv.URL)

	res, err := (&WebWellKnownTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("status = %v, want skipped (disabled)", res.Status)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Errorf("disabled task fetched %d time(s); want 0", got)
	}
}

func TestWebWellKnownNoTargetsSkips(t *testing.T) {
	app := newWellknownApp(t, true) // no hosts.jsonl written

	res, err := (&WebWellKnownTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("status = %v, want skipped (no web targets)", res.Status)
	}
}
