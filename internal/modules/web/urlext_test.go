// urlext_test.go — behavior tests for WebURLExtTask (13-04 Task 1).
//
// Internal (package web) so the pure-transform helpers (urlextExtOf) and the
// shared fakeToolBackend (portscan_test.go) are reachable. The zero-tool-call
// assertion proves url_ext is a pure awk-style transform (no external binary).
package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

// newURLExtTestApp builds a minimal AppContext for url_ext (no Tree needed — the
// task writes a plain-text contract file, not a scoped JSONL artefact).
func newURLExtTestApp(t *testing.T, isIP bool) *appctx.AppContext {
	t.Helper()
	cfg := &config.Config{}
	cfg.Web.URLs.ExtClassify = true
	return &appctx.AppContext{
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir(), IsIP: isIP},
		Cfg:    cfg,
	}
}

// writeURLCorpus writes artefacts/urls.jsonl from the given URL strings.
func writeURLCorpus(t *testing.T, app *appctx.AppContext, urls ...string) {
	t.Helper()
	dir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	var b strings.Builder
	for _, u := range urls {
		b.WriteString(`{"url":"` + u + `","source":"test","host":"example.com"}` + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "urls.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write urls.jsonl: %v", err)
	}
}

func TestWebURLExtTaskIdentity(t *testing.T) {
	tsk := &WebURLExtTask{}
	if tsk.Name() != "web.url_ext" {
		t.Errorf("Name() = %q, want web.url_ext", tsk.Name())
	}
	if tsk.Module() != "web" {
		t.Errorf("Module() = %q, want web", tsk.Module())
	}
	if tsk.DependsOn() != nil {
		t.Errorf("DependsOn() = %v, want nil", tsk.DependsOn())
	}
	cfg := &config.Config{}
	cfg.Web.URLs.ExtClassify = true
	if !tsk.Enabled(cfg) {
		t.Error("Enabled should be true when cfg.Web.URLs.ExtClassify=true")
	}
	cfg.Web.URLs.ExtClassify = false
	if tsk.Enabled(cfg) {
		t.Error("Enabled should be false when cfg.Web.URLs.ExtClassify=false")
	}
}

// TestWebURLExtBucketing exercises the core classification: sensitive extensions
// are bucketed (grouped by ext), non-sensitive are excluded, matching is
// case-insensitive, and query/fragment + trailing slash are stripped before the
// extension is extracted — while the ORIGINAL URL string is what gets written.
func TestWebURLExtBucketing(t *testing.T) {
	app := newURLExtTestApp(t, false)
	writeURLCorpus(t, app,
		"https://example.com/db.sql",           // sql
		"https://example.com/config.BAK",       // bak (case-insensitive)
		"https://example.com/app.env?token=1",  // env (query stripped for ext)
		"https://example.com/settings.config/", // config (trailing slash stripped)
		"https://example.com/image.png",        // png — NOT sensitive
		"https://example.com/assets/style.css", // css — NOT sensitive
	)

	res, err := (&WebURLExtTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("status = %v, want done", res.Status)
	}

	data, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "webs", "urls_by_ext.txt"))
	if err != nil {
		t.Fatalf("read urls_by_ext.txt: %v", err)
	}
	out := string(data)

	// Sensitive URLs present (as ORIGINAL strings, including query/trailing slash).
	for _, want := range []string{
		"https://example.com/db.sql",
		"https://example.com/config.BAK",
		"https://example.com/app.env?token=1",
		"https://example.com/settings.config/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("urls_by_ext.txt missing sensitive URL %q; got:\n%s", want, out)
		}
	}
	// Non-sensitive extensions excluded.
	for _, notWant := range []string{"image.png", "style.css"} {
		if strings.Contains(out, notWant) {
			t.Errorf("urls_by_ext.txt should NOT contain non-sensitive URL %q; got:\n%s", notWant, out)
		}
	}
	// Grouped by extension header block (bash web.sh:2194 shape).
	for _, hdr := range []string{" + sql + ", " + bak + ", " + env + ", " + config + "} {
		if !strings.Contains(out, hdr) {
			t.Errorf("urls_by_ext.txt missing extension header %q; got:\n%s", hdr, out)
		}
	}
}

func TestWebURLExtSkipsIPTarget(t *testing.T) {
	app := newURLExtTestApp(t, true) // IsIP=true
	writeURLCorpus(t, app, "https://8.8.8.8/db.sql")

	res, err := (&WebURLExtTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("status = %v, want skipped (IP target)", res.Status)
	}
	// No artefact should be produced for an IP target.
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "webs", "urls_by_ext.txt")); err == nil {
		t.Error("urls_by_ext.txt written for IP target (should skip before write)")
	}
}

func TestWebURLExtSkipsEmptyCorpus(t *testing.T) {
	app := newURLExtTestApp(t, false) // no urls.jsonl written

	res, err := (&WebURLExtTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("status = %v, want skipped (empty corpus)", res.Status)
	}
}

// TestWebURLExtNoToolCalls proves url_ext is a pure transform: with a recording
// backend wired in, Run must invoke ZERO external tools.
func TestWebURLExtNoToolCalls(t *testing.T) {
	be := newFakeToolBackend()
	app := newURLExtTestApp(t, false)
	app.Tools = backend.NewRunner(be, backend.NewToolRegistry(), nil)
	writeURLCorpus(t, app, "https://example.com/backup.sql")

	if _, err := (&WebURLExtTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(be.calls); n != 0 {
		t.Errorf("url_ext invoked %d external tool call(s); want 0 (pure transform)", n)
	}
}
