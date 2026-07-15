// wordlistgen_test.go — behavior tests for WebWordlistGenTask (13-04 Task 3).
//
// Internal (package web) to override the unexported roboxtractor / getjswords
// runner seams and reach the shared corpus writers (writeWellknownTargets,
// writeURLCorpus). Each generator's independent-degrade behaviour is proven by
// stubbing one runner to fail while the other succeeds. pydictor's deferral is
// asserted via the documented sentinel (it has no runner — structurally never
// invoked).
package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
)

func newWordlistgenApp(t *testing.T, isIP bool) *appctx.AppContext {
	t.Helper()
	cfg := &config.Config{}
	cfg.Web.Wordlist = config.WebWordlist{Enabled: true, RobotsEnabled: true}
	cfg.Web.JS.GetJSWordsPython = "python3"
	return &appctx.AppContext{
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir(), IsIP: isIP},
	}
}

// stubRobox overrides the roboxtractor runner seam (restored on cleanup).
func stubRobox(t *testing.T, fn func(context.Context, *appctx.AppContext, []string) ([]byte, error)) {
	t.Helper()
	orig := wordlistgenRoboxtractorRunner
	t.Cleanup(func() { wordlistgenRoboxtractorRunner = orig })
	wordlistgenRoboxtractorRunner = fn
}

// stubGetJSW overrides the getjswords runner seam (restored on cleanup).
func stubGetJSW(t *testing.T, fn func(context.Context, *appctx.AppContext, []string) ([]byte, error)) {
	t.Helper()
	orig := wordlistgenGetJSWordsRunner
	t.Cleanup(func() { wordlistgenGetJSWordsRunner = orig })
	wordlistgenGetJSWordsRunner = fn
}

func robotsPath(app *appctx.AppContext) string {
	return filepath.Join(app.Target.WorkDir, "webs", "robots_wordlist.txt")
}
func dictWordsPath(app *appctx.AppContext) string {
	return filepath.Join(app.Target.WorkDir, "webs", "dict_words.txt")
}

func TestWebWordlistGenTaskIdentity(t *testing.T) {
	tsk := &WebWordlistGenTask{}
	if tsk.Name() != "web.wordlistgen" {
		t.Errorf("Name() = %q, want web.wordlistgen", tsk.Name())
	}
	if tsk.Module() != "web" {
		t.Errorf("Module() = %q, want web", tsk.Module())
	}
	if tsk.DependsOn() != nil {
		t.Errorf("DependsOn() = %v, want nil", tsk.DependsOn())
	}
	cfg := &config.Config{}
	cfg.Web.Wordlist.Enabled = true
	if !tsk.Enabled(cfg) {
		t.Error("Enabled should be true when cfg.Web.Wordlist.Enabled=true")
	}
	cfg.Web.Wordlist.Enabled = false
	if tsk.Enabled(cfg) {
		t.Error("Enabled should be false when cfg.Web.Wordlist.Enabled=false")
	}
}

// TestWebWordlistGenRoboxtractor: with a stubbed roboxtractor and web targets
// present, the robots-derived wordlist artefact is produced.
func TestWebWordlistGenRoboxtractor(t *testing.T) {
	app := newWordlistgenApp(t, false)
	writeWellknownTargets(t, app, "http://example.com") // artefacts/hosts.jsonl
	stubRobox(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
		return []byte("admin\nlogin\nwp-admin\n"), nil
	})
	stubGetJSW(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
		return nil, nil // getjswords not exercised here
	})

	res, err := (&WebWordlistGenTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("status = %v, want done", res.Status)
	}
	data, err := os.ReadFile(robotsPath(app))
	if err != nil {
		t.Fatalf("read robots_wordlist.txt: %v", err)
	}
	for _, w := range []string{"admin", "login", "wp-admin"} {
		if !strings.Contains(string(data), w) {
			t.Errorf("robots_wordlist.txt missing %q; got:\n%s", w, data)
		}
	}
}

// TestWebWordlistGenGetJSWords: with a stubbed getjswords and a JS corpus present,
// the JS-words wordlist artefact is produced.
func TestWebWordlistGenGetJSWords(t *testing.T) {
	app := newWordlistgenApp(t, false)
	writeURLCorpus(t, app, "https://example.com/app.js") // artefacts/urls.jsonl (JS URL)
	stubRobox(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
		return nil, nil // roboxtractor not exercised here (no hosts.jsonl either)
	})
	stubGetJSW(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
		return []byte("token\nsecret\napikey\n"), nil
	})

	res, err := (&WebWordlistGenTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("status = %v, want done", res.Status)
	}
	data, err := os.ReadFile(dictWordsPath(app))
	if err != nil {
		t.Fatalf("read dict_words.txt: %v", err)
	}
	for _, w := range []string{"token", "secret", "apikey"} {
		if !strings.Contains(string(data), w) {
			t.Errorf("dict_words.txt missing %q; got:\n%s", w, data)
		}
	}
}

// TestWebWordlistGenIndependentDegrade proves that a failure in one generator
// never prevents the other from producing its artefact — and never errors the
// task (T-13-04-02).
func TestWebWordlistGenIndependentDegrade(t *testing.T) {
	t.Run("roboxtractor_fails_getjswords_runs", func(t *testing.T) {
		app := newWordlistgenApp(t, false)
		writeWellknownTargets(t, app, "http://example.com")
		writeURLCorpus(t, app, "https://example.com/app.js")
		stubRobox(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
			return nil, os.ErrNotExist // simulate absent/failed tool
		})
		stubGetJSW(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
			return []byte("jsword\n"), nil
		})

		res, err := (&WebWordlistGenTask{}).Run(context.Background(), app)
		if err != nil {
			t.Fatalf("Run returned error (must degrade): %v", err)
		}
		if res.Status != "done" {
			t.Fatalf("status = %v, want done", res.Status)
		}
		// getjswords artefact present; roboxtractor artefact absent.
		if _, err := os.Stat(dictWordsPath(app)); err != nil {
			t.Error("dict_words.txt missing — getjswords should still run when roboxtractor fails")
		}
		if _, err := os.Stat(robotsPath(app)); err == nil {
			t.Error("robots_wordlist.txt written despite roboxtractor failing")
		}
	})

	t.Run("getjswords_fails_roboxtractor_runs", func(t *testing.T) {
		app := newWordlistgenApp(t, false)
		writeWellknownTargets(t, app, "http://example.com")
		writeURLCorpus(t, app, "https://example.com/app.js")
		stubRobox(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
			return []byte("robots-path\n"), nil
		})
		stubGetJSW(t, func(context.Context, *appctx.AppContext, []string) ([]byte, error) {
			return nil, os.ErrNotExist // simulate absent/failed tool
		})

		res, err := (&WebWordlistGenTask{}).Run(context.Background(), app)
		if err != nil {
			t.Fatalf("Run returned error (must degrade): %v", err)
		}
		if res.Status != "done" {
			t.Fatalf("status = %v, want done", res.Status)
		}
		if _, err := os.Stat(robotsPath(app)); err != nil {
			t.Error("robots_wordlist.txt missing — roboxtractor should still run when getjswords fails")
		}
		if _, err := os.Stat(dictWordsPath(app)); err == nil {
			t.Error("dict_words.txt written despite getjswords failing")
		}
	})
}

// TestWebWordlistGenPydictorDeferred asserts pydictor is documented as deferred
// (→ Phase 14) and — having no runner seam — is structurally never invoked.
func TestWebWordlistGenPydictorDeferred(t *testing.T) {
	if !strings.Contains(wordlistgenPydictorDeferred, "pydictor") {
		t.Errorf("deferral sentinel must mention pydictor; got %q", wordlistgenPydictorDeferred)
	}
	if !strings.Contains(wordlistgenPydictorDeferred, "Phase 14") {
		t.Errorf("deferral sentinel must document the Phase 14 target; got %q", wordlistgenPydictorDeferred)
	}
}

func TestWebWordlistGenDisabledSkips(t *testing.T) {
	app := newWordlistgenApp(t, false)
	app.Cfg.Web.Wordlist.Enabled = false
	res, err := (&WebWordlistGenTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("status = %v, want skipped (disabled)", res.Status)
	}
}

func TestWebWordlistGenIPTargetSkips(t *testing.T) {
	app := newWordlistgenApp(t, true) // IsIP=true
	res, err := (&WebWordlistGenTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("status = %v, want skipped (IP target)", res.Status)
	}
}
