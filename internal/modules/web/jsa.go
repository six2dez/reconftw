// jsa.go — JsaTask: JavaScript static analysis via JSA (repo-clone Python venv tool).
//
// Name: "web.jsa"  DependsOn: ["web.subjs"]
//
// JsaTask invokes JSA (jsa.py) per JS URL from urls.jsonl. JSA is a
// REPO-CLONE Python venv tool (not on PATH); it must be invoked as:
//
//	<data_dir>/JSA/venv/bin/python3 <data_dir>/JSA/jsa.py -f <url>
//
// RESEARCH §JSA — v1 form (web.sh:2008):
//
//	${tools}/JSA/venv/bin/python3 ${tools}/JSA/jsa.py -f <js_url>
//
// T-05-14 mitigation: the JSA python3 path is derived from cfg.Paths.DataDir
// (validated at config load via nopath_traversal). The Task additionally
// performs os.Stat on the binary before executing. If absent → StatusSkipped.
//
// Fan-out: goroutines bounded by a semaphore (safe concurrency for JSA).
//
// Axiom: LocalBackend only (D-W13 — JSA has no axiom module).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2.
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	urlsextract "github.com/six2dez/reconftw/internal/extract/urls"
)

// JsaTask runs JSA static analysis per JS URL.
type JsaTask struct{}

func (t *JsaTask) Name() string        { return "web.jsa" }
func (t *JsaTask) Module() string      { return "web" }
func (t *JsaTask) Description() string { return "JS static analysis (JSA → urls.jsonl)" }
func (t *JsaTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.JS.Enabled
}
func (t *JsaTask) DependsOn() []string { return []string{"web.subjs"} }

// Run executes jsa.py per JS URL and appends discovered URL records.
func (t *JsaTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg

	// Resolve tools root directory (T-05-14: DataDir validated at config load).
	// v1 uses ${tools} which defaults to $HOME/Tools. We use cfg.Paths.DataDir
	// when set; otherwise fall back to $HOME/Tools.
	toolsDir := resolveToolsDir(cfg)
	if toolsDir == "" {
		if app.Log != nil {
			app.Log.Info("web.jsa: tools directory not resolvable — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Check JSA venv python3 binary exists (T-05-14 additional guard).
	jsaPython := filepath.Join(toolsDir, "JSA", "venv", "bin", "python3")
	if _, err := os.Stat(jsaPython); err != nil {
		if app.Log != nil {
			app.Log.Info("web.jsa: JSA venv not found — skipping",
				"path", jsaPython, "err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	jsaScript := filepath.Join(toolsDir, "JSA", "jsa.py")
	if _, err := os.Stat(jsaScript); err != nil {
		if app.Log != nil {
			app.Log.Info("web.jsa: jsa.py not found — skipping",
				"path", jsaScript, "err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read JS URLs from artefacts/urls.jsonl.
	jsURLs, err := readJSURLsFromJSONL(app)
	if err != nil || len(jsURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.jsa: no JS URLs in urls.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Fan-out: bounded goroutines per JS URL.
	// Concurrency derived from config (WR-04: not hardcoded).
	// Conservative fallback for python venv tools.
	maxConcurrency := cfg.Concurrency.MaxJobs
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}

	sem := make(chan struct{}, maxConcurrency)
	var mu sync.Mutex
	var allRecords [][]byte
	var wg sync.WaitGroup

	for _, jsURL := range jsURLs {
		jsURL := jsURL // capture for goroutine
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			records := runJSAForURL(ctx, app, jsaPython, jsaScript, jsURL)
			if len(records) > 0 {
				mu.Lock()
				allRecords = append(allRecords, records...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// WriteJSONL called ONCE after all goroutines join (wg.Wait above).
	// allRecords is fully populated (mutex-protected collector) — no concurrent writes.
	if len(allRecords) > 0 {
		stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.jsa.jsonl")
		if wErr := output.WriteJSONL(stagingPath, allRecords); wErr != nil && app.Log != nil {
			app.Log.Debug("web.jsa: staging write failed",
				"path", stagingPath, "err", wErr)
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.jsa: completed",
			"js_input_urls", len(jsURLs),
			"urls_found", len(allRecords))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"urls_found": len(allRecords)},
	}, nil
}

// runJSAForURL invokes jsa.py for a single JS URL and returns URLRecord JSONL lines.
// Uses direct exec.CommandContext (CR-03 fix: repo-clone venv tools bypass registry).
// Returns nil on error or no results (best_effort).
func runJSAForURL(ctx context.Context, app *appctx.AppContext,
	jsaPython, jsaScript, jsURL string) [][]byte {
	// Conservative per-URL timeout (no JSA entry in tools.lock for per-URL cap).
	const toolTimeout = 30 * time.Second

	// CR-03 fix: direct exec.CommandContext (registry lookup is wrong for absolute paths).
	// jsaPython is an absolute path validated by os.Stat in Run().
	cmdCtx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()

	//nolint:gosec // jsaPython validated by os.Stat; jsaScript validated by os.Stat; jsURL scope-filtered
	cmd := exec.CommandContext(cmdCtx, jsaPython, jsaScript, "-f", jsURL)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		if app.Log != nil {
			app.Log.Debug("web.jsa: jsa invocation failed (non-fatal)",
				"url", jsURL, "err", err)
		}
		return nil
	}

	raw := outBuf.Bytes()
	if len(raw) == 0 {
		return nil
	}

	// Parse plain-text URL output from JSA.
	records, _ := urlsextract.ExtractURLs(raw, "jsa", app.Target.Domain)
	if len(records) == 0 {
		return nil
	}

	var lines [][]byte
	for _, rec := range records {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	return lines
}

// resolveToolsDir returns the tools root directory path.
// Priority: cfg.Paths.DataDir → $HOME/Tools (v1 default).
func resolveToolsDir(cfg *config.Config) string {
	if cfg.Paths.DataDir != "" {
		return cfg.Paths.DataDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Tools")
}

func init() { task.Register(&JsaTask{}) }
