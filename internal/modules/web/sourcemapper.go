// sourcemapper.go — SourcemapperTask: source map extraction via sourcemapper.
//
// Name: "web.sourcemapper"  DependsOn: ["web.subjs"]
//
// SourcemapperTask runs sourcemapper per JS URL, extracting source-mapped
// files to raw/sourcemaps/<host>/ directories. Output is written by
// sourcemapper itself; JsluiceTask reads from these directories.
//
// ARG VECTOR (verbatim v1 form, web.sh:2289, 2302):
//
//	sourcemapper -jsurl <url> -output raw/sourcemaps/<host>/
//
// Fan-out: goroutines bounded by a semaphore (safe concurrency for sourcemapper).
//
// Axiom: LocalBackend only.
package web

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/six2dez/reconftw/v5/internal/core/appctx"
	"github.com/six2dez/reconftw/v5/internal/core/config"
	"github.com/six2dez/reconftw/v5/internal/core/task"
)

// SourcemapperTask runs sourcemapper source extraction per JS URL.
type SourcemapperTask struct{}

func (t *SourcemapperTask) Name() string   { return "web.sourcemapper" }
func (t *SourcemapperTask) Module() string { return "web" }
func (t *SourcemapperTask) Description() string {
	return "Source map extraction (sourcemapper → raw/sourcemaps/)"
}

func (t *SourcemapperTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.JS.Enabled
}
func (t *SourcemapperTask) DependsOn() []string { return []string{"web.subjs"} }

// Run executes sourcemapper per JS URL and writes extracted files to raw/sourcemaps/.
func (t *SourcemapperTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "sourcemapper"

	// Read JS URLs from artefacts/urls.jsonl.
	jsURLs, err := readJSURLsFromJSONL(app)
	if err != nil || len(jsURLs) == 0 {
		app.Log.Info("web.sourcemapper: no JS URLs in urls.jsonl — skipping")
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Ensure raw/sourcemaps/ base directory exists.
	sourcemapBase := filepath.Join(app.Target.WorkDir, "raw", "sourcemaps")
	if err := os.MkdirAll(sourcemapBase, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.sourcemapper: mkdir raw/sourcemaps/: %w", err)
	}

	// Fan-out: bounded goroutines per JS URL.
	// Derived from config rather than a hardcoded 5.
	maxConcurrency := app.Cfg.Concurrency.MaxJobs
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var totalRan int
	var firstErr error // the first per-URL tool error, for the final verdict
	var mu sync.Mutex

	for _, jsURL := range jsURLs {
		jsURL := jsURL // capture for goroutine
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			// Derive output dir: raw/sourcemaps/<host>/.
			host := extractURLHost(jsURL)
			if host == "" {
				return
			}
			outputDir := filepath.Join(sourcemapBase, host)
			if err := os.MkdirAll(outputDir, 0o755); err != nil {
				return
			}

			// Run sourcemapper for this JS URL.
			// v1 form: sourcemapper -jsurl <url> -output <dir>
			args := []string{"-jsurl", jsURL, "-output", outputDir}
			_, runErr := app.Tools.Run(ctx, toolName, args)
			if runErr != nil {
				// best_effort: log at debug and continue.
				app.Log.Debug("web.sourcemapper: run failed",
					"url", jsURL, "err", runErr)
				mu.Lock()
				if firstErr == nil {
					firstErr = runErr
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			totalRan++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if totalRan == 0 {
		// Absent-vs-failed policy (task.ClassifyToolErr) on the first error seen:
		// a sourcemapper that never started is "tool absent"; one that ran and
		// failed on every URL is degraded with its own account of why.
		status, reason := task.StatusSkipped, "no runnable JS URLs"
		if firstErr != nil {
			status, reason = task.ClassifyToolErr(firstErr)
		}
		app.Log.Info("web.sourcemapper: nothing extracted — skipping", "reason", reason)
		return task.Result{Status: status, Reason: reason}, nil
	}

	app.Log.Debug("web.sourcemapper: completed",
		"js_input_urls", len(jsURLs),
		"successful_runs", totalRan)

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"sourcemaps_extracted": totalRan},
	}, nil
}

// extractURLHost returns the lowercase hostname from a URL string.
// Returns "" for invalid or relative URLs.
func extractURLHost(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func init() { task.Register(&SourcemapperTask{}) }
