// subjs.go — SubjsTask: JavaScript URL extraction via subjs.
//
// Name: "web.subjs"  DependsOn: ["web.katana", "web.urlfinder", "web.waymore"]
//
// SubjsTask reads JavaScript URLs from urls.jsonl, runs subjs to extract
// all linked JS files, and appends new URL records to artefacts/urls.jsonl.
//
// DEPENDENCY DIRECTION (CR-01 fix): subjs is a URL *producer* that urldedup
// CONSUMES, so subjs MUST run BEFORE urldedup — it cannot DependsOn urldedup
// (that backwards edge formed the web.urldedup → web.subjs → web.urldedup cycle
// that aborted the entire `web` subcommand at startup). subjs's real data input
// is artefacts/urls.jsonl, which the intermediate MergeStage("urls") populates
// from the fetch-stage producers (katana/urlfinder/waymore) after urls-fetch.
// Declaring DependsOn on those fetch producers sequences subjs after the data it
// reads while keeping the DAG acyclic; urldedup unions every producer afterward.
//
// ARG VECTOR (RESEARCH §subjs — verbatim v1 form, web.sh:2244):
//
//	subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
//	      -c 40
//	      < <js_url_list>  (stdin)
//
// subjs reads JS URL list from stdin. Since Backend.Runner does not expose
// stdin injection, we filter JS URLs from urls.jsonl and write them to a
// temp file, then pass via -i flag if supported, or fall back to direct
// execution approach.
//
// NOTE: v1 uses stdin. subjs also accepts -i flag for file input.
// We use -i for Backend.Runner compatibility.
//
// Axiom: subjs is in the D-W13 axiom map.
// T-05-15: out-of-scope URLs filtered by ExtractURLs domain check.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	urlsextract "github.com/six2dez/reconftw/internal/extract/urls"
)

const subjsUserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"

// SubjsTask runs subjs JavaScript URL extraction.
type SubjsTask struct{}

func (t *SubjsTask) Name() string        { return "web.subjs" }
func (t *SubjsTask) Module() string      { return "web" }
func (t *SubjsTask) Description() string { return "JS URL extraction (subjs → urls.jsonl)" }
func (t *SubjsTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.JS.Enabled
}

// DependsOn returns the fetch-stage URL producers whose output the intermediate
// MergeStage("urls") consolidates into artefacts/urls.jsonl — subjs reads that
// file. subjs is itself a urldedup producer, so it MUST NOT depend on urldedup
// (CR-01: that backwards edge created a cycle and the web pipeline never ran).
func (t *SubjsTask) DependsOn() []string {
	return []string{"web.katana", "web.urlfinder", "web.waymore"}
}

// Run reads JS URLs from urls.jsonl, runs subjs, and appends new URL records.
func (t *SubjsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "subjs"

	// Read JS URLs from artefacts/urls.jsonl (filter to .js entries).
	jsURLs, err := readJSURLsFromJSONL(app)
	if err != nil || len(jsURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.subjs: no JS URLs in urls.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.subjs: mkdir inputs/: %w", err)
	}

	// Write JS URL list to temp file for subjs input.
	jsURLsFile := filepath.Join(inputsDir, "subjs_urls.txt.tmp")
	if err := os.WriteFile(jsURLsFile,
		[]byte(strings.Join(jsURLs, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.subjs: write js urls file: %w", err)
	}

	// Build arg vector (RESEARCH §subjs verbatim v1 form web.sh:2244).
	// Use -i flag for file input (FOUND-10 compliant — no stdin needed).
	args := []string{
		"-ua", subjsUserAgent,
		"-c", "40",
		"-i", jsURLsFile,
	}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.subjs: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Parse stdout URL results.
	var raw []byte
	if res != nil && len(res.Stdout) > 0 {
		raw = res.Stdout
	}

	// Extract and scope-filter URLs via extract/urls.
	records, _ := urlsextract.ExtractURLs(raw, "subjs", app.Target.Domain)

	// F3 (phase 15): the old `if len(records) == 0 { return StatusDone }`
	// short-circuit here left a previous run's inputs/urls.subjs.jsonl on disk
	// for the urls merge to republish. subjs RAN (the absent-binary case
	// returned StatusSkipped above), so stage unconditionally and let
	// StageJSONL remove the file when this run extracted no JS links.
	var lines [][]byte
	for _, rec := range records {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.subjs.jsonl")
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("web.subjs: staging write failed",
			"path", stagingPath, "err", wErr)
	}

	// Clean up temp file.
	os.Remove(jsURLsFile) //nolint:errcheck

	if app.Log != nil {
		app.Log.Debug("web.subjs: completed",
			"js_input_urls", len(jsURLs),
			"js_links_found", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"urls_found": len(records)},
	}, nil
}

// readJSURLsFromJSONL reads artefacts/urls.jsonl and returns only the JS URLs
// (URLs ending in .js or containing /js/ path segment).
func readJSURLsFromJSONL(app *appctx.AppContext) ([]string, error) {
	urlsPath := filepath.Join(app.Target.WorkDir, "artefacts", "urls.jsonl")
	data, err := os.ReadFile(urlsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read urls.jsonl: %w", err)
	}
	return filterJSURLs(data), nil
}

// filterJSURLs returns URLs that appear to be JavaScript files.
// Matches URLs ending in .js (with optional query/fragment) or containing /js/.
func filterJSURLs(data []byte) []string {
	records, _ := extractURLStringsAndSources(data)
	var jsURLs []string
	for _, u := range records {
		lower := strings.ToLower(u)
		// Match: ends in .js, .js?, .js#, or path contains /js/
		isJS := strings.HasSuffix(lower, ".js") ||
			strings.Contains(lower, ".js?") ||
			strings.Contains(lower, ".js#") ||
			strings.Contains(lower, "/js/")
		if isJS {
			jsURLs = append(jsURLs, u)
		}
	}
	return jsURLs
}

func init() { task.Register(&SubjsTask{}) }
