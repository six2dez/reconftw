// jsa.go — JsaTask: JavaScript static analysis via JSA (repo-clone Python venv tool).
//
// Name: "web.jsa"  DependsOn: ["web.subjs"]
//
// JsaTask invokes JSA (jsa.py) per JS URL from urls.jsonl. JSA is a
// REPO-CLONE Python venv tool (not on PATH); it must be invoked as:
//
//	<tools_root>/JSA/venv/bin/python3 <tools_root>/JSA/jsa.py -f <url>
//
// RESEARCH §JSA — v1 form (web.sh:2008):
//
//	${tools}/JSA/venv/bin/python3 ${tools}/JSA/jsa.py -f <js_url>
//
// 18-05: IT COMES HOME. That two-part command line — an interpreter plus the
// script it runs — is EXACTLY the shape 18-01 added Tool.ArgvPrefix for and
// 18-02 taught the registry to derive from clone_interpreter + clone_entry. So
// the file no longer builds either path: Tool.Path is the venv python3,
// Tool.ArgvPrefix is [jsa.py], and this Task supplies only ["-f", <url>].
//
// T-05-14 is SATISFIED MORE STRONGLY THAN BEFORE, not weakened. The old
// mitigation was "derive from cfg.Paths.DataDir, then os.Stat it" — a check the
// module performed on a path the module built. The registry now joins the
// coordinates under paths.tools_dir and REFUSES any result that escapes that
// root (18-02 containment), which the module could not do for itself.
//
// clone_workdir is NOT declared for JSA, and that was checked rather than
// assumed: `cd / && ~/Tools/JSA/venv/bin/python3 ~/Tools/JSA/jsa.py --help`
// exits 0 on 2026-08-26. jsa.py opens no data file relative to its own
// directory, so it inherits the process cwd exactly as it always has.
//
// DEADLINE: the file's own 30s per-URL context.WithTimeout is gone and
// tools.lock owns the bound. The row said 300 and the file said 30 — a
// DISAGREEMENT, reconciled by lowering the manifest to 30, because 30 is the
// bound production has actually been enforcing and this dispatch is per URL.
// See the JSA row's derivation and TestJSADeadlineMatchesItsFormerBound.
//
// Fan-out: goroutines bounded by a semaphore (safe concurrency for JSA).
// ONE RECORDER ENTRY PER JS URL is the consequence, and it is the intended
// gain: JSA's per-URL argv has never been visible in logs/tools.jsonl. On a
// large JS corpus that is a lot of entries.
//
// Axiom: LocalBackend only (D-W13 — JSA has no axiom module).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2;
// .planning/phases/18-the-runner-seam-close-the-bypass/18-05-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	urlsextract "github.com/six2dez/reconftw/internal/extract/urls"
)

// jsaToolName is the tools.lock entry. Its clone_interpreter (venv/bin/python3)
// becomes Tool.Path and its clone_entry (jsa.py) becomes Tool.ArgvPrefix.
const jsaToolName = "JSA"

// jsaArgs is the per-URL arg vector THIS TASK supplies. The full command line
// the process receives is Tool.Path + Tool.ArgvPrefix + these, i.e.
//
//	<...>/JSA/venv/bin/python3 <...>/JSA/jsa.py -f <url>
//
// which is byte-for-byte the pre-move exec.CommandContext(cmdCtx, jsaPython,
// jsaScript, "-f", jsURL). Asserted IN FULL by
// TestJsaArgvIncludesTheScriptPrefix — a prefix or length check would pass with
// the script missing, which is the exact failure ArgvPrefix exists to prevent.
func jsaArgs(jsURL string) []string { return []string{"-f", jsURL} }

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

	// NO os.Stat PROBES and no module-side join into the tools root: the two
	// paths this Task used to build are now Tool.Path and Tool.ArgvPrefix. An
	// unresolvable JSA is detected from the DISPATCH (unresolvable tools are
	// registered with an empty Path, so cmd.Start fails and the Runner reports
	// NeverStarted) and is recorded as dispatch_failed instead of vanishing —
	// while the task's STATUS stays StatusSkipped, see unresolvable below.

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

	// unresolvable is set by the first goroutine whose dispatch never started a
	// process. Later goroutines bail on it so an absent JSA writes a handful of
	// dispatch_failed records rather than one per JS URL — and the Task can
	// return the SAME StatusSkipped the os.Stat gate used to return, instead of
	// a StatusDone that claims a clean run over zero results.
	var unresolvable atomic.Bool

	for _, jsURL := range jsURLs {
		jsURL := jsURL // capture for goroutine
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if unresolvable.Load() {
				return
			}
			records, dispatchFailed := runJSAForURL(ctx, app, jsURL)
			if dispatchFailed {
				unresolvable.Store(true)
				return
			}
			if len(records) > 0 {
				mu.Lock()
				allRecords = append(allRecords, records...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// WR-07: ANY latched unresolvable is did-not-run for staging purposes — not
	// only the all-or-nothing case.
	//
	// The old condition also required len(allRecords) == 0. If a handful of
	// goroutines finished before the latch was set, the task fell through to
	// StageJSONL with a TRUNCATED corpus and overwrote the previous run's complete
	// one. The comment below claimed "a run in which JSA never executed cannot
	// clear a previous run's URLs (F3 did-not-run)", which held only for the
	// all-or-nothing case — a partial run is precisely the case that silently
	// destroys more than it replaces.
	//
	// An unresolvable JSA that produced nothing is a SKIP, exactly as before —
	// and nothing is staged, so a run in which JSA never executed cannot clear a
	// previous run's URLs (F3 did-not-run).
	if unresolvable.Load() {
		if app.Log != nil {
			app.Log.Info("web.jsa: JSA unavailable — run reconftw install",
				"records_discarded", len(allRecords))
		}
		return task.Result{
			Status:     task.StatusSkipped,
			Incomplete: len(allRecords) > 0,
		}, nil
	}

	// StageJSONL called ONCE after all goroutines join (wg.Wait above).
	// allRecords is fully populated (mutex-protected collector) — no concurrent writes.
	//
	// F3 (phase 15): staged UNCONDITIONALLY — StageJSONL removes the staging
	// file when this run extracted no URLs, so a previous run's JSA output
	// cannot be republished by the urls merge.
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.jsa.jsonl")
	if wErr := output.StageJSONL(stagingPath, allRecords); wErr != nil && app.Log != nil {
		app.Log.Debug("web.jsa: staging write failed",
			"path", stagingPath, "err", wErr)
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

// runJSAForURL invokes jsa.py for a single JS URL through backend.Runner and
// returns URLRecord JSONL lines plus whether the dispatch NEVER STARTED.
//
// The second return value is the distinction 18-01's typed errors made possible
// and the old code could not draw: "JSA is not installed" and "JSA ran and found
// nothing" both used to arrive here as a non-nil error over an empty buffer.
// Conflating them is what let an absent tool report a clean empty result — the
// outcome-mislabelling shape phase 16 spent two plans removing.
//
// The interpreter and the script come from Tool.Path / Tool.ArgvPrefix; the
// deadline comes from the JSA row's timeout_seconds. Neither is built here.
func runJSAForURL(ctx context.Context, app *appctx.AppContext, jsURL string) ([][]byte, bool) {
	res, err := app.Tools.Run(ctx, jsaToolName, jsaArgs(jsURL))
	if err != nil {
		// BOTH ARMS LOG AT INFO OR ABOVE, and that is a change the move forced.
		// Before 18-05 this function dispatched with exec.CommandContext, which
		// the internal/modules silent-success detector does not recognise as a
		// tool call — so its Debug-only logging was invisible to the rule as well
		// as to the operator. Coming onto the seam made the branch visible and
		// TestSilentSuccess failed on it immediately. Raising the level is the
		// fix the rule names; an allowlist entry is explicitly not.
		if coreerrors.IsDispatchFailure(err) {
			if app.Log != nil {
				// WARN: an unresolvable JSA is operator-actionable and rare — the
				// caller latches on the first one, so this fires at most a handful
				// of times per run, not once per JS URL.
				app.Log.Warn("web.jsa: JSA never started (unresolvable) — run reconftw install",
					"url", jsURL, "err", err)
			}
			return nil, true
		}
		if app.Log != nil {
			// INFO, not Warn: this is the per-URL best-effort arm and fires once
			// per failing JS URL. Info is on the operator's screen (the default
			// handler level) which is what the rule requires, without turning a
			// large corpus into a wall of warnings.
			app.Log.Info("web.jsa: jsa invocation failed for this URL (non-fatal)",
				"url", jsURL, "err", err)
		}
		return nil, false
	}

	var raw []byte
	if res != nil {
		raw = res.Stdout
	}
	if len(raw) == 0 {
		return nil, false
	}

	// Parse plain-text URL output from JSA.
	records, _ := urlsextract.ExtractURLs(raw, "jsa", app.Target.Domain)
	if len(records) == 0 {
		return nil, false
	}

	var lines [][]byte
	for _, rec := range records {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	return lines, false
}

// resolveToolsDir is GONE (18-05 Task 2). It was the LAST of the three
// hand-rolled tools-root resolvers 18-02 named, and the one the other two were
// copied from. Every consumer now comes through config.Config.ToolsRoot() over
// paths.tools_dir — including the one place that still needs a raw path,
// wordlistgen.go's getjswords leg.
//
// It read cfg.Paths.DataDir, which is exactly the hazard 17-06 wrote down:
// data_dir already meant the workspace root, so the same key meant two things.
// Under a default config both resolvers answer $HOME/Tools identically; the
// only behaviour that changes is for an operator who had set paths.data_dir and
// relied on it as the tools root, and 18-02's migrator now pins v1's ${tools}
// to paths.tools_dir precisely so that operator is told where to move it.

func init() { task.Register(&JsaTask{}) }
