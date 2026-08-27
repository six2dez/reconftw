// gxss.go — GxssTask: XSS reflection scanner → artefacts/findings.jsonl.
//
// GxssTask reads parameterized URLs (containing '?') from artefacts/urls.jsonl,
// replaces parameter values with "FUZZ" inline in Go, then pipes the result to
// Gxss to detect reflected XSS candidates.
//
// DEPENDENCY: DependsOn ["web.urldedup"] — reads artefacts/urls.jsonl.
//
// ARG VECTOR (RESEARCH §Gxss, vulns.sh:27):
//
//	qsreplace FUZZ < gf/xss.txt | Gxss -c 100 -p Xss
//
// v2 form: FUZZ replacement implemented inline in Go (url.Parse + url.Values)
// — no shell interpolation (T-05-17 mitigation). Gxss reads from stdin.
//
// T-05-17 mitigation: FUZZ replacement uses pure Go string ops (url.Parse +
// url.Values), no shell string interpolation.
// T-05-19 mitigation: Gxss stdout routed to the Result only; not logged at INFO.
//
// 18-04: THIS FILE NO LONGER BYPASSES THE SEAM. It used to build its own
// exec.CommandContext with cmd.Stdin, because the name-keyed Backend/Runner had
// no way to inject standard input — the reason recorded on its FOUND-10 bypass
// manifest entry. backend.Runner.RunOpts carries stdin since 18-01, so the
// reason is gone and the manifest entry has been REMOVED. Gxss was invisible to
// logs/tools.jsonl, to the arg-vector census and to the tools.lock contract for
// its whole life; it is now recorded like any other tool.
//
// TIMEOUT: the local 120s context.WithTimeout is GONE, deliberately. tools.lock
// OWNS the bound — the Gxss row carries timeout_seconds = 120, exactly the value
// this file used to apply, and applyToolContract derives it inside the Runner.
// Two bounds for one tool drift apart the moment the manifest is edited.
//
// DEFAULT ARGS: the Gxss row carries default_args = [], so the argv the process
// receives is byte-for-byte the pre-move one (-c 100 -p Xss). Pinned by
// TestGxssArgvUnchangedAcrossTheMove.
//
// BEHAVIOUR CHANGE, STATED RATHER THAN HIDDEN: on a NON-ZERO EXIT the old code
// parsed whatever partial stdout it had captured; LocalBackend returns a
// *ToolError with no Result, so partial output from a failing Gxss is no longer
// parsed. Accepted for THIS tool on evidence rather than by analogy: Gxss exits 0
// both when it finds reflections and when it finds none (verified 2026-08-26
// against the real binary), so the non-zero arm is a genuine failure and its
// output is not a result worth publishing. The staging write still happens on
// that arm — the tool RAN, so zero reflections is a real observation (F3).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-05-PLAN.md Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// GxssTask scans for reflected XSS candidates via Gxss.
type GxssTask struct{}

func (t *GxssTask) Name() string        { return "web.gxss" }
func (t *GxssTask) Module() string      { return "web" }
func (t *GxssTask) Description() string { return "XSS reflection scanner (Gxss → findings.jsonl)" }

// Enabled reports whether param/XSS discovery is configured.
func (t *GxssTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.ParamDiscover.Enabled
}

// DependsOn returns the DAG edges: Gxss reads urls.jsonl from web.urldedup.
func (t *GxssTask) DependsOn() []string { return []string{"web.urldedup"} }

// Run reads parameterized URLs, FUZZ-replaces values, runs Gxss, writes findings.
func (t *GxssTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// NO exec.LookPath GATE. An unresolvable Gxss now returns a typed dispatch
	// failure from the Runner and is RECORDED as dispatch_failed in
	// logs/tools.jsonl, instead of vanishing silently — the conflation phase 16
	// removed for dnstake. The task's status on an absent binary is unchanged
	// (StatusSkipped, see the dispatch below).

	// Read urls.jsonl; filter URLs containing "?" (parameterized).
	paramURLs, readErr := readParamURLsFromJSONL(app)
	if readErr != nil && app.Log != nil {
		app.Log.Debug("web.gxss: read urls.jsonl error", "err", readErr)
	}
	if len(paramURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.gxss: no parameterized URLs in urls.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// T-05-17: inline FUZZ replacement (no shell interpolation).
	// Replaces each query parameter value with "FUZZ" using url.Parse.
	fuzzedURLs := fuzzReplaceURLParams(paramURLs)
	if len(fuzzedURLs) == 0 {
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Feed FUZZ-replaced URLs to Gxss via stdin.
	// ARG VECTOR: Gxss -c 100 -p Xss (RESEARCH §Gxss vulns.sh:27).
	stdinData := []byte(strings.Join(fuzzedURLs, "\n") + "\n")

	res, runErr := app.Tools.RunOpts(ctx, gxssToolName, gxssArgs(),
		backend.ExecOptions{Stdin: stdinData})
	if runErr != nil {
		// A tool that is not registered, or registered but absent from PATH
		// (Discover leaves Path empty, so cmd.Start fails and LocalBackend
		// reports NeverStarted), is the SAME graceful skip the exec.LookPath
		// gate used to give — including not staging, so a run in which Gxss
		// never ran cannot clear a previous run's reflections (F3 did-not-run).
		if coreerrors.IsDispatchFailure(runErr) {
			if app.Log != nil {
				app.Log.Info("web.gxss: Gxss unavailable — skipping")
			}
			return task.Result{Status: task.StatusSkipped}, nil
		}
		if app.Log != nil {
			app.Log.Debug("web.gxss: Gxss exited non-zero (no partial output on this path)",
				"err", runErr)
		}
	}

	var outBytes []byte
	if res != nil {
		outBytes = res.Stdout
	}
	findings := parseGxssOutput(outBytes)

	// Stage reflection hits for the findings merge (best_effort D-W12).
	//
	// F3 (phase 15): staged UNCONDITIONALLY — StageJSONL removes the staging
	// file when this run found no reflections, so a previous run's hits cannot
	// be republished.
	var lines [][]byte
	for _, rec := range findings {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	// F3 DID-NOT-RUN, deadline arm (18-06 code review, CR-03). Reaching here with
	// res == nil means the tool did NOT complete — a tools.lock deadline, a crash,
	// or a cancelled context. Before the move each of these files applied its own
	// context.WithTimeout and PARSED the partially-filled buffer, so a timeout
	// still staged what it had seen. The move removed both, so res is nil and
	// findings is empty — and StageJSONL implements an empty input as os.Remove.
	// A run that never observed the corpus has no standing to delete what a
	// previous run did observe, which is exactly what the F3 comment below claims
	// and, on this path, did not deliver.
	if res == nil {
		if app.Log != nil {
			app.Log.Warn("web.gxss: incomplete run — previous staging preserved",
				"err", runErr)
		}
	} else {
		stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.gxss.jsonl")
		if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
			app.Log.Debug("web.gxss: staging write failed",
				"path", stagingPath, "err", wErr)
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.gxss: completed",
			"param_urls", len(paramURLs),
			"reflections", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"xss_reflections": len(findings)},
		// V-04: the tool did not finish (deadline, crash, cancellation), so this run
		// must NOT be checkpointed as done — otherwise the next run with the same
		// input hash skips it and the deadline becomes a permanent, silent hole.
		// Status stays non-error on purpose: this is best-effort and must not fail
		// the scan. See task.Result.Incomplete.
		Incomplete: res == nil,
	}, nil
}

// gxssToolName is the tools.lock registry key. Kept as a named constant so the
// test that pins the recorded argv names the same string the dispatch does.
const gxssToolName = "Gxss"

// gxssArgs returns the Gxss arg vector, VERBATIM as it stood before 18-04 moved
// this dispatch onto the Runner: `Gxss -c 100 -p Xss` (RESEARCH §Gxss,
// vulns.sh:27). It is a function rather than an inline literal so
// TestGxssArgvUnchangedAcrossTheMove can assert the process received exactly
// this slice and nothing prepended it.
func gxssArgs() []string { return []string{"-c", "100", "-p", "Xss"} }

// fuzzReplaceURLParams replaces all query parameter values with "FUZZ".
// Implements the qsreplace FUZZ step in pure Go (T-05-17 mitigation).
// Skips URLs where url.Parse fails or there are no query parameters.
func fuzzReplaceURLParams(rawURLs []string) []string {
	var result []string
	for _, raw := range rawURLs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			continue
		}
		qvals := parsed.Query()
		for k := range qvals {
			qvals[k] = []string{"FUZZ"}
		}
		parsed.RawQuery = qvals.Encode()
		result = append(result, parsed.String())
	}
	return result
}

// parseGxssOutput parses Gxss stdout.
// Each non-empty line is a reflection candidate URL.
func parseGxssOutput(data []byte) []FindingRecord {
	if len(data) == 0 {
		return nil
	}
	var records []FindingRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		records = append(records, FindingRecord{
			Type:       "xss",
			Host:       extractHostFromURL(line),
			TemplateID: "gxss-reflection",
			Severity:   "medium",
			MatchedAt:  line,
			Confidence: "medium",
			Refs:       []string{},
		})
	}
	return records
}

// readParamURLsFromJSONL reads artefacts/urls.jsonl and returns URLs containing
// "?" (parameterized URLs that are XSS reflection candidates).
func readParamURLsFromJSONL(app *appctx.AppContext) ([]string, error) {
	urlsPath := filepath.Join(app.Target.WorkDir, "artefacts", "urls.jsonl")
	data, err := os.ReadFile(urlsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // urls.jsonl not yet produced — not an error
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var paramURLs []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		// Filter: only URLs with query parameters (contain "?").
		if rec.URL != "" && strings.Contains(rec.URL, "?") {
			paramURLs = append(paramURLs, rec.URL)
		}
	}
	return paramURLs, nil
}

func init() { task.Register(&GxssTask{}) }
