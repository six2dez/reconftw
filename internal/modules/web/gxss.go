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
// T-05-19 mitigation: Gxss stdout routed to outBuf only; not logged at INFO.
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
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
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
	// Check Gxss binary availability (A11: assumed flags).
	gxssPath, err := exec.LookPath("Gxss")
	if err != nil {
		if app.Log != nil {
			app.Log.Info("web.gxss: Gxss binary not found — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

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

	//nolint:gosec // gxssPath from exec.LookPath; stdinData built from scope-filtered URLs
	cmd := exec.CommandContext(ctx, gxssPath, "-c", "100", "-p", "Xss")
	cmd.Stdin = bytes.NewReader(stdinData)

	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	// Stderr intentionally not captured (T-05-19: no terminal logging of raw output).

	if runErr := cmd.Run(); runErr != nil {
		// Gxss may exit non-zero when no reflections found.
		if app.Log != nil {
			app.Log.Debug("web.gxss: process exited non-zero (may be normal)", "err", runErr)
		}
	}

	findings := parseGxssOutput(outBuf.Bytes())

	// Write reflection hits to artefacts/findings.jsonl (best_effort D-W12).
	if len(findings) > 0 {
		var lines [][]byte
		for _, rec := range findings {
			b, merr := json.Marshal(rec)
			if merr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			if appendErr := app.Tree.Append("findings", lines); appendErr != nil && app.Log != nil {
				app.Log.Debug("web.gxss: Tree.Append failed",
					"records", len(lines), "err", appendErr)
			}
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
	}, nil
}

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
