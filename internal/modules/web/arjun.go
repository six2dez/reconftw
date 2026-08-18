// arjun.go — ArjunTask: parameter discovery → artefacts/findings.jsonl.
//
// ArjunTask discovers hidden HTTP parameters using arjun. Reads URL list from
// artefacts/urls.jsonl, respects ParamMaxURLs cap, writes discovered parameter
// endpoints to artefacts/findings.jsonl.
//
// DEPENDENCY: DependsOn ["web.urldedup"] — reads artefacts/urls.jsonl.
//
// DEEP MODE (RESEARCH §arjun, web.sh:1289; Open Question 1 RESOLVED):
// v1 runs arjun only in DEEP mode. v2 default mirrors this: skip unless
// cfg.Advanced.Deep is true. This matches v1 fidelity (Q1 resolution).
//
// ARG VECTOR (RESEARCH §arjun, web.sh:1329):
//
//	arjun -i <urlfile> -t <threads> -oT <outputfile>
//
// FLAGS: -i (input file), -t (threads), -oT (plain-text output).
// THREADS default: cfg.Advanced.Tools.Arjun.Threads (default 10, v1 AVAILABLE_CORES * 5).
// INPUT CAP: cfg.Web.ParamDiscover.Enabled only; no separate max_urls in config.
//
// XCUT-09 / Pitfall 5: arjun can run up to 2h (tools.lock timeout 7200s).
// Backend.Stream is MANDATORY for heartbeat delivery.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-05-PLAN.md Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// ArjunTask runs arjun for parameter discovery.
type ArjunTask struct{}

func (t *ArjunTask) Name() string        { return "web.arjun" }
func (t *ArjunTask) Module() string      { return "web" }
func (t *ArjunTask) Description() string { return "Parameter discovery (arjun → findings.jsonl)" }

// Enabled reports whether parameter discovery is configured.
func (t *ArjunTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.ParamDiscover.Enabled
}

// DependsOn returns the DAG edges: arjun reads urls.jsonl from web.urldedup.
func (t *ArjunTask) DependsOn() []string { return []string{"web.urldedup"} }

// Run reads urls.jsonl, runs arjun with Backend.Stream, writes param findings.
func (t *ArjunTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "arjun"
	cfg := app.Cfg

	// DEEP mode only (Open Question 1 RESOLVED: v1 default, cfg.Advanced.Deep).
	// DeepOnly behavior: skip if deep mode is not active.
	if !cfg.Advanced.Deep {
		if app.Log != nil {
			app.Log.Info("web.arjun: skipped — deep_only=true and not in deep mode",
				"deep", cfg.Advanced.Deep)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read urls.jsonl for all URLs.
	allURLs, readErr := readAllURLsFromJSONL(app)
	if readErr != nil && app.Log != nil {
		app.Log.Debug("web.arjun: read urls.jsonl error", "err", readErr)
	}
	if len(allURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.arjun: no URLs in urls.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Prepare inputs directory.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.arjun: mkdir inputs/: %w", err)
	}
	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.arjun: mkdir artefacts/: %w", err)
	}

	// Write URL list to temp input file (arjun -i <file>).
	inputFile := filepath.Join(inputsDir, "arjun_input.txt.tmp")
	if err := os.WriteFile(inputFile, []byte(strings.Join(allURLs, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.arjun: write input file: %w", err)
	}
	defer os.Remove(inputFile) //nolint:errcheck

	// Staging output file.
	stagingFile := filepath.Join(artefactsDir, "arjun_output.txt.tmp")
	defer os.Remove(stagingFile) //nolint:errcheck

	// Resolve thread count: prefer cfg.Advanced.Tools.Arjun.Threads; fall back
	// to AVAILABLE_CORES * 5 (v1 ARJUN_THREADS default).
	threads := cfg.Advanced.Tools.Arjun.Threads
	if threads <= 0 {
		threads = runtime.NumCPU() * 5
	}
	if threads <= 0 {
		threads = 10 // absolute fallback
	}

	// Build arg vector (RESEARCH §arjun, web.sh:1329):
	// arjun -i <urlfile> -t <threads> -oT <outputfile>
	args := []string{
		"-i", inputFile,
		"-t", strconv.Itoa(threads),
		"-oT", stagingFile,
	}

	// XCUT-09 / Pitfall 5: arjun runs up to 2h; Backend.Stream is MANDATORY.
	eventCh, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		// arjun not on PATH: StatusSkipped (best_effort D-W12).
		if app.Log != nil {
			app.Log.Info("web.arjun: arjun binary not found or stream failed — skipping",
				"err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	// Drain stream (Backend contract: caller MUST drain until closed).
	for range eventCh { //nolint:revive // intentional drain
	}

	// Parse staging file (plain text, one endpoint per line).
	//
	// F3 (phase 15): the "no output file" case used to `return StatusDone`
	// right here, which SKIPPED the staging write below and left a previous
	// run's inputs/findings.arjun.jsonl for the findings merge to republish.
	// arjun RAN and found no parameters, so it must fall through to the
	// unconditional StageJSONL and clear its own staging.
	var stagingData []byte
	if data, readStagingErr := os.ReadFile(stagingFile); readStagingErr != nil { //nolint:gosec // path within WorkDir
		if !os.IsNotExist(readStagingErr) {
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("web.arjun: read staging file: %w", readStagingErr)
		}
	} else {
		stagingData = data
	}

	findings := parseArjunOutput(stagingData)

	// Stage findings for the findings merge (best_effort D-W12).
	//
	// F3 (phase 15): staged UNCONDITIONALLY. output.StageJSONL removes the
	// staging file when this run produced nothing, so a previous run's arjun
	// findings can never be republished by the merge. This task reaching here
	// means it RAN; the early StatusSkipped returns above never get here.
	var lines [][]byte
	for _, rec := range findings {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.arjun.jsonl")
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("web.arjun: staging write failed",
			"path", stagingPath, "err", wErr)
	}

	if app.Log != nil {
		app.Log.Debug("web.arjun: completed",
			"input_urls", len(allURLs),
			"params", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"params": len(findings)},
	}, nil
}

// parseArjunOutput parses arjun -oT plain-text output.
// Each non-empty line is a discovered parameter endpoint.
func parseArjunOutput(data []byte) []FindingRecord {
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
			Type:       "parameter",
			Host:       extractHostFromURL(line),
			TemplateID: "arjun-param",
			Severity:   "info",
			MatchedAt:  line,
			Confidence: "medium",
			Refs:       []string{},
		})
	}
	return records
}

// readAllURLsFromJSONL reads artefacts/urls.jsonl and returns all URL strings.
func readAllURLsFromJSONL(app *appctx.AppContext) ([]string, error) {
	urlsPath := filepath.Join(app.Target.WorkDir, "artefacts", "urls.jsonl")
	data, err := os.ReadFile(urlsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var urls []string
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
		if rec.URL != "" {
			urls = append(urls, rec.URL)
		}
	}
	return urls, nil
}

func init() { task.Register(&ArjunTask{}) }
