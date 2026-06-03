// nomore403.go — Nomore403Task: 4xx bypass scanner → artefacts/findings.jsonl.
//
// Nomore403Task reads 4xx URLs (status 400-499, excluding 404) from
// artefacts/fuzz.jsonl and runs the nomore403 repo-clone binary to discover
// bypass techniques for hardened 4xx responses.
//
// DEPENDENCY: DependsOn ["web.ffuf"] — reads artefacts/fuzz.jsonl as input.
//
// REPO-CLONE BINARY (RESEARCH §nomore403, Pitfall 2):
// nomore403 is NOT a `go install` tool. It is cloned from GitHub and built
// locally. The binary is resolved via os.Stat (not exec.LookPath) at:
//
//	<tools_dir>/nomore403/nomore403
//
// CRITICAL (T-05-16 / Pitfall 2 mitigation): nomore403 must run with
// cmd.Dir = <tools_dir>/nomore403 because it references wordlists at paths
// relative to its own directory. The absolute binary path is used to avoid
// CWD-relative binary resolution.
//
// INPUT FILTER (RESEARCH §nomore403): only 4xx responses excluding 404 are
// meaningful bypass candidates (v1 vulns.sh:762: grep 4xx not 404, awk $3).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-05-PLAN.md Task 1.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// Nomore403Task runs nomore403 against 4xx URLs and writes bypass findings
// to artefacts/findings.jsonl.
type Nomore403Task struct{}

func (t *Nomore403Task) Name() string        { return "web.nomore403" }
func (t *Nomore403Task) Module() string      { return "web" }
func (t *Nomore403Task) Description() string { return "4xx bypass scanner (nomore403 → findings.jsonl)" }

// Enabled reports whether 4xx bypass scanning is configured.
// Maps to cfg.Vulns.Bypass4xx.Enabled (v1: bypass_4xx flag, default true).
func (t *Nomore403Task) Enabled(cfg *config.Config) bool {
	return cfg.Vulns.Bypass4xx.Enabled
}

// DependsOn returns the DAG edges: nomore403 reads fuzz.jsonl from web.ffuf.
func (t *Nomore403Task) DependsOn() []string { return []string{"web.ffuf"} }

// Run reads 4xx URLs from fuzz.jsonl, invokes nomore403, writes findings.
func (t *Nomore403Task) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	toolsDir := resolveToolsDir(cfg)

	// T-05-16 / Pitfall 2: check binary via os.Stat (not exec.LookPath — repo-clone tool).
	binaryPath := filepath.Join(toolsDir, "nomore403", "nomore403")
	if _, err := os.Stat(binaryPath); err != nil {
		if app.Log != nil {
			app.Log.Info("web.nomore403: binary not found — run reconftw install",
				"path", binaryPath)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read fuzz.jsonl; collect 4xx URLs excluding 404.
	fuzzURLs, err := read4xxURLsFromFuzzJSONL(app)
	if err != nil && app.Log != nil {
		app.Log.Debug("web.nomore403: read fuzz.jsonl error", "err", err)
	}
	if len(fuzzURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.nomore403: no 4xx bypass candidates in fuzz.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Build input payload: newline-separated URLs.
	inputData := []byte(strings.Join(fuzzURLs, "\n") + "\n")

	// Invoke nomore403:
	// v1 form: cd <toolsDir>/nomore403 && ./nomore403 < <input>
	// v2 form: exec.Command(binaryPath) with Stdin + cmd.Dir (T-05-16 mitigation).
	//
	// nomore403 is a repo-clone tool with relative-path wordlist dependencies.
	// Backend.Stream/Run does not expose cmd.Dir or Stdin; exec.Cmd is used
	// directly here as the sanctioned approach for repo-clone tools.
	toolDir := filepath.Join(toolsDir, "nomore403")
	//nolint:gosec // binaryPath validated by os.Stat; toolDir from validated config
	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Dir = toolDir // CRITICAL: nomore403 resolves wordlists relative to its own dir
	cmd.Stdin = bytes.NewReader(inputData)

	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	if runErr := cmd.Run(); runErr != nil {
		// nomore403 may exit non-zero when no bypasses are found; treat as empty.
		if app.Log != nil {
			app.Log.Debug("web.nomore403: process exited non-zero (may be normal)",
				"err", runErr)
		}
	}

	findings := parseNomore403Output(outBuf.Bytes())

	// Write findings to artefacts/findings.jsonl (best_effort D-W12).
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
			stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.nomore403.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("web.nomore403: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.nomore403: completed",
			"input_urls", len(fuzzURLs),
			"bypasses", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"bypasses": len(findings)},
	}, nil
}

// parseNomore403Output parses nomore403 stdout.
// Each non-empty line is a bypass URL/result.
func parseNomore403Output(data []byte) []FindingRecord {
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
			Type:       "http",
			Host:       extractHostFromURL(line),
			TemplateID: "nomore403-bypass",
			Severity:   "medium",
			MatchedAt:  line,
			Confidence: "medium",
			Refs:       []string{},
		})
	}
	return records
}

// read4xxURLsFromFuzzJSONL reads artefacts/fuzz.jsonl and returns URLs with
// status codes 400-499 excluding 404 (bypass candidates per v1 vulns.sh:762).
func read4xxURLsFromFuzzJSONL(app *appctx.AppContext) ([]string, error) {
	fuzzPath := filepath.Join(app.Target.WorkDir, "artefacts", "fuzz.jsonl")
	data, err := os.ReadFile(fuzzPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read fuzz.jsonl: %w", err)
	}
	var urls []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec FuzzRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		// Filter: 4xx excluding 404 (status >= 400 AND <= 499 AND != 404).
		if rec.Status >= 400 && rec.Status <= 499 && rec.Status != 404 && rec.URL != "" {
			urls = append(urls, rec.URL)
		}
	}
	return urls, nil
}

func init() { task.Register(&Nomore403Task{}) }
