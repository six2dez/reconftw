// shortscan.go — ShortscanTask: IIS short filename scanner → findings staging file.
//
// ShortscanTask reads IIS targets from inputs/findings.nuclei.jsonl (the nuclei
// staging file written by NucleiTask under the staging contract), filtering entries
// where template_id == "iis-version", then runs shortscan per target to discover
// IIS short filename (8.3) vulnerabilities.
//
// DEPENDENCY: DependsOn ["web.nuclei"] — reads inputs/findings.nuclei.jsonl (staging).
//
// INPUT FILTER (RESEARCH §shortscan, web.sh:1609):
// v1 extracts IIS targets from nuclei info.txt: `awk '/iis-version/ {print $4}'`
// v2 reads inputs/findings.nuclei.jsonl (nuclei staging), filtering records where
// TemplateID == "iis-version". No fallback to artefacts/ (WARNING-3 fix).
//
// ARG VECTOR (RESEARCH §shortscan, web.sh:1609-1612 via interlace):
//
//	shortscan <url> -F -s -p 1
//
// FLAGS: -F (follow redirects), -s (silent), -p 1 (path depth 1).
// OUTPUT FILTER: v1 deletes output files not containing "Vulnerable: Yes".
// Only findings with "Vulnerable: Yes" in stdout are written as records.
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
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// ShortscanTask runs shortscan against IIS targets and writes findings.
type ShortscanTask struct{}

func (t *ShortscanTask) Name() string   { return "web.shortscan" }
func (t *ShortscanTask) Module() string { return "web" }
func (t *ShortscanTask) Description() string {
	return "IIS short filename scanner (shortscan → findings.jsonl)"
}

// Enabled reports whether IIS shortname scanning is configured.
func (t *ShortscanTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.IISShortname.Enabled
}

// DependsOn returns the DAG edges: shortscan reads findings.jsonl from web.nuclei.
func (t *ShortscanTask) DependsOn() []string { return []string{"web.nuclei"} }

// Run reads IIS targets from findings.jsonl and runs shortscan per target.
func (t *ShortscanTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Check shortscan binary availability via exec.LookPath.
	shortscanPath, err := exec.LookPath("shortscan")
	if err != nil {
		if app.Log != nil {
			app.Log.Info("web.shortscan: shortscan binary not found — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read inputs/findings.nuclei.jsonl (nuclei staging file); filter records
	// where TemplateID == "iis-version". DependsOn ["web.nuclei"] ensures
	// nuclei's staging file exists before shortscan runs.
	iisTargets, readErr := readIISTargetsFromNucleiStaging(app)
	if readErr != nil && app.Log != nil {
		app.Log.Debug("web.shortscan: read nuclei staging error", "err", readErr)
	}
	if len(iisTargets) == 0 {
		if app.Log != nil {
			app.Log.Info("web.shortscan: no IIS targets found in nuclei staging — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	var allFindings []FindingRecord

	for _, targetURL := range iisTargets {
		findings, runErr := runShortscan(ctx, shortscanPath, targetURL)
		if runErr != nil && app.Log != nil {
			app.Log.Debug("web.shortscan: scan error",
				"url", targetURL, "err", runErr)
		}
		allFindings = append(allFindings, findings...)
	}

	// Stage findings into inputs/findings.shortscan.jsonl (staging contract).
	//
	// F3 (phase 15): staged UNCONDITIONALLY — StageJSONL removes the staging
	// file when this run found no IIS short names, so a previous run's findings
	// cannot be republished.
	var lines [][]byte
	for _, rec := range allFindings {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.shortscan.jsonl")
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("web.shortscan: staging write failed",
			"path", stagingPath, "err", wErr)
	}

	if app.Log != nil {
		app.Log.Debug("web.shortscan: completed",
			"iis_targets", len(iisTargets),
			"findings", len(allFindings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"iis_findings": len(allFindings)},
	}, nil
}

// runShortscan runs shortscan for a single URL.
// ARG VECTOR: shortscan <url> -F -s -p 1  (RESEARCH §shortscan, web.sh:1610).
// Returns findings only if stdout contains "Vulnerable: Yes" (v1 output filter).
func runShortscan(ctx context.Context, shortscanPath, targetURL string) ([]FindingRecord, error) {
	// CR-07: derive bounded context from tools.lock shortscan.timeout_seconds=300.
	toolTimeout := 300 * time.Second
	cmdCtx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()

	//nolint:gosec // shortscanPath from exec.LookPath; targetURL scope-filtered upstream
	cmd := exec.CommandContext(cmdCtx, shortscanPath, targetURL, "-F", "-s", "-p", "1")
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	if err := cmd.Run(); err != nil {
		// shortscan may exit non-zero on non-vulnerable targets; not a fatal error.
		return nil, fmt.Errorf("shortscan %s: %w", targetURL, err)
	}

	output := outBuf.String()

	// v1 filter: only process output containing "Vulnerable: Yes" (web.sh:1611).
	if !strings.Contains(output, "Vulnerable: Yes") {
		return nil, nil
	}

	// Collect output lines as extracted results.
	var extractedLines []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			extractedLines = append(extractedLines, line)
		}
	}

	record := FindingRecord{
		Type:             "iis-shortname",
		Host:             extractHostFromURL(targetURL),
		TemplateID:       "shortscan",
		Severity:         "medium",
		MatchedAt:        targetURL,
		ExtractedResults: extractedLines,
		Confidence:       "high",
		Refs:             []string{},
	}
	return []FindingRecord{record}, nil
}

// readIISTargetsFromNucleiStaging reads inputs/findings.nuclei.jsonl (the nuclei
// staging file written by NucleiTask under the staging contract) and returns URLs
// from records where TemplateID == "iis-version".
//
// This function ONLY reads inputs/findings.nuclei.jsonl. There is NO fallback to
// the merged artefact file — that file may be stale/previous-run data (WARNING-3
// fix). If the staging file is absent, logs an Info message and returns nil, nil.
//
// DependsOn ["web.nuclei"] ensures nuclei has written its staging file before
// shortscan runs.
func readIISTargetsFromNucleiStaging(app *appctx.AppContext) ([]string, error) {
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.nuclei.jsonl")
	data, err := os.ReadFile(stagingPath) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			if app.Log != nil {
				app.Log.Info("web.shortscan: inputs/findings.nuclei.jsonl absent — IIS target detection skipped")
			}
			return nil, nil
		}
		return nil, fmt.Errorf("read inputs/findings.nuclei.jsonl: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var targets []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			TemplateID string `json:"template_id"`
			MatchedAt  string `json:"matched_at"`
			Host       string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.TemplateID == "iis-version" {
			target := rec.MatchedAt
			if target == "" {
				target = rec.Host
			}
			if target != "" {
				targets = append(targets, target)
			}
		}
	}
	return targets, nil
}

func init() { task.Register(&ShortscanTask{}) }
