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
// 18-04: THIS FILE NEVER HAD A REASON TO BYPASS THE SEAM, and it is now home.
//
// It was carried for a long time under a blanket allowlist comment asserting
// that the registry "does not support cmd.Dir or stdin injection" — a claim
// about two capabilities THIS FILE DEMANDS NEITHER OF. 18-03 replaced that prose
// with a typed manifest and could find no corroborated reason for it at all, so
// it was declared `pending_removal` with HomeBy 18-04. The four facts, RE-DERIVED
// FROM THIS FILE on 2026-08-26 rather than quoted from a plan:
//
//	0 assignments to a cmd.Stdin field
//	0 assignments to a cmd.Dir field
//	resolution through exec.LookPath("shortscan"), like any registered tool
//	`shortscan` is a tools.lock entry, timeout_seconds = 300
//
// So the verdict is plain: route it onto backend.Runner. It needs no
// ExecOptions, so it uses Run rather than RunOpts — the simpler call.
//
// TIMEOUT: the local 300s context.WithTimeout is GONE. 300 in the manifest, 300
// in this file: they AGREED, which is why the local one was pure duplication
// waiting to drift. tools.lock owns the bound.
//
// DEFAULT ARGS: the shortscan row carries default_args = [], so the argv is
// byte-for-byte the pre-move `<url> -F -s -p 1`, positional target first.
//
// NON-ZERO EXIT: nothing changes here, and that is worth saying because it is
// the one file in this cohort where it does not. runShortscan already returned
// `nil, err` on a non-zero exit and discarded the buffer, so the Runner's
// no-Result-on-error contract reproduces the old behaviour exactly.
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
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
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
	// NO exec.LookPath GATE. An unresolvable shortscan now returns a typed
	// dispatch failure from the Runner and is RECORDED as dispatch_failed rather
	// than vanishing silently; the task's status on an absent binary is
	// unchanged (StatusSkipped, in the loop below).

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
	unresolvable := false

	for _, targetURL := range iisTargets {
		findings, runErr := runShortscan(ctx, app, targetURL)
		if runErr != nil {
			// The tool never started: the same graceful skip the exec.LookPath
			// gate gave, including NO staging write, so a run in which shortscan
			// never ran cannot clear a previous run's findings (F3 did-not-run).
			// WR-06: LATCH, do not return from inside the loop.
			//
			// Returning here threw away every result the earlier iterations had already
			// collected. With CR-04 fixed, a rate-limiter or context error mid-loop IS a
			// dispatch failure, so a Ctrl-C or a task deadline part-way through now
			// reaches this arm and silently discarded a partial but perfectly valid set.
			// The decision belongs after the loop, where "the tool never ran" and "the
			// tool ran for a while then the scan was cancelled" are distinguishable —
			// the pattern web/jsa.go already uses.
			if coreerrors.IsDispatchFailure(runErr) {
				unresolvable = true
				break
			}
			if app.Log != nil {
				app.Log.Debug("web.shortscan: scan error",
					"url", targetURL, "err", runErr)
			}
		}
		allFindings = append(allFindings, findings...)
	}

	// WR-06: only a run that collected NOTHING is a skip — see the loop above.
	if unresolvable && len(allFindings) == 0 {
		if app.Log != nil {
			app.Log.Info("web.shortscan: shortscan unavailable — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if unresolvable && app.Log != nil {
		app.Log.Warn("web.shortscan: dispatch stopped part-way — staging the findings "+
			"collected before it (WR-06)", "findings", len(allFindings))
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
		Status:     task.StatusDone,
		Stats:      map[string]int{"iis_findings": len(allFindings)},
		Incomplete: unresolvable,
	}, nil
}

// shortscanToolName is the tools.lock registry key.
const shortscanToolName = "shortscan"

// shortscanArgs returns the arg vector for one target, VERBATIM as it stood
// before 18-04 moved this dispatch onto the Runner:
//
//	shortscan <url> -F -s -p 1   (RESEARCH §shortscan, v1 web.sh:1610)
//
// The target URL is POSITIONAL and comes FIRST; that ordering is part of the
// vector, and TestShortscanArgvUnchangedAcrossTheMove asserts it in order.
func shortscanArgs(targetURL string) []string {
	return []string{targetURL, "-F", "-s", "-p", "1"}
}

// runShortscan runs shortscan for a single URL through backend.Runner.
// Returns findings only if stdout contains "Vulnerable: Yes" (v1 output filter).
//
// The returned error is the Runner's, wrapped: the caller distinguishes a
// dispatch failure (tool absent — a task-level skip) from a per-target run error
// (best-effort, logged and stepped over), exactly as before.
func runShortscan(ctx context.Context, app *appctx.AppContext, targetURL string) ([]FindingRecord, error) {
	if app == nil || app.Tools == nil {
		return nil, nil
	}
	res, err := app.Tools.Run(ctx, shortscanToolName, shortscanArgs(targetURL))
	if err != nil {
		// shortscan may exit non-zero on non-vulnerable targets; not a fatal
		// error. The old code discarded its buffer on this path too, so the
		// Runner's no-Result-on-error contract changes nothing here.
		return nil, fmt.Errorf("shortscan %s: %w", targetURL, err)
	}

	output := string(res.Stdout)

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
