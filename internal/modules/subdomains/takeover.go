// takeover.go — TakeoverSubzyTask + TakeoverDNSTakeTask.
//
// FINDINGS STAGING CONTRACT (doc.go B2 fix):
// Both TakeoverSubzyTask and TakeoverDNSTakeTask run CONCURRENTLY in the
// enrichment RunStage (plan-06). Since OutputTree.Append is REPLACE semantics,
// if both called Append("findings") the second would destroy the first's results.
// Therefore BOTH Tasks write to private staging files; the command layer in
// plan-06 merges them and calls Append("findings", merged) exactly ONCE after
// RunStage returns.
//
//	TakeoverSubzyTask → inputs/takeover.subzy.jsonl
//	TakeoverDNSTakeTask → inputs/takeover.dnstake.jsonl
//
// DO NOT call app.Tree.Append("findings", ...) here.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-05-PLAN.md Task 1.
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// TakeoverSubzyTask
// -------------------------------------------------------------------------

// TakeoverSubzyTask runs subzy to detect HTTP/HTTPS subdomain takeovers.
// Writes TakeoverRecord JSON lines to inputs/takeover.subzy.jsonl staging file.
// Does NOT call app.Tree.Append — B2 fix, see package header.
type TakeoverSubzyTask struct{}

// Name returns the task identifier.
func (TakeoverSubzyTask) Name() string { return "subdomains.takeover.subzy" }

// Module returns the owning module.
func (TakeoverSubzyTask) Module() string { return "subdomains" }

// Description returns a short description.
func (TakeoverSubzyTask) Description() string {
	return "Subdomain takeover detection via subzy (HTTP/HTTPS fingerprinting)"
}

// Enabled returns true when cfg.Subdomains.Takeover.Enabled is set.
func (TakeoverSubzyTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Takeover.Enabled
}

// DependsOn returns nil — sequential RunStage ordering in command layer.
func (TakeoverSubzyTask) DependsOn() []string { return nil }

// Run executes subzy against resolved.merged.txt and writes TakeoverRecord
// JSON lines to inputs/takeover.subzy.jsonl. Does NOT call Tree.Append.
func (TakeoverSubzyTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "subzy"
	const stagingName = "takeover.subzy.jsonl"

	resolvedFile := filepath.Join(app.Target.WorkDir, "inputs", "resolved.merged.txt")

	// Ensure the raw directory exists for temporary output.
	rawDir := filepath.Join(app.Target.WorkDir, "raw")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: mkdir raw/: %w", toolName, err)
	}

	tmpOutFile := filepath.Join(rawDir, "subzy.out.json")

	// --verify_ssl, with an UNDERSCORE. subzy defines the underscore form
	// (`subzy run --help`, v1.2.0 on this box, v2.0.4 in knownToolFlags) and
	// exits `Error: unknown flag: --verify-ssl` on the hyphenated one, so subzy
	// takeover detection produced ZERO results for as long as that vector
	// existed. Found by 16-04 Task 1, fixed here with a real-tool acceptance
	// check (17-04 Task 2) and the knownBadArgVectors entry deleted in the same
	// change.
	args := []string{
		"run",
		"--targets", resolvedFile,
		"--verify_ssl",
		"--output", tmpOutFile,
	}

	if _, err := app.Tools.Run(ctx, toolName, args); err != nil {
		// RULE B1, same shape as the dnstake branch below: the tool FAILED, and
		// reporting that as StatusDone/takeovers_found:0 is indistinguishable from
		// a clean target. WARN so it is visible at the default log level.
		if app.Log != nil {
			app.Log.Warn("subzy: tool failed — takeover detection did not run",
				"event", "takeover_tool_failed",
				"tool", toolName, "err", err.Error())
		}
		// Still write the empty staging file so the plan-06 merge does not fail.
		stagingPath, wErr := writeTakeoverStagingFile(app, stagingName, nil)
		if wErr != nil {
			return task.Result{Status: task.StatusErrored}, wErr
		}
		// nil error preserves CONTINUE_ON_TOOL_ERROR.
		return task.ToolDegraded(toolName, err, stagingPath), nil
	}

	// Parse subzy JSON output. Subzy writes one JSON object per line when
	// using --output; each line has fields: subdomain, vulnerable, service.
	var records []TakeoverRecord
	if data, err := os.ReadFile(tmpOutFile); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var entry struct {
				Subdomain  string `json:"subdomain"`
				Vulnerable bool   `json:"vulnerable"`
				Service    string `json:"service"`
			}
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}
			if !entry.Vulnerable {
				continue
			}
			records = append(records, TakeoverRecord{
				Type:       "subdomain-takeover",
				Host:       entry.Subdomain,
				Service:    entry.Service,
				Confidence: "high",
				Severity:   "high",
				Refs:       []string{},
			})
		}
	}

	stagingPath, err := writeTakeoverStagingFile(app, stagingName, records)
	if err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"takeovers_found": len(records)},
	}, nil
}

// -------------------------------------------------------------------------
// TakeoverDNSTakeTask
// -------------------------------------------------------------------------

// TakeoverDNSTakeTask runs dnstake to detect DNS-level subdomain takeovers.
// Writes TakeoverRecord JSON lines to inputs/takeover.dnstake.jsonl staging file.
// Does NOT call app.Tree.Append — B2 fix, see package header.
type TakeoverDNSTakeTask struct{}

// Name returns the task identifier.
func (TakeoverDNSTakeTask) Name() string { return "subdomains.takeover.dnstake" }

// Module returns the owning module.
func (TakeoverDNSTakeTask) Module() string { return "subdomains" }

// Description returns a short description.
func (TakeoverDNSTakeTask) Description() string {
	return "DNS subdomain takeover detection via dnstake"
}

// Enabled returns true when cfg.Subdomains.Takeover.Enabled is set.
func (TakeoverDNSTakeTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Takeover.Enabled
}

// DependsOn returns nil — sequential RunStage ordering in command layer.
func (TakeoverDNSTakeTask) DependsOn() []string { return nil }

// Run executes dnstake against resolved.merged.txt and writes TakeoverRecord
// JSON lines to inputs/takeover.dnstake.jsonl. Does NOT call Tree.Append.
func (TakeoverDNSTakeTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "dnstake"
	const stagingName = "takeover.dnstake.jsonl"

	resolvedFile := filepath.Join(app.Target.WorkDir, "inputs", "resolved.merged.txt")

	// dnstake's flags are "-t/--target <HOST/FILE>" and "-s/--silent" (v0.1.1
	// --help). This passed "-f <file> -silent"; NEITHER exists, so dnstake exited
	// with `flag provided but not defined: -f` on every run and takeover detection
	// silently produced nothing — the task still reported success because the
	// error was swallowed as "tool not registered" below. v1 pipes stdin with
	// "-c N -s" (modules/subdomains.sh:2084); -t accepts a file, so it is the
	// direct equivalent of the file-based call here.
	args := []string{"-t", resolvedFile, "-s"}

	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		// RULE B1: the tool FAILED and this task continues by design. That is not
		// the same fact as "the tool ran and the target is clean", and conflating
		// them is not hypothetical — this exact branch swallowed dnstake's
		// `flag provided but not defined: -f` as a Debug line and returned
		// StatusDone with takeovers_found: 0, so takeover detection produced zero
		// for months while every run reported success.
		//
		// WARN, not Debug: an operator running at the default level must see it.
		if app.Log != nil {
			app.Log.Warn("dnstake: tool failed — takeover detection did not run",
				"event", "takeover_tool_failed",
				"tool", toolName, "err", err.Error())
		}
		// Still write the (empty) staging file: the merge contract is unchanged.
		stagingPath, wErr := writeTakeoverStagingFile(app, stagingName, nil)
		if wErr != nil {
			return task.Result{Status: task.StatusErrored}, wErr
		}
		// nil error preserves CONTINUE_ON_TOOL_ERROR: the stage keeps going.
		return task.ToolDegraded(toolName, err, stagingPath), nil
	}

	// dnstake outputs one vulnerable subdomain per line (plain text or JSON).
	// Parse each line: if it parses as JSON with a "host" field, use that;
	// otherwise treat the line as a plain subdomain.
	var records []TakeoverRecord
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Try JSON parse first.
		var entry struct {
			Host    string `json:"host"`
			Service string `json:"service"`
		}
		if err := json.Unmarshal(line, &entry); err == nil && entry.Host != "" {
			records = append(records, TakeoverRecord{
				Type:       "subdomain-takeover",
				Host:       entry.Host,
				Service:    entry.Service,
				Confidence: "high",
				Severity:   "high",
				Refs:       []string{},
			})
		} else {
			// Plain text line = vulnerable subdomain.
			records = append(records, TakeoverRecord{
				Type:       "subdomain-takeover",
				Host:       string(line),
				Service:    "unknown",
				Confidence: "medium",
				Severity:   "high",
				Refs:       []string{},
			})
		}
	}

	stagingPath, err := writeTakeoverStagingFile(app, stagingName, records)
	if err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"takeovers_found": len(records)},
	}, nil
}

// -------------------------------------------------------------------------
// Shared helper
// -------------------------------------------------------------------------

// writeTakeoverStagingFile writes TakeoverRecord JSON lines to the given
// staging file at filepath.Join(app.Target.WorkDir, "inputs", name), or REMOVES
// that file when records is empty. Returns the staging path in both cases.
//
// F3 (phase 15): write-or-REMOVE via output.StageJSONL. It previously wrote an
// EMPTY file for zero records, which is one step short: an empty file still
// exists, and "the scanner found nothing" stayed indistinguishable from "the
// scanner did not run" for anything that stats the path.
//
// These takeover.*.jsonl files are read by a FIFTH merger, mergeTakeoverFindings
// (internal/mcp/handlers/common.go), not by any *StagingPrefixes slice.
// Removing them is safe there: it reads each path through readJSONLLines, whose
// os.Open error on a missing file is caught and skipped at Debug before the
// merged set is assembled — verified on the tree at common.go:531-540.
func writeTakeoverStagingFile(app *appctx.AppContext, name string, records []TakeoverRecord) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("takeover staging %s: mkdir inputs/: %w", name, err)
	}

	stagingPath := filepath.Join(inputsDir, name)

	var lines [][]byte
	for _, rec := range records {
		line, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		lines = append(lines, line)
	}

	if err := output.StageJSONL(stagingPath, lines); err != nil {
		return "", fmt.Errorf("takeover staging %s: write: %w", name, err)
	}
	return stagingPath, nil
}

// -------------------------------------------------------------------------
// init() — Task self-registration
// -------------------------------------------------------------------------

func init() { task.Register(TakeoverSubzyTask{}) }
func init() { task.Register(TakeoverDNSTakeTask{}) }
