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
//   TakeoverSubzyTask → inputs/takeover.subzy.jsonl
//   TakeoverDNSTakeTask → inputs/takeover.dnstake.jsonl
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

	args := []string{
		"run",
		"--targets", resolvedFile,
		"--verify-ssl",
		"--output", tmpOutFile,
	}

	if _, err := app.Tools.Run(ctx, toolName, args); err != nil {
		if app.Log != nil {
			app.Log.Debug("subzy run failed or tool not registered",
				"tool", toolName, "err", err.Error())
		}
		// Non-fatal: write empty staging file so plan-06 merge doesn't fail.
		stagingPath, wErr := writeTakeoverStagingFile(app, stagingName, nil)
		if wErr != nil {
			return task.Result{Status: task.StatusErrored}, wErr
		}
		return task.Result{
			Status:  task.StatusDone,
			Outputs: []string{stagingPath},
			Stats:   map[string]int{"takeovers_found": 0},
		}, nil
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

	args := []string{"-f", resolvedFile, "-silent"}

	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("dnstake run failed or tool not registered",
				"tool", toolName, "err", err.Error())
		}
		// Non-fatal: write empty staging file.
		stagingPath, wErr := writeTakeoverStagingFile(app, stagingName, nil)
		if wErr != nil {
			return task.Result{Status: task.StatusErrored}, wErr
		}
		return task.Result{
			Status:  task.StatusDone,
			Outputs: []string{stagingPath},
			Stats:   map[string]int{"takeovers_found": 0},
		}, nil
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
// staging file at filepath.Join(app.Target.WorkDir, "inputs", name).
// Creates the inputs/ directory if needed. An empty records slice writes
// an empty file (never returns error for empty input).
func writeTakeoverStagingFile(app *appctx.AppContext, name string, records []TakeoverRecord) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("takeover staging %s: mkdir inputs/: %w", name, err)
	}

	stagingPath := filepath.Join(inputsDir, name)

	var buf bytes.Buffer
	for _, rec := range records {
		line, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	if err := os.WriteFile(stagingPath, buf.Bytes(), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("takeover staging %s: write: %w", name, err)
	}
	return stagingPath, nil
}

// -------------------------------------------------------------------------
// init() — Task self-registration
// -------------------------------------------------------------------------

func init() { task.Register(TakeoverSubzyTask{}) }
func init() { task.Register(TakeoverDNSTakeTask{}) }
