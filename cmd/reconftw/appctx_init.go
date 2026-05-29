// appctx_init.go — helpers for newSubsCmd RunE wiring.
//
// filterByModuleAndEnabled: filters tasks by module + t.Enabled(cfg) + prefix match.
// mergeTakeoverFindings: reads both takeover staging files and calls app.Tree.Append
// exactly once (B2 fix — single-writer invariant for findings artefact).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-06-PLAN.md Task 2.
package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/core/ui"
)

// badgeForStatus maps a task.Status to the corresponding ui.Badge for progress display.
// Used by the StageProgress TaskDone callback wired in runSubsCmd.
//
// task.StatusDone → BadgeOK (tool completed successfully)
// task.StatusSkipped → BadgeSKIP (task disabled or dependency not met)
// task.StatusErrored / StatusCancelled → BadgeFAIL (tool failed or run cancelled)
func badgeForStatus(s task.Status) ui.Badge {
	switch s {
	case task.StatusDone:
		return ui.BadgeOK
	case task.StatusSkipped:
		return ui.BadgeSKIP
	default:
		return ui.BadgeFAIL
	}
}

// filterByModuleAndEnabled returns tasks where:
//   - t.Module() == module
//   - t.Enabled(cfg) == true (REVIEWS finding #4 fix — Scheduler never calls Enabled())
//   - t.Name() has a prefix matching any element of prefixes
//
// Calling t.Enabled(cfg) here is the canonical REVIEWS finding #4 fix: the Scheduler
// never calls Enabled() before Run(), so the command layer MUST gate tasks here.
func filterByModuleAndEnabled(tasks []task.Task, module string, cfg *config.Config, prefixes []string) []task.Task {
	var result []task.Task
	for _, t := range tasks {
		if t.Module() != module {
			continue
		}
		if !t.Enabled(cfg) {
			continue
		}
		if matchesAnyPrefix(t.Name(), prefixes) {
			result = append(result, t)
		}
	}
	return result
}

// matchesAnyPrefix returns true if name has any of the given prefixes.
func matchesAnyPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// mergeTakeoverFindings reads inputs/takeover.subzy.jsonl and
// inputs/takeover.dnstake.jsonl (written by TakeoverSubzyTask and
// TakeoverDNSTakeTask in the enrichment stage), concatenates their lines,
// and calls app.Tree.Append("findings", merged) ONCE.
//
// This is the B2 fix: TakeoverSubzyTask and TakeoverDNSTakeTask each write
// their own staging file (not app.Tree.Append) to avoid concurrent-write
// data loss (OutputTree.Append uses REPLACE semantics). The command layer
// serializes the merge after the enrichment RunStage completes.
//
// Empty or missing staging files are silently ignored (no findings is valid).
// app.Tree.Append is called only when there are non-empty records to write.
func mergeTakeoverFindings(ctx context.Context, app *appctx.AppContext) error {
	_ = ctx // available for future cancellation checks

	subzyPath := filepath.Join(app.Target.WorkDir, "inputs", "takeover.subzy.jsonl")
	dnstakePath := filepath.Join(app.Target.WorkDir, "inputs", "takeover.dnstake.jsonl")

	var merged [][]byte

	for _, p := range []string{subzyPath, dnstakePath} {
		lines, err := readJSONLLines(p)
		if err != nil {
			// Missing or empty staging file is OK — non-fatal.
			if app.Log != nil {
				app.Log.Debug("mergeTakeoverFindings: skipping staging file",
					"path", p, "err", err)
			}
			continue
		}
		merged = append(merged, lines...)
	}

	if len(merged) == 0 {
		return nil
	}

	// Single app.Tree.Append call for "findings" — B2 fix: single-writer invariant.
	if err := app.Tree.Append("findings", merged); err != nil {
		if app.Log != nil {
			app.Log.Debug("mergeTakeoverFindings: Tree.Append failed",
				"records", len(merged), "err", err)
		}
		return err
	}
	return nil
}

// readJSONLLines reads a JSONL file and returns each non-empty line as []byte.
// Returns (nil, error) if the file cannot be opened; returns (lines, nil)
// including an empty slice if the file exists but has no non-empty lines.
func readJSONLLines(path string) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is derived from trusted WorkDir
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		b := scanner.Bytes()
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		// Copy — scanner reuses its internal buffer.
		line := make([]byte, len(b))
		copy(line, b)
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}
