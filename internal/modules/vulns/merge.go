// merge.go — MergeVulnsFindings helper for vuln artefact merge phases.
//
// Mirrors internal/modules/web/merge.go in shape: reads staging files,
// deduplicates by raw JSON line bytes, and calls app.Tree.Append once as
// the single writer (multi-writer staging contract per doc.go).
//
// The vulns pipeline uses this for findings.jsonl, which accumulates across
// parallel scanner tasks (dalfox, sqlmap, crlfuzz, commix, etc.) before the
// final deduplicated write to artefacts/findings.jsonl.
//
// gf bucket files (inputs/gf/<class>.txt) are EXCLUDED — they are
// single-writer artefacts written directly by GFTask. Only findings.jsonl
// goes through the staging+merge pipeline.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-01-PLAN.md Task 2.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

// MergeVulnsFindings reads all inputs/<stage>.*.jsonl staging files written by
// vuln Tasks, deduplicates JSON lines by their raw byte content, and calls
// app.Tree.Append(<stage>, records) exactly once.
//
// stage is the artefact name (e.g. "findings") used to:
//   - glob files matching filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
//   - write to app.Tree.Append(stage, ...)
//
// Unlike the subdomains MergeStage which deduplicates plain hostnames,
// MergeVulnsFindings deduplicates by raw JSON line bytes. This is correct for
// structured artefacts where the full record is the unit of uniqueness.
//
// Empty glob (no staging files found) is a no-op; returns nil.
// app.Tree.Append errors are returned — callers should log and continue
// (best_effort policy, D-V7).
func MergeVulnsFindings(ctx context.Context, app *appctx.AppContext, stage string) error {
	pattern := filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("vulns.MergeVulnsFindings %s: glob %q: %w", stage, pattern, err)
	}
	if len(matches) == 0 {
		if app.Log != nil {
			app.Log.Debug("vulns.MergeVulnsFindings: no staging files found",
				"stage", stage, "pattern", pattern)
		}
		return nil
	}

	// Sort for deterministic processing order.
	sort.Strings(matches)

	// dedup maps raw JSON line (as string) → present, preserving first-seen order.
	dedup := make(map[string]struct{})
	var ordered [][]byte

	for _, fpath := range matches {
		lines, rerr := readVulnsJSONLFile(fpath)
		if rerr != nil {
			if app.Log != nil {
				app.Log.Debug("vulns.MergeVulnsFindings: error reading staging file",
					"file", fpath, "err", rerr)
			}
			continue // non-fatal per best_effort policy
		}
		for _, line := range lines {
			key := string(line)
			if _, exists := dedup[key]; !exists {
				dedup[key] = struct{}{}
				ordered = append(ordered, line)
			}
		}
	}

	if len(ordered) == 0 {
		return nil
	}

	if err := app.Tree.Append(stage, ordered); err != nil {
		if app.Log != nil {
			app.Log.Debug("vulns.MergeVulnsFindings: Tree.Append failed",
				"stage", stage, "records", len(ordered), "err", err)
		}
		return fmt.Errorf("vulns.MergeVulnsFindings %s: Tree.Append: %w", stage, err)
	}

	_ = ctx // available for future cancellation checks
	return nil
}

// readVulnsJSONLFile reads a JSONL file and returns each non-empty, non-whitespace
// trimmed line as a []byte copy. Missing files return (nil, error).
func readVulnsJSONLFile(path string) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is from trusted Glob within WorkDir
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	var lines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		b := bytes.TrimSpace(scanner.Bytes())
		if len(b) == 0 {
			continue
		}
		// Copy — scanner reuses its internal buffer.
		line := make([]byte, len(b))
		copy(line, b)
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

// vulnsStagingPrefixes lists the vuln pipeline staging artefact names, in
// logical processing order. At Phase 6, only "findings" is multi-writer.
// gf bucket files are single-writer and excluded from this list.
var vulnsStagingPrefixes = []string{"findings"}

// MergeAllVulnsArtefacts consolidates each vuln staging artefact into its
// final artefact file. Called once after all vuln pipeline stages complete.
// Non-fatal: errors are logged at Debug level and the function continues.
func MergeAllVulnsArtefacts(ctx context.Context, app *appctx.AppContext) error {
	var firstErr error
	for _, prefix := range vulnsStagingPrefixes {
		// Check if any staging files exist before attempting merge.
		pattern := filepath.Join(app.Target.WorkDir, "inputs", prefix+".*.jsonl")
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		if mergeErr := MergeVulnsFindings(ctx, app, prefix); mergeErr != nil {
			if app.Log != nil {
				app.Log.Debug("vulns.MergeAllVulnsArtefacts: MergeVulnsFindings failed",
					"stage", prefix, "err", mergeErr)
			}
			if firstErr == nil {
				firstErr = mergeErr
			}
		}
	}
	return firstErr
}
