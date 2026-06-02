// merge.go — MergeStage helper for web artefact merge phases.
//
// Mirrors internal/modules/subdomains/merge.go in shape: reads staging
// files, deduplicates, and calls app.Tree.Append once as the single writer.
//
// The web pipeline uses this for artefacts that accumulate across parallel
// tasks (e.g. URL records from katana + urlfinder + waymore) before the
// final deduplicated write to artefacts/urls.jsonl.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-01-PLAN.md Task 2.
package web

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

// MergeStage reads all inputs/<stage>.*.jsonl staging files written by web
// Tasks, deduplicates JSON lines by their raw byte content, and calls
// app.Tree.Append(<stage>, records) exactly once.
//
// stage is the artefact name (e.g. "urls", "waf") used to:
//   - glob files matching filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
//   - write to app.Tree.Append(stage, ...)
//
// Unlike the subdomains MergeStage which deduplicates plain hostnames,
// the web MergeStage deduplicates by raw JSON line bytes. This is correct
// for structured artefacts where the full record is the unit of uniqueness.
//
// Empty glob (no staging files found) is a no-op; returns nil.
// app.Tree.Append errors are returned — callers should log and continue
// (best_effort policy, D-W12).
func MergeStage(ctx context.Context, app *appctx.AppContext, stage string) error {
	pattern := filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("web.MergeStage %s: glob %q: %w", stage, pattern, err)
	}
	if len(matches) == 0 {
		if app.Log != nil {
			app.Log.Debug("web.MergeStage: no staging files found",
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
		lines, rerr := readJSONLFile(fpath)
		if rerr != nil {
			if app.Log != nil {
				app.Log.Debug("web.MergeStage: error reading staging file",
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
			app.Log.Debug("web.MergeStage: Tree.Append failed",
				"stage", stage, "records", len(ordered), "err", err)
		}
		return fmt.Errorf("web.MergeStage %s: Tree.Append: %w", stage, err)
	}

	_ = ctx // available for future cancellation checks
	return nil
}

// readJSONLFile reads a JSONL file and returns each non-empty, non-whitespace
// trimmed line as a []byte copy. Missing files return (nil, error).
func readJSONLFile(path string) ([][]byte, error) {
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

// webStagingPrefixes lists the web pipeline staging artefact names, in
// logical processing order. Used for reference by the command layer.
var webStagingPrefixes = []string{"hosts", "fuzz", "waf", "origins", "urls", "findings"}

// MergeAllWebArtefacts consolidates each web staging artefact into its
// final artefact file. Called once after all web pipeline stages complete.
// Non-fatal: errors are logged at Debug level and the function continues.
func MergeAllWebArtefacts(ctx context.Context, app *appctx.AppContext) error {
	var firstErr error
	for _, prefix := range webStagingPrefixes {
		// Check if any staging files exist before attempting merge.
		pattern := filepath.Join(app.Target.WorkDir, "inputs", prefix+".*.jsonl")
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		if mergeErr := MergeStage(ctx, app, prefix); mergeErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.MergeAllWebArtefacts: MergeStage failed",
					"stage", prefix, "err", mergeErr)
			}
			if firstErr == nil {
				firstErr = mergeErr
			}
		}
	}
	return firstErr
}
