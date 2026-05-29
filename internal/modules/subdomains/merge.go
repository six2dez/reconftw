// merge.go — MergeStage: the single app.Tree.Append caller for the subdomains artefact.
//
// STAGING CONTRACT (doc.go): MergeStage reads all inputs/<stage>.*.txt staging
// files written by Tasks, deduplicates, converts to SubdomainRecord JSON,
// and calls app.Tree.Append("subdomains", records) EXACTLY ONCE.
//
// MERGED-TXT CONTRACT (04-02):
// After calling Append, MergeStage writes inputs/<stage>.merged.txt — a plain
// newline-delimited hostname file used by subsequent-stage Tasks as their input
// list (e.g. SubActiveTask reads inputs/passive.merged.txt, permutation Tasks
// read inputs/resolved.merged.txt). This keeps the tool invocation pattern
// simple (Task reads one file) and avoids redundant glob+dedup per tool.
//
// This function is NOT a Task. It is called by the command layer (newSubsCmd in
// cmd/reconftw/stub_subcommands.go) after each sequential RunStage call returns.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-01-PLAN.md
// Task 1 Step C (MergeStage). Extended by 04-02 to write merged.txt.
package subdomains

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

// MergeStage reads all inputs/<stage>.*.txt staging files written by passive
// Tasks, deduplicates (case-insensitive, first-seen source wins), converts
// to SubdomainRecord JSON lines, and calls app.Tree.Append("subdomains", records)
// exactly once as the single writer for the passive stage.
//
// stage is the stage prefix (e.g. "passive") used to glob files matching
// filepath.Join(app.Target.WorkDir, "inputs", stage+".*.txt").
//
// On success, returns nil. On error from app.Tree.Append, logs at Debug level
// and returns the error — out-of-scope rejections are expected and logged at
// Debug, not Error.
//
// Empty glob (no staging files written) is a no-op; returns nil with no Append call.
func MergeStage(ctx context.Context, app *appctx.AppContext, stage string) error {
	pattern := filepath.Join(app.Target.WorkDir, "inputs", stage+".*.txt")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("MergeStage %s: glob %q: %w", stage, pattern, err)
	}
	if len(matches) == 0 {
		if app.Log != nil {
			app.Log.Debug("MergeStage: no staging files found", "stage", stage, "pattern", pattern)
		}
		return nil
	}

	// dedupe maps lowercased hostname → first-seen source tool name.
	dedupe := make(map[string]string)
	// Order files for deterministic first-seen assignment.
	sort.Strings(matches)

	for _, fpath := range matches {
		toolName := extractToolName(fpath, stage)
		if err := readStagingFile(fpath, toolName, dedupe); err != nil {
			if app.Log != nil {
				app.Log.Debug("MergeStage: error reading staging file",
					"file", fpath, "err", err)
			}
			// Non-fatal: skip this file, continue with others.
			continue
		}
	}

	if len(dedupe) == 0 {
		return nil
	}

	// Build sorted hostname list for deterministic output.
	hosts := make([]string, 0, len(dedupe))
	for h := range dedupe {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	now := stagingTimestamp()
	records := make([][]byte, 0, len(hosts))
	for _, host := range hosts {
		rec := SubdomainRecord{
			Subdomain: host,
			Source:    dedupe[host],
			FirstSeen: now,
		}
		line, err := json.Marshal(rec)
		if err != nil {
			// Hostname serialization should never fail; skip defensively.
			if app.Log != nil {
				app.Log.Debug("MergeStage: marshal SubdomainRecord failed",
					"host", host, "err", err)
			}
			continue
		}
		records = append(records, line)
	}

	if len(records) == 0 {
		return nil
	}

	// Single app.Tree.Append call — REPLACE semantics are safe because this is
	// the ONLY writer for the "subdomains" artefact in this stage.
	if err := app.Tree.Append("subdomains", records); err != nil {
		if app.Log != nil {
			// Out-of-scope rejections are expected (e.g. wildcard scope
			// filtering); log at Debug, not Error.
			app.Log.Debug("MergeStage: Tree.Append failed",
				"stage", stage,
				"records", len(records),
				"err", err)
		}
		return fmt.Errorf("MergeStage %s: Tree.Append: %w", stage, err)
	}

	// Write inputs/<stage>.merged.txt — plain newline-delimited hostname list
	// used by downstream Tasks as their input file (MERGED-TXT CONTRACT 04-02).
	// Non-fatal: if this write fails we log at Debug and continue — the artefact
	// was already written to Tree successfully.
	mergedPath := filepath.Join(app.Target.WorkDir, "inputs", stage+".merged.txt")
	if writeErr := writeMergedTxt(mergedPath, hosts); writeErr != nil {
		if app.Log != nil {
			app.Log.Debug("MergeStage: write merged.txt failed",
				"path", mergedPath, "err", writeErr)
		}
		// Non-fatal: log and continue.
	}

	_ = ctx // context available for future cancellation checks
	return nil
}

// writeMergedTxt writes a sorted, newline-delimited list of hostnames to path.
// Creates the parent directory if it does not exist.
func writeMergedTxt(path string, hosts []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("writeMergedTxt: mkdir %q: %w", dir, err)
	}
	content := strings.Join(hosts, "\n")
	if len(hosts) > 0 {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644) //nolint:gosec
}

// extractToolName parses the tool name from a staging filename.
// Pattern: inputs/<stage>.<toolName>.txt → returns "<toolName>".
// Falls back to the full basename if parsing fails.
func extractToolName(fpath, stage string) string {
	base := filepath.Base(fpath)
	// base looks like "passive.subfinder.txt" or "passive.github-subdomains.txt"
	prefix := stage + "."
	if !strings.HasPrefix(base, prefix) {
		return base
	}
	name := strings.TrimPrefix(base, prefix)
	name = strings.TrimSuffix(name, ".txt")
	return name
}

// readStagingFile reads a per-source staging file line by line and populates
// the dedupe map. First-seen source wins (earlier file in sorted order wins
// for any given hostname).
func readStagingFile(fpath, toolName string, dedupe map[string]string) error {
	f, err := os.Open(fpath) //nolint:gosec // fpath comes from trusted Glob within WorkDir
	if err != nil {
		return fmt.Errorf("open %q: %w", fpath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		// First-seen source wins for dedup.
		if _, exists := dedupe[line]; !exists {
			dedupe[line] = toolName
		}
	}
	return scanner.Err()
}
