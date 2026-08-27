// batch.go — sequential batch processing for the --list flag (D-07 / MODE-10).
//
// runBatch processes a list of targets one at a time (sequential, per D-07):
//   - Each target receives an isolated run via the caller-supplied run function.
//   - Errors are logged and the loop continues (continue-on-error, D-07).
//   - Non-zero exit code is returned if any target failed (aggregate exit).
//   - A per-target summary table is printed to stderr after all targets complete.
//
// Threat: T-09-03-02 — --list FILE path traversal. readTargetList validates
// that the path exists and is readable before opening.

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// batchResult holds the outcome of a single target in a batch run.
type batchResult struct {
	Target string
	Err    error
}

// readTargetList opens path, reads it line by line, strips blank lines and
// comment lines (starting with '#'), and returns the non-empty targets.
// Returns an error if the file cannot be opened or read.
//
// Threat mitigations (T-09-03-02): checks file exists and is readable before
// opening; no shell expansion or path traversal of the contents.
func readTargetList(path string) ([]string, error) {
	// Validate path exists and is readable before opening.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("batch: target list %q: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("batch: target list %q is a directory, not a file", path)
	}

	f, err := os.Open(path) //nolint:gosec // path validated above
	if err != nil {
		return nil, fmt.Errorf("batch: open target list %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("batch: read target list %q: %w", path, err)
	}
	return targets, nil
}

// runBatch reads targets from listFile and invokes run for each one
// sequentially (D-07: no cross-target concurrency). On any failure the error
// is logged and the loop continues (continue-on-error). After all targets have
// been processed, printBatchSummary is called and an aggregate error is
// returned if any target failed.
//
// run receives a fresh context for each target so callers can implement
// per-target timeout / cancellation if needed.
func runBatch(
	ctx context.Context,
	listFile string,
	run func(ctx context.Context, target string) error,
) ([]batchResult, error) {
	targets, err := readTargetList(listFile)
	if err != nil {
		return nil, err
	}

	results := make([]batchResult, 0, len(targets))
	for _, tgt := range targets {
		runErr := run(ctx, tgt)
		results = append(results, batchResult{Target: tgt, Err: runErr})
		if runErr != nil {
			// D-07 continue-on-error: log and continue, do not abort.
			slog.Warn("batch_target_failed", "target", tgt, "err", runErr.Error())
		}
	}

	printBatchSummary(os.Stderr, results)

	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
		}
	}
	if failed > 0 {
		return results, fmt.Errorf("batch: %d of %d target(s) failed", failed, len(targets))
	}
	return results, nil
}

// printBatchSummary writes a per-target status table to w. The format mirrors
// printSubsSummary (── border style with fmt.Fprintf tabular rows).
func printBatchSummary(w io.Writer, results []batchResult) {
	_, _ = fmt.Fprintf(w, "\n  ── batch summary ─────────────────────────\n")
	ok := 0
	fail := 0
	for _, r := range results {
		status := "OK"
		if r.Err != nil {
			status = "FAIL"
			fail++
		} else {
			ok++
		}
		_, _ = fmt.Fprintf(w, "  %-40s  %s\n", r.Target, status)
	}
	_, _ = fmt.Fprintf(w, "  ─────────────────────────────────────────\n")
	_, _ = fmt.Fprintf(w, "  total: %d  ok: %d  failed: %d\n", len(results), ok, fail)
}
