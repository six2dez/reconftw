// merge.go — MergeOSINTFindings helper for osint artefact merge phases.
//
// Mirrors internal/modules/vulns/merge.go in shape: reads staging files,
// deduplicates by raw JSON line bytes, and calls app.Tree.Append once as
// the single writer (multi-writer staging contract per doc.go — D-O3/D-O5).
//
// The osint pipeline uses this for findings.jsonl, which accumulates across
// parallel scanner tasks (domain_info, ip_info, emails, github_*, cloud_enum,
// postman, swagger, etc.) before the final deduplicated write to
// artefacts/findings.jsonl.
//
// osint/*.txt files (emails.txt, ip_*_whois.txt, azure_tenant_domains.txt) are
// EXCLUDED — they are single-writer human-facing artefacts written directly by
// their owning Tasks. Only findings.jsonl goes through the staging+merge
// pipeline.
//
// Source analog: internal/modules/vulns/merge.go (Phase 6 plan-01 Task 2).
package osint

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// MergeOSINTFindings reads all inputs/<stage>.*.jsonl staging files written by
// osint Tasks, deduplicates JSON lines by their raw byte content, and calls
// app.Tree.Append(<stage>, records) exactly once.
//
// stage is the artefact name (e.g. "findings") used to:
//   - glob files matching filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
//   - write to app.Tree.Append(stage, ...)
//
// Like MergeVulnsFindings, this deduplicates by raw JSON line bytes — correct
// for structured artefacts where the full record is the unit of uniqueness.
//
// EMPTY UNION (F3, 15-03). An empty glob, an empty post-dedup set or an empty
// post-scope-filter set PUBLISHES A PRESENT, EMPTY ARTEFACT rather than
// returning nil. "findings" is a Case-A stage: nothing writes
// artefacts/findings.jsonl outside the merge path, so replacing it is safe.
// Returning nil left the PREVIOUS run's findings on disk — workspaces are
// stable across runs — and a stale OSINT finding was republished into the
// report, SARIF, store and notifications of every later run as though this run
// had observed it.
//
// app.Tree.Append errors are returned — callers should log and continue
// (best_effort policy, D-O8).
func MergeOSINTFindings(ctx context.Context, app *appctx.AppContext, stage string) error {
	pattern := filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("osint.MergeOSINTFindings %s: glob %q: %w", stage, pattern, err)
	}
	if len(matches) == 0 {
		if app.Log != nil {
			app.Log.Debug("osint.MergeOSINTFindings: no staging files found",
				"stage", stage, "pattern", pattern)
		}
		return publishEmptyOSINTStage(app, stage, "no staging files")
	}

	// Sort for deterministic processing order.
	sort.Strings(matches)

	// dedup maps raw JSON line (as string) → present, preserving first-seen order.
	dedup := make(map[string]struct{})
	var ordered [][]byte

	for _, fpath := range matches {
		lines, rerr := readOSINTJSONLFile(fpath)
		if rerr != nil {
			if app.Log != nil {
				app.Log.Debug("osint.MergeOSINTFindings: error reading staging file",
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
		return publishEmptyOSINTStage(app, stage, "staging files held no records")
	}

	// Multi-source aggregator: drop what the scope gate would reject before
	// Append. Company-seeded OSINT records (class=="osint" with neither host
	// nor url, D-O1) are preserved by FilterInScope — it applies the same
	// skipScope exemption the gate does, so this filter cannot silently eat
	// the whois/postman/ASN findings that legitimately carry no locator.
	kept, dropped := output.FilterInScope(app.Tree, stage, ordered)
	if dropped > 0 && app.Log != nil {
		app.Log.Warn("osint.MergeOSINTFindings: dropped records the scope gate would reject",
			"stage", stage, "dropped", dropped, "kept", len(kept))
	}
	if len(kept) == 0 {
		return publishEmptyOSINTStage(app, stage, "every record was rejected by the scope gate")
	}
	ordered = kept

	if err := app.Tree.Append(stage, ordered); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.MergeOSINTFindings: Tree.Append failed",
				"stage", stage, "records", len(ordered), "err", err)
		}
		return fmt.Errorf("osint.MergeOSINTFindings %s: Tree.Append: %w", stage, err)
	}

	_ = ctx // available for future cancellation checks
	return nil
}

// publishEmptyOSINTStage publishes a present, zero-length artefact for an empty
// merge union (F3, 15-03). osintStagingPrefixes holds only "findings", which has
// NO direct app.Tree.Append writer outside the merge path, so this is a Case-A
// stage and an unconditional empty publish is safe.
//
// output.PublishArtefact bypasses app.Tree.Append deliberately: Append
// short-circuits at len(lines) == 0 (internal/core/output/tree.go:59-61) and so
// cannot express an empty publish. Bypassing the scope-enforcement boundary is
// safe HERE SPECIFICALLY because there are no records to scope-check.
func publishEmptyOSINTStage(app *appctx.AppContext, stage, reason string) error {
	if err := output.PublishArtefact(app.Target.WorkDir, stage, nil); err != nil {
		return fmt.Errorf("osint.MergeOSINTFindings %s: publish empty artefact: %w", stage, err)
	}
	if app.Log != nil {
		app.Log.Debug("osint.MergeOSINTFindings: empty union — published empty artefact",
			"stage", stage, "reason", reason)
	}
	return nil
}

// readOSINTJSONLFile reads a JSONL file and returns each non-empty, non-whitespace
// trimmed line as a []byte copy. Missing files return (nil, error).
func readOSINTJSONLFile(path string) ([][]byte, error) {
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

// osintStagingPrefixes lists the osint pipeline staging artefact names, in
// logical processing order. At Phase 7, only "findings" is multi-writer.
// osint/*.txt human files are single-writer and excluded from this list.
var osintStagingPrefixes = []string{"findings"}

// MergeAllOSINTArtefacts consolidates each osint staging artefact into its
// final artefact file. Called once after all osint pipeline stages complete.
// Non-fatal: errors are logged at Debug level and the function continues
// (best_effort, D-O8).
//
// The pre-glob "no staging files → skip" shortcut was removed in 15-03:
// MergeOSINTFindings now OWNS the empty case, and skipping the call here would
// have left the previous run's findings artefact in place (F3).
func MergeAllOSINTArtefacts(ctx context.Context, app *appctx.AppContext) error {
	var firstErr error
	for _, prefix := range osintStagingPrefixes {
		if mergeErr := MergeOSINTFindings(ctx, app, prefix); mergeErr != nil {
			if app.Log != nil {
				app.Log.Debug("osint.MergeAllOSINTArtefacts: MergeOSINTFindings failed",
					"stage", prefix, "err", mergeErr)
			}
			if firstErr == nil {
				firstErr = mergeErr
			}
		}
	}
	return firstErr
}
