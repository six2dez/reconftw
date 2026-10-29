// merge.go — MergeOSINTFindings helper for osint artefact merge phases.
//
// Mirrors internal/modules/vulns/merge.go in shape: reads staging files,
// deduplicates by raw JSON line bytes, and calls app.Tree.Append once as
// the single writer (multi-writer staging contract per doc.go).
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
// Source analog: internal/modules/vulns/merge.go.
package osint

import (
	"bytes"
	"context"
	"fmt"
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
// EMPTY UNION (run isolation). An empty glob, an empty post-dedup set or an empty
// post-scope-filter set PUBLISHES A PRESENT, EMPTY ARTEFACT rather than
// returning nil. "findings" is a Case-A stage: nothing writes
// artefacts/findings.jsonl outside the merge path, so replacing it is safe.
// Returning nil left the PREVIOUS run's findings on disk — workspaces are
// stable across runs — and a stale OSINT finding was republished into the
// report, SARIF, store and notifications of every later run as though this run
// had observed it.
//
// app.Tree.Append errors are returned — callers should log and continue
// (best_effort policy).
func MergeOSINTFindings(ctx context.Context, app *appctx.AppContext, stage string) error {
	pattern := filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("osint.MergeOSINTFindings %s: glob %q: %w", stage, pattern, err)
	}
	if len(matches) == 0 {
		app.Log.Debug("osint.MergeOSINTFindings: no staging files found",
			"stage", stage, "pattern", pattern)
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
			app.Log.Debug("osint.MergeOSINTFindings: error reading staging file",
				"file", fpath, "err", rerr)
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
	// nor url) are preserved by FilterInScope — it applies the same
	// skipScope exemption the gate does, so this filter cannot silently eat
	// the whois/postman/ASN findings that legitimately carry no locator.
	kept, dropped := output.FilterInScope(app.Tree, stage, ordered)
	if dropped > 0 {
		app.Log.Warn("osint.MergeOSINTFindings: dropped records the scope gate would reject",
			"stage", stage, "dropped", dropped, "kept", len(kept))
	}
	if len(kept) == 0 {
		return publishEmptyOSINTStage(app, stage, "every record was rejected by the scope gate")
	}
	ordered = kept

	if err := app.Tree.Append(stage, ordered); err != nil {
		app.Log.Debug("osint.MergeOSINTFindings: Tree.Append failed",
			"stage", stage, "records", len(ordered), "err", err)
		return fmt.Errorf("osint.MergeOSINTFindings %s: Tree.Append: %w", stage, err)
	}

	_ = ctx // available for future cancellation checks
	return nil
}

// publishEmptyOSINTStage publishes a present, zero-length artefact for an empty
// merge union (run isolation). osintStagingPrefixes holds only "findings", which has
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
	app.Log.Debug("osint.MergeOSINTFindings: empty union — published empty artefact",
		"stage", stage, "reason", reason)
	return nil
}

// readOSINTJSONLFile reads a JSONL file and returns each non-empty, non-whitespace
// trimmed line. A missing file is empty (the path comes from a Glob, so it
// exists); a read failure past the line cap is returned, not swallowed.
func readOSINTJSONLFile(path string) ([][]byte, error) {
	var lines [][]byte
	err := output.ForEachJSONLLine(path, 0, func(line []byte) error {
		lines = append(lines, bytes.TrimSpace(line))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lines, nil
}

// osintStagingPrefixes lists the osint pipeline staging artefact names, in
// logical processing order. Only "findings" is multi-writer.
// osint/*.txt human files are single-writer and excluded from this list.
var osintStagingPrefixes = []string{"findings"}

// MergeAllOSINTArtefacts consolidates each osint staging artefact into its
// final artefact file. Called once after all osint pipeline stages complete.
// Non-fatal: errors are logged at Debug level and the function continues
// (best_effort).
//
// The pre-glob "no staging files → skip" shortcut was removed with the empty-union fix:
// MergeOSINTFindings now OWNS the empty case, and skipping the call here would
// have left the previous run's findings artefact in place (run isolation).
func MergeAllOSINTArtefacts(ctx context.Context, app *appctx.AppContext) error {
	var firstErr error
	for _, prefix := range osintStagingPrefixes {
		if mergeErr := MergeOSINTFindings(ctx, app, prefix); mergeErr != nil {
			app.Log.Debug("osint.MergeAllOSINTArtefacts: MergeOSINTFindings failed",
				"stage", prefix, "err", mergeErr)
			if firstErr == nil {
				firstErr = mergeErr
			}
		}
	}
	return firstErr
}
