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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// MergeStage reads all inputs/<stage>.*.jsonl staging files written by web
// Tasks, deduplicates JSON lines by their raw byte content, and calls
// app.Tree.Append(<stage>, records) exactly once.
//
// stage is the artefact name (e.g. "urls", "waf") used to:
//   - glob files matching filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")
//   - write to app.Tree.Append(stage, ...)
//
// The web MergeStage deduplicates by raw JSON line bytes for every stage EXCEPT
// "hosts", which dedups by DECODED host identity (one artefact line per host —
// IN-13-03) because httpx/wellknown/portscan emit different JSON shapes for the
// SAME host ({"host":"x","tech":[…]} vs {"host":"x","ip":…,"port":…}); raw-byte
// dedup would let all of them survive and a line-counting consumer would over-count.
// Raw-byte dedup remains correct for the other structured artefacts where the full
// record is the unit of uniqueness.
//
// EMPTY UNION (F3, 15-03). An empty glob, an empty post-dedup set or an empty
// post-scope-filter set is NOT a no-op. Workspaces are stable across runs, so
// returning nil left the PREVIOUS run's artefact in place and every downstream
// consumer — report, SARIF, store, notifications — reported a stale finding as
// though this run had observed it. The empty case now dispatches through
// publishEmptyStage:
//
//   - Case A (waf, findings — no direct artefact writer): publish a present,
//     empty artefact, so "this run found nothing" is representable.
//   - Case B (directArtefactWriterStages): never truncate a non-empty artefact
//     the merge does not own.
//
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
		return publishEmptyStage(app, stage, "no staging files")
	}

	// Sort for deterministic processing order.
	sort.Strings(matches)

	// dedup key: the "hosts" stage keys by DECODED host identity so same-host
	// records of different JSON shape collapse to one artefact line (IN-13-03);
	// every other stage keys by raw JSON bytes (full-record uniqueness).
	keyFor := func(line []byte) string { return string(line) }
	if stage == "hosts" {
		keyFor = hostsDedupKey
	}

	// dedup maps the stage key → present, preserving first-seen order.
	dedup := make(map[string]struct{})
	var ordered [][]byte

	// REPLACE-preservation for the "hosts" artefact (13-08): web.httpx is a DIRECT
	// writer of artefacts/hosts.jsonl via app.Tree.Append, which has REPLACE
	// semantics. A hosts merge sourced from the portscan/nerva/wellknown staging
	// files (inputs/hosts.*.jsonl) must therefore UNION the existing artefact FIRST,
	// otherwise the subsequent Tree.Append would overwrite httpx's probed hosts.
	// The existing artefact lines are seeded first (preserving order + dedup key) so
	// portscan/nerva/wellknown records are ADDED to, not substituted for, httpx's.
	// Other stages (waf/findings/urls) have no direct artefact writer preceding
	// their merge, so they keep the staging-only union semantics.
	//
	// "findings" used to be an exception that this comment wrongly denied:
	// mergeTakeoverFindings wrote takeover records straight to the artefact
	// during the subs stage, and the REPLACE here erased them in every composite
	// mode. That was fixed at the source — takeover now stages to
	// inputs/findings.takeover.jsonl — so the artefact stays a pure function of
	// the staging files and no preservation branch is needed here. Any future
	// direct writer of artefacts/findings.jsonl reintroduces the bug; stage it
	// instead.
	if artefactSeedStages[stage] {
		existingArtefact := filepath.Join(app.Target.WorkDir, "artefacts", stage+".jsonl")
		if existingLines, rerr := readJSONLFile(existingArtefact); rerr == nil {
			for _, line := range existingLines {
				key := keyFor(line)
				if _, exists := dedup[key]; !exists {
					dedup[key] = struct{}{}
					ordered = append(ordered, line)
				}
			}
		}
	}

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
			key := keyFor(line)
			if _, exists := dedup[key]; !exists {
				dedup[key] = struct{}{}
				ordered = append(ordered, line)
			}
		}
	}

	if len(ordered) == 0 {
		return publishEmptyStage(app, stage, "staging files held no records")
	}

	// Multi-source aggregator: drop what the scope gate would reject before
	// Append, so one noisy record from one producer cannot discard the merged
	// batch from all the others. Pass-through artefacts (fuzz, waf, origins)
	// keep every syntactically valid line — FilterInScope dispatches on the
	// artefact exactly as Append does.
	kept, dropped := output.FilterInScope(app.Tree, stage, ordered)
	if dropped > 0 && app.Log != nil {
		app.Log.Warn("web.MergeStage: dropped records the scope gate would reject",
			"stage", stage, "dropped", dropped, "kept", len(kept))
	}
	if len(kept) == 0 {
		return publishEmptyStage(app, stage, "every record was rejected by the scope gate")
	}
	ordered = kept

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

// artefactSeedStages lists the stages whose merge must SEED the union with the
// EXISTING artefact before folding in the staging files. This is the 13-08
// union-preservation behaviour and it is scoped to "hosts" ALONE: the
// portscan/nerva/wellknown host records must be ADDED to httpx's probed hosts,
// not substituted for them.
//
// Do NOT widen this set. Applying it to "urls" would re-import the pre-dedup
// staging URLs on top of urldedup's deduplicated artefact, undoing WEB-14.
//
// This is a DIFFERENT concern from directArtefactWriterStages below (which is
// about never TRUNCATING an artefact the merge does not own); they are two
// named sets precisely so a later reader cannot conflate them.
var artefactSeedStages = map[string]bool{"hosts": true}

// directArtefactWriterStages lists the merged stages whose artefact ALSO has a
// direct app.Tree.Append writer OUTSIDE the merge path. Evidence, verified on
// the tree (grep -rn 'Tree\.Append(' internal/ --include='*.go' | grep -v _test):
//
//	hosts   → internal/modules/web/httpx.go:228, internal/modules/subdomains/geo.go:196
//	          (staging producers: web/portscan.go, web/wellknown.go)
//	fuzz    → internal/modules/web/ffuf.go:203            (NO staging producer — glob is permanently empty)
//	origins → internal/modules/web/hakoriginfinder.go:146 (NO staging producer — glob is permanently empty)
//	urls    → internal/modules/web/urldedup.go:230
//	          (staging producers: katana, urlfinder, waymore, subjs, jsluice, jsa)
//
// THE RULE THIS SET ENCODES IS ABOUT THE MERGE ONLY: the merge is not the
// authoritative writer of these four artefacts and must never truncate them.
// An unconditional empty-publish would zero artefacts/fuzz.jsonl and
// artefacts/origins.jsonl in the very run ffuf and hakoriginfinder produced
// them — their globs are permanently empty — and web/nomore403.go,
// vulns/bypass4xx.go and web/portscan.go would then consume the empty files.
//
// IT DOES NOT SAY THESE FOUR ARTEFACTS ARE NEVER EMPTIED. They MUST be emptied
// when their own direct writer RUNS and finds nothing — that is F3 for them,
// and it is delivered by plan 15-13 Task 3 at web/ffuf.go,
// web/hakoriginfinder.go, web/urldedup.go and web/httpx.go. The empty-publish
// belongs to the producer because only the producer can tell "did not run"
// (preserve) from "ran and found nothing" (empty); the merge cannot, which is
// exactly why the never-truncate rule belongs here.
var directArtefactWriterStages = map[string]bool{
	"hosts":   true,
	"fuzz":    true,
	"origins": true,
	"urls":    true,
}

// publishEmptyStage handles a merge whose union came out EMPTY (F3, 15-03).
//
// Case A (stage NOT in directArtefactWriterStages — waf, findings): publish a
// present, zero-length artefact so "this run found nothing" is representable
// and distinguishable from "this run did not look".
//
// Case B (stage IN directArtefactWriterStages): publish empty ONLY when the
// existing artefact is also empty (absent, or zero non-blank lines). Otherwise
// leave it untouched and log the retained line count at Debug.
func publishEmptyStage(app *appctx.AppContext, stage, reason string) error {
	if directArtefactWriterStages[stage] {
		existing := filepath.Join(app.Target.WorkDir, "artefacts", stage+".jsonl")
		if n := countArtefactLines(existing); n > 0 {
			if app.Log != nil {
				app.Log.Debug("web.MergeStage: empty union — artefact retained, the merge does not own it",
					"stage", stage, "reason", reason, "retained", n)
			}
			return nil
		}
	}
	// output.PublishArtefact bypasses app.Tree.Append deliberately: Append
	// short-circuits at len(lines) == 0 (internal/core/output/tree.go:59-61) and
	// so cannot express an empty publish. Bypassing the scope-enforcement
	// boundary is safe HERE SPECIFICALLY because there are no records to
	// scope-check.
	if err := output.PublishArtefact(app.Target.WorkDir, stage, nil); err != nil {
		return fmt.Errorf("web.MergeStage %s: publish empty artefact: %w", stage, err)
	}
	if app.Log != nil {
		app.Log.Debug("web.MergeStage: empty union — published empty artefact",
			"stage", stage, "reason", reason)
	}
	return nil
}

// countArtefactLines returns the number of non-blank lines in a JSONL file.
// A missing or unreadable file counts as 0.
func countArtefactLines(path string) int {
	lines, err := readJSONLFile(path)
	if err != nil {
		return 0
	}
	return len(lines)
}

// hostsDedupKey returns the dedup identity for a "hosts"-stage JSON line (IN-13-03).
// httpx, wellknown and portscan all emit a "host" field but with different record
// shapes; keying by the decoded, trimmed, lower-cased host collapses those to ONE
// artefact line per host (DNS hostnames are case-insensitive). A line that is not
// parseable JSON, or that carries no non-empty host, falls back to its raw bytes in
// a separate namespace ("raw\x00…") so malformed or host-less records are never
// merged together and never collide with a real host key.
func hostsDedupKey(line []byte) string {
	var rec struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(line, &rec); err == nil {
		if h := strings.ToLower(strings.TrimSpace(rec.Host)); h != "" {
			return "host\x00" + h
		}
	}
	return "raw\x00" + string(line)
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
//
// The pre-glob "no staging files → skip" shortcut this function used to carry
// was removed in 15-03: MergeStage now OWNS the empty case (publish empty for
// Case A, never truncate for Case B), and skipping the call here would have
// left the previous run's artefact in place. NOTE this function is called only
// from tests and doc comments — production calls MergeStage directly
// (internal/mcp/handlers/web.go, internal/mcp/handlers/composite.go), which is
// why the fix has to live in MergeStage and not here.
func MergeAllWebArtefacts(ctx context.Context, app *appctx.AppContext) error {
	var firstErr error
	for _, prefix := range webStagingPrefixes {
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
