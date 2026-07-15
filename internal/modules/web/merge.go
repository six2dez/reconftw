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
	// Other stages (waf/findings/urls) have no direct artefact writer preceding their
	// merge, so they are unaffected and keep the staging-only union semantics.
	if stage == "hosts" {
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
