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
	"github.com/six2dez/reconftw/internal/core/output"
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
// EMPTY UNION (F3, 15-03) — this function is CASE C, and it behaves differently
// from the web/vulns/osint mergers on purpose.
//
//  1. It must NOT publish an empty artefacts/subdomains.jsonl. MergeStage is not
//     the authoritative writer of that artefact — MergeAllSubdomains is (see its
//     doc-comment) — and MergeStage runs once per stage, four times per run in
//     composite modes. An empty publish here would truncate the artefact MID-RUN
//     for every stage that produced nothing, and any consumer reading between
//     that call and MergeAllSubdomains would see an empty file. On an empty union
//     it therefore skips the Append entirely and logs at Debug.
//  2. It MUST still refresh the derived inputs/<stage>.merged.txt intermediate,
//     INCLUDING with an empty file. Eight downstream stages open that path as an
//     input FILE (resolve, permut, recursive ×2, geo, buckets, takeover ×2), so
//     leaving the previous run's copy in place fed run A's hostnames into run B's
//     stages. It writes an EMPTY file rather than removing, because subdomains is
//     PolicyFailFast (internal/core/scheduler/policy.go) and a MISSING input file
//     can fail-fast the whole subdomains spine.
func MergeStage(ctx context.Context, app *appctx.AppContext, stage string) error {
	pattern := filepath.Join(app.Target.WorkDir, "inputs", stage+".*.txt")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("MergeStage %s: glob %q: %w", stage, pattern, err)
	}
	if len(matches) == 0 && app.Log != nil {
		app.Log.Debug("MergeStage: no staging files found", "stage", stage, "pattern", pattern)
	}

	// dedupe maps lowercased hostname → first-seen source tool name.
	dedupe := make(map[string]string)
	// Order files for deterministic first-seen assignment.
	sort.Strings(matches)

	for _, fpath := range matches {
		// Skip the DERIVED intermediate this function itself writes.
		// inputs/<stage>.merged.txt matches this function's own glob
		// <stage>.*.txt, exactly as it matches MergeAllSubdomains' (which skips
		// it the same way at "derived output, not a source"). Without this skip
		// the derived file feeds itself: a run whose producers all found nothing
		// would still see a NON-empty glob — its own previous-run merged.txt —
		// re-merge the PREVIOUS run's hostnames, and rewrite merged.txt with
		// them, so the empty-union refresh below could never be reached and
		// permut/recursive/geo/buckets/takeover kept consuming run A's hosts
		// forever. That is F3 at the derived layer (15-03 Case D).
		if strings.HasSuffix(fpath, ".merged.txt") {
			continue
		}
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

	// Build sorted hostname list for deterministic output.
	hosts := make([]string, 0, len(dedupe))
	for h := range dedupe {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	// Pre-filter out-of-scope hosts BEFORE Append. Append rejects the WHOLE
	// batch on the first out-of-scope line (kernel contract), so a single
	// noisy source line (a cross-domain SAN from crt.sh, an API error string)
	// would otherwise discard every merged host. Dropping them here keeps the
	// multi-source merge resilient while preserving Append's strict per-Task
	// guard. merged.txt is also written from the filtered set so downstream
	// stages only consume in-scope hosts.
	if app.Tree != nil {
		filtered := hosts[:0:0]
		var dropped int
		for _, h := range hosts {
			if app.Tree.InScope(h) {
				filtered = append(filtered, h)
			} else {
				dropped++
			}
		}
		if dropped > 0 && app.Log != nil {
			app.Log.Debug("MergeStage: dropped out-of-scope hosts",
				"stage", stage, "dropped", dropped, "kept", len(filtered))
		}
		hosts = filtered
	}

	// CASE D — refresh the DERIVED inputs/<stage>.merged.txt intermediate on EVERY
	// call, including the empty one, and BEFORE the artefact Append so downstream
	// stages never read a previous run's hostnames.
	//
	// This is NOT producer staging and must NOT be routed through
	// output.StageLines: remove-on-empty is the wrong contract for a file eight
	// consumers open by path in a PolicyFailFast module. It is also the sole
	// reason internal/modules/subdomains/merge.go carries an entry in
	// derivedOutputExemptions in internal/modules/staging_contract_test.go — the
	// name <stage>.merged.txt DOES match this merger's own glob <stage>.*.txt,
	// which is exactly why MergeAllSubdomains has to skip it by hand when
	// collecting sources.
	//
	// Non-fatal: a failure here is logged at Debug and the merge continues.
	mergedPath := filepath.Join(app.Target.WorkDir, "inputs", stage+".merged.txt")
	if writeErr := writeMergedTxt(mergedPath, hosts); writeErr != nil && app.Log != nil {
		app.Log.Debug("MergeStage: write merged.txt failed",
			"path", mergedPath, "err", writeErr)
	}

	if len(hosts) == 0 {
		// CASE C: do NOT publish an empty artefact here — MergeAllSubdomains is the
		// authoritative writer and an empty publish would truncate it mid-run.
		if app.Log != nil {
			app.Log.Debug("MergeStage: empty union — artefact left to MergeAllSubdomains",
				"stage", stage)
		}
		return nil
	}

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
		// Every host failed to marshal (should never happen). Same CASE C rule:
		// leave the artefact to MergeAllSubdomains. merged.txt is already refreshed.
		if app.Log != nil {
			app.Log.Debug("MergeStage: no marshalable records — artefact left to MergeAllSubdomains",
				"stage", stage)
		}
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

	_ = ctx // context available for future cancellation checks
	return nil
}

// subdomainStagingPrefixes are the per-source staging prefixes that
// contribute hostnames to the subdomains.jsonl artefact, in first-seen
// precedence order. ".merged.txt" derived files are excluded by MergeAllSubdomains.
var subdomainStagingPrefixes = []string{"passive", "resolved", "permut", "recursive"}

// MergeAllSubdomains consolidates the UNION of every per-source subdomain
// staging file (passive/resolved/permut/recursive) into subdomains.jsonl,
// scope-filtered. It is the single source of truth for the final artefact.
//
// Why this exists: Tree.Append has REPLACE (truncate) semantics, so the
// per-stage MergeStage calls each OVERWRITE subdomains.jsonl with only that
// stage's hosts — the artefact would end up holding just the last stage's
// output, not the cumulative union. Call this ONCE after all stages complete
// to write the full union. Per-stage MergeStage still produces the
// <stage>.merged.txt files that downstream stages consume as input.
//
// Out-of-scope hosts are dropped (non-fatal); *.merged.txt derived files are
// skipped to avoid double counting.
//
// EMPTY UNION (F3, 15-03). This is the ONE empty-publish site for the
// subdomains artefact — MergeStage is barred from it (CASE C above). An empty
// union here means every producer that ran this invocation found nothing, so
// the artefact is REPLACED with a present, empty file. Returning nil left the
// PREVIOUS run's subdomains on disk (workspaces are stable across runs) and
// republished them into the store, report and notifications of every later run.
// artefacts/subdomains.jsonl has no direct app.Tree.Append writer outside this
// file, so the replace is safe (Case A).
func MergeAllSubdomains(ctx context.Context, app *appctx.AppContext) error {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	dedupe := make(map[string]string)

	for _, prefix := range subdomainStagingPrefixes {
		matches, err := filepath.Glob(filepath.Join(inputsDir, prefix+".*.txt"))
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, fpath := range matches {
			if strings.HasSuffix(fpath, ".merged.txt") {
				continue // derived output, not a source
			}
			toolName := extractToolName(fpath, prefix)
			if rerr := readStagingFile(fpath, toolName, dedupe); rerr != nil && app.Log != nil {
				app.Log.Debug("MergeAllSubdomains: read staging file failed", "file", fpath, "err", rerr)
			}
		}
	}

	if len(dedupe) == 0 {
		return publishEmptySubdomains(app, "no staging files held any hostname")
	}

	hosts := make([]string, 0, len(dedupe))
	for h := range dedupe {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	now := stagingTimestamp()
	records := make([][]byte, 0, len(hosts))
	var dropped int
	for _, host := range hosts {
		if app.Tree != nil && !app.Tree.InScope(host) {
			dropped++
			continue
		}
		line, err := json.Marshal(SubdomainRecord{Subdomain: host, Source: dedupe[host], FirstSeen: now})
		if err != nil {
			continue
		}
		records = append(records, line)
	}
	if dropped > 0 && app.Log != nil {
		app.Log.Debug("MergeAllSubdomains: dropped out-of-scope hosts", "dropped", dropped, "kept", len(records))
	}
	if len(records) == 0 {
		return publishEmptySubdomains(app, "every hostname was rejected by the scope gate")
	}

	if err := app.Tree.Append("subdomains", records); err != nil {
		return fmt.Errorf("MergeAllSubdomains: Tree.Append: %w", err)
	}
	_ = ctx
	return nil
}

// publishEmptySubdomains replaces artefacts/subdomains.jsonl with a present,
// zero-length file (F3, 15-03). Only MergeAllSubdomains may call it — see the
// CASE C note on MergeStage for why the per-stage merge must not.
//
// output.PublishArtefact bypasses app.Tree.Append deliberately: Append
// short-circuits at len(lines) == 0 (internal/core/output/tree.go:59-61) and so
// cannot express an empty publish. Bypassing the scope-enforcement boundary is
// safe HERE SPECIFICALLY because there are no records to scope-check.
func publishEmptySubdomains(app *appctx.AppContext, reason string) error {
	if err := output.PublishArtefact(app.Target.WorkDir, "subdomains", nil); err != nil {
		return fmt.Errorf("MergeAllSubdomains: publish empty artefact: %w", err)
	}
	if app.Log != nil {
		app.Log.Debug("MergeAllSubdomains: empty union — published empty artefact",
			"reason", reason)
	}
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
	defer f.Close() //nolint:errcheck // read/cleanup path

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
