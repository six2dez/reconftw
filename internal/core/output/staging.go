// staging.go — the write-or-remove staging lifecycle, and the truncate-on-empty
// artefact publisher.
//
// Phase 15 / audit finding F3 ("results from previous runs persist into later
// ones"). Workspaces are STABLE across runs by design — that is what makes
// checkpoints.db resume work (internal/core/output/init.go). Producers used to
// write their staging file only when they had data:
//
//	if len(findings) > 0 { output.WriteJSONL(stagingPath, lines) }
//
// so a run that observed NOTHING left the previous run's staging file on disk,
// and the next merge republished it. A remediated vulnerability reappeared in
// every subsequent report, and "this run found nothing" was indistinguishable
// from "this run did not look".
//
// The one correct implementation already in the tree is mergeTakeoverFindings
// (internal/mcp/handlers/common.go — "No takeovers this run: REMOVE any staging
// file a previous run left behind"). StageJSONL and StageLines generalise it.
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-03-PLAN.md
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// StageJSONL writes lines to path, or REMOVES path when lines is empty.
//
// Called by a producer task that RAN this invocation. Zero results means this
// run observed nothing, so the staging file from a previous run must be removed
// or the merger will republish it. A task skipped by the checkpoint never calls
// this, so its staging survives and resume still merges its data.
//
// BOUNDARY — these helpers are for PRODUCER staging that a merger globs
// (inputs/<stage>.<tool>.jsonl, inputs/<stage>.<tool>.txt). Two other kinds of
// file under inputs/ must NOT use them:
//
//   - A DERIVED intermediate that a merge regenerates every run and that
//     downstream stages open as an input file — inputs/<stage>.merged.txt
//     (internal/modules/subdomains/merge.go) and inputs/gf/<class>.txt
//     (internal/modules/vulns/gf.go). Remove-on-empty is the wrong contract:
//     their consumers open the path, and subdomains is PolicyFailFast, so a
//     missing file can fail-fast the whole spine. Those write an EMPTY file
//     instead.
//   - A TOOL-INPUT or scratch file — inputs/katana_targets.txt,
//     inputs/wafw00f.hosts.txt, inputs/tmp_sqli.txt, inputs/csprecon.hosts.txt
//     and ~31 more. No merger reads them, they are rebuilt from scratch on
//     every invocation, and routing them through a remove-on-empty helper would
//     change the contract of a file handed to an external binary.
//
// Do not "finish the migration" by routing either category through these
// helpers. The repo-wide guard in internal/modules/staging_contract_test.go is
// STAGING-GLOB-triggered precisely so both categories stay out of scope.
//
// The write path goes through WriteJSONL — the ONLY sanctioned write path
// (temp + fsync + rename + parent-dir fsync, ADR §3.5) — so a concurrent merger
// glob can never observe a half-written staging file. The parent directory is
// created on the write path only; the remove path never creates a directory,
// because a dry run must not touch the filesystem it did not already touch.
func StageJSONL(path string, lines [][]byte) error {
	if len(lines) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("output: StageJSONL: clear stale %s: %w", path, err)
		}
		return nil
	}
	if err := ensureStagingParent(path); err != nil {
		return fmt.Errorf("output: StageJSONL: %w", err)
	}
	return WriteJSONL(path, lines)
}

// StageLines is the plain-text sibling of StageJSONL, for the subdomains
// inputs/<stage>.<tool>.txt staging contract. It writes lines joined by "\n"
// with a trailing "\n", or REMOVES path when the input is empty.
//
// Called by a producer task that RAN this invocation. Zero results means this
// run observed nothing, so the staging file from a previous run must be removed
// or the merger will republish it. A task skipped by the checkpoint never calls
// this, so its staging survives and resume still merges its data.
//
// BOUNDARY — identical to StageJSONL: this is for PRODUCER staging a merger
// globs, NOT for a derived intermediate (inputs/<stage>.merged.txt,
// inputs/gf/<class>.txt — those write an empty file) and NOT for a tool-input
// or scratch file (inputs/katana_targets.txt, inputs/csprecon.hosts.txt, …).
//
// Blank handling: entries are trimmed and empty ones dropped BEFORE the
// empty decision, so a producer that emits []string{""} clears its staging
// rather than writing a file holding one blank line that a downstream
// line-counter reports as 1 result.
//
// The write goes through WriteFile, giving plain-text staging the same
// temp + fsync + rename + parent-dir-fsync guarantee that the ad-hoc
// atomicWriteLines helper (internal/mcp/handlers/common.go) only approximated —
// that one does temp + rename without an fsync.
func StageLines(path string, lines []string) error {
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("output: StageLines: clear stale %s: %w", path, err)
		}
		return nil
	}
	if err := ensureStagingParent(path); err != nil {
		return fmt.Errorf("output: StageLines: %w", err)
	}
	data := []byte(strings.Join(kept, "\n") + "\n")
	return WriteFile(path, data, 0o644)
}

// PublishArtefact writes <workDir>/artefacts/<artefact>.jsonl via WriteJSONL,
// INCLUDING when lines is empty — in which case the artefact becomes a present,
// zero-byte file.
//
// This exists because OutputTree.Append SHORT-CIRCUITS on an empty batch
// (tree.go: `if len(lines) == 0 { return nil }`, before the WriteJSONL at the
// end of the function), so Append(stage, nil) does NOT touch the file and
// cannot express "this run found nothing". Do not change Append's semantics to
// make it able to — other callers depend on the short-circuit.
//
// SCOPE: PublishArtefact performs NO scope check. Tree.Append is the
// scope-enforcement boundary (ADR §3.2) and a caller holding a non-empty batch
// must still go through it. PublishArtefact is correct only for
//   - the EMPTY case, where there are no records to check, or
//   - a caller that has already scope-filtered its batch.
func PublishArtefact(workDir, artefact string, lines [][]byte) error {
	target := filepath.Join(workDir, "artefacts", artefact+".jsonl")
	if err := ensureStagingParent(target); err != nil {
		return fmt.Errorf("output: PublishArtefact: %w", err)
	}
	if err := WriteJSONL(target, lines); err != nil {
		return fmt.Errorf("output: PublishArtefact %s: %w", artefact, err)
	}
	return nil
}

// ensureStagingParent creates the parent directory of path. Called on the WRITE
// path only — never on a remove path, where creating a directory would be a
// side effect on a filesystem the caller is only cleaning up.
func ensureStagingParent(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}
