// Source:
//   - ADR §3.1 lines 1183-1186 (target-id sanitization mirrors v1
//     lib/validation.sh:sanitize_domain — lowercase, scheme stripped,
//     shell metacharacters rejected).
//   - ADR §3.1 lines 1188-1222 (workspace tree shape).
//   - 15-CONTEXT.md F2 — the sanitized-hostname slug is REPLACED by the
//     canonical target identity in identity.go.
package output

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// IdentityMarkerName is the per-workspace file recording which canonical target
// owns the directory. Its presence is what lets a later run distinguish "this
// workspace is mine" from "this workspace belongs to a different engagement".
const IdentityMarkerName = ".target-identity.json"

// workspaceIdentityMarker is the on-disk payload of IdentityMarkerName. The
// TargetIdentity fields are embedded (flattened in JSON), so the file reads:
//
//	{"raw":"…","canonical":"…","kind":"domain","slug":"…","adopted_from":""}
//
// adopted_from names the legacy directory this workspace was renamed from on
// the first run after upgrading, and is empty otherwise. It is the audit trail
// for the most destructive operation in this package.
type workspaceIdentityMarker struct {
	TargetIdentity
	AdoptedFrom string `json:"adopted_from"`
}

// WorkspaceInit creates (or reuses) the STABLE per-target workspace directory
// under rootDir and returns its path. The directory name is the CANONICAL
// TARGET IDENTITY slug with NO timestamp suffix:
// filepath.Join(rootDir, "<readable>-<hash8>").
//
// IDENTITY RULE (F2): the slug comes from CanonicalTargetID, not from a plain
// sanitized hostname. It preserves the target's kind (domain / IP / CIDR) and
// its full canonical form — including a CIDR's prefix length — inside an
// 8-hex-character SHA-256 suffix. The previous rule split the target on the
// first '/', so 10.0.0.0/24, 10.0.0.0/16 and the bare IP 10.0.0.0 all addressed
// ONE workspace and therefore shared one inputs/, one artefacts/ and one
// checkpoints.db across three distinct engagements. Two structurally different
// targets can no longer collide.
//
// STABILITY RATIONALE (INTEG-03 — resume across runs): a stable, timestamp-free
// directory is what lets <workspace>/checkpoints.db persist across invocations,
// so a second `reconftw <mode> --target X` run resumes from checkpoints instead
// of redoing completed work. A fresh timestamped dir each run would orphan the
// prior checkpoints.db and defeat resume entirely. The canonical identity is a
// pure function of the target, so it is just as stable as the old slug. The
// queryable cross-run scan history lives in the SHARED <dataDir>/store.db
// (INTEG-01), not in per-run workspace copies, so dropping the timestamp loses
// no history.
//
// Idempotent: a second call for the same (rootDir, target) returns the same
// path and re-creates the standard subdirs via os.MkdirAll without error,
// preserving any files (checkpoints.db, artefacts, …) written by a prior run.
//
// MIGRATION (first run after upgrading to the identity slug): the directory
// name changes for every pre-existing target. adoptLegacyWorkspace renames an
// UNAMBIGUOUS legacy directory onto the new slug before anything is created, so
// checkpoints.db, inputs/, artefacts/, reports/, logs/ and _compat/ move with
// it. Ambiguous legacy names are left untouched — see adoptLegacyWorkspace.
func WorkspaceInit(rootDir, target string) (string, error) {
	if rootDir == "" {
		return "", fmt.Errorf("output: WorkspaceInit: empty rootDir")
	}
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("output: WorkspaceInit: empty target")
	}
	id, err := CanonicalTargetID(target)
	if err != nil {
		return "", err
	}

	// Adoption runs BEFORE MkdirAll: once the new slug directory exists, the
	// legacy tree can no longer be moved onto it without merging.
	adoptedFrom, err := adoptLegacyWorkspace(rootDir, id)
	if err != nil {
		return "", err
	}

	workspace := filepath.Join(rootDir, id.Slug)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return "", fmt.Errorf("output: WorkspaceInit: mkdir workspace: %w", err)
	}
	for _, sub := range []string{"inputs", "artefacts", "raw", "reports", "logs"} {
		if err := os.MkdirAll(filepath.Join(workspace, sub), 0o755); err != nil {
			return "", fmt.Errorf("output: WorkspaceInit: mkdir %s: %w", sub, err)
		}
	}

	// The marker write is FATAL, not best-effort. It is the only mechanism the
	// marker branch of adoptLegacyWorkspace has for telling "this directory is
	// mine" from "this directory belongs to a different engagement"; silently
	// swallowing a write failure would disarm that safety check for every
	// subsequent run — strictly worse than refusing to start.
	if err := writeIdentityMarker(workspace, id, adoptedFrom); err != nil {
		return "", fmt.Errorf("output: WorkspaceInit: write identity marker: %w", err)
	}
	return workspace, nil
}

// writeIdentityMarker persists id (plus the adopted-from audit field) into
// <workspace>/.target-identity.json through the sanctioned atomic writer.
// Called on EVERY WorkspaceInit — intentionally idempotent.
func writeIdentityMarker(workspace string, id TargetIdentity, adoptedFrom string) error {
	data, err := json.MarshalIndent(workspaceIdentityMarker{
		TargetIdentity: id,
		AdoptedFrom:    adoptedFrom,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return WriteFile(filepath.Join(workspace, IdentityMarkerName), data, 0o644)
}

// readIdentityMarker loads <workspace>/.target-identity.json. A missing file
// returns an error satisfying os.IsNotExist — callers MUST distinguish that
// (the pre-upgrade state) from a corrupt marker.
func readIdentityMarker(workspace string) (workspaceIdentityMarker, error) {
	data, err := os.ReadFile(filepath.Join(workspace, IdentityMarkerName)) //nolint:gosec // path built from a sanitized slug
	if err != nil {
		return workspaceIdentityMarker{}, err
	}
	var m workspaceIdentityMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return workspaceIdentityMarker{}, fmt.Errorf("output: parse identity marker: %w", err)
	}
	return m, nil
}

// beforeAdoptRename is a test-only seam. It is nil in production and MUST
// stay nil; the adoption concurrency test sets it to force both goroutines
// past the existence check above before either renames, so the os.IsNotExist
// convergence branch below is actually exercised.
var beforeAdoptRename func()

// adoptLegacyWorkspace renames a workspace written by a PRE-IDENTITY release
// onto the new canonical slug, returning the legacy directory name it adopted
// ("" when it adopted nothing).
//
// WHY THIS EXISTS. CLAUDE.md declares the per-target output tree a public
// contract. Changing the directory name from "example.com" to
// "example.com-a1b2c3d4" orphans, for every existing installation:
// <workspace>/checkpoints.db (the documented reason the slug is timestamp-free),
// <workspace>/_compat/ (the 6-month bash→Go compatibility tree), every staged
// and merged artefact, and the targets.recon_dir values already in store.db.
// Without adoption the next run silently creates an empty tree beside the old
// one, resume restarts from zero, and NO gate detects it.
//
// WHY IT IS THE MOST DANGEROUS CODE IN THE PACKAGE. It moves whole engagements,
// it runs on the hottest path, and it runs UNLOCKED — the workspace flock is
// acquired only after WorkspaceInit returns. Two preconditions are therefore
// non-negotiable, and both are easy to omit without any test noticing:
//
//   - An ambiguous legacy name must be refused EVEN WHEN NO MARKER EXISTS. That
//     is the state of every pre-upgrade directory, since the marker is
//     introduced by the same change as the rename. LegacyTargetSlug splits on
//     the first '/', so 10.0.0.0/24, 10.0.0.0/16 and the bare 10.0.0.0 all
//     produce "10.0.0.0": adopting without the check would let the first target
//     to run after the upgrade claim up to three engagements' checkpoints.db,
//     inputs/, artefacts/ and _compat/ as its own — re-materialising F2 through
//     the fix for F2. Refusing is always safe: nothing is deleted and the
//     operator is told.
//   - A LOST adoption race must converge, not fail. Two concurrent first runs
//     can both reach the rename; the loser's ENOENT is benign and must not kill
//     a legitimate scan.
func adoptLegacyWorkspace(rootDir string, id TargetIdentity) (string, error) {
	// 1. Nothing to adopt when the old and new names agree (or there is no old
	//    name at all).
	legacy := LegacyTargetSlug(id.Raw)
	if legacy == "" || legacy == id.Slug {
		return "", nil
	}

	// 2. No legacy directory on disk.
	legacyPath := filepath.Join(rootDir, legacy)
	info, err := os.Stat(legacyPath)
	if err != nil || !info.IsDir() {
		return "", nil
	}

	// 3. The new workspace is authoritative — NEVER merge two trees.
	newPath := filepath.Join(rootDir, id.Slug)
	if _, statErr := os.Stat(newPath); statErr == nil {
		slog.Warn("workspace_adoption_declined",
			"reason", "new workspace already exists; not merging",
			"legacy", legacyPath, "workspace", newPath)
		return "", nil
	}

	marker, markerErr := readIdentityMarker(legacyPath)
	switch {
	case markerErr == nil:
		// 4a. Claimed directory: adopt only when it is claimed by US.
		if marker.Canonical != id.Canonical {
			slog.Warn("workspace_adoption_declined",
				"reason", "legacy workspace is claimed by a different target identity",
				"legacy", legacyPath,
				"legacy_canonical", marker.Canonical,
				"target_canonical", id.Canonical)
			return "", nil
		}
	case os.IsNotExist(markerErr):
		// 4b. THE UPGRADE PATH — the only branch that fires in practice.
		// Adopt only when the legacy name is provably unambiguous: the old
		// sanitizer left a domain untouched, so no other input folded onto it.
		// Every KindIP and KindCIDR target is ambiguous by construction, and so
		// is any domain the sanitizer rewrote.
		if id.Kind != KindDomain || legacy != id.Canonical {
			slog.Warn("workspace_adoption_declined",
				"reason", "legacy workspace could have been produced by more than one target identity; not adopting — reconcile by hand",
				"legacy", legacyPath,
				"target", id.Raw,
				"kind", id.Kind)
			return "", nil
		}
	default:
		// A marker exists but cannot be read or parsed. Refuse: an unreadable
		// claim is not an absent claim.
		slog.Warn("workspace_adoption_declined",
			"reason", "legacy identity marker is unreadable",
			"legacy", legacyPath, "err", markerErr)
		return "", nil
	}

	if beforeAdoptRename != nil {
		beforeAdoptRename()
	}

	// 5. Rename within one parent directory is atomic on POSIX, so a crash
	//    mid-adoption leaves exactly one of the two names and the next run
	//    converges.
	if renameErr := os.Rename(legacyPath, newPath); renameErr != nil {
		// BENIGN CONVERGENCE. WorkspaceInit runs before the workspace flock is
		// acquired, so two first runs after an upgrade can both reach this
		// line. One rename wins; the loser gets ENOENT on the SOURCE. If the
		// destination now exists, the other process already did the work and
		// this run must proceed normally. Hard-failing here would kill a
		// legitimate scan over a race that caused no damage.
		if os.IsNotExist(renameErr) {
			if newInfo, statErr := os.Stat(newPath); statErr == nil && newInfo.IsDir() {
				return "", nil
			}
		}
		// Every OTHER rename error is fatal: a half-adopted state must be loud.
		return "", fmt.Errorf("output: WorkspaceInit: adopt legacy workspace %q: %w", legacyPath, renameErr)
	}

	slog.Info("workspace_adopted",
		"legacy", legacyPath, "workspace", newPath, "target", id.Raw)
	return legacy, nil
}
