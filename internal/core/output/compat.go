// Source:
//   - ADR §4.1 lines 1376-1411 (AtomicSymlink — BINDING, lifted verbatim).
//   - ADR §4.3 lines 1443-1467 (representative V1→V2 mapping table).
//   - ADR §4.4 lines 1469-1489 (compat writer lifecycle — LifecycleAware.OnEnd).
//
// Phase 3 ships the skeleton: AtomicSymlink (production-grade) +
// CompatWriter.WriteCompat (no-op skeleton that creates the _compat/
// subtrees) + V1ToV2Mapping seed table (3 representative entries per
// ADR §4.3). The real symlink farm lifecycle ties in at Phase 12 cutover
// — see Phase 12 plan-01 for the full population work.
package output

import (
	"log/slog"
	"os"
	"path/filepath"
)

// AtomicSymlink creates link → target atomically. Lifted from ADR §4.1
// lines 1392-1404 verbatim, hardened with error wrapping.
//
// The temp-path-in-same-dir pattern ensures os.Rename is atomic (same
// filesystem). os.Symlink is POSIX-atomic; os.Rename over the temp slot
// then atomically swaps the symlink. A reader that opens `link` at any
// point either sees the previous symlink (if any) or the new one;
// neither a stale nor missing intermediate state is observable.
//
// Idempotent: calling twice with the same arguments leaves the symlink
// pointing at target.
func AtomicSymlink(target, link string) error {
	dir := filepath.Dir(link)
	tmp, err := os.CreateTemp(dir, ".symlink-tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = os.Remove(tmpName)
		}
	}()

	// Close + Remove the placeholder file — we need only the unique name
	// slot for os.Symlink to write into.
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}

	if err := os.Symlink(target, tmpName); err != nil {
		return err
	}
	// Atomic swap. After Rename, tmpName no longer exists — flag so the
	// defer skips the (failing) os.Remove.
	if err := os.Rename(tmpName, link); err != nil {
		return err
	}
	cleanedUp = true
	return nil
}

// CompatWriter is the Phase 3 skeleton for the V1 compat symlink farm.
// It registers the LifecycleAware.OnEnd hook surface that Phase 12
// cutover wires up.
//
// Phase 3 contract:
//   - WriteCompat creates the workspaces/<target-id>/_compat/{subdomains,
//     webs, vulns, osint}/ subdirectory structure (so Phase 4-7 module
//     ports can atomic-symlink into it as their lifecycle progresses).
//   - The Recon/<domain> top-level symlink is NOT created in Phase 3 —
//     Phase 12 cutover plan-01 adds that.
//
// Phase 12 swap-in: replace the WriteCompat body with the real
// extraction loop driven by V1ToV2Mapping (read JSONL artefact →
// extract field → write plain-text compat file via WriteFile).
type CompatWriter struct {
	// WorkspaceRoot is the absolute path to workspaces/<target-id>/.
	WorkspaceRoot string
	// ReconDir is the absolute path to Recon/<domain>/ — Phase 12 cutover
	// uses this to create the top-level symlink. Empty in Phase 3.
	ReconDir string
}

// WriteCompat is the Phase 3 NO-OP skeleton. Creates the _compat/ subtree
// and logs a one-line INFO marker pointing at Phase 12 for the real
// implementation. The tree parameter is reserved for the future
// extraction loop — currently unused.
func (c *CompatWriter) WriteCompat(_ *OutputTree) error {
	slog.Info("compat_writer_skeleton",
		"workspace_root", c.WorkspaceRoot,
		"recon_dir", c.ReconDir,
		"note", "Phase 12 will implement the v1 symlink farm per ADR §4.3",
	)
	compatRoot := filepath.Join(c.WorkspaceRoot, "_compat")
	for _, sub := range []string{"subdomains", "webs", "vulns", "osint"} {
		if err := os.MkdirAll(filepath.Join(compatRoot, sub), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// V1ToV2Mapping is the canonical compat-path → artefact-path table.
// Seeded with the 3 representative entries from ADR §4.3 line 1451-1454.
// Phase 12 extends this map with the full 40+ v1 output file shapes
// (per ADR §4.3 "Scope of full mapping" — implemented at Phase 11 cutover).
//
// Key:   compat file path relative to workspaces/<target-id>/.
// Value: canonical artefact path relative to workspaces/<target-id>/.
var V1ToV2Mapping = map[string]string{
	"_compat/subdomains/all.txt": "artefacts/subdomains.jsonl",
	"_compat/webs/webs.txt":      "artefacts/hosts.jsonl",
	"_compat/vulns/findings.txt": "artefacts/findings.jsonl",
	// Phase 12 extends this with at least:
	//   _compat/subdomains/alive.txt → artefacts/hosts.jsonl (.host field)
	//   _compat/osint/...            → artefacts/<various>.jsonl
}
