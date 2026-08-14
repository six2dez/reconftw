// Source:
//   - ADR §3.1 lines 1183-1186 (target-id sanitization mirrors v1
//     lib/validation.sh:sanitize_domain — lowercase, scheme stripped,
//     shell metacharacters rejected).
//   - ADR §3.1 lines 1188-1222 (workspace tree shape).
//   - 15-CONTEXT.md F2 — the sanitized-hostname slug is REPLACED by the
//     canonical target identity in identity.go.
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
	workspace := filepath.Join(rootDir, id.Slug)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return "", fmt.Errorf("output: WorkspaceInit: mkdir workspace: %w", err)
	}
	for _, sub := range []string{"inputs", "artefacts", "raw", "reports", "logs"} {
		if err := os.MkdirAll(filepath.Join(workspace, sub), 0o755); err != nil {
			return "", fmt.Errorf("output: WorkspaceInit: mkdir %s: %w", sub, err)
		}
	}
	return workspace, nil
}
