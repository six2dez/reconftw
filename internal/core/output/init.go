// Source:
//   - ADR §3.1 lines 1183-1186 (target-id sanitization mirrors v1
//     lib/validation.sh:sanitize_domain — lowercase, scheme stripped,
//     shell metacharacters rejected).
//   - ADR §3.1 lines 1188-1222 (workspace tree shape).
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// WorkspaceInit creates (or reuses) the STABLE per-target workspace directory
// under rootDir and returns its path. The directory name is the sanitized
// target slug with NO timestamp suffix: filepath.Join(rootDir, "<slug>").
//
// STABILITY RATIONALE (INTEG-03 — resume across runs): a stable, timestamp-free
// directory is what lets <workspace>/checkpoints.db persist across invocations,
// so a second `reconftw <mode> --target X` run resumes from checkpoints instead
// of redoing completed work. A fresh timestamped dir each run would orphan the
// prior checkpoints.db and defeat resume entirely. The queryable cross-run scan
// history lives in the SHARED <dataDir>/store.db (INTEG-01), not in per-run
// workspace copies, so dropping the timestamp loses no history. This is the
// "one dir per target" option from 12-CONTEXT.md (Claude's Discretion), and is
// consistent with the single-operator / no-concurrent-runs-per-target contract
// (CLAUDE.md).
//
// Idempotent: a second call for the same (rootDir, target) returns the same
// path and re-creates the standard subdirs via os.MkdirAll without error,
// preserving any files (checkpoints.db, artefacts, …) written by a prior run.
//
// Sanitization mirrors v1 lib/validation.sh:sanitize_domain — strips URL scheme,
// drops any path component, lowercases, replaces non-alphanumeric characters
// with `_`.
func WorkspaceInit(rootDir, target string) (string, error) {
	if rootDir == "" {
		return "", fmt.Errorf("output: WorkspaceInit: empty rootDir")
	}
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("output: WorkspaceInit: empty target")
	}
	slug := sanitizeTargetName(target)
	if slug == "" {
		return "", fmt.Errorf("output: WorkspaceInit: target sanitized to empty: %q", target)
	}
	workspace := filepath.Join(rootDir, slug)
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

// targetSanitizerRe matches any character NOT in the canonical
// "letters / digits / dot / dash / underscore" set. Replaced with `_`.
var targetSanitizerRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// sanitizeTargetName slugifies the operator-supplied target string.
// Strategy (matches the v1 sanitize_domain intent):
//
//  1. Strip leading "http://" / "https://" scheme prefix.
//  2. Drop URL path and trailing components (split on first "/").
//  3. Lowercase.
//  4. Trim leading/trailing whitespace.
//  5. Replace any remaining non-alphanumeric (excluding `.-_`) with `_`.
//  6. Collapse repeated `_` and trim leading/trailing `_`.
func sanitizeTargetName(t string) string {
	s := strings.TrimSpace(t)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	s = strings.ToLower(s)
	s = targetSanitizerRe.ReplaceAllString(s, "_")
	// Collapse repeated underscores.
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return strings.Trim(s, "_")
}
