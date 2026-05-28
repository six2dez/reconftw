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
	"time"
)

// WorkspaceInit creates a new workspace directory under rootDir for the
// given target and returns the absolute workspace path. The directory
// name is "<sanitized-target>-<timestamp>" per ADR §3.1.
//
// Sanitization mirrors v1 lib/validation.sh:sanitize_domain — strips
// URL scheme, lowercases, replaces non-alphanumeric characters with `_`.
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
	timestamp := time.Now().UTC().Format("20060102-150405")
	workspace := filepath.Join(rootDir, fmt.Sprintf("%s-%s", slug, timestamp))
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
