// github_common.go — shared helpers for the GitHub OSINT cluster (OSINT-04/05/06).
//
// These helpers centralize the D-O8 key gate and XCUT-07 token handling used by
// github_dorks.go, gitdorks.go, github_repos.go, github_leaks.go, and
// github_actions.go:
//
//   - gitHubTokenFile  → the cfg.Paths.GitHubTokens FILE path (v1 $GITHUB_TOKENS),
//     validated to exist and be non-empty. "" means "no token configured".
//   - readGitHubToken  → the FIRST token line read from that file (v1
//     `head -n 1 "$GITHUB_TOKENS"`). The raw value is returned ONLY for passing
//     into a subprocess env/arg — callers MUST NEVER log it (XCUT-07 / T-07-03-02).
//   - companyName      → the registrable label of the root domain (the
//     `unfurl format %r` analog) used to seed org-scoped GitHub tools.
//   - writeTokenFile   → writes a token to a 0600 temp file for tools that take
//     a -token-file argument (enumerepo), avoiding the process-listing exposure
//     of putting the token on argv (v1 osint.sh:80-85).
//
// Source: .planning/phases/07-osint-e2e/07-03-PLAN.md (Tasks 1 + 2).
package osint

import (
	"os"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

// gitHubTokenFile returns the configured GitHub-tokens file path when it exists
// and is non-empty; otherwise "". This is the D-O8 key gate that callers use to
// decide whether to run or emit a logged StatusSkipped.
func gitHubTokenFile(app *appctx.AppContext) string {
	if app == nil || app.Cfg == nil {
		return ""
	}
	path := strings.TrimSpace(app.Cfg.Paths.GitHubTokens)
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return ""
	}
	return path
}

// readGitHubToken returns the first non-empty token from the configured tokens
// file (v1 `head -n 1 "$GITHUB_TOKENS"`). The boolean reports whether a usable
// token was found (the D-O8 gate). The returned string is a LIVE SECRET — it
// MUST only be passed into a subprocess env/arg and MUST NEVER be logged
// (XCUT-07 / T-07-03-02).
func readGitHubToken(app *appctx.AppContext) (string, bool) {
	path := gitHubTokenFile(app)
	if path == "" {
		return "", false
	}
	data, err := os.ReadFile(path) //nolint:gosec // path from validated config
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		tok := strings.TrimSpace(line)
		if tok != "" {
			return tok, true
		}
	}
	return "", false
}

// writeTokenFile writes token to a 0600 temp file and returns its path. Tools
// that accept a -token-file argument (enumerepo) read the token from disk rather
// than argv, avoiding exposure in the process listing (v1 osint.sh:80-85). The
// caller is responsible for removing the file after the tool completes.
func writeTokenFile(token string) (string, error) {
	f, err := os.CreateTemp("", "ghtoken-*.txt")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if cErr := f.Chmod(0o600); cErr != nil {
		f.Close() //nolint:errcheck
		os.Remove(name) //nolint:errcheck
		return "", cErr
	}
	if _, wErr := f.WriteString(token); wErr != nil {
		f.Close() //nolint:errcheck
		os.Remove(name) //nolint:errcheck
		return "", wErr
	}
	if cErr := f.Close(); cErr != nil {
		os.Remove(name) //nolint:errcheck
		return "", cErr
	}
	return name, nil
}

// companyName derives the registrable label (the part before the public suffix)
// from a root domain — the v1 `unfurl format %r` analog used to seed org-scoped
// GitHub tools (gato org list, enumerepo usernames). For "example.com" it
// returns "example"; for "example.co.uk" it returns "example" (best-effort,
// handling the common two-label public suffixes). Returns the full root domain
// unchanged when no label can be derived.
func companyName(root string) string {
	root = strings.TrimSpace(strings.ToLower(root))
	if root == "" {
		return ""
	}
	labels := strings.Split(root, ".")
	if len(labels) < 2 {
		return root
	}
	// Common multi-label public suffixes (best-effort, mirrors v1's %r which
	// relies on the public-suffix list; we cover the frequent two-label TLDs).
	twoLabelTLD := map[string]struct{}{
		"co.uk": {}, "org.uk": {}, "gov.uk": {}, "ac.uk": {},
		"com.au": {}, "net.au": {}, "org.au": {},
		"co.jp": {}, "co.nz": {}, "com.br": {}, "co.za": {}, "com.mx": {},
	}
	if len(labels) >= 3 {
		lastTwo := labels[len(labels)-2] + "." + labels[len(labels)-1]
		if _, ok := twoLabelTLD[lastTwo]; ok {
			return labels[len(labels)-3]
		}
	}
	// Registrable label = the label immediately left of the (single-label) TLD.
	return labels[len(labels)-2]
}
