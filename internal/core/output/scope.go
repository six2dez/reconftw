// Source:
//   - ADR §3.2 lines 1250-1252 (OutputTree.Append scope-filter mandate;
//     out-of-scope returns OutOfScope error class per §6).
//   - lib/validation.sh:is_in_scope_host (CANONICAL v1 anchored hostname
//     check — this Go implementation mirrors its semantics exactly).
//   - spike/go/cmd/spike/main.go:29 (canonical domain regex
//     ^[a-zA-Z0-9.-]+$ — REUSED from spike + v1 per ADR §"Reused Assets").
//
// CANONICAL v1 fix: scope matching is ANCHORED — a pattern of *.example.com
// matches only `example.com` itself or `<label>.example.com`, NEVER any
// arbitrary substring containing `example.com`. The "examplecom.evil.org"
// substring false positive was a documented v1 bug; the anchored check
// (line: `host == base || strings.HasSuffix(host, "."+base)`) closes it.
package output

import (
	"net/url"
	"regexp"
	"strings"
)

// ScopeFilter is the interface OutputTree consumes to validate each
// artefact line at the Append boundary. Production callers wire
// *DefaultScopeFilter from the resolved Config; tests may substitute a
// permissive mock.
type ScopeFilter interface {
	// IsInScope reports whether host matches any configured pattern.
	IsInScope(host string) bool
	// IsInScopeURL extracts the URL's host and applies IsInScope.
	IsInScopeURL(rawurl string) bool
}

// DefaultScopeFilter implements the anchored-hostname scope check.
//
// Pattern syntax (matches v1 lib/validation.sh:is_in_scope_host):
//
//   - "example.com" — exact host match, no subdomains.
//   - "*.example.com" — wildcard suffix; matches `example.com` (apex)
//     OR any host ending in `.example.com`.
//
// Hosts are lowercased + trimmed before matching. Hosts containing shell
// metacharacters (anything outside the canonical domain regex
// ^[a-zA-Z0-9.-]+$) are rejected unconditionally.
type DefaultScopeFilter struct {
	Patterns []string
}

// domainRe is the canonical input-validation regex shared with
// spike/go/cmd/spike/main.go:29 and v1 lib/validation.sh:validate_domain.
// Anchored to the whole string by Go regexp's default semantics for
// MatchString — see anchor of `^...$`.
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// IsInScope reports whether host is in scope.
func (f *DefaultScopeFilter) IsInScope(host string) bool {
	if f == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Reject shell metacharacters / structurally invalid hostnames.
	if !domainRe.MatchString(host) {
		return false
	}
	for _, pat := range f.Patterns {
		if matchScopePattern(host, pat) {
			return true
		}
	}
	return false
}

// IsInScopeURL parses rawurl and applies IsInScope to its host.
//
// SUBD-05 userinfo rejection: URLs containing userinfo (user:password@ or
// user@ prefix) are unconditionally rejected — regardless of whether the
// hostname itself matches. Userinfo in HTTP(S) URLs is a credential-leak
// vector; the v1 filter_in_scope_urls Python implementation rejects them
// via urllib.parse.urlparse(url).userinfo != "" check (see
// modules/subdomains.sh filter_in_scope_urls helper).
func (f *DefaultScopeFilter) IsInScopeURL(rawurl string) bool {
	if f == nil || strings.TrimSpace(rawurl) == "" {
		return false
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	// SUBD-05: reject URLs with userinfo (e.g. "http://u:p@example.com/").
	if u.User != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	return f.IsInScope(host)
}

// matchScopePattern is the ANCHORED scope check — the canonical v1 fix.
// `host == base || strings.HasSuffix(host, "."+base)` is the exact line
// that prevents the "examplecom.evil.org" substring false positive
// (a documented v1 bug per `lib/validation.sh:is_in_scope_host`).
//
// For exact-host patterns (no wildcard), only equality matches —
// subdomains do NOT match.
func matchScopePattern(host, pat string) bool {
	pat = strings.ToLower(strings.TrimSpace(pat))
	if pat == "" {
		return false
	}
	if strings.HasPrefix(pat, "*.") {
		base := strings.TrimPrefix(pat, "*.")
		// Anchored — prevents substring false positives like
		// `examplecom.evil.org` matching `*.example.com`.
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == pat
}
