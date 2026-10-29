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
	"fmt"
	"net/netip"
	"net/url"
	"os"
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

	// Include / Exclude are the v1 `-i <file>` / `-x <file>` scope lists
	// (subdomains.scope.include_file / exclude_file, or --include-file /
	// --exclude-file). Entries use the same syntax as Patterns: exact host,
	// `*.sub.example.com` wildcard, IP literal or CIDR.
	//
	// Evaluation order, applied to a value that already matched Patterns:
	//   1. Exclude — any match drops the value.
	//   2. Include — when non-empty, the value must match one entry.
	// Include narrows; it never admits a value outside Patterns, so an include
	// list cannot widen the engagement past the target's own scope.
	Include []string
	Exclude []string
}

// NewScopeFilter builds the production filter: patterns from the target plus
// the optional include/exclude list files. An empty path means "no list". A
// path that cannot be read is an error — config.ValidateScopeFiles rejects it
// earlier on every path that loads config, so this is the last line, not the
// first.
func NewScopeFilter(patterns []string, includeFile, excludeFile string) (*DefaultScopeFilter, error) {
	f := &DefaultScopeFilter{Patterns: patterns}
	var err error
	if f.Include, err = LoadScopeList(includeFile); err != nil {
		return nil, fmt.Errorf("output: include scope list: %w", err)
	}
	if f.Exclude, err = LoadScopeList(excludeFile); err != nil {
		return nil, fmt.Errorf("output: exclude scope list: %w", err)
	}
	return f, nil
}

// LoadScopeList reads one scope entry per line from path. Blank lines and
// `#` comments are skipped; entries are trimmed and lowercased. An empty path
// yields nil, nil.
func LoadScopeList(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied scope list
	if err != nil {
		return nil, err
	}
	return ParseScopeList(string(data)), nil
}

// ParseScopeList is LoadScopeList over in-memory content.
func ParseScopeList(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// domainRe is the canonical input-validation regex shared with
// spike/go/cmd/spike/main.go:29 and v1 lib/validation.sh:validate_domain.
// Anchored to the whole string by Go regexp's default semantics for
// MatchString — see anchor of `^...$`.
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// IsInScope reports whether host is in scope.
//
// The value may be a hostname OR an IP literal, and the two are matched by
// disjoint rules — a hostname pattern NEVER admits an IP, and an IP/CIDR
// pattern NEVER admits a hostname. That separation is deliberate: on shared
// hosting or behind a CDN, one IP serves third-party assets, so letting a
// domain-scoped run admit an IP because some in-scope host resolved to it
// would pull assets outside the engagement into scanning and reporting.
// IPs enter scope only when the operator scoped the run to an IP or CIDR.
//
// Before this, the canonical domain regex was applied to every value, so an
// IPv6 literal was rejected outright — including when the operator had
// explicitly scoped the run to that exact address.
func (f *DefaultScopeFilter) IsInScope(host string) bool {
	if f == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if !matchAnyScope(host, f.Patterns) {
		return false
	}
	// Exclude list wins over everything: an operator's -x entry must never be
	// written, whatever the target scope or include list says.
	if matchAnyScope(host, f.Exclude) {
		return false
	}
	// Include list narrows within Patterns.
	if len(f.Include) > 0 && !matchAnyScope(host, f.Include) {
		return false
	}
	return true
}

// matchAnyScope reports whether the (already lowercased, trimmed) value matches
// any pattern. Hostnames and IP literals are matched by disjoint rules — see
// IsInScope.
func matchAnyScope(host string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	// IP-shaped value: only IP and CIDR patterns can admit it. Unmap so an
	// IPv4-mapped IPv6 form compares equal to its plain IPv4 pattern.
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		for _, pat := range patterns {
			if matchScopeAddr(addr, pat) {
				return true
			}
		}
		return false
	}

	// Hostname value: reject shell metacharacters / structurally invalid names.
	if !domainRe.MatchString(host) {
		return false
	}
	for _, pat := range patterns {
		if isAddrPattern(pat) {
			continue // an IP/CIDR pattern never admits a hostname
		}
		if matchScopePattern(host, pat) {
			return true
		}
	}
	return false
}

// isAddrPattern reports whether pat is an IP literal or a CIDR prefix rather
// than a hostname pattern.
func isAddrPattern(pat string) bool {
	pat = strings.ToLower(strings.TrimSpace(pat))
	if _, err := netip.ParsePrefix(pat); err == nil {
		return true
	}
	_, err := netip.ParseAddr(pat)
	return err == nil
}

// matchScopeAddr matches an IP value against one pattern: exact equality for
// an IP literal, containment for a CIDR prefix. Hostname patterns never match.
func matchScopeAddr(addr netip.Addr, pat string) bool {
	pat = strings.ToLower(strings.TrimSpace(pat))
	if pat == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(pat); err == nil {
		return prefix.Contains(addr)
	}
	if patAddr, err := netip.ParseAddr(pat); err == nil {
		return patAddr.Unmap() == addr
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
