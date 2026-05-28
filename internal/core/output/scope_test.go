// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 2 (ScopeFilter).
// CRITICAL: Test 8 (anchored / no substring false positive) is the v1 bug fix
// per lib/validation.sh:is_in_scope_host (anchored hostname check).
package output_test

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/six2dez/reconftw/internal/core/output"
)

// Test 6: positive wildcard match.
func TestScopeWildcardSubdomainMatches(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	if !f.IsInScope("api.example.com") {
		t.Fatal("api.example.com should match *.example.com")
	}
}

// Test 7: non-match.
func TestScopeRejectsOutsidePattern(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	if f.IsInScope("evil.com") {
		t.Fatal("evil.com must NOT match *.example.com")
	}
}

// Test 8 — CANONICAL ANCHORED CHECK (v1 fix):
// `examplecom.evil.org` does NOT match `*.example.com`. The anchored
// pattern means the matched suffix is `.example.com`, NOT any substring
// containing `example.com`.
func TestScopeAnchored(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	// Both must be REJECTED — they only superficially contain "example.com".
	if f.IsInScope("examplecom.evil.org") {
		t.Fatal("FOUND-04/SCOPE: substring false positive (anchored check failed)")
	}
	if f.IsInScope("notexample.com") {
		t.Fatal("notexample.com should not match (anchored)")
	}
	if f.IsInScope("attacker-example.com") {
		t.Fatal("attacker-example.com should not match (anchored)")
	}
}

// Test 9: apex match — per v1 lib/validation.sh:is_in_scope_host, the apex
// also matches the wildcard pattern.
func TestScopeApexMatchesWildcard(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	if !f.IsInScope("example.com") {
		t.Fatal("apex example.com should match *.example.com (v1 semantics)")
	}
}

// Test 10: URL scope filter — host extraction; query string and fragment
// are ignored.
func TestScopeIsInScopeURL(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://api.example.com/path?q=1#frag", true},
		{"http://api.example.com:8080/", true},
		{"https://evil.com/page", false},
		{"not a url", false},
		{"", false},
	}
	for _, tc := range cases {
		got := f.IsInScopeURL(tc.raw)
		if got != tc.want {
			t.Errorf("IsInScopeURL(%q) = %v; want %v", tc.raw, got, tc.want)
		}
	}
}

// Additional direct-match (no wildcard) case.
func TestScopeExactHostMatches(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"example.com"}}
	if !f.IsInScope("example.com") {
		t.Fatal("exact host should match itself")
	}
	if f.IsInScope("sub.example.com") {
		t.Fatal("subdomain should NOT match exact pattern")
	}
}

// Multiple patterns: any one match wins.
func TestScopeMultiplePatterns(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com", "other.org"}}
	if !f.IsInScope("api.example.com") {
		t.Fatal("matches first pattern")
	}
	if !f.IsInScope("other.org") {
		t.Fatal("matches second pattern")
	}
	if f.IsInScope("nope.net") {
		t.Fatal("matches no pattern")
	}
}

// Empty patterns: nothing is in scope.
func TestScopeEmptyPatterns(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{}}
	if f.IsInScope("example.com") {
		t.Fatal("empty scope list should reject everything")
	}
}

// Injection rejection: shell metacharacters fail the domain regex.
func TestScopeRejectsInjection(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	for _, bad := range []string{
		"foo;rm -rf /",
		"foo bar",
		"foo$(cmd).example.com",
		"foo`cmd`.example.com",
		"foo|cmd.example.com",
		"foo\nexample.com",
	} {
		if f.IsInScope(bad) {
			t.Errorf("must reject injection %q", bad)
		}
	}
}

// Test 11 — property test:
// rapid generates random strings (host) and random pattern lists; the
// scope filter must never panic, must be idempotent (same input → same
// result), and the anchored semantics MUST hold:
//
//   for every match host h matched by pattern *.b:
//       h == b  OR  strings.HasSuffix(h, "."+b)
//
// We do a positive-side property: if rapid produces a *.b pattern and a
// random subdomain `<random>.b`, the filter must return true.
func TestScopeProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		// Random base domain — restricted to ascii lowercase.
		base := rapid.StringMatching(`[a-z]+\.[a-z]+`).Draw(rt, "base")
		pat := "*." + base
		f := &output.DefaultScopeFilter{Patterns: []string{pat}}

		// 1) Apex must match (per v1 semantics).
		if !f.IsInScope(base) {
			rt.Fatalf("apex %q must match %q", base, pat)
		}

		// 2) <prefix>.<base> must match for any valid label prefix.
		prefix := rapid.StringMatching(`[a-z]+`).Draw(rt, "prefix")
		host := prefix + "." + base
		if !f.IsInScope(host) {
			rt.Fatalf("subdomain %q must match %q", host, pat)
		}

		// 3) Anchored: <prefix><base> (no dot separator) must NOT match.
		// Skip ill-formed cases where prefix+base could itself become a
		// valid TLD-shaped string identical to base.
		joined := prefix + base
		if joined == base {
			return
		}
		if f.IsInScope(joined) {
			rt.Fatalf("anchored check violated: %q must NOT match %q", joined, pat)
		}

		// 4) Idempotent: calling twice returns the same value.
		first := f.IsInScope(host)
		second := f.IsInScope(host)
		if first != second {
			rt.Fatalf("idempotency violated: %v vs %v", first, second)
		}
	})
}

// rapid-driven crash safety: random garbage strings must not panic.
func TestScopeNoPanicOnRandomInput(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		host := rapid.String().Draw(rt, "host")
		patterns := rapid.SliceOf(rapid.String()).Draw(rt, "patterns")
		f := &output.DefaultScopeFilter{Patterns: patterns}
		// Sanity: must terminate (Go regexes don't blow up on garbage).
		_ = f.IsInScope(host)
		// URL form too.
		if utf8.ValidString(host) {
			ur := "https://" + url.QueryEscape(strings.TrimSpace(host)) + "/"
			_ = f.IsInScopeURL(ur)
		}
	})
}
