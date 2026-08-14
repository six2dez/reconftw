// scope_addr_test.go — exhaustive matrix for the address-aware scope filter.
//
// scope.go is an XCUT-03 critical file held to a ≥90% coverage gate. The
// net/netip branches (IP values, CIDR containment, the hostname/address
// disjointness rule) arrived with their behaviour proven end-to-end in
// appctx's tests — but coverage is measured per package, so from this
// package's profile matchScopeAddr read 0%.
//
// Beyond the gate, these are the cases that decide whether an asset is
// scanned: a filter that is too loose scans out of scope, one that is too
// strict silently drops findings.
package output

import "testing"

func TestIsInScopeMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		patterns []string
		value    string
		want     bool
	}{
		// --- hostname patterns ---
		{"wildcard matches apex", []string{"*.example.com"}, "example.com", true},
		{"wildcard matches subdomain", []string{"*.example.com"}, "api.example.com", true},
		{"wildcard matches deep subdomain", []string{"*.example.com"}, "a.b.example.com", true},
		{"wildcard anchored, no substring match", []string{"*.example.com"}, "examplecom.evil.org", false},
		{"wildcard rejects lookalike suffix", []string{"*.example.com"}, "notexample.com", false},
		{"exact matches only itself", []string{"example.com"}, "example.com", true},
		{"exact rejects subdomain", []string{"example.com"}, "api.example.com", false},
		{"case insensitive", []string{"*.EXAMPLE.com"}, "API.Example.Com", true},
		{"surrounding whitespace in pattern", []string{"  *.example.com  "}, "api.example.com", true},

		// --- rejected inputs ---
		{"empty value", []string{"*.example.com"}, "", false},
		{"whitespace value", []string{"*.example.com"}, "   ", false},
		{"shell metacharacters", []string{"*.example.com"}, "api.example.com;id", false},
		{"no patterns configured", nil, "api.example.com", false},
		{"empty pattern string", []string{""}, "api.example.com", false},
		{"whitespace pattern", []string{"   "}, "api.example.com", false},

		// --- IP values against IP patterns ---
		{"ipv4 exact", []string{"10.0.0.5"}, "10.0.0.5", true},
		{"ipv4 mismatch", []string{"10.0.0.5"}, "10.0.0.6", false},
		{"ipv4-mapped ipv6 equals plain ipv4", []string{"10.0.0.5"}, "::ffff:10.0.0.5", true},
		{"ipv6 exact", []string{"2001:db8::1"}, "2001:db8::1", true},
		{"ipv6 mismatch", []string{"2001:db8::1"}, "2001:db8::2", false},
		{"ipv6 zero-compression equivalence", []string{"2001:db8:0:0:0:0:0:1"}, "2001:db8::1", true},

		// --- CIDR containment ---
		{"cidr contains member", []string{"10.0.0.0/24"}, "10.0.0.7", true},
		{"cidr contains network address", []string{"10.0.0.0/24"}, "10.0.0.0", true},
		{"cidr contains broadcast", []string{"10.0.0.0/24"}, "10.0.0.255", true},
		{"cidr excludes neighbour", []string{"10.0.0.0/24"}, "10.0.1.7", false},
		{"cidr valid but non-matching", []string{"192.168.0.0/16"}, "10.0.0.7", false},
		{"ipv6 cidr contains member", []string{"2001:db8::/32"}, "2001:db8:1::9", true},
		{"ipv6 cidr excludes outsider", []string{"2001:db8::/32"}, "2001:db9::1", false},
		// netip.ParsePrefix accepts host bits and Contains masks them off, so
		// "10.0.0.5/24" means the /24 holding that address. That is what an
		// operator writing it almost certainly intends; pinned so a future
		// switch to a stricter parser is a deliberate decision, not a silent
		// narrowing of everyone's scope file.
		{"prefix with host bits set means its network", []string{"10.0.0.5/24"}, "10.0.0.7", true},
		{"prefix with host bits set still excludes outsiders", []string{"10.0.0.5/24"}, "10.0.1.7", false},

		// --- disjointness: the conservative rule ---
		{"hostname pattern never admits an IP", []string{"*.example.com"}, "93.184.216.34", false},
		{"cidr pattern never admits a hostname", []string{"10.0.0.0/24"}, "api.example.com", false},
		{"ip pattern never admits a hostname", []string{"10.0.0.5"}, "api.example.com", false},

		// --- mixed scopes match each value by its own kind ---
		{"mixed admits hostname", []string{"*.example.com", "10.0.0.0/24"}, "api.example.com", true},
		{"mixed admits address", []string{"*.example.com", "10.0.0.0/24"}, "10.0.0.7", true},
		{"mixed rejects foreign hostname", []string{"*.example.com", "10.0.0.0/24"}, "evil.org", false},
		{"mixed rejects foreign address", []string{"*.example.com", "10.0.0.0/24"}, "192.0.2.1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &DefaultScopeFilter{Patterns: tc.patterns}
			if got := f.IsInScope(tc.value); got != tc.want {
				t.Errorf("IsInScope(%q) with patterns %v = %v, want %v",
					tc.value, tc.patterns, got, tc.want)
			}
		})
	}
}

// TestIsInScopeNilFilter — a nil filter is fail-closed, never permissive.
func TestIsInScopeNilFilter(t *testing.T) {
	t.Parallel()
	var f *DefaultScopeFilter
	if f.IsInScope("api.example.com") {
		t.Error("a nil filter must admit nothing")
	}
	if f.IsInScopeURL("https://api.example.com/") {
		t.Error("a nil filter must admit no URL")
	}
}

func TestIsInScopeURLAddresses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		patterns []string
		rawurl   string
		want     bool
	}{
		{"ipv6 bracketed with port", []string{"2001:db8::1"}, "https://[2001:db8::1]:8443/admin", true},
		{"ipv6 bracketed no port", []string{"2001:db8::1"}, "https://[2001:db8::1]/", true},
		{"ipv6 out of scope", []string{"2001:db8::1"}, "https://[2001:db8::2]/", false},
		{"ipv6 inside cidr", []string{"2001:db8::/32"}, "https://[2001:db8:5::9]/x", true},
		{"ipv4 with port", []string{"10.0.0.5"}, "http://10.0.0.5:8080/x", true},
		{"ipv4 in cidr", []string{"10.0.0.0/24"}, "http://10.0.0.9/x", true},
		{"hostname url under domain scope", []string{"*.example.com"}, "https://api.example.com/x", true},
		{"userinfo rejected even when host matches", []string{"*.example.com"}, "https://u:p@api.example.com/x", false},
		{"empty url", []string{"*.example.com"}, "", false},
		{"whitespace url", []string{"*.example.com"}, "   ", false},
		{"unparseable url", []string{"*.example.com"}, "https://exa mple.com/\x7f", false},
		{"url with no host", []string{"*.example.com"}, "file:///etc/passwd", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &DefaultScopeFilter{Patterns: tc.patterns}
			if got := f.IsInScopeURL(tc.rawurl); got != tc.want {
				t.Errorf("IsInScopeURL(%q) with patterns %v = %v, want %v",
					tc.rawurl, tc.patterns, got, tc.want)
			}
		})
	}
}

// TestIsAddrPattern pins the classifier that keeps hostnames and addresses in
// separate matching universes.
func TestIsAddrPattern(t *testing.T) {
	t.Parallel()
	addrLike := []string{"10.0.0.5", "10.0.0.0/24", "2001:db8::1", "2001:db8::/32", " 10.0.0.5 "}
	hostLike := []string{"example.com", "*.example.com", "", "   ", "10.0.0.5.example.com", "not/a/cidr"}

	for _, p := range addrLike {
		if !isAddrPattern(p) {
			t.Errorf("isAddrPattern(%q) = false, want true", p)
		}
	}
	for _, p := range hostLike {
		if isAddrPattern(p) {
			t.Errorf("isAddrPattern(%q) = true, want false", p)
		}
	}
}
