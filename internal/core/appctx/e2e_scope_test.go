// e2e_scope_test.go — IP, IPv6 and CIDR targets must produce artefacts.
//
// Regression for a total, silent failure: NewTarget returned early for IP and
// CIDR targets without assigning a default scope, DefaultScopeFilter rejects
// everything when Patterns is empty, and so `--target 10.0.0.5` refused every
// artefact write and produced an empty workspace. The canonical domain regex
// compounded it by rejecting any value containing ':', which made IPv6
// unrepresentable even when the operator scoped the run to that exact address.
//
// The existing tests only asserted the IsIP / IsCIDR booleans, which stayed
// correct throughout — the target was classified perfectly and then produced
// nothing. These tests instead drive the chain that actually matters:
// NewTarget → scope filter (exactly as appctx.Boot builds it) → OutputTree
// → Append.
package appctx_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// treeForTarget mirrors appctx.Boot: build the scope filter from the resolved
// Target.Scope, then the OutputTree from it.
func treeForTarget(t *testing.T, target string) (*output.OutputTree, string) {
	t.Helper()
	workDir := t.TempDir()
	tgt, err := appctx.NewTarget(target, nil, workDir)
	if err != nil {
		t.Fatalf("NewTarget(%s): %v", target, err)
	}
	if len(tgt.Scope) == 0 {
		t.Fatalf("NewTarget(%s): empty default scope — every artefact write will be refused", target)
	}
	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{Patterns: tgt.Scope})
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	return tree, workDir
}

func TestE2EIPTargetsProduceArtefacts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		target  string
		host    string
		wantIn  bool
		comment string
	}{
		{"ipv4 exact", "10.0.0.5", "10.0.0.5", true, "the scanned address itself"},
		{"ipv4 other", "10.0.0.5", "10.0.0.9", false, "a different address"},
		{"ipv6 exact", "2001:db8::1", "2001:db8::1", true, "IPv6 must be representable"},
		{"ipv6 other", "2001:db8::1", "2001:db8::2", false, "a different IPv6 address"},
		{"cidr member", "10.0.0.0/24", "10.0.0.7", true, "containment, not equality"},
		{"cidr edge", "10.0.0.0/24", "10.0.0.255", true, "broadcast is still inside /24"},
		{"cidr outside", "10.0.0.0/24", "10.0.1.7", false, "outside the prefix"},
		{"cidr v6 member", "2001:db8::/32", "2001:db8:1::9", true, "IPv6 containment"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tree, workDir := treeForTarget(t, tc.target)

			line := []byte(`{"host":"` + tc.host + `","source":"portscan"}`)
			err := tree.Append("hosts", [][]byte{line})

			if tc.wantIn {
				if err != nil {
					t.Fatalf("target %s: host %s (%s) rejected: %v",
						tc.target, tc.host, tc.comment, err)
				}
				if _, serr := os.Stat(filepath.Join(workDir, "artefacts", "hosts.jsonl")); serr != nil {
					t.Fatalf("target %s: nothing written for %s: %v", tc.target, tc.host, serr)
				}
				return
			}
			if err == nil {
				t.Fatalf("target %s: host %s (%s) should be out of scope but was admitted",
					tc.target, tc.host, tc.comment)
			}
		})
	}
}

// TestE2EScopeKeepsHostsAndAddressesDisjoint pins the conservative rule: a
// domain-scoped run never admits a bare IP, and an IP-scoped run never admits a
// hostname. On shared hosting or behind a CDN one address serves third-party
// assets, so admitting IPs into a domain scope would pull assets outside the
// engagement into scanning and reporting.
func TestE2EScopeKeepsHostsAndAddressesDisjoint(t *testing.T) {
	t.Parallel()

	domainScope := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	if domainScope.IsInScope("93.184.216.34") {
		t.Error("a domain scope must not admit a bare IP")
	}
	if !domainScope.IsInScope("api.example.com") {
		t.Error("a domain scope must still admit its own hostnames")
	}

	ipScope := &output.DefaultScopeFilter{Patterns: []string{"10.0.0.0/24"}}
	if ipScope.IsInScope("api.example.com") {
		t.Error("an IP/CIDR scope must not admit a hostname")
	}
	if !ipScope.IsInScope("10.0.0.7") {
		t.Error("an IP/CIDR scope must admit addresses it contains")
	}

	// Mixed scope: each value type matched by its own pattern kind.
	mixed := &output.DefaultScopeFilter{Patterns: []string{"*.example.com", "10.0.0.0/24"}}
	for _, in := range []string{"api.example.com", "10.0.0.7"} {
		if !mixed.IsInScope(in) {
			t.Errorf("mixed scope should admit %s", in)
		}
	}
	for _, out := range []string{"evil.org", "192.0.2.1"} {
		if mixed.IsInScope(out) {
			t.Errorf("mixed scope should reject %s", out)
		}
	}
}

// TestE2EIPv6URLScope covers the URL path, which reduces to IsInScope via
// url.Hostname() — that returns the bracketed IPv6 literal unbracketed, so it
// must survive the same way a bare address does.
func TestE2EIPv6URLScope(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{Patterns: []string{"2001:db8::1"}}
	if !f.IsInScopeURL("https://[2001:db8::1]:8443/admin") {
		t.Error("an IPv6 URL must be in scope when the address is scoped")
	}
	if f.IsInScopeURL("https://[2001:db8::2]/") {
		t.Error("a different IPv6 address must be out of scope")
	}
}
