// favicon_test.go — TDD tests for favicon.Extract pure-transform function.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-03-PLAN.md
// Task 1 behavior tests 1-5.
package favicon_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/extract/favicon"
)

// Sample favirecon output: one line per match, format "hash subdomain"
const sampleFaviconOutput = `1234567890 api.example.com
0987654321 mail.example.com
1111111111 unrelated.other.org
`

// Test 1: Extract returns Result entries with Subdomain and Hash fields populated.
func TestFaviconExtractReturnsResults(t *testing.T) {
	results, err := favicon.Extract([]byte(sampleFaviconOutput), "example.com")
	if err != nil {
		t.Fatalf("Extract: unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Extract returned no results, want at least 1")
	}
	for _, r := range results {
		if r.Subdomain == "" {
			t.Errorf("result has empty Subdomain: %+v", r)
		}
		if r.Hash == "" {
			t.Errorf("result has empty Hash: %+v", r)
		}
	}
}

// Test 2: Extract filters to domain-matching subdomains only.
func TestFaviconExtractFiltersToTargetDomain(t *testing.T) {
	results, err := favicon.Extract([]byte(sampleFaviconOutput), "example.com")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, r := range results {
		if r.Subdomain == "unrelated.other.org" {
			t.Errorf("Extract returned out-of-scope subdomain %q", r.Subdomain)
		}
	}
	// Must contain api.example.com and mail.example.com.
	found := map[string]bool{}
	for _, r := range results {
		found[r.Subdomain] = true
	}
	if !found["api.example.com"] {
		t.Errorf("Extract missing api.example.com in results")
	}
	if !found["mail.example.com"] {
		t.Errorf("Extract missing mail.example.com in results")
	}
}

// Test 4: Extract returns empty slice (not error) for empty input.
func TestFaviconExtractEmptyInput(t *testing.T) {
	results, err := favicon.Extract([]byte{}, "example.com")
	if err != nil {
		t.Fatalf("Extract(empty): unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Extract(empty) = %d results, want 0", len(results))
	}
}

// Test 5: Extract rejects subdomains not matching target domain.
func TestFaviconExtractRejectsUnrelatedDomains(t *testing.T) {
	input := []byte("1234567890 totally.different.org\n9876543210 another.net\n")
	results, err := favicon.Extract(input, "example.com")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Extract returned %d results for unrelated domains, want 0: %v", len(results), results)
	}
}
