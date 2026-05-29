// analytics_test.go — TDD tests for analytics.Extract pure-transform function.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-03-PLAN.md
// Task 1 behavior tests 1-5.
package analytics_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/extract/analytics"
)

// sampleAnalyticsOutput is representative analyticsrelationships output.
// The tool emits related domains, one per line, with optional tracking ID prefix.
const sampleAnalyticsOutput = `example.com UA-12345678-1
related.example.com UA-12345678-1
partner.example.com UA-87654321-2
unrelated.org UA-99999999-9
`

// Test 3: Extract returns related domains from analytics output.
func TestAnalyticsExtractReturnsResults(t *testing.T) {
	results, err := analytics.Extract([]byte(sampleAnalyticsOutput), "example.com")
	if err != nil {
		t.Fatalf("Extract: unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Extract returned no results, want at least 1")
	}
}

// Test for domain filtering.
func TestAnalyticsExtractFiltersToTargetDomain(t *testing.T) {
	results, err := analytics.Extract([]byte(sampleAnalyticsOutput), "example.com")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, r := range results {
		if r.Subdomain == "unrelated.org" {
			t.Errorf("Extract returned out-of-scope domain %q", r.Subdomain)
		}
	}
	found := map[string]bool{}
	for _, r := range results {
		found[r.Subdomain] = true
	}
	if !found["related.example.com"] {
		t.Errorf("Extract missing related.example.com")
	}
}

// Test 4: Extract returns empty slice (not error) for empty input.
func TestAnalyticsExtractEmptyInput(t *testing.T) {
	results, err := analytics.Extract([]byte{}, "example.com")
	if err != nil {
		t.Fatalf("Extract(empty): unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Extract(empty) = %d results, want 0", len(results))
	}
}

// Test 5: Extract rejects subdomains not matching target domain.
func TestAnalyticsExtractRejectsUnrelatedDomains(t *testing.T) {
	input := []byte("totally.different.org UA-99999999\nanother.net UA-11111111\n")
	results, err := analytics.Extract(input, "example.com")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Extract returned %d results for unrelated domains, want 0", len(results))
	}
}
