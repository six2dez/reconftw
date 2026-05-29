// js_test.go — TDD tests for js.Extract pure-transform function.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-03-PLAN.md
// Task 1 behavior tests 1-5.
package js_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/extract/js"
)

// sampleJsluiceOutput is a representative set of jsluice JSON output lines.
// jsluice emits one JSON object per line with at minimum a "url" field.
const sampleJsluiceOutput = `{"url":"https://api.example.com/v1/users","kind":"URL"}
{"url":"https://mail.example.com/login","kind":"URL"}
{"url":"https://cdn.other.org/script.js","kind":"URL"}
{"url":"/relative/path","kind":"URL"}
`

// Test 1: Extract returns Results with non-empty Subdomain fields.
func TestJsExtractReturnsSubdomains(t *testing.T) {
	results, err := js.Extract([]byte(sampleJsluiceOutput), "example.com")
	if err != nil {
		t.Fatalf("Extract: unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Extract returned no results")
	}
	for _, r := range results {
		if r.Subdomain == "" {
			t.Errorf("result has empty Subdomain: %+v", r)
		}
	}
}

// Test 2: Extract returns only subdomains of example.com.
func TestJsExtractFiltersToTargetDomain(t *testing.T) {
	results, err := js.Extract([]byte(sampleJsluiceOutput), "example.com")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, r := range results {
		if r.Subdomain == "cdn.other.org" {
			t.Errorf("Extract returned out-of-scope subdomain %q", r.Subdomain)
		}
	}
	found := map[string]bool{}
	for _, r := range results {
		found[r.Subdomain] = true
	}
	if !found["api.example.com"] {
		t.Errorf("Extract missing api.example.com")
	}
	if !found["mail.example.com"] {
		t.Errorf("Extract missing mail.example.com")
	}
}

// Test 4: Extract returns empty slice (not error) for empty input.
func TestJsExtractEmptyInput(t *testing.T) {
	results, err := js.Extract([]byte{}, "example.com")
	if err != nil {
		t.Fatalf("Extract(empty): unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Extract(empty) = %d results, want 0", len(results))
	}
}

// Test 5: Extract rejects subdomains not matching target domain.
func TestJsExtractRejectsUnrelatedDomains(t *testing.T) {
	input := []byte(`{"url":"https://totally.different.org/foo","kind":"URL"}` + "\n")
	results, err := js.Extract(input, "example.com")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Extract returned %d results for unrelated domains, want 0", len(results))
	}
}
