// Package analytics is a pure-transform extractor for analyticsrelationships output.
//
// Design constraints (04-03-PLAN.md D-02):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Phase 5 may import this package and extend it without modification.
//
// analyticsrelationships output format:
// One domain per line, optionally followed by a tracking ID:
//
//	related.example.com UA-12345678-1
//	partner.example.com UA-87654321-2
//
// Subdomains are filtered to the target domain using anchored hostname matching.
// The TrackingID field is preserved for Phase 5 correlation use cases.
package analytics

import (
	"bufio"
	"bytes"
	"strings"
)

// Result is a single analyticsrelationships match: a related domain plus its
// Google Analytics tracking ID (if present in the output line).
type Result struct {
	// Subdomain is the related domain extracted from analyticsrelationships output.
	Subdomain string
	// TrackingID is the Google Analytics UA-XXXXXXXX-N identifier (may be empty).
	TrackingID string
}

// Extract parses rawOutput (analyticsrelationships stdout) and returns all
// domain candidates that are equal to or a subdomain of domain.
//
// Returns an empty (non-nil) slice if rawOutput is empty or no in-scope matches
// are found. Never returns a non-nil error for well-formed input.
func Extract(rawOutput []byte, domain string) ([]Result, error) {
	if len(rawOutput) == 0 {
		return []Result{}, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	seen := make(map[string]bool)
	var results []Result

	scanner := bufio.NewScanner(bytes.NewReader(rawOutput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Expected format: "<domain>" or "<domain> <tracking_id>"
		// Some versions of the tool may emit "|__ <domain>" prefix; strip it.
		line = strings.TrimPrefix(line, "|__ ")

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		subdomain := strings.ToLower(fields[0])
		var trackingID string
		if len(fields) >= 2 {
			trackingID = fields[1]
		}

		if !inScope(subdomain, domain) {
			continue
		}
		if seen[subdomain] {
			continue
		}
		seen[subdomain] = true
		results = append(results, Result{Subdomain: subdomain, TrackingID: trackingID})
	}

	if results == nil {
		return []Result{}, nil
	}
	return results, nil
}

// inScope is the anchored hostname scope check mirroring
// lib/validation.sh:is_in_scope_host semantics.
func inScope(host, domain string) bool {
	if domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}
