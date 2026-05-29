// Package favicon is a pure-transform extractor for favirecon output.
//
// Design constraints (04-03-PLAN.md D-02):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Phase 5 may import this package and extend it for web outputs without
//     modification (pure function, no side effects).
//
// favirecon output format (one line per match):
//
//	<hash> <subdomain>
//
// Lines that do not match the format are silently skipped.
// Subdomains are filtered to the target domain using anchored hostname matching
// (mirrors lib/validation.sh:is_in_scope_host semantics).
package favicon

import (
	"bufio"
	"bytes"
	"strings"
)

// Result is a single favirecon match: a subdomain candidate plus its favicon hash.
// The Hash field is included for Phase 5 favicon-correlation use cases.
type Result struct {
	// Subdomain is the hostname extracted from the favirecon output.
	Subdomain string
	// Hash is the favicon murmur3 hash reported by favirecon.
	Hash string
}

// Extract parses rawOutput (favirecon stdout) and returns all subdomain candidates
// that are equal to or a subdomain of domain. The comparison is case-insensitive
// and anchored (prevents "examplecom.evil.org" from matching "example.com").
//
// Returns an empty (non-nil) slice if rawOutput is empty or no in-scope matches
// are found. Never returns a non-nil error for well-formed input; error is
// reserved for future input-validation extensions.
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
		// Expected format: "<hash> <subdomain>"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := fields[0]
		subdomain := strings.ToLower(fields[1])

		if !inScope(subdomain, domain) {
			continue
		}
		if seen[subdomain] {
			continue
		}
		seen[subdomain] = true
		results = append(results, Result{Subdomain: subdomain, Hash: hash})
	}

	if results == nil {
		return []Result{}, nil
	}
	return results, nil
}

// inScope is the anchored hostname scope check mirroring
// lib/validation.sh:is_in_scope_host semantics.
// host is in scope if it equals domain (apex) OR ends with "."+domain (subdomain).
func inScope(host, domain string) bool {
	if domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}
