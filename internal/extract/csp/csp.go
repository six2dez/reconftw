// Package csp is a pure-transform extractor for csprecon output.
//
// Design constraints (D-W3):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Pure-transform function: Extract(rawOutput, domain) shape.
//   - Never break Phase-4 callers.
//
// csprecon output format: one hostname per line (plain text, no JSON).
// Lines are filtered to in-scope hostnames using anchored suffix matching
// (mirrors lib/validation.sh:is_in_scope_host semantics).
package csp

import (
	"bufio"
	"bytes"
	"strings"
)

// HostnameResult is the csprecon.jsonl record shape for in-scope CSP hostnames.
type HostnameResult struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
}

// Extract parses csprecon plain-text output (one hostname per line) and
// returns only the hostnames that are in scope for the target domain.
// Source field is always "csp".
//
// Returns an empty (non-nil) slice if rawOutput is empty or no in-scope
// hostnames are found.
func Extract(cspreconText []byte, domain string) ([]HostnameResult, error) {
	if len(cspreconText) == 0 {
		return []HostnameResult{}, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	seen := make(map[string]bool)
	var results []HostnameResult

	scanner := bufio.NewScanner(bytes.NewReader(cspreconText))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		hostname := strings.ToLower(line)
		if !inScope(hostname, domain) {
			continue
		}
		if seen[hostname] {
			continue
		}
		seen[hostname] = true
		results = append(results, HostnameResult{
			Subdomain: hostname,
			Source:    "csp",
		})
	}
	if results == nil {
		return []HostnameResult{}, nil
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
