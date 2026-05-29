// Package js is a pure-transform extractor for jsluice output.
//
// Design constraints (04-03-PLAN.md D-02):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Phase 5 may import this package and extend it for web outputs (secret
//     extraction, endpoint cataloguing) without modification to this package.
//
// jsluice output format (one JSON object per line):
//
//	{"url":"https://api.example.com/v1","kind":"URL"}
//	{"url":"https://cdn.other.org/js","kind":"URL","secret":"..."}
//
// The extractor parses the "url" field, extracts the hostname, and filters
// to subdomains of the target domain. Secret and endpoint fields are intentionally
// NOT surfaced in Result here — Phase 5 owns that extraction layer.
package js

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

// Result is a single JS-link match: a subdomain candidate plus the source URL.
// The URL field is included to give Phase 5 a context anchor for the subdomain.
type Result struct {
	// Subdomain is the hostname extracted from the jsluice output URL.
	Subdomain string
	// URL is the full URL from which the subdomain was extracted.
	URL string
}

// jsluiceLine is the minimal shape we need from jsluice JSON output.
// Additional fields (kind, secret, endpoint, etc.) are ignored at this layer.
type jsluiceLine struct {
	URL string `json:"url"`
}

// Extract parses rawOutput (jsluice stdout, one JSON object per line) and returns
// subdomain candidates that are equal to or a subdomain of domain.
//
// Relative URLs (no scheme or host) are silently skipped.
// Returns an empty (non-nil) slice if rawOutput is empty or no in-scope matches
// are found. Error is reserved for future extensions; current implementation
// never returns a non-nil error for well-formed JSON input.
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

		var entry jsluiceLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip malformed JSON lines without failing the whole parse.
			continue
		}
		if entry.URL == "" {
			continue
		}

		// Parse URL to extract hostname.
		u, err := url.Parse(entry.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			// Relative URL — no hostname.
			continue
		}

		if !inScope(host, domain) {
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		results = append(results, Result{Subdomain: host, URL: entry.URL})
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
