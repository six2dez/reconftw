// Package urls is a pure-transform extractor for URL discovery tool output.
//
// Design constraints (D-W3):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Pure-transform function only: ExtractURLs(plainText, source, domain) shape.
//   - Never break Phase-4 callers.
//
// Input format: plain text URL list, one URL per line (output of katana,
// urlfinder, waymore, subjs, p1radup, urless, JSA, etc.).
//
// D-W11 URL record schema: {url, source, host}
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 1.
package urls

import (
	"bufio"
	"bytes"
	"net/url"
	"strings"
)

// URLRecord is the D-W11 URL artefact record shape.
// Written to artefacts/urls.jsonl by Tasks after dedup.
type URLRecord struct {
	URL    string `json:"url"`
	Source string `json:"source"`
	Host   string `json:"host"`
}

// ExtractURLs parses a plain-text URL list (one URL per line) and returns
// URLRecord values for in-scope URLs.
//
// source is the producer name (e.g. "katana", "urlfinder", "waymore") and
// is embedded in each record for provenance tracking.
//
// domain is used for in-scope filtering: only URLs whose hostname is equal to
// or a subdomain of domain are returned. Pass "" to accept all URLs.
//
// Lines longer than 2048 bytes are skipped (v1 katana behaviour for oversized URLs).
// Empty lines and lines that fail URL parsing are silently skipped.
//
// Returns an empty (non-nil) slice if plainText is empty or no in-scope URLs found.
func ExtractURLs(plainText []byte, source string, domain string) ([]URLRecord, error) {
	if len(plainText) == 0 {
		return []URLRecord{}, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	var results []URLRecord
	scanner := bufio.NewScanner(bytes.NewReader(plainText))
	// Use a 4 MiB buffer to handle large lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		rawLine := scanner.Bytes()
		line := string(bytes.TrimSpace(rawLine))
		if line == "" {
			continue
		}
		// Skip oversized lines (v1 katana strips > 2048 chars).
		if len(line) > 2048 {
			continue
		}

		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		// Only accept http/https URLs (ignore relative URLs, data URIs, etc.).
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}

		// Scope filter: skip out-of-scope hosts when domain is set.
		if domain != "" && !inScope(host, domain) {
			continue
		}

		results = append(results, URLRecord{
			URL:    line,
			Source: source,
			Host:   host,
		})
	}

	if results == nil {
		return []URLRecord{}, nil
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
