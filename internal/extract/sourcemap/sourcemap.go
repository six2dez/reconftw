// Package sourcemap is a pure-transform extractor for jsluice URL-mode output
// and sourcemapper directory trees.
//
// Design constraints (D-W3):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Pure-transform function only: ExtractFromJSluice(jsonl, domain) shape.
//   - Never break Phase-4 callers.
//
// jsluice urls mode output format (NDJSON, one JSON object per line):
//
//	{"url":"https://api.example.com/v1","kind":"URL"}
//
// Fields: "url" and "kind" (vs secrets mode which uses "filename" and "kind").
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 1.
package sourcemap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

// SourceMapEntry is a URL extracted from jsluice urls-mode JSONL output.
// Used to represent URLs discovered in source-mapped files.
type SourceMapEntry struct {
	URL      string `json:"url"`
	Type     string `json:"type"`     // jsluice "kind" field (e.g. "URL", "FormAction")
	FilePath string `json:"filepath"` // path of the JS/TS file that contained this URL (if available)
}

// jsluiceURLLine is the internal parse shape for jsluice urls JSONL.
// jsluice urls mode uses "url" and "kind" fields.
type jsluiceURLLine struct {
	URL      string `json:"url"`
	Kind     string `json:"kind"`
	Filename string `json:"filename"` // sometimes present in urls mode too
}

// ExtractFromJSluice parses jsluice "urls" mode JSONL output and returns
// SourceMapEntry values for URLs that are in-scope.
//
// domain is used for in-scope filtering: only URLs whose hostname is equal to
// or a subdomain of domain are returned. Pass "" to accept all URLs.
//
// Empty lines and lines that fail to parse are silently skipped.
// Returns an empty (non-nil) slice if jsonl is empty or no records found.
func ExtractFromJSluice(jsonl []byte, domain string) ([]SourceMapEntry, error) {
	if len(jsonl) == 0 {
		return []SourceMapEntry{}, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	var results []SourceMapEntry
	scanner := bufio.NewScanner(bytes.NewReader(jsonl))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var entry jsluiceURLLine
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.URL == "" {
			continue
		}

		// Scope filter via hostname extraction.
		u, err := url.Parse(entry.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			// Relative URL — include without scope filter.
		} else if domain != "" && !inScope(host, domain) {
			continue
		}

		results = append(results, SourceMapEntry{
			URL:      entry.URL,
			Type:     entry.Kind,
			FilePath: entry.Filename,
		})
	}

	if results == nil {
		return []SourceMapEntry{}, nil
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
