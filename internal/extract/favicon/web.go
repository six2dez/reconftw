// web.go — ExtractWeb: JSON-format favicon parser for the web pipeline.
//
// This file EXTENDS the favicon package without modifying favicon.go.
// The existing Extract function parses the Phase-4 plain-text format
// ("<hash> <subdomain>") used by the subdomains pipeline.
//
// ExtractWeb parses favirecon -j JSON output (array or NDJSON) used by the
// WEB-10 web pipeline Task.
//
// CRITICAL (Pitfall 7): Do NOT call Extract on JSON output — the two formats
// are incompatible. WEB-10 FaviReconTask calls ExtractWeb exclusively.
//
// Open Question 4 resolution: favirecon -j field names vary by version
// (URL/url, Name/name, Hash/hash). ExtractWeb uses case-insensitive fallback
// mirroring v1's jq style: (.URL // .url // ""), (.Name // .name // ""),
// (.Hash // .hash // "").
//
// Design constraints (D-W3):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Adds to the existing favicon package; does NOT modify favicon.go.
package favicon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

// WebResult is the D-W11 favicons.jsonl record shape for favirecon JSON output.
// Host is the per-record hostname (from u.Hostname()) — not the apex domain.
// Field renamed from Domain to Host (WR-03: the value is a hostname, not a domain).
type WebResult struct {
	URL  string `json:"url"`
	Tech string `json:"tech"`
	Hash string `json:"hash"` // Shodan mmh3 favicon hash
	Host string `json:"host"` // WR-03: renamed from Domain (value is per-record hostname)
}

// rawFaviconItem is used for case-insensitive field access (Open Question 4).
// We unmarshal into map[string]interface{} then probe both Title-case and
// lower-case variants to handle all observed favirecon output versions.
type rawFaviconItem map[string]interface{}

func (r rawFaviconItem) getString(keys ...string) string {
	for _, k := range keys {
		if v, ok := r[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// ExtractWeb parses favirecon -j JSON output and returns in-scope WebResults.
//
// Input may be a JSON array or NDJSON (one JSON object per line).
// ExtractWeb tries the JSON array form first; if that fails it falls back to
// line-by-line NDJSON parsing.
//
// Only records whose URL hostname is in scope for domain are returned.
// Records with no URL field are silently dropped.
//
// Returns an empty (non-nil) slice if jsonBytes is empty or no in-scope
// results are found.
func ExtractWeb(jsonBytes []byte, domain string) ([]WebResult, error) {
	if len(jsonBytes) == 0 {
		return []WebResult{}, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	var items []rawFaviconItem

	// Try JSON array first.
	trimmed := bytes.TrimSpace(jsonBytes)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &items); err != nil {
			items = nil // fall through to NDJSON
		}
	}

	// NDJSON fallback: parse line by line.
	if items == nil {
		scanner := bufio.NewScanner(bytes.NewReader(jsonBytes))
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var fi rawFaviconItem
			if err := json.Unmarshal(line, &fi); err != nil {
				continue
			}
			items = append(items, fi)
		}
	}

	if len(items) == 0 {
		return []WebResult{}, nil
	}

	var results []WebResult
	// WR-03: iterate items directly with non-shadowing loop variable fi.
	// Removed item() identity function — it was dead-weight indirection.
	for _, fi := range items {
		rawURL := fi.getString("URL", "url")
		if rawURL == "" {
			continue
		}
		// Extract hostname for scope check.
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}
		if !inScope(host, domain) {
			continue
		}
		tech := fi.getString("Name", "name")
		hash := fi.getString("Hash", "hash")
		results = append(results, WebResult{
			URL:  rawURL,
			Tech: tech,
			Hash: hash,
			Host: host, // WR-03: renamed from Domain; value is hostname not apex
		})
	}

	if results == nil {
		return []WebResult{}, nil
	}
	return results, nil
}
