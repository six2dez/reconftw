// Package waf is a pure-transform extractor for wafw00f and cdncheck output.
//
// Design constraints (D-W3):
//   - NO imports from internal/core/* (no Backend, AppContext, OutputTree).
//   - Pure-transform functions only: Extract(rawOutput, domain) shape.
//   - Never break Phase-4 callers.
//
// wafw00f output format (text, one entry per host):
//
//	<url> : <waf_name>
//
// Lines containing "(None)" are skipped (no WAF detected).
//
// cdncheck output format (text, one IP per line when CDN detected):
//
//	<ip> [<provider>]
package waf

import (
	"bufio"
	"bytes"
	"strings"
)

// WAFResult is the D-W11 waf.jsonl record shape for wafw00f detections.
type WAFResult struct {
	Host       string `json:"host"`
	WAF        string `json:"waf"`
	DetectedBy string `json:"detected_by"`
}

// CDNResult is the D-W11 waf.jsonl record shape for cdncheck detections.
type CDNResult struct {
	Host       string `json:"host"`
	CDN        string `json:"cdn"`
	DetectedBy string `json:"detected_by"`
}

// ExtractWafw00f parses wafw00f text output and returns WAF detection records.
// Lines containing "(None)" are skipped. Only in-scope hosts (suffix match
// against domain) are returned. DetectedBy is always "wafw00f".
//
// Returns an empty (non-nil) slice if rawOutput is empty or no in-scope
// WAF detections are found.
func ExtractWafw00f(text []byte, domain string) ([]WAFResult, error) {
	if len(text) == 0 {
		return []WAFResult{}, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	var results []WAFResult
	scanner := bufio.NewScanner(bytes.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "(None)") {
			continue
		}
		// Expected format: "<url> : <waf_name>" (whitespace-flexible).
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		host := strings.TrimSpace(line[:idx])
		wafName := strings.TrimSpace(line[idx+1:])
		if host == "" || wafName == "" {
			continue
		}
		// Normalise host for scope check (strip scheme/path).
		hostOnly := normalizeHost(host)
		if !inScope(hostOnly, domain) {
			continue
		}
		results = append(results, WAFResult{
			Host:       host,
			WAF:        wafName,
			DetectedBy: "wafw00f",
		})
	}
	if results == nil {
		return []WAFResult{}, nil
	}
	return results, nil
}

// ExtractCDNCheck parses cdncheck -silent -resp -nc output and returns CDN
// classification records.
// Expected line format: "<ip> [<provider>]"
// Only lines with a bracketed provider are returned. The domain parameter is
// unused for IP results (IPs are already scope-validated by the caller) but
// kept for API consistency with the pure-transform shape.
//
// Returns an empty (non-nil) slice if text is empty or no CDN detections found.
func ExtractCDNCheck(text []byte, _ string) ([]CDNResult, error) {
	if len(text) == 0 {
		return []CDNResult{}, nil
	}

	var results []CDNResult
	scanner := bufio.NewScanner(bytes.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Expected format: "<ip> [<provider>]"
		start := strings.Index(line, "[")
		end := strings.Index(line, "]")
		if start < 0 || end <= start {
			continue
		}
		ip := strings.TrimSpace(line[:start])
		provider := strings.TrimSpace(line[start+1 : end])
		if ip == "" || provider == "" {
			continue
		}
		results = append(results, CDNResult{
			Host:       ip,
			CDN:        provider,
			DetectedBy: "cdncheck",
		})
	}
	if results == nil {
		return []CDNResult{}, nil
	}
	return results, nil
}

// normalizeHost strips scheme and path from a URL/host string.
func normalizeHost(h string) string {
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if idx := strings.IndexByte(h, '/'); idx >= 0 {
		h = h[:idx]
	}
	// Strip port for scope check.
	if idx := strings.LastIndex(h, ":"); idx >= 0 {
		// Only strip if no colon in the hostname (i.e., not IPv6).
		if !strings.Contains(h[:idx], ":") {
			h = h[:idx]
		}
	}
	return strings.ToLower(h)
}

// inScope is the anchored hostname scope check mirroring
// lib/validation.sh:is_in_scope_host semantics.
func inScope(host, domain string) bool {
	if domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}
