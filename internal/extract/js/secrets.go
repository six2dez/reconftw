// secrets.go — ExtractSecrets: jsluice "secrets" mode JSONL parser.
//
// Phase 5 in-place extension of extract/js per D-W3.
// The existing Extract function (js.go) is NOT modified.
//
// XCUT-07 / T-05-12 CRITICAL:
// jsluice secrets output contains raw credential values in the "value" field.
// ExtractSecrets NEVER propagates the raw value to SecretRecord.
// SecretRecord.Redacted is ALWAYS "***" — hardcoded, never derived from input.
//
// jsluice secrets mode field names (RESEARCH §Extractor Extension Shape / A6):
//
//	{"kind":"AWS_ACCESS_KEY","value":"AKIA...","filename":"/path/to/file.js","severity":"high"}
//
// CRITICAL: jsluice uses "filename" (not "url") for the source file path.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 1.
package js

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// SecretRecord is the D-W11 JS-secret artefact record shape.
// The raw credential value is intentionally NEVER stored (XCUT-07).
type SecretRecord struct {
	URL      string `json:"url"`              // filename/source path from jsluice
	Type     string `json:"type"`             // secret kind (from jsluice "kind" field)
	Severity string `json:"severity"`         // jsluice severity level
	Redacted string `json:"secret_redacted"`  // always "***" — never the raw value
}

// jsluiceSecretLine is the internal parse shape for jsluice secrets JSONL.
// The Value field is read-only; it is NEVER propagated to SecretRecord (XCUT-07).
//
// CRITICAL: jsluice secrets mode uses "filename" for the source file path,
// not "url". Both URL and url JSON tags omitted — only "filename" is used.
type jsluiceSecretLine struct {
	URL      string `json:"filename"` // CRITICAL: jsluice secrets uses "filename" not "url"
	Kind     string `json:"kind"`
	Value    string `json:"value"`    // read-only; NEVER propagated
	Severity string `json:"severity"`
}

// ExtractSecrets parses jsluice "secrets" mode JSONL output and returns
// SecretRecord values with mandatory redaction applied.
//
// Every SecretRecord.Redacted is hardcoded to "***". The raw jsluice value
// field is read internally for metadata but is NEVER propagated to any
// returned field. This is the XCUT-07 / T-05-12 guarantee.
//
// The domain parameter is accepted for API consistency with other extractors;
// all records from file paths are returned regardless of domain match
// (secret findings from any analysed file are relevant to the run).
//
// Returns an empty (non-nil) slice if rawOutput is empty or no records found.
func ExtractSecrets(rawOutput []byte, _ string) ([]SecretRecord, error) {
	if len(rawOutput) == 0 {
		return []SecretRecord{}, nil
	}

	var results []SecretRecord
	scanner := bufio.NewScanner(bytes.NewReader(rawOutput))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var entry jsluiceSecretLine
		if err := json.Unmarshal(line, &entry); err != nil {
			// Skip malformed lines; partial parse is acceptable.
			continue
		}

		// XCUT-07: Value is parsed above (read-only) but NEVER propagated.
		// entry.Value is intentionally discarded here.

		rec := SecretRecord{
			URL:      entry.URL, // "filename" field from jsluice
			Type:     entry.Kind,
			Severity: strings.ToLower(strings.TrimSpace(entry.Severity)),
			Redacted: "***", // ALWAYS "***" — never entry.Value
		}

		// Accept all records (file paths are in-scope by definition).
		// Empty URL is acceptable for records without a filename field.
		results = append(results, rec)
	}

	if results == nil {
		return []SecretRecord{}, nil
	}
	return results, nil
}
