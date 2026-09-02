// parity_test.go — Frozen-replay parity harness for the web pipeline (D-W7, WEB-16).
//
// Purpose: detect porting bugs by replaying v1-captured (or synthetic) tool
// output through v2 web pipeline logic and asserting per-category behaviour
// matches exactly. This is a CI hard gate (~0% tolerance for deterministic
// categories; exact match for parse/redact logic).
//
// FIXTURE NOTES:
//   - Stub fixtures (httpx, nuclei, katana): header starts "# TODO: capture from: ..."
//     → test t.Skip()s cleanly. Populate via Plan 05-07 instructions.
//   - Synthetic fixtures (jsluice_secrets.jsonl, wafw00f_example.txt): committed
//     right now. Tests backed by these MUST PASS (no t.Skip).
//   - jsluice_secrets.jsonl uses clearly-fake token "FAKE_AWS_AAAA0000BBBBCCCC"
//     to verify ExtractSecrets redaction without committing real credentials (T-05-20).
//
// FIXTURE CAPTURE INSTRUCTIONS (for stub fixtures):
//
//	After running bash v1 against example.com, copy real tool output:
//	  cp Recon/example.com/webs/webs_all.jsonl testdata/fixtures/httpx/httpx_example.jsonl
//	Then replace the stub header line with:
//	  # captured-from: httpx -follow-host-redirects ... -json -l hosts_seed.txt | date: YYYY-MM-DD
//
// Source: .planning/phases/05-web-pipeline-e2e/05-06-PLAN.md Task 1.
// PACKAGE web, NOT web_test. These tests must call parseHTTPXOutput and
// parseNucleiOutput, which are unexported — and calling the production parser is
// the entire point of this file after the 2026-08-21 dead-web-layer bug. The
// file used zero `web.`-qualified names and shares no helper with the other
// web_test files, so the move is mechanical.
package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/extract/js"
	"github.com/six2dez/reconftw/internal/extract/waf"
)

// webParitySkip checks the first non-empty line of fixtureBytes:
//   - Empty file or "# TODO:" header → t.Skip (fixture not captured yet).
//   - Other "# "-prefixed line → return without skip (synthetic/captured).
//   - No # prefix on non-empty line → return without skip (data file).
func webParitySkip(t *testing.T, fixtureBytes []byte, fixturePath string) {
	t.Helper()
	if len(fixtureBytes) == 0 {
		t.Skipf("fixture not captured yet (empty file): %s", fixturePath)
	}
	scanner := bufio.NewScanner(bytes.NewReader(fixtureBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# TODO:") {
			t.Skipf("fixture not captured yet (stub header): %s — populate via Plan 05-07", fixturePath)
		}
		return
	}
	t.Skipf("fixture not captured yet (all-whitespace): %s", fixturePath)
}

// fixturesBase returns the path to the testdata/fixtures directory
// relative to this test file's package directory.
func fixturesBase() string { return filepath.Join("testdata", "fixtures") }

// -------------------------------------------------------------------------
// TestWebParityHTTPX / TestWebParityNuclei
//
// THESE TWO TESTS USED TO REIMPLEMENT THE PARSERS THEY NAMED.
//
// Their doc-comments said "verifies that httpx JSONL output feeds through
// parseHTTPXOutput" and "feeds through parseNucleiOutput". Neither ever called
// either function. Each declared a two-field anonymous struct inline, decoded
// with that, and asserted on the result — so what was validated was a parser
// written in this file, against a fixture, while the production parser went
// unexecuted.
//
// The cost: testdata/fixtures/httpx/httpx_example.jsonl has been in the repo
// since 2026-06-02 and contains `"port":"443"` — a STRING. httpxRaw.Port was an
// `int`, so json.Unmarshal failed on every real line and parseHTTPXOutput
// returned "all N lines failed to parse". The falsifying evidence sat beside the
// test for two and a half months, and the first live parity run scored 0 live
// hosts against v1's 12 because artefacts/hosts.jsonl was truncated to 0 bytes.
//
// Two rules follow, and both are enforced below rather than described:
//
//  1. CALL THE PRODUCTION PARSER. A test that reimplements the function under
//     test cannot falsify that function's struct — it can only agree with its
//     own copy.
//  2. ASSERT AT FIELD LEVEL, NOT AT COUNT LEVEL. The old tests counted records.
//     Two of the three real bugs (`status-code` and `content-length` against
//     httpx's `status_code`/`content_length`) decoded to a silent ZERO, so a
//     count assertion stayed green through both.
// -------------------------------------------------------------------------

// TestWebParityHTTPX decodes the June 2026 captured httpx fixture through the
// PRODUCTION parseHTTPXOutput and asserts, per field, that the three tags/types
// that were wrong now carry real values from the fixture.
//
// This is the regression guard for the dead-web-layer bug, pinned against the
// fixture that was already present when the bug shipped.
func TestWebParityHTTPX(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "httpx", "httpx_example.jsonl")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	webParitySkip(t, data, fixturePath)
	requireCapturedProvenance(t, data, fixturePath)

	// THE PRODUCTION PARSER. Not a copy of it.
	records, parseErr := parseHTTPXOutput(data)
	if parseErr != nil {
		t.Fatalf("parseHTTPXOutput rejected REAL captured httpx output: %v\n"+
			"  fixture: %s\n"+
			"  This is the exact failure that emptied artefacts/hosts.jsonl and took the whole web\n"+
			"  layer with it. A struct tag or field type disagrees with what httpx emits.", parseErr, fixturePath)
	}
	if len(records) == 0 {
		t.Fatalf("parseHTTPXOutput returned ZERO records from %s — the state that killed the web layer", fixturePath)
	}

	// FIELD-LEVEL ASSERTIONS. Each names the field's failure mode, because a
	// combined "some field is empty" message would not say which contract broke.
	var sawPort, sawStatus, sawLength, sawHost bool
	for _, r := range records {
		if r.Host != "" {
			sawHost = true
		}
		if r.Port != "" {
			sawPort = true
		}
		if r.Status != 0 {
			sawStatus = true
		}
		if r.ContentLength != 0 {
			sawLength = true
		}
	}
	if !sawHost {
		t.Errorf("no decoded record carries a host — parseHTTPXOutput produced records with nothing in them")
	}
	if !sawPort {
		t.Errorf("PORT is empty in every decoded record.\n"+
			"  httpx emits `\"port\":\"443\"` as a STRING. A numeric httpxRaw.Port makes json.Unmarshal\n"+
			"  fail on the WHOLE line, which is the fatal form of this bug: every record is lost, not\n"+
			"  just the port. Fixture: %s", fixturePath)
	}
	if !sawStatus {
		t.Errorf("STATUS is zero in every decoded record.\n"+
			"  httpx emits `status_code` with an UNDERSCORE. A `status-code` tag decodes to a silent\n"+
			"  zero — the record survives and the data does not, so a count-only assertion stays green.\n"+
			"  Fixture: %s", fixturePath)
	}
	if !sawLength {
		t.Errorf("CONTENT LENGTH is zero in every decoded record.\n"+
			"  httpx emits `content_length` with an UNDERSCORE. Same silent-zero shape as status.\n"+
			"  Fixture: %s", fixturePath)
	}

	// Name a specific record so a failure identifies the fixture line.
	first := records[0]
	t.Logf("TestWebParityHTTPX: %d record(s) via parseHTTPXOutput; first = host=%q port=%q status=%d len=%d",
		len(records), first.Host, first.Port, first.Status, first.ContentLength)
}

// TestWebParityNuclei decodes the June 2026 captured nuclei fixture through the
// PRODUCTION parseNucleiOutput and asserts severity counts from the DECODED
// records rather than from a private copy of the decoder.
//
// nuclei's field names are hyphenated (`template-id`, `matched-at`,
// `extracted-results`) where httpx's are underscored — the two ProjectDiscovery
// tools disagree with each other, which is precisely why a struct tag can only
// be validated against captured output.
func TestWebParityNuclei(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "nuclei", "nuclei_example.jsonl")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	webParitySkip(t, data, fixturePath)
	requireCapturedProvenance(t, data, fixturePath)

	records := parseNucleiOutput(data)
	if len(records) == 0 {
		t.Fatalf("parseNucleiOutput returned ZERO records from REAL captured nuclei output (%s).\n"+
			"  Every finding would be dropped and the run would report no vulnerabilities — a report\n"+
			"  that understates risk, which is the worst failure mode available to a security tool.",
			fixturePath)
	}

	severity := map[string]int{}
	var sawTemplateID, sawMatchedAt, sawHost bool
	for _, r := range records {
		if s := strings.ToLower(r.Severity); s != "" {
			severity[s]++
		}
		if r.TemplateID != "" {
			sawTemplateID = true
		}
		if r.MatchedAt != "" {
			sawMatchedAt = true
		}
		if r.Host != "" {
			sawHost = true
		}
	}
	if len(severity) == 0 {
		t.Errorf("SEVERITY is empty in every decoded record.\n"+
			"  nuclei nests it as info.severity. An empty severity means every finding is unclassified\n"+
			"  and triage cannot rank anything. Fixture: %s", fixturePath)
	}
	if !sawTemplateID {
		t.Errorf("TEMPLATE ID is empty in every decoded record — nuclei emits `template-id` with a "+
			"HYPHEN, unlike httpx's underscored fields. Fixture: %s", fixturePath)
	}
	if !sawMatchedAt {
		t.Errorf("MATCHED-AT is empty in every decoded record — nuclei emits `matched-at`; without it "+
			"a finding names no location. Fixture: %s", fixturePath)
	}
	if !sawHost {
		t.Errorf("HOST is empty in every decoded record — findings would fail the scope gate and the "+
			"whole merged batch would be rejected. Fixture: %s", fixturePath)
	}
	t.Logf("TestWebParityNuclei: %d record(s) via parseNucleiOutput; severity split %v", len(records), severity)
}

// requireCapturedProvenance fails a fixture that does not say where it came from.
//
// A hand-written fixture for a third-party format AGREES WITH THE STRUCT AND
// DISAGREES WITH THE TOOL: it is written by reading the Go struct, so it can
// only ever confirm what the struct already believes. Only captured output can
// falsify a struct, so a fixture without recorded provenance is not evidence.
func requireCapturedProvenance(t *testing.T, data []byte, fixturePath string) {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.Contains(line, "captured-from:") {
				return
			}
			continue
		}
		break
	}
	t.Fatalf("%s has no `# captured-from:` provenance header.\n"+
		"  A fixture for a third-party tool's output format is only evidence if it came FROM that\n"+
		"  tool. A hand-written one agrees with the struct by construction and cannot falsify it —\n"+
		"  which is how httpxRaw.Port stayed wrong through a passing test suite.", fixturePath)
}

// -------------------------------------------------------------------------
// TestWebParityFFUF — stub-backed: skips when results array is empty.
// -------------------------------------------------------------------------

// TestWebParityFFUF verifies ffuf JSON output structure and status-code buckets.
// Skips when the fixture contains an empty results array (stub state).
func TestWebParityFFUF(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "ffuf", "ffuf_example.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	if len(data) == 0 {
		t.Skip("ffuf fixture is empty — populate via Plan 05-07")
	}

	var fj struct {
		Results []struct {
			Status int    `json:"status"`
			URL    string `json:"url"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &fj); err != nil {
		t.Fatalf("TestWebParityFFUF: parse fixture JSON: %v", err)
	}
	if len(fj.Results) == 0 {
		t.Skip("ffuf fixture has empty results — populate with real data via Plan 05-07")
	}

	// Count status code buckets.
	buckets := make(map[int]int)
	for _, r := range fj.Results {
		buckets[r.Status]++
	}
	t.Logf("TestWebParityFFUF: %d results; status buckets: %v", len(fj.Results), buckets)
}

// -------------------------------------------------------------------------
// TestWebParityWAF — SYNTHETIC fixture: MUST PASS without t.Skip.
// -------------------------------------------------------------------------

// TestWebParityWAF exercises extract/waf.ExtractWafw00f against the synthetic
// wafw00f fixture. Asserts:
//   - Lines with "(None)" are excluded from results.
//   - In-scope hosts with a WAF name are returned.
//   - The detected WAF host set matches the synthetic fixture golden.
//
// This test MUST PASS (not skip) — it uses a committed synthetic fixture.
func TestWebParityWAF(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "waf", "wafw00f_example.txt")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	if len(data) == 0 {
		t.Fatal("TestWebParityWAF: fixture is empty — this is a committed synthetic fixture; check git history")
	}

	// Call ExtractWafw00f with the synthetic fixture.
	results, err := waf.ExtractWafw00f(data, "example.com")
	if err != nil {
		t.Fatalf("ExtractWafw00f error: %v", err)
	}

	// Golden: support.example.com and api.example.com have Cloudflare.
	// docs.example.com and example.com are "(None)" — must be excluded.
	if len(results) != 2 {
		t.Errorf("TestWebParityWAF: expected 2 WAF results (Cloudflare hosts), got %d: %+v",
			len(results), results)
	}

	// Build detected host→WAF map.
	detected := make(map[string]string)
	for _, r := range results {
		detected[r.Host] = r.WAF
	}

	// Assert support.example.com and api.example.com detected as Cloudflare.
	for _, expectedHost := range []string{
		"https://support.example.com",
		"https://api.example.com",
	} {
		wafName, ok := detected[expectedHost]
		if !ok {
			t.Errorf("TestWebParityWAF: expected host %q in results but not found; detected: %v",
				expectedHost, detected)
			continue
		}
		if wafName != "Cloudflare" {
			t.Errorf("TestWebParityWAF: expected WAF=Cloudflare for %q, got %q", expectedHost, wafName)
		}
	}

	// Assert "(None)" lines excluded: no result with empty WAF name or WAF="(None)".
	for _, r := range results {
		if r.WAF == "" || strings.Contains(r.WAF, "(None)") {
			t.Errorf("TestWebParityWAF: result with no/None WAF leaked through: %+v", r)
		}
	}

	// Assert DetectedBy is always "wafw00f".
	for _, r := range results {
		if r.DetectedBy != "wafw00f" {
			t.Errorf("TestWebParityWAF: expected DetectedBy=wafw00f, got %q in %+v", r.DetectedBy, r)
		}
	}

	t.Logf("TestWebParityWAF: PASS — %d WAF detections: %v", len(results), detected)
}

// -------------------------------------------------------------------------
// TestWebParityJSSecrets — SYNTHETIC fixture: MUST PASS without t.Skip.
// -------------------------------------------------------------------------

// TestWebParityJSSecrets exercises extract/js.ExtractSecrets against the
// synthetic jsluice_secrets fixture. Asserts:
//   - All 3 records are returned (one per fixture line).
//   - Every record has Redacted == "***".
//   - No record field contains the fake raw token "FAKE_AWS_AAAA0000BBBBCCCC"
//     (XCUT-07: raw secret values must never propagate).
//
// This test MUST PASS (not skip) — it uses a committed synthetic fixture.
func TestWebParityJSSecrets(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "js", "jsluice_secrets.jsonl")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	if len(data) == 0 {
		t.Fatal("TestWebParityJSSecrets: fixture is empty — this is a committed synthetic fixture; check git history")
	}

	// Call ExtractSecrets with the synthetic fixture.
	records, err := js.ExtractSecrets(data, "example.com")
	if err != nil {
		t.Fatalf("ExtractSecrets error: %v", err)
	}

	// Assert count: 3 records (one per fixture line).
	if len(records) != 3 {
		t.Errorf("TestWebParityJSSecrets: expected 3 records, got %d", len(records))
	}

	// The raw fake token that must NEVER appear in any output field.
	const forbiddenRaw = "FAKE_AWS_AAAA0000BBBBCCCC"

	for i, rec := range records {
		// Assert Redacted is always "***" (XCUT-07 guarantee).
		if rec.Redacted != "***" {
			t.Errorf("TestWebParityJSSecrets: record[%d].Redacted = %q; want \"***\"", i, rec.Redacted)
		}

		// Assert the fake raw value does NOT appear in any exported field.
		// Marshal to JSON and search for the forbidden string as a belt-and-suspenders check.
		recJSON, merr := json.Marshal(rec)
		if merr != nil {
			t.Errorf("TestWebParityJSSecrets: marshal record[%d]: %v", i, merr)
			continue
		}
		if strings.Contains(string(recJSON), forbiddenRaw) {
			t.Errorf("TestWebParityJSSecrets: record[%d] JSON contains forbidden raw value %q: %s",
				i, forbiddenRaw, recJSON)
		}

		// Also check individual fields explicitly.
		for fieldName, fieldVal := range map[string]string{
			"URL":      rec.URL,
			"Type":     rec.Type,
			"Severity": rec.Severity,
			"Redacted": rec.Redacted,
		} {
			if strings.Contains(fieldVal, forbiddenRaw) {
				t.Errorf("TestWebParityJSSecrets: record[%d].%s contains forbidden raw value: %q",
					i, fieldName, fieldVal)
			}
		}
	}

	t.Logf("TestWebParityJSSecrets: PASS — %d records, all redacted", len(records))
}

// -------------------------------------------------------------------------
// TestWebParityURLDedup — stub-backed: skips until Plan 05-07 populates fixture.
// -------------------------------------------------------------------------

// TestWebParityURLDedup verifies URL list fixture can be parsed and counted.
// Skips cleanly when the fixture has not been captured yet.
func TestWebParityURLDedup(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "urls", "katana_example.txt")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	webParitySkip(t, data, fixturePath)

	// Count unique non-empty non-comment URLs.
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		seen[line] = struct{}{}
	}
	if len(seen) == 0 {
		t.Error("TestWebParityURLDedup: fixture parsed 0 URLs — fixture may be malformed")
	}
	t.Logf("TestWebParityURLDedup: %d unique URLs in fixture", len(seen))
}
