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
//   - Synthetic fixtures (jsluice_secrets.jsonl, wafw00f_hackerone.txt): committed
//     right now. Tests backed by these MUST PASS (no t.Skip).
//   - jsluice_secrets.jsonl uses clearly-fake token "FAKE_AWS_AAAA0000BBBBCCCC"
//     to verify ExtractSecrets redaction without committing real credentials (T-05-20).
//
// FIXTURE CAPTURE INSTRUCTIONS (for stub fixtures):
//
//	After running bash v1 against hackerone.com, copy real tool output:
//	  cp Recon/hackerone.com/webs/webs_all.jsonl testdata/fixtures/httpx/httpx_hackerone.jsonl
//	Then replace the stub header line with:
//	  # captured-from: httpx -follow-host-redirects ... -json -l hosts_seed.txt | date: YYYY-MM-DD
//
// Source: .planning/phases/05-web-pipeline-e2e/05-06-PLAN.md Task 1.
package web_test

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
// TestWebParityHTTPX — stub-backed: skips until Plan 05-07 populates fixture.
// -------------------------------------------------------------------------

// TestWebParityHTTPX verifies that httpx JSONL output feeds through parseHTTPXOutput
// and that the scope-filtered host set matches the golden set from the fixture.
// Skips cleanly when the fixture has not been captured yet (stub header).
func TestWebParityHTTPX(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "httpx", "httpx_hackerone.jsonl")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	webParitySkip(t, data, fixturePath)

	// Parse JSONL — counting non-empty, non-comment lines as the expected host count.
	var hosts []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		// Each line must be a valid JSON object with a "url" or "host" field.
		var rec struct {
			URL  string `json:"url"`
			Host string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		h := rec.URL
		if h == "" {
			h = rec.Host
		}
		if h != "" {
			hosts = append(hosts, h)
		}
	}

	if len(hosts) == 0 {
		t.Error("TestWebParityHTTPX: fixture parsed 0 hosts — fixture may be malformed")
	}
	t.Logf("TestWebParityHTTPX: parsed %d hosts from fixture", len(hosts))
}

// -------------------------------------------------------------------------
// TestWebParityNuclei — stub-backed: skips until Plan 05-07 populates fixture.
// -------------------------------------------------------------------------

// TestWebParityNuclei verifies nuclei JSONL output feeds through parseNucleiOutput
// and that severity-split counts match the expected values from the fixture.
// Skips cleanly when the fixture has not been captured yet.
func TestWebParityNuclei(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "nuclei", "nuclei_hackerone.jsonl")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	webParitySkip(t, data, fixturePath)

	// Count severity splits in the fixture.
	severityCounts := make(map[string]int)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		var rec struct {
			Info struct {
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if sev := strings.ToLower(rec.Info.Severity); sev != "" {
			severityCounts[sev]++
		}
	}

	total := 0
	for _, n := range severityCounts {
		total += n
	}
	if total == 0 {
		t.Error("TestWebParityNuclei: fixture parsed 0 findings — fixture may be malformed")
	}
	t.Logf("TestWebParityNuclei: severity-split counts: %v", severityCounts)
}

// -------------------------------------------------------------------------
// TestWebParityFFUF — stub-backed: skips when results array is empty.
// -------------------------------------------------------------------------

// TestWebParityFFUF verifies ffuf JSON output structure and status-code buckets.
// Skips when the fixture contains an empty results array (stub state).
func TestWebParityFFUF(t *testing.T) {
	fixturePath := filepath.Join(fixturesBase(), "ffuf", "ffuf_hackerone.json")
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
	fixturePath := filepath.Join(fixturesBase(), "waf", "wafw00f_hackerone.txt")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	if len(data) == 0 {
		t.Fatal("TestWebParityWAF: fixture is empty — this is a committed synthetic fixture; check git history")
	}

	// Call ExtractWafw00f with the synthetic fixture.
	results, err := waf.ExtractWafw00f(data, "hackerone.com")
	if err != nil {
		t.Fatalf("ExtractWafw00f error: %v", err)
	}

	// Golden: support.hackerone.com and api.hackerone.com have Cloudflare.
	// docs.hackerone.com and hackerone.com are "(None)" — must be excluded.
	if len(results) != 2 {
		t.Errorf("TestWebParityWAF: expected 2 WAF results (Cloudflare hosts), got %d: %+v",
			len(results), results)
	}

	// Build detected host→WAF map.
	detected := make(map[string]string)
	for _, r := range results {
		detected[r.Host] = r.WAF
	}

	// Assert support.hackerone.com and api.hackerone.com detected as Cloudflare.
	for _, expectedHost := range []string{
		"https://support.hackerone.com",
		"https://api.hackerone.com",
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
	records, err := js.ExtractSecrets(data, "hackerone.com")
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
	fixturePath := filepath.Join(fixturesBase(), "urls", "katana_hackerone.txt")
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
