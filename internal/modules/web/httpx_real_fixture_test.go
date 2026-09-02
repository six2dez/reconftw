// httpx_real_fixture_test.go — the guard that closes the dead-web-layer bug.
//
// testdata/httpx_real_output.jsonl is VERBATIM output from a real httpx run
// (v1.6, `-json`), captured on reconbox3 against example.com. It is not
// hand-written, because hand-written fixtures are exactly how this bug survived:
// the pre-existing parser tests used JSON somebody typed to match the struct, so
// they agreed with the struct and disagreed with httpx.
//
// What shipped: httpxRaw declared `Port int` while httpx emits `"port":"80"` (a
// STRING), so json.Unmarshal failed on EVERY line and parseHTTPXOutput returned
// "all 20 lines failed to parse". artefacts/hosts.jsonl was truncated to 0 bytes,
// every downstream web task skipped with "no hosts in hosts.jsonl", and the first
// live parity run scored 0 live hosts and 2 finding classes against v1's 12 and
// 50 — while web.httpx itself reported "[OK] web.httpx 31s".
//
// Two more fields were wrong in a quieter way: the tags read "status-code" and
// "content-length" but httpx emits "status_code" and "content_length", so both
// would have decoded as zero even once the line parsed.

package web

import (
	"os"
	"path/filepath"
	"testing"
)

func loadRealHTTPXFixture(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join("testdata", "httpx_real_output.jsonl")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	if len(data) == 0 {
		t.Fatalf("%s is empty — the fixture must be real captured httpx output", p)
	}
	return data
}

// TestParseHTTPXOutputRealFixture is the regression guard. Every assertion here
// failed before the field fix.
func TestParseHTTPXOutputRealFixture(t *testing.T) {
	data := loadRealHTTPXFixture(t)

	records, err := parseHTTPXOutput(data)
	if err != nil {
		t.Fatalf("real httpx output failed to parse: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("parsed ZERO records from real httpx output — this is the exact state " +
			"that emptied artefacts/hosts.jsonl and killed the whole web layer")
	}

	var sawPort, sawStatus, sawHost bool
	for _, r := range records {
		if r.Host == "" {
			t.Errorf("record has no host: %+v", r)
		} else {
			sawHost = true
		}
		if r.Port != "" {
			sawPort = true
		}
		if r.Status != 0 {
			sawStatus = true
		}
	}

	// Each of these pins one of the three wrong fields. Without them the test
	// would still pass with status_code/content_length silently zeroed.
	if !sawHost {
		t.Error("no record carried a host")
	}
	if !sawPort {
		t.Error(`every record has an empty Port — httpx emits "port" as a STRING; ` +
			`decoding it as an int discards the entire line`)
	}
	if !sawStatus {
		t.Error(`every record has Status 0 — the httpx field is "status_code", ` +
			`not "status-code"`)
	}
}

// TestParseHTTPXOutputContentLength pins the third field separately: it can be a
// legitimate 0, so it is asserted against the fixture's own decoded JSON rather
// than "non-zero somewhere".
func TestParseHTTPXOutputContentLength(t *testing.T) {
	data := loadRealHTTPXFixture(t)
	records, err := parseHTTPXOutput(data)
	if err != nil || len(records) == 0 {
		t.Fatalf("fixture must parse: err=%v records=%d", err, len(records))
	}
	total := 0
	for _, r := range records {
		total += r.ContentLength
	}
	if total == 0 {
		t.Error(`every record has ContentLength 0 — the httpx field is ` +
			`"content_length", not "content-length"`)
	}
}

// TestHTTPXFixtureIsRealOutput guards the fixture itself. A future edit that
// "tidies" it into hand-written JSON matching the struct would silently restore
// the blind spot this whole file exists to remove.
func TestHTTPXFixtureIsRealOutput(t *testing.T) {
	data := loadRealHTTPXFixture(t)
	// Markers httpx emits that nobody writing a minimal fixture by hand would add.
	for _, marker := range []string{`"timestamp"`, `"knowledgebase"`, `"failed":`} {
		if !containsBytes(data, marker) {
			t.Errorf("fixture is missing %s — it no longer looks like verbatim httpx "+
				"output. Re-capture it with: httpx -duc -silent -json -l <hosts> -o <file>", marker)
		}
	}
}

func containsBytes(haystack []byte, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexOf(string(haystack), needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
