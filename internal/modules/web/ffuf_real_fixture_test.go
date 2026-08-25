// ffuf_real_fixture_test.go — parseFFUFOutput against REAL captured ffuf output.
//
// Plan 16-07 Task 2's census found parseFFUFOutput and parseFFUFJSONL classified
// third-party and NEVER reached by a test that passes captured output through
// them. A captured ffuf fixture already sat in testdata/fixtures/ffuf/ — nothing
// decoded it with the production parser, which is precisely the shape that let
// httpxRaw.Port stay wrong for two and a half months with the falsifying
// evidence sitting beside the test.
//
// FIELD-LEVEL, NOT COUNT-LEVEL. Two of the three real httpx bugs
// (`status-code`, `content-length`) decoded to a silent ZERO: the record
// survived and the data did not, so a count assertion stayed green through both.
// Every field parseFFUFOutput maps is asserted here, against a named record.
package web

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseFFUFOutputRealFixture decodes a real ffuf JSON document through the
// production parser and asserts every mapped field.
//
// The fixture carries two deliberately different shapes:
//   - /admin   301 with a redirectlocation and length 0 (the redirect case)
//   - /robots.txt 200 with length/words/lines populated and an EMPTY
//     redirectlocation (the optional-field-absent case)
//
// Both are needed: a fixture of only redirects would never prove `length` is
// mapped, and a fixture of only 200s would never prove an absent optional field
// decodes cleanly rather than failing the line.
func TestParseFFUFOutputRealFixture(t *testing.T) {
	path := filepath.Join("testdata", "fixtures", "ffuf", "ffuf_local_capture.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	records := parseFFUFOutput(data)
	if len(records) == 0 {
		t.Fatalf("parseFFUFOutput returned ZERO records from REAL captured ffuf output (%s).\n"+
			"  artefacts/fuzz.jsonl would be empty and every fuzz-derived task downstream would skip —\n"+
			"  the same cascade that emptied the web layer when httpx stopped parsing.", path)
	}
	if len(records) != 2 {
		t.Fatalf("parseFFUFOutput returned %d records, want 2 (the fixture has exactly two results)", len(records))
	}

	byURL := map[string]FuzzRecord{}
	for _, r := range records {
		byURL[r.URL] = r
	}

	// --- record 1: the 301, which is where `redirect` is mapped -----------------
	admin, ok := byURL["http://127.0.0.1:8733/admin"]
	if !ok {
		t.Fatalf("the /admin record is missing — URL is the field parseFFUFOutput filters on, so an\n"+
			"  unmapped `url` drops the record silently. got: %+v", records)
	}
	if admin.Status != 301 {
		t.Errorf("/admin STATUS = %d, want 301 — ffuf emits `status`; an unmapped status makes every "+
			"finding look like a zero-status result", admin.Status)
	}
	if admin.Redirect != "/admin/" {
		t.Errorf("/admin REDIRECT = %q, want %q — ffuf emits `redirectlocation` (one word, no "+
			"separator). A wrong tag here silently drops the redirect target from every 3xx finding.",
			admin.Redirect, "/admin/")
	}

	// --- record 2: the 200, which is where length/words/lines are mapped --------
	robots, ok := byURL["http://127.0.0.1:8733/robots.txt"]
	if !ok {
		t.Fatalf("the /robots.txt record is missing. got: %+v", records)
	}
	if robots.Status != 200 {
		t.Errorf("/robots.txt STATUS = %d, want 200", robots.Status)
	}
	if robots.Length != 48 {
		t.Errorf("/robots.txt LENGTH = %d, want 48 — ffuf emits `length`. A silent zero here is the "+
			"`content-length` bug's exact shape: the record survives, the size does not.", robots.Length)
	}
	if robots.Words != 7 {
		t.Errorf("/robots.txt WORDS = %d, want 7 — ffuf emits `words`", robots.Words)
	}
	if robots.Lines != 3 {
		t.Errorf("/robots.txt LINES = %d, want 3 — ffuf emits `lines`", robots.Lines)
	}
	if robots.Redirect != "" {
		t.Errorf("/robots.txt REDIRECT = %q, want empty — an absent optional field must decode to the "+
			"zero value, not fail the line", robots.Redirect)
	}
}
