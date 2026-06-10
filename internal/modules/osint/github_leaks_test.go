// github_leaks_test.go — XCUT-07 three-layer redaction assertions for the
// highest-secret-leak-risk Task (OSINT-05 github_leaks: ghleaks + trufflehog).
//
// CRITICAL (T-07-03-01): trufflehog/ghleaks emit LIVE credentials. These tests
// prove the raw secret VALUE is NEVER propagated to a record (L3) and IS
// registered with the slog Redactor (L2) so it is scrubbed from logs.
//
// Synthetic FAKE secrets (mirroring the vulns dalfox FAKE_XSS_MARKER convention)
// verify redaction without committing a real credential.
package osint

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	corelog "github.com/six2dez/reconftw/internal/core/log"
)

const (
	fakeTrufflehogSecret = "FAKE_LEAK_SECRET_AAAA_ghp_0123456789abcdef0123456789abcdef01234567"
	fakeGhleaksSecret    = "FAKE_LEAK_SECRET_BBBB_AKIAIOSFODNN7EXAMPLEKEY"
)

// assertNoRawSecret marshals every record and fails if the raw secret appears.
func assertNoRawSecret(t *testing.T, records []OSINTFindingRecord, secret string) {
	t.Helper()
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if strings.Contains(string(b), secret) {
			t.Fatalf("XCUT-07 VIOLATION: raw secret leaked into record: %s", string(b))
		}
		if rec.Category == "leaked-secret" && rec.ValueRedacted != "***" {
			t.Fatalf("expected ValueRedacted=*** for leaked-secret record, got %q", rec.ValueRedacted)
		}
	}
}

func TestParseTrufflehogOutput_RedactsAndRegisters(t *testing.T) {
	// Build a logger whose RedactingHandler we can inspect via the Redactor.
	redactor := &corelog.Redactor{}
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(corelog.NewRedactingHandler(inner, redactor))

	// trufflehog -j JSONL: one finding with a verified live secret.
	thLine := `{"DetectorName":"GitHub","Verified":true,"Raw":"` + fakeTrufflehogSecret +
		`","Redacted":"ghp_***","SourceMetadata":{"Data":{"Git":{"repository":"https://github.com/acme/ci","file":"ci.yml","commit":"deadbeef","line":42}}}}`

	records := parseTrufflehogOutput([]byte(thLine), logger)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	rec := records[0]

	// L3: raw secret never in record; ValueRedacted="***".
	assertNoRawSecret(t, records, fakeTrufflehogSecret)
	if rec.Severity != "critical" {
		t.Errorf("verified secret should be critical, got %q", rec.Severity)
	}
	// Locator must carry the NON-secret git path, proving useful records survive.
	if !strings.Contains(rec.PoCRedacted, "acme/ci") || !strings.Contains(rec.PoCRedacted, "ci.yml") {
		t.Errorf("locator missing git path: %q", rec.PoCRedacted)
	}

	// L2: the raw secret must have been Registered → scrubbed from logs.
	logger.Info("github_leaks: surfaced", "value", fakeTrufflehogSecret)
	if strings.Contains(buf.String(), fakeTrufflehogSecret) {
		t.Fatalf("XCUT-07 L2 VIOLATION: secret not registered, leaked into log: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "***") {
		t.Fatalf("expected redacted *** marker in log output, got: %s", buf.String())
	}
}

func TestParseGhleaksReport_RedactsAndRegisters(t *testing.T) {
	redactor := &corelog.Redactor{}
	var buf bytes.Buffer
	logger := slog.New(corelog.NewRedactingHandler(slog.NewJSONHandler(&buf, nil), redactor))

	// ghleaks JSON-array report with one leaked secret.
	report := `[{"repository":"acme/api","file":"config.py","line":7,"ruleID":"aws-key","secret":"` +
		fakeGhleaksSecret + `","match":"key = ` + fakeGhleaksSecret + `"}]`

	records := parseGhleaksReport([]byte(report), logger)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	assertNoRawSecret(t, records, fakeGhleaksSecret)
	if !strings.Contains(records[0].PoCRedacted, "acme/api") {
		t.Errorf("locator missing repo: %q", records[0].PoCRedacted)
	}

	// L2 scrub check.
	logger.Info("github_leaks: surfaced", "value", fakeGhleaksSecret)
	if strings.Contains(buf.String(), fakeGhleaksSecret) {
		t.Fatalf("XCUT-07 L2 VIOLATION: ghleaks secret leaked into log: %s", buf.String())
	}
}

func TestParseTrufflehogOutput_Empty(t *testing.T) {
	if recs := parseTrufflehogOutput(nil, nil); recs != nil {
		t.Fatalf("expected nil for empty input, got %v", recs)
	}
	if recs := parseTrufflehogOutput([]byte("not json\n"), nil); recs != nil {
		t.Fatalf("expected nil for non-json input, got %v", recs)
	}
}

func TestParseEnumerepoOutput_RepoURLs(t *testing.T) {
	// enumerepo array shape with repos carrying clone URLs.
	js := `[{"username":"acme","repos":[{"html_url":"https://github.com/acme/api"},{"clone_url":"https://github.com/acme/web.git"}]}]`
	// Write to a temp file (parseEnumerepoOutput reads a path).
	dir := t.TempDir()
	path := dir + "/repos.json"
	if err := os.WriteFile(path, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	repos := parseEnumerepoOutput(path)
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d: %v", len(repos), repos)
	}
}
