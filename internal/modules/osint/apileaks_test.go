// apileaks_test.go — XCUT-07 three-layer redaction assertions for the
// secret-emitting API/SaaS-leak Tasks (OSINT-08 postman, OSINT-09 swagger).
//
// CRITICAL (T-07-04-01): porch-pirate/postleaksNg/SwaggerSpy/sj surface LIVE API
// tokens. These tests prove the raw secret VALUE is NEVER propagated to a record
// (L3, ValueRedacted="***") and IS registered with the slog Redactor (L2) so it
// is scrubbed from logs. Synthetic FAKE secrets verify redaction without
// committing a real credential.
package osint

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corelog "github.com/six2dez/reconftw/internal/core/log"
)

const (
	fakePostmanSecret = "FAKE_LEAK_SECRET_CCCC_pk_live_0123456789abcdef0123"
	fakeSwaggerSecret = "FAKE_LEAK_SECRET_DDDD_apikey_ABCDEF0123456789"
)

// redactingLogger returns a logger whose RedactingHandler writes to buf.
func redactingLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	redactor := &corelog.Redactor{}
	return slog.New(corelog.NewRedactingHandler(slog.NewJSONHandler(&buf, nil), redactor)), &buf
}

// assertNoRawSecretAPILeak fails if the raw secret appears in any record, and
// asserts the leak record carries ValueRedacted="***".
func assertNoRawSecretAPILeak(t *testing.T, records []OSINTFindingRecord, secret, category string) {
	t.Helper()
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if strings.Contains(string(b), secret) {
			t.Fatalf("XCUT-07 VIOLATION: raw secret leaked into record: %s", string(b))
		}
		if rec.Category == category && rec.ValueRedacted != "***" {
			t.Fatalf("expected ValueRedacted=*** for %s record, got %q", category, rec.ValueRedacted)
		}
	}
}

func TestParsePorchPirateOutput_RedactsAndRegisters(t *testing.T) {
	logger, buf := redactingLogger()
	// porch-pirate dump line: workspace URL followed by an embedded secret.
	out := "https://www.postman.com/acme/workspace/api token=" + fakePostmanSecret + "\n" +
		"no url on this line " + fakePostmanSecret + "\n"

	records := parsePorchPirateOutput([]byte(out), logger)
	if len(records) != 1 {
		t.Fatalf("expected 1 record (only the URL line), got %d: %+v", len(records), records)
	}
	assertNoRawSecretAPILeak(t, records, fakePostmanSecret, "postman-leak")
	if !strings.Contains(records[0].PoCRedacted, "postman.com/acme") {
		t.Errorf("locator missing workspace URL: %q", records[0].PoCRedacted)
	}
	if records[0].Severity != "high" {
		t.Errorf("postman leak should be high, got %q", records[0].Severity)
	}

	// L2: the raw secret must have been Registered → scrubbed from logs.
	logger.Info("postman: surfaced", "value", fakePostmanSecret)
	if strings.Contains(buf.String(), fakePostmanSecret) {
		t.Fatalf("XCUT-07 L2 VIOLATION: secret not registered, leaked into log: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "***") {
		t.Fatalf("expected redacted *** marker in log output, got: %s", buf.String())
	}
}

func TestParsePostleaksJSON_RedactsAndRegisters(t *testing.T) {
	logger, buf := redactingLogger()
	report := `[{"url":"https://www.postman.com/acme/req/1","secret":"` + fakePostmanSecret + `"}]`

	records := parsePostleaksJSON([]byte(report), logger)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	assertNoRawSecretAPILeak(t, records, fakePostmanSecret, "postman-leak")
	if !strings.Contains(records[0].PoCRedacted, "postman.com/acme/req/1") {
		t.Errorf("locator missing URL: %q", records[0].PoCRedacted)
	}

	logger.Info("postman: surfaced", "value", fakePostmanSecret)
	if strings.Contains(buf.String(), fakePostmanSecret) {
		t.Fatalf("XCUT-07 L2 VIOLATION: postleaks secret leaked into log: %s", buf.String())
	}
}

func TestParseSwaggerOutput_RedactsAndRegisters(t *testing.T) {
	logger, buf := redactingLogger()
	out := "[*] https://api.acme.com/swagger.json apikey=" + fakeSwaggerSecret + "\n"

	records := parseSwaggerOutput([]byte(out), "sj", logger)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d: %+v", len(records), records)
	}
	assertNoRawSecretAPILeak(t, records, fakeSwaggerSecret, "swagger-leak")
	if !strings.Contains(records[0].PoCRedacted, "api.acme.com/swagger.json") {
		t.Errorf("locator missing spec URL: %q", records[0].PoCRedacted)
	}
	if !strings.HasPrefix(records[0].PoCRedacted, "sj ") {
		t.Errorf("locator should be engine-tagged: %q", records[0].PoCRedacted)
	}

	logger.Info("swagger: surfaced", "value", fakeSwaggerSecret)
	if strings.Contains(buf.String(), fakeSwaggerSecret) {
		t.Fatalf("XCUT-07 L2 VIOLATION: swagger secret leaked into log: %s", buf.String())
	}
}

func TestReadWorkspaceHosts_OpportunisticAndAbsent(t *testing.T) {
	// Absent: no artefacts dir → nil (the D-O2 log-skip path).
	if hosts := readWorkspaceHosts(t.TempDir()); hosts != nil {
		t.Fatalf("expected nil hosts when artefacts absent, got %v", hosts)
	}

	// Present: hosts.jsonl + urls.jsonl are read and deduped.
	dir := t.TempDir()
	artefacts := filepath.Join(dir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artefacts, "hosts.jsonl"),
		[]byte(`{"host":"api.acme.com"}`+"\n"+`{"host":"www.acme.com"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artefacts, "urls.jsonl"),
		[]byte(`{"url":"https://api.acme.com/v1"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hosts := readWorkspaceHosts(dir)
	if len(hosts) != 3 {
		t.Fatalf("expected 3 deduped host/url entries, got %d: %v", len(hosts), hosts)
	}
}

func TestParseSwaggerOutput_Empty(t *testing.T) {
	if recs := parseSwaggerOutput(nil, "sj", nil); recs != nil {
		t.Fatalf("expected nil for empty input, got %v", recs)
	}
}
