package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/report"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// TestWriteSARIF_CallsBuildSarifLog verifies that WriteSARIF calls
// findings.BuildSarifLog and writes valid JSON to the target path.
func TestWriteSARIF_CallsBuildSarifLog(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "findings.sarif")

	findings := []*sqlcgen.Finding{
		{
			ID:                1,
			Severity:          "high",
			Title:             "SQL Injection",
			TemplateSignature: "sqli-001",
			MatchedAt:         "https://example.com/search?q=1",
			Tool:              "nuclei",
		},
	}

	if err := report.WriteSARIF(destPath, "1.0.0", findings); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var sarifDoc map[string]any
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		t.Fatalf("invalid JSON from WriteSARIF: %v", err)
	}

	version, _ := sarifDoc["version"].(string)
	if version != "2.1.0" {
		t.Errorf("SARIF version: got %q, want %q", version, "2.1.0")
	}
}
