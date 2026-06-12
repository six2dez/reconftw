package report_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/report"
)

// TestWriteNotesJSONL_FileExists verifies that WriteNotesJSONL creates the
// canonical notes.jsonl artefact under <reportsDir>/notes.jsonl (REPORT-01).
func TestWriteNotesJSONL_FileExists(t *testing.T) {
	tmpDir := t.TempDir()

	if err := report.WriteNotesJSONL(tmpDir); err != nil {
		t.Fatalf("WriteNotesJSONL: %v", err)
	}

	notesPath := filepath.Join(tmpDir, "notes.jsonl")
	info, err := os.Stat(notesPath)
	if err != nil {
		t.Fatalf("notes.jsonl does not exist: %v", err)
	}
	if info.IsDir() {
		t.Fatal("notes.jsonl is a directory, expected a file")
	}
	// File must not be a JSON parse error — empty content is valid JSONL.
	// (0 bytes satisfies the "valid empty JSONL" contract.)
}
