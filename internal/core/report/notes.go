// Package report provides the reconFTW report renderer. It reads from store.db
// (read-only) and writes all report formats to the workspace reports/ directory
// without re-running scans (REPORT-08 / D-03).
package report

import (
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/output"
)

// WriteNotesJSONL creates the canonical notes.jsonl artefact required by REPORT-01.
// The file is empty on creation; future phases or operators append JSONL records to it.
//
// The empty file satisfies the REPORT-01 canonical artefact contract: downstream
// consumers can unconditionally open reports/notes.jsonl without a missing-file check.
func WriteNotesJSONL(reportsDir string) error {
	notesPath := filepath.Join(reportsDir, "notes.jsonl")
	return output.WriteFile(notesPath, []byte{}, 0o644)
}
