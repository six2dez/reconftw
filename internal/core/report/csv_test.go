package report_test

import (
	"bytes"
	"encoding/csv"
	"testing"

	"github.com/six2dez/reconftw/internal/core/report"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// TestWriteCSV_FindingsColumns verifies the CSV header for findings matches
// the canonical column order.
func TestWriteCSV_FindingsColumns(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteFindingsCSV(&buf, []*sqlcgen.Finding{})
	if err != nil {
		t.Fatalf("WriteFindingsCSV: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected at least a header row, got none")
	}

	wantHeader := []string{"id", "severity", "title", "matched_at", "tool", "template_signature", "cvss_score"}
	got := records[0]
	if len(got) != len(wantHeader) {
		t.Fatalf("header length mismatch: got %d, want %d (%v)", len(got), len(wantHeader), got)
	}
	for i, col := range wantHeader {
		if got[i] != col {
			t.Errorf("column[%d]: got %q, want %q", i, got[i], col)
		}
	}
}
