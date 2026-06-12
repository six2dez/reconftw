package report_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/report"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// TestScoreFinding_Criticality verifies that a finding on an "admin" fqdn
// scores higher than an identical finding on a non-critical fqdn.
func TestScoreFinding_Criticality(t *testing.T) {
	f := &sqlcgen.Finding{
		ID:       1,
		Severity: "critical",
		Title:    "Open Redirect",
	}

	scoreAdmin := report.ScoreFinding(f, "admin.example.com", nil)
	scoreNormal := report.ScoreFinding(f, "www.example.com", nil)

	if scoreAdmin <= scoreNormal {
		t.Errorf("expected admin fqdn score (%f) > normal fqdn score (%f)", scoreAdmin, scoreNormal)
	}
}

// TestBuildHotlist_TopN verifies that BuildHotlist returns at most topN items.
func TestBuildHotlist_TopN(t *testing.T) {
	findings := []*sqlcgen.Finding{
		{ID: 1, Severity: "critical", Title: "A"},
		{ID: 2, Severity: "high", Title: "B"},
		{ID: 3, Severity: "medium", Title: "C"},
		{ID: 4, Severity: "low", Title: "D"},
		{ID: 5, Severity: "info", Title: "E"},
	}

	items := report.BuildHotlist(findings, nil, 3)
	if len(items) != 3 {
		t.Errorf("BuildHotlist: got %d items, want 3", len(items))
	}
}
