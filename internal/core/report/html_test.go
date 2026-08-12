package report_test

import (
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/report"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// TestRenderHTML_XSSEscape verifies that a finding Title containing raw
// HTML script tags is rendered as HTML entities by html/template (REPORT-02).
func TestRenderHTML_XSSEscape(t *testing.T) {
	findings := []*sqlcgen.Finding{
		{
			ID:        1,
			Severity:  "high",
			Title:     "<script>alert(1)</script>",
			MatchedAt: "https://example.com",
			Tool:      "nuclei",
		},
	}

	data := report.ReportData{
		Target:   "example.com",
		ScanID:   "scan-01",
		Findings: report.FindingsToRows(findings),
	}

	var buf strings.Builder
	if err := report.RenderHTMLWriter(data, &buf); err != nil {
		t.Fatalf("RenderHTMLWriter error: %v", err)
	}

	html := buf.String()

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("XSS: raw <script> tag present in HTML output — html/template did not escape it")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("XSS: expected &lt;script&gt; in HTML output, not found. Output snippet: %q",
			extractSnippet(html, "script", 200))
	}
}

// TestRenderHTML_OfflineFile verifies that the rendered HTML does not reference
// external URLs (src=http, href=http, @import url(http)).
func TestRenderHTML_OfflineFile(t *testing.T) {
	data := report.ReportData{
		Target: "example.com",
		ScanID: "scan-01",
	}

	var buf strings.Builder
	if err := report.RenderHTMLWriter(data, &buf); err != nil {
		t.Fatalf("RenderHTMLWriter error: %v", err)
	}

	html := buf.String()
	forbidden := []string{"src=http", "href=http", "@import url(http"}
	for _, f := range forbidden {
		if strings.Contains(html, f) {
			t.Errorf("external reference found in offline HTML: %q", f)
		}
	}
}

// extractSnippet returns up to maxLen chars centered around needle in s.
func extractSnippet(s, needle string, maxLen int) string {
	idx := strings.Index(s, needle)
	if idx < 0 {
		if len(s) > maxLen {
			return s[:maxLen]
		}
		return s
	}
	start := idx - maxLen/4
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + maxLen/4
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
