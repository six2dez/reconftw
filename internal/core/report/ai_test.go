package report_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/report"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// TestAIReporter_RedactBeforeSend verifies that secrets registered with the
// Redactor do NOT appear in the outbound HTTP request body sent to the AI API.
func TestAIReporter_RedactBeforeSend(t *testing.T) {
	const secret = "SUPER_SECRET_TOKEN_XYZ"

	// Record the body sent to the "AI API".
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = string(body)
		// Return a minimal valid Anthropic response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"summary"}]}`)
	}))
	defer srv.Close()

	rdct := &log.Redactor{}
	rdct.Register(secret)

	aiCfg := &config.AIConfig{
		Enabled:  true,
		Provider: "anthropic",
		Model:    "claude-opus-4-5",
		AnthropicKey: log.Secret(secret), // the key itself should also be redacted
	}

	reporter := report.NewAIReporterWithClient(aiCfg, rdct, nil, srv.Client(), srv.URL)

	scan := &sqlcgen.Scan{ID: "scan-01", TargetID: "example.com"}
	findings := []*sqlcgen.Finding{
		{ID: 1, Severity: "high", Title: "Injected SECRET: " + secret},
	}

	_, _ = reporter.Generate(t.Context(), scan, findings)

	if strings.Contains(captured, secret) {
		t.Errorf("redact-before-send FAILED: secret %q found in outbound request body", secret)
	}
	if !strings.Contains(captured, "***") {
		t.Logf("note: redacted body: %q", captured)
	}
}

// TestAIReporter_EvidenceExcluded verifies that Finding.Evidence does not
// appear in the assembled prompt passed to buildPrompt (REPORT-04).
func TestAIReporter_EvidenceExcluded(t *testing.T) {
	const evidenceSecret = "evidence-secret-token-12345"

	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"ok"}]}`)
	}))
	defer srv.Close()

	rdct := &log.Redactor{}
	aiCfg := &config.AIConfig{
		Enabled:  true,
		Provider: "anthropic",
		Model:    "claude-opus-4-5",
	}

	reporter := report.NewAIReporterWithClient(aiCfg, rdct, nil, srv.Client(), srv.URL)

	scan := &sqlcgen.Scan{ID: "scan-01", TargetID: "example.com"}
	findings := []*sqlcgen.Finding{
		{
			ID:       1,
			Severity: "critical",
			Title:    "Some vulnerability",
			Evidence: evidenceSecret,
		},
	}

	_, _ = reporter.Generate(t.Context(), scan, findings)

	if strings.Contains(captured, evidenceSecret) {
		t.Errorf("evidence exclusion FAILED: Finding.Evidence %q found in outbound prompt body", evidenceSecret)
	}
}
