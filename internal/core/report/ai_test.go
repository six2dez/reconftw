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
		Enabled:      true,
		Provider:     "anthropic",
		Model:        "claude-opus-4-5",
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

// TestAIReporter_OllamaSuccess verifies the local Ollama path: Generate with
// Provider="ollama" POSTs to {OllamaHost}/api/generate and returns the parsed
// .response text. No API key is set — the local path requires none (INTEG-06).
func TestAIReporter_OllamaSuccess(t *testing.T) {
	const wantResp = "OLLAMA_LOCAL_SUMMARY_42"

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"response":"`+wantResp+`"}`)
	}))
	defer srv.Close()

	aiCfg := &config.AIConfig{
		Enabled:    true,
		Provider:   "ollama",
		Model:      "llama3:8b",
		OllamaHost: srv.URL, // callOllama reads OllamaHost (NOT the baseURL seam)
		// NOTE: no OpenAIKey / AnthropicKey — the local path needs no key.
	}

	// baseURL left empty so the endpoint is resolved from cfg.OllamaHost.
	reporter := report.NewAIReporterWithClient(aiCfg, &log.Redactor{}, nil, srv.Client(), "")

	scan := &sqlcgen.Scan{ID: "scan-01", TargetID: "example.com"}
	got, err := reporter.Generate(t.Context(), scan, nil)
	if err != nil {
		t.Fatalf("Generate(ollama) err = %v; want nil", err)
	}
	if got != wantResp {
		t.Errorf("Generate(ollama) = %q; want %q", got, wantResp)
	}
	if gotPath != "/api/generate" {
		t.Errorf("ollama request path = %q; want /api/generate", gotPath)
	}
}

// TestAIReporter_OllamaRedactBeforeSend proves REPORT-04 holds on the LOCAL
// path too: a registered secret in a finding title must not appear in the
// outbound Ollama request body.
func TestAIReporter_OllamaRedactBeforeSend(t *testing.T) {
	const secret = "OLLAMA_LEAK_TOKEN_ZZZ"

	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"response":"ok"}`)
	}))
	defer srv.Close()

	rdct := &log.Redactor{}
	rdct.Register(secret)

	aiCfg := &config.AIConfig{
		Enabled:    true,
		Provider:   "ollama",
		Model:      "llama3:8b",
		OllamaHost: srv.URL,
	}
	reporter := report.NewAIReporterWithClient(aiCfg, rdct, nil, srv.Client(), "")

	scan := &sqlcgen.Scan{ID: "scan-01", TargetID: "example.com"}
	findings := []*sqlcgen.Finding{
		{ID: 1, Severity: "high", Title: "Injected SECRET: " + secret},
	}
	if _, err := reporter.Generate(t.Context(), scan, findings); err != nil {
		t.Fatalf("Generate(ollama) err = %v", err)
	}
	if strings.Contains(captured, secret) {
		t.Errorf("redact-before-send FAILED on ollama path: secret %q found in request body", secret)
	}
}

// countingRoundTripper records how many HTTP requests were attempted so the
// cloud-egress guard can be proven to make ZERO outbound calls.
type countingRoundTripper struct{ calls int }

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
	}, nil
}

// TestAIReporter_EmptyCloudKeyGuard verifies that selecting a cloud provider
// with an empty key returns an error and makes NO HTTP request — recon data is
// never silently sent to the cloud (INTEG-06 / T-12-02-01).
func TestAIReporter_EmptyCloudKeyGuard(t *testing.T) {
	cases := []struct {
		name     string
		provider string
	}{
		{"openai empty key", "openai"},
		{"anthropic empty key", "anthropic"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &countingRoundTripper{}
			client := &http.Client{Transport: spy}

			aiCfg := &config.AIConfig{
				Enabled:  true,
				Provider: tc.provider,
				// No OpenAIKey / AnthropicKey set.
			}
			reporter := report.NewAIReporterWithClient(aiCfg, &log.Redactor{}, nil, client, "")

			scan := &sqlcgen.Scan{ID: "scan-01", TargetID: "example.com"}
			_, err := reporter.Generate(t.Context(), scan, nil)
			if err == nil {
				t.Fatalf("Generate(%s, empty key) err = nil; want a refuse-to-send error", tc.provider)
			}
			if spy.calls != 0 {
				t.Errorf("cloud-egress guard FAILED: %d HTTP calls made; want 0", spy.calls)
			}
		})
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
