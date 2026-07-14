package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// AIReporter generates AI-powered scan summaries using direct provider HTTP APIs.
//
// Security invariants (REPORT-04):
//   - redactor.Redact(prompt) is called BEFORE any outbound HTTP request
//   - Finding evidence field is NEVER included in the prompt (may contain secrets/raw tool output)
//   - Endpoint URLs are hardcoded (no SSRF from user-supplied URLs)
//   - API keys are log.Secret typed (redacted from log lines automatically)
type AIReporter struct {
	cfg      *config.AIConfig
	redactor *log.Redactor
	client   *http.Client
	log      *slog.Logger
	// baseURL allows tests to override the Anthropic/OpenAI endpoint.
	// Empty string uses the production endpoint.
	baseURL string
}

// NewAIReporter constructs an AIReporter with a 120s HTTP timeout for slow AI calls.
func NewAIReporter(cfg *config.AIConfig, rdct *log.Redactor, logger *slog.Logger) *AIReporter {
	return NewAIReporterWithClient(cfg, rdct, logger, nil, "")
}

// NewAIReporterWithClient constructs an AIReporter with an injected HTTP client
// and optional base URL override (for testing with httptest.Server).
func NewAIReporterWithClient(cfg *config.AIConfig, rdct *log.Redactor, logger *slog.Logger, client *http.Client, baseURL string) *AIReporter {
	if logger == nil {
		logger = slog.Default()
	}
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	return &AIReporter{
		cfg:      cfg,
		redactor: rdct,
		client:   client,
		log:      logger,
		baseURL:  baseURL,
	}
}

// profilePreamble returns the prompt preamble for the given report profile.
func profilePreamble(profile string) string {
	switch strings.ToLower(profile) {
	case "executive":
		return "You are a security advisor. Summarise the following reconFTW scan findings for an executive audience in plain language. Focus on business risk and recommended actions."
	case "brief":
		return "Provide a concise technical summary of the following reconFTW scan findings. List only the most critical issues."
	case "bughunter":
		return "You are an expert bug bounty hunter. Analyse the following reconFTW scan findings. Prioritise high-impact, exploitable vulnerabilities and suggest PoC approaches."
	default:
		return "Summarise the following reconFTW reconnaissance scan findings. Provide a structured security assessment."
	}
}

// buildPrompt constructs the AI prompt from scan metadata and findings.
//
// INVARIANT (REPORT-04 / T-10-03-02): finding evidence is NEVER included.
// Rationale: The evidence field may contain raw tool output including secrets/tokens.
func (r *AIReporter) buildPrompt(scan *sqlcgen.Scan, findings []*sqlcgen.Finding) string {
	limit := r.cfg.MaxCharsPerFile
	if limit <= 0 {
		limit = 50000 // safe default for large workspaces
	}

	profile := r.cfg.ReportProfile
	preamble := profilePreamble(profile)

	var sb strings.Builder
	sb.WriteString(preamble)
	sb.WriteString("\n\n")
	sb.WriteString("## Scan Information\n")
	fmt.Fprintf(&sb, "- Target: %s\n", scan.TargetID)
	fmt.Fprintf(&sb, "- Scan ID: %s\n", scan.ID)
	fmt.Fprintf(&sb, "- Mode: %s\n", scan.Mode)
	fmt.Fprintf(&sb, "- Findings: %d\n", scan.FindingsCount)
	fmt.Fprintf(&sb, "- Subdomains: %d\n", scan.SubdomainCount)
	fmt.Fprintf(&sb, "- URLs: %d\n", scan.UrlCount)
	sb.WriteString("\n## Findings Summary\n")

	included := 0
	for _, f := range findings {
		// INVARIANT: Do NOT include the evidence field in the prompt.
		line := fmt.Sprintf("- [%s] %s (tool: %s, matched: %s)\n",
			f.Severity, f.Title, f.Tool, f.MatchedAt)
		if sb.Len()+len(line) > limit {
			remaining := len(findings) - included
			fmt.Fprintf(&sb, "…and %d more findings (truncated at %d chars per MaxCharsPerFile)\n",
				remaining, limit)
			break
		}
		sb.WriteString(line)
		included++
	}

	return sb.String()
}

// anthropicRequest is the request body for the Anthropic Messages API.
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// callAnthropic sends the prompt to the Anthropic Messages API.
// Endpoint is hardcoded to prevent SSRF (T-10-03-04).
func (r *AIReporter) callAnthropic(ctx context.Context, prompt string) (string, error) {
	model := r.cfg.Model
	if model == "" {
		model = "claude-opus-4-5"
	}

	endpoint := "https://api.anthropic.com/v1/messages"
	if r.baseURL != "" {
		endpoint = r.baseURL + "/v1/messages"
	}

	reqBody, err := json.Marshal(anthropicRequest{
		Model:     model,
		MaxTokens: 4096,
		Messages:  []anthropicMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", fmt.Errorf("ai: anthropic: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("ai: anthropic: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", string(r.cfg.AnthropicKey))
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: anthropic: request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ai: anthropic: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ai: anthropic: read response: %w", err)
	}

	var aresp anthropicResponse
	if err := json.Unmarshal(body, &aresp); err != nil {
		return "", fmt.Errorf("ai: anthropic: parse response: %w", err)
	}
	if len(aresp.Content) == 0 {
		return "", fmt.Errorf("ai: anthropic: empty content in response")
	}
	return aresp.Content[0].Text, nil
}

// openAIRequest is the request body for the OpenAI Chat Completions API.
type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// callOpenAI sends the prompt to the OpenAI Chat Completions API.
// Endpoint is hardcoded to prevent SSRF (T-10-03-04).
func (r *AIReporter) callOpenAI(ctx context.Context, prompt string) (string, error) {
	endpoint := "https://api.openai.com/v1/chat/completions"
	if r.baseURL != "" {
		endpoint = r.baseURL + "/v1/chat/completions"
	}

	model := r.cfg.Model
	if model == "" {
		model = "gpt-4o"
	}

	reqBody, err := json.Marshal(openAIRequest{
		Model:    model,
		Messages: []openAIMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", fmt.Errorf("ai: openai: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("ai: openai: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(r.cfg.OpenAIKey))

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: openai: request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ai: openai: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ai: openai: read response: %w", err)
	}

	var oresp openAIResponse
	if err := json.Unmarshal(body, &oresp); err != nil {
		return "", fmt.Errorf("ai: openai: parse response: %w", err)
	}
	if len(oresp.Choices) == 0 {
		return "", fmt.Errorf("ai: openai: empty choices in response")
	}
	return oresp.Choices[0].Message.Content, nil
}

// ollamaRequest is the request body for the local Ollama /api/generate API.
// stream=false requests a single non-streamed JSON response.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

// callOllama sends the prompt to a LOCAL Ollama endpoint (INTEG-06). No API key
// is attached — the request never leaves the host. The endpoint is derived from
// the operator-configured OllamaHost (validated to http/https scheme upstream),
// falling back to the canonical local default; r.baseURL is honoured as a
// secondary test seam.
func (r *AIReporter) callOllama(ctx context.Context, prompt string) (string, error) {
	host := r.cfg.OllamaHost
	if host == "" {
		host = "http://localhost:11434"
	}
	if r.baseURL != "" {
		host = r.baseURL
	}
	endpoint := strings.TrimRight(host, "/") + "/api/generate"

	model := r.cfg.Model
	if model == "" {
		model = "llama3:8b"
	}

	reqBody, err := json.Marshal(ollamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return "", fmt.Errorf("ai: ollama: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("ai: ollama: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: ollama: request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ai: ollama: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ai: ollama: read response: %w", err)
	}

	var oresp ollamaResponse
	if err := json.Unmarshal(body, &oresp); err != nil {
		return "", fmt.Errorf("ai: ollama: parse response: %w", err)
	}
	if oresp.Response == "" {
		return "", fmt.Errorf("ai: ollama: empty response")
	}
	return oresp.Response, nil
}

// Generate assembles the prompt, redacts secrets, then dispatches to the
// configured AI provider.
//
// REPORT-04 invariant: r.redactor.Redact(rawPrompt) is called BEFORE the HTTP
// request. The order is enforced in-process and verified by TestAIReporter_RedactBeforeSend.
//
// Cloud-egress guard (INTEG-06 / T-12-02-01): a cloud provider (openai/anthropic)
// is dispatched ONLY when its key is present. An empty cloud key returns a clear
// error and makes NO HTTP request — recon data is never silently sent to the
// cloud. An unknown provider errors instead of falling through to a cloud path.
func (r *AIReporter) Generate(ctx context.Context, scan *sqlcgen.Scan, findings []*sqlcgen.Finding) (string, error) {
	raw := r.buildPrompt(scan, findings)
	// REPORT-04: Redact MUST happen before the HTTP call.
	prompt := r.redactor.Redact(raw) //nolint:gocritic

	switch strings.ToLower(r.cfg.Provider) {
	case "ollama":
		// Local provider — no key required, no cloud egress.
		return r.callOllama(ctx, prompt)
	case "openai":
		if strings.TrimSpace(string(r.cfg.OpenAIKey)) == "" {
			return "", fmt.Errorf("ai: openai provider selected but openai_key is empty — refusing to send recon data to the cloud")
		}
		return r.callOpenAI(ctx, prompt)
	case "anthropic", "": // "" — Anthropic/Claude is the historical cloud default per D-09
		if strings.TrimSpace(string(r.cfg.AnthropicKey)) == "" {
			return "", fmt.Errorf("ai: anthropic provider selected but anthropic_key is empty — refusing to send recon data to the cloud")
		}
		return r.callAnthropic(ctx, prompt)
	default:
		return "", fmt.Errorf("ai: unknown provider %q (expected ollama, openai, or anthropic)", r.cfg.Provider)
	}
}
