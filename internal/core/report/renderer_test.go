package report_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/report"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// seedStore populates <workDir>/store.db with one completed scan (+ a finding
// and a host) attached to target, using the real ingest path — the same store
// the production report renderer reads. Returns the target it seeded.
func seedStore(t *testing.T, workDir, target string) {
	t.Helper()
	ctx := context.Background()

	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	writeLines := func(name string, lines ...string) {
		body := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(filepath.Join(artefacts, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	writeLines("hosts.jsonl", `{"host":"api.example.com","ip":"1.2.3.4"}`)
	writeLines("findings.jsonl",
		`{"type":"http","host":"api.example.com","template_id":"exposed-panel","severity":"high","matched_at":"https://api.example.com/admin"}`,
	)

	// dataDir == workDir so store.db lands at <workDir>/store.db (where the
	// renderer reads it); artefacts are read from <workDir>/artefacts.
	if _, err := ingest.ScanIntoStore(ctx, workDir, workDir, target, "all", quietLogger()); err != nil {
		t.Fatalf("seed ScanIntoStore: %v", err)
	}
}

// TestRenderAll_OllamaWritesAIReport is the production-path proof for INTEG-06:
// with AI.Enabled=true and Provider="ollama" pointed at an httptest server,
// RenderAll (reached by `reconftw report`) writes reports/ai-report.md
// containing the local server's response. This is the gap the direct-Generate
// unit test cannot catch — before the Step-10 gate was opened, the keyless
// ollama default never ran through RenderAll.
func TestRenderAll_OllamaWritesAIReport(t *testing.T) {
	const wantResp = "RENDERALL_OLLAMA_SUMMARY_99"
	ctx := context.Background()
	target := "example.com"
	workDir := t.TempDir()
	seedStore(t, workDir, target)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("ollama request path = %q; want /api/generate", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"response":"`+wantResp+`"}`)
	}))
	defer srv.Close()

	cfg := config.Defaults()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "ollama"
	cfg.AI.OllamaHost = srv.URL

	renderer, err := report.NewReportRenderer(workDir, cfg, quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer renderer.Close() //nolint:errcheck

	if err := renderer.RenderAll(ctx, target, "", false); err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	aiPath := filepath.Join(workDir, "reports", "ai-report.md")
	data, err := os.ReadFile(aiPath)
	if err != nil {
		t.Fatalf("ai-report.md not written (production ollama gate did not fire): %v", err)
	}
	if !strings.Contains(string(data), wantResp) {
		t.Errorf("ai-report.md = %q; want it to contain %q", string(data), wantResp)
	}
}

// TestRenderAll_AnthropicEmptyKeyWritesNothing verifies the renderer gate is
// closed for a cloud provider with no key: no ai-report.md, no cloud egress.
func TestRenderAll_AnthropicEmptyKeyWritesNothing(t *testing.T) {
	ctx := context.Background()
	target := "example.com"
	workDir := t.TempDir()
	seedStore(t, workDir, target)

	cfg := config.Defaults()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "anthropic"
	cfg.AI.AnthropicKey = "" // empty cloud key — gate must stay closed

	renderer, err := report.NewReportRenderer(workDir, cfg, quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer renderer.Close() //nolint:errcheck

	if err := renderer.RenderAll(ctx, target, "", false); err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	aiPath := filepath.Join(workDir, "reports", "ai-report.md")
	if _, err := os.Stat(aiPath); !os.IsNotExist(err) {
		t.Errorf("ai-report.md exists for anthropic+empty-key; want no file (gate should be closed), stat err=%v", err)
	}
}

// TestRenderAll_AIDisabledWritesNothing verifies AI reporting stays opt-in: with
// AI.Enabled=false, no ai-report.md is written even for the ollama default.
func TestRenderAll_AIDisabledWritesNothing(t *testing.T) {
	ctx := context.Background()
	target := "example.com"
	workDir := t.TempDir()
	seedStore(t, workDir, target)

	cfg := config.Defaults() // AI.Enabled defaults to false, Provider defaults to ollama

	renderer, err := report.NewReportRenderer(workDir, cfg, quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer renderer.Close() //nolint:errcheck

	if err := renderer.RenderAll(ctx, target, "", false); err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	aiPath := filepath.Join(workDir, "reports", "ai-report.md")
	if _, err := os.Stat(aiPath); !os.IsNotExist(err) {
		t.Errorf("ai-report.md exists with AI.Enabled=false; want no file, stat err=%v", err)
	}
}
