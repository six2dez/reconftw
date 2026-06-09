// llm.go — LLMTask: julius LLM endpoint probe (D-V3).
//
// LLMTask is a D-V3 fold-in from web.sh llm_probe(), routed to the
// vulns pipeline per plan 06-08 (VULN-14 parity completeness gate).
//
// XCUT-07 BINDING CONSTRAINT (T-06-08-05):
// LLM response content (model output, API response body, generated text, token
// counts, prompt echoes) is NEVER logged at any level and NEVER written to any
// artefact field. Only the detected boolean + endpoint URL is recorded.
// This is a hard constraint — any violation triggers XCUT-07 audit failure.
//
// INPUT: artefacts/urls.jsonl — URL corpus from Phase 5.
//        Empty → StatusSkipped (best_effort per D-V7).
//
// ARG VECTOR (v1 web.sh llm_probe verbatim):
//
//	julius -o jsonl -q probe -f <hostsFile>           (base)
//	julius -o jsonl -q probe --augustus -f <hostsFile> (when augustus=true)
//
// Non-zero exit → log.Debug + continue (best_effort per-host, ADR §7).
//
// OUTPUT: artefacts/llm.jsonl — single-writer; direct app.Tree.Append OK
// (doc.go: single-writer artefacts do NOT go through the staging+merge pipeline).
// Record fields: {url, target, detected:bool, type:"llm-endpoint"}.
// NEVER includes response_body, generated_text, token_count, or any LLM content.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-08-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// LLMTask runs the julius LLM endpoint probe against the URL corpus
// (D-V3, VULN-14 parity completeness).
type LLMTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *LLMTask) Name() string { return "vulns.llm" }

// Module returns the owning module group.
func (t *LLMTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *LLMTask) Description() string {
	return "LLM endpoint probe (julius)"
}

// Enabled reads cfg.Vulns.LLM.Enabled.
func (t *LLMTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.LLM.Enabled }

// DependsOn declares GFTask as the DAG root dependency.
func (t *LLMTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes julius LLM endpoint probing.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract URL strings — StatusSkipped if empty.
//  2. Write host list to inputs/llm_targets.txt.
//  3. Run julius -o jsonl -q probe [-augustus] -f inputs/llm_targets.txt.
//     On error → log.Debug (best_effort).
//  4. Parse stdout JSONL for LLM endpoint indicators (detected bool only).
//     XCUT-07: response body, generated text, token data NEVER stored or logged.
//  5. Write artefacts/llm.jsonl via app.Tree.Append (single-writer).
func (t *LLMTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "julius"
	cfg := app.Cfg

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	urls, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.llm: read URL corpus error (best_effort)", "err", err)
	}
	if len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.llm: no URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.llm: mkdir inputs/: %w", err)
	}

	// Step 2: Write host list to inputs/llm_targets.txt.
	hostsFile := filepath.Join(inputsDir, "llm_targets.txt")
	if wErr := os.WriteFile(hostsFile,
		[]byte(strings.Join(urls, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.llm: write llm_targets.txt: %w", wErr)
	}

	// Step 3: Build arg vector.
	// v1: julius -o jsonl -q probe [-augustus] -f <hostsFile>
	args := []string{"-o", "jsonl", "-q", "probe", "-f", hostsFile}
	if cfg.Vulns.LLM.Augustus {
		// Insert --augustus between "probe" and "-f"
		args = []string{"-o", "jsonl", "-q", "probe", "--augustus", "-f", hostsFile}
	}

	// Context cancellation check.
	select {
	case <-ctx.Done():
		return task.Result{Status: task.StatusCancelled},
			fmt.Errorf("vulns.llm: cancelled: %w", ctx.Err())
	default:
	}

	res, runErr := app.Tools.Run(ctx, toolName, args)
	if runErr != nil && app.Log != nil {
		app.Log.Debug("vulns.llm: julius error (best_effort)", "err", runErr)
	}

	// Step 4: Parse stdout JSONL for LLM endpoint indicators.
	// XCUT-07 (T-06-08-05 BINDING): only detected bool + endpoint URL extracted.
	// Response body, generated text, token counts NEVER stored or logged at any level.
	records := parseLLMProbeOutput(res.Stdout)

	// Step 5: Write artefacts/llm.jsonl via direct app.Tree.Append (single-writer).
	if len(records) > 0 {
		var lines [][]byte
		for _, rec := range records {
			b, mErr := json.Marshal(rec)
			if mErr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			if wErr := app.Tree.Append("llm", lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.llm: Tree.Append failed",
					"records", len(lines), "err", wErr)
			}
		}
	}

	// XCUT-07: log only count — never raw julius output.
	if app.Log != nil {
		app.Log.Info("vulns.llm: completed", "endpoints", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"endpoints": len(records)},
	}, nil
}

// llmRecord is the artefacts/llm.jsonl schema for a detected LLM endpoint.
//
// XCUT-07 BINDING: this struct MUST NOT contain response_body, generated_text,
// token_count, prompt_echo, api_response, model_output, or any field that
// could hold raw LLM response content. Only detected:bool + endpoint URL.
type llmRecord struct {
	URL      string `json:"url"`
	Target   string `json:"target"`
	Detected bool   `json:"detected"`
	Type     string `json:"type"` // "llm-endpoint"
	// Provider/service name from julius output (safe to record — it's a label, not content).
	Provider string `json:"provider,omitempty"`
}

// juliusOutputLine is the subset of julius JSONL output fields consumed for
// LLM endpoint detection. Only safe label fields are extracted.
//
// XCUT-07: Fields deliberately excluded from this struct:
//   - response / body / content / text / generated / output — raw LLM content
//   - probe / payload — probe data that may echo LLM responses
//   - tokens / token_count — LLM metadata that may correlate with content
//
// The "probe" field in v1 jq filter (.probe // "n/a") is used only for display;
// here we exclude it entirely — detected bool is sufficient for vuln-class recording.
type juliusOutputLine struct {
	Target   string `json:"target"`
	URL      string `json:"url"`
	Provider string `json:"provider"`
	Service  string `json:"service"`
	// Detected: inferred from presence of a non-empty target/url in the output line.
	// julius emits a JSONL record per detected endpoint — presence IS the detection.
}

// parseLLMProbeOutput parses julius JSONL stdout into llmRecord slice.
// XCUT-07 (T-06-08-05 BINDING): only endpoint URL + provider label extracted.
// Raw output bytes are NEVER logged; response content is NEVER stored.
func parseLLMProbeOutput(data []byte) []llmRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var records []llmRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var jl juliusOutputLine
		if err := json.Unmarshal(line, &jl); err != nil {
			continue
		}
		// Determine the endpoint URL (julius uses "target" or "url").
		endpoint := jl.Target
		if endpoint == "" {
			endpoint = jl.URL
		}
		if endpoint == "" {
			continue
		}
		provider := jl.Provider
		if provider == "" {
			provider = jl.Service
		}
		records = append(records, llmRecord{
			URL:      endpoint,
			Target:   extractHostFromURL(endpoint),
			Detected: true,
			Type:     "llm-endpoint",
			Provider: provider,
		})
	}
	return records
}

// init self-registers LLMTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&LLMTask{}) }
