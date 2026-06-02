// mantra.go — MantraTask: JavaScript secret scanner via mantra.
//
// Name: "web.mantra"  DependsOn: ["web.subjs"]
//
// MantraTask runs mantra against JS URLs extracted by subjs, collecting
// secrets from JavaScript files. All output is REDACTED before writing
// to artefacts/js_secrets.jsonl (XCUT-07 / T-05-13).
//
// ARG VECTOR (RESEARCH §mantra — verbatim v1 form, web.sh:2329):
//
//	cat js/js_livelinks.txt | mantra -ua "<HEADER>" -s
//
// mantra reads JS URL list from stdin. We pass via -i file flag for
// Backend.Runner compatibility (FOUND-10 compliant; no raw exec needed).
//
// XCUT-07 / T-05-13 CRITICAL:
// mantra output is plain text with potential raw secret values. EVERY
// output line is written with Redacted="***"; the raw line content is
// NEVER propagated to artefact fields beyond the URL.
//
// [ASSUMED A5: mantra -ua flag is current — verify at install (DoD-1).]
//
// Axiom: mantra is in the D-W13 axiom map.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2.
package web

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

// MantraTask runs mantra JS secret scanning.
type MantraTask struct{}

func (t *MantraTask) Name() string        { return "web.mantra" }
func (t *MantraTask) Module() string      { return "web" }
func (t *MantraTask) Description() string { return "JS secret scanner (mantra → js_secrets.jsonl)" }
func (t *MantraTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.JS.Enabled
}
func (t *MantraTask) DependsOn() []string { return []string{"web.subjs"} }

// Run executes mantra against JS URLs and writes REDACTED secret records.
func (t *MantraTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "mantra"

	// Read JS URLs from artefacts/urls.jsonl.
	jsURLs, err := readJSURLsFromJSONL(app)
	if err != nil || len(jsURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.mantra: no JS URLs in urls.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.mantra: mkdir inputs/: %w", err)
	}

	// Write JS URL list to temp file for mantra input.
	jsURLsFile := filepath.Join(inputsDir, "mantra_urls.txt.tmp")
	if err := os.WriteFile(jsURLsFile,
		[]byte(strings.Join(jsURLs, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.mantra: write js urls file: %w", err)
	}

	// Build arg vector (RESEARCH §mantra verbatim v1 form web.sh:2329).
	// [ASSUMED A5: -ua flag is current for mantra]
	// Use -i for file input (FOUND-10 compliant; v1 uses stdin but -i is equivalent).
	args := []string{
		"-ua", subjsUserAgent, // reuse same UA as subjs (v1 uses same HEADER)
		"-s",                  // silent/no-banner
		"-i", jsURLsFile,
	}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.mantra: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Parse plain-text output.
	// XCUT-07 / T-05-13: ALL output lines written with Redacted="***".
	// The raw line content (which may contain secrets) is NEVER written to artefacts.
	var raw []byte
	if res != nil && len(res.Stdout) > 0 {
		raw = res.Stdout
	}

	var lines [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// XCUT-07: extract only the URL part (the line may contain "url: secret_value").
		// Split on common separators: whitespace, ':', '='.
		// The URL is typically the first word, and the secret follows.
		// We record the URL (first non-empty token) and always set Redacted="***".
		urlPart := extractURLFromMantraLine(line)
		rec := jsSecretRecord{
			URL:      urlPart,
			Type:     "mantra",
			Severity: "unknown",
			Redacted: "***", // XCUT-07: raw value NEVER propagated
		}
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}

	if len(lines) > 0 {
		if appendErr := app.Tree.Append("js_secrets", lines); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.mantra: Tree.Append failed",
					"records", len(lines), "err", appendErr)
			}
			// Non-fatal per best_effort (D-W12).
		}
	}

	// Clean up temp file.
	os.Remove(jsURLsFile) //nolint:errcheck

	if app.Log != nil {
		app.Log.Debug("web.mantra: completed",
			"js_input_urls", len(jsURLs),
			"secrets_found", len(lines))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"secrets_found": len(lines)},
	}, nil
}

// extractURLFromMantraLine extracts the URL portion from a mantra output line.
// mantra output is plain text; the URL typically appears as the first field.
// Returns the full line if no URL separator is found.
func extractURLFromMantraLine(line string) string {
	// mantra output format is typically: "<url>  <secret_type>: <value>"
	// Extract first whitespace-delimited token as the URL reference.
	fields := strings.Fields(line)
	if len(fields) > 0 && (strings.HasPrefix(fields[0], "http://") ||
		strings.HasPrefix(fields[0], "https://")) {
		return fields[0]
	}
	// If no clear URL prefix, return empty (unknown URL context).
	return ""
}

func init() { task.Register(&MantraTask{}) }
