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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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
	// [A5-fix: mantra reads from stdin (no -i flag); use exec.Command to pipe.]
	// ARG VECTOR: mantra -ua <UA> -s  (reads JS URLs from stdin)
	args := []string{
		"-ua", subjsUserAgent, // reuse same UA as subjs (v1 uses same HEADER)
		"-s",                  // silent/no-banner
	}

	// mantra reads from stdin; use exec.Command (same pattern as nomore403/hakoriginfinder).
	mantraBin, lookErr := exec.LookPath(toolName)
	if lookErr != nil {
		if app.Log != nil {
			app.Log.Info("web.mantra: binary not on PATH — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	jsData, readErr := os.ReadFile(jsURLsFile) //nolint:gosec
	if readErr != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.mantra: read js urls file: %w", readErr)
	}

	// CR-07: derive bounded context from tools.lock mantra.timeout_seconds=300.
	toolTimeout := 300 * time.Second
	cmdCtx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()

	var outBuf bytes.Buffer
	//nolint:gosec // mantraBin from LookPath; args are fixed
	cmd := exec.CommandContext(cmdCtx, mantraBin, args...)
	cmd.Stdin = bytes.NewReader(jsData)
	cmd.Stdout = &outBuf

	runErr := cmd.Run()
	var res struct{ Stdout []byte }
	if outBuf.Len() > 0 {
		res.Stdout = outBuf.Bytes()
	}

	// WR-04: mantra exits non-zero when no secrets are found, but a real failure
	// (timeout, missing shared lib, OOM-kill, panic) also exits non-zero. The
	// premise "non-zero == no secrets" silently swallows those, returning
	// StatusDone with secrets_found:0 — dropping ALL JS-secret coverage with no
	// signal (XCUT-07: we must not silently miss secrets). Distinguish the cases:
	//   - context deadline exceeded  → the 300s timeout fired → Warn (real failure)
	//   - non-zero exit WITH stdout  → benign (mantra printed findings then exited
	//     non-zero, or printed nothing meaningful) — proceed to parse
	//   - non-zero exit with NO stdout and NOT an *exec.ExitError (e.g. exec
	//     failure) → Warn so a broken install is distinguishable from "0 secrets"
	if runErr != nil {
		switch {
		case cmdCtx.Err() == context.DeadlineExceeded:
			if app.Log != nil {
				app.Log.Warn("web.mantra: timed out — JS-secret results may be incomplete",
					"timeout", toolTimeout, "err", runErr)
			}
		case outBuf.Len() == 0:
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				// Not a clean tool exit and no output — the binary likely failed
				// to launch / crashed before producing anything.
				if app.Log != nil {
					app.Log.Warn("web.mantra: tool failed to run (no output) — distinct from 'no secrets'",
						"err", runErr)
				}
			} else if app.Log != nil {
				// Documented "no findings" non-zero exit with empty output.
				app.Log.Debug("web.mantra: non-zero exit, no output (likely no secrets)", "err", runErr)
			}
		default:
			if app.Log != nil {
				app.Log.Debug("web.mantra: non-zero exit with output (may be normal)", "err", runErr)
			}
		}
	}

	// Parse plain-text output.
	// XCUT-07 / T-05-13: ALL output lines written with Redacted="***".
	// The raw line content (which may contain secrets) is NEVER written to artefacts.
	var raw []byte
	if len(res.Stdout) > 0 {
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
			// WR-02: promote to Warn — a dropped Append means redacted JS-secret
			// records reported in secrets_found never reached js_secrets.jsonl.
			// Non-fatal per best_effort (D-W12): mantra has the js_secrets writer
			// shared with jsluice, so we continue rather than erroring the task.
			if app.Log != nil {
				app.Log.Warn("web.mantra: Tree.Append(js_secrets) failed — records not persisted",
					"records", len(lines), "err", appendErr)
			}
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

// ansiRE matches ANSI escape sequences (e.g. color codes) in terminal output.
// mantra colorizes output by default; strip before tokenizing (WR-07).
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// extractURLFromMantraLine extracts the URL portion from a mantra output line.
// mantra output is plain text; the URL typically appears as the first http(s):// field.
// Returns empty string if no http(s):// prefix token is found.
func extractURLFromMantraLine(line string) string {
	// WR-07: strip ANSI escape codes before tokenizing (mantra colorizes by default).
	line = ansiRE.ReplaceAllString(line, "")
	// Scan all fields for the first http(s):// token.
	fields := strings.Fields(line)
	for _, f := range fields {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			return f
		}
	}
	// No URL token found — return empty (unknown URL context).
	return ""
}

func init() { task.Register(&MantraTask{}) }
