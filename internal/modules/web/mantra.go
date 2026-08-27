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
// mantra reads its JS URL list on STANDARD INPUT — it has no input flag.
//
// 18-04: THIS FILE NO LONGER BYPASSES THE SEAM. Its only manifest reason was
// `stdin`, and backend.Runner.RunOpts has carried stdin since 18-01. (The
// comment that stood here claimed a `-i file` flag "for Backend.Runner
// compatibility"; the code below never used one, and the A5-fix note further
// down says so. The claim is deleted rather than left to mislead.)
//
// TIMEOUT: the local 300s context.WithTimeout is GONE. tools.lock OWNS the
// bound — the mantra row carries timeout_seconds = 300, exactly the value this
// file used to apply.
//
// DEFAULT ARGS: the mantra row carries default_args = [], so the argv is
// byte-for-byte the pre-move `-ua <UA> -s`.
//
// BEHAVIOUR CHANGE, STATED RATHER THAN HIDDEN: WR-04's switch below used to
// parse partial stdout on a non-zero exit. LocalBackend returns a *ToolError
// with no Result, so it can no longer do so. Two things make that acceptable
// HERE rather than by analogy:
//   - WR-04's premise ("mantra exits non-zero when no secrets are found") does
//     NOT hold for the installed build: a run over a JS URL with no secrets
//     exits 0 (verified 2026-08-26 against the real binary). The non-zero arm is
//     therefore a genuine failure, not the routine no-findings path.
//   - WR-04's real requirement was to tell a timeout and a failed launch apart
//     from "0 secrets" rather than swallow them. The Runner does that BETTER
//     than the old switch: coreerrors.ErrTimeout, IsDispatchFailure and a typed
//     *ToolError name each case, and logs/tools.jsonl records the outcome label.
//     The switch below is rewritten onto those types, not deleted.
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
	"path/filepath"
	"regexp"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
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

	jsData, readErr := os.ReadFile(jsURLsFile) //nolint:gosec
	if readErr != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.mantra: read js urls file: %w", readErr)
	}

	// NO exec.LookPath GATE. An unresolvable mantra now returns a typed dispatch
	// failure and is RECORDED as dispatch_failed instead of vanishing. The task's
	// status on an absent binary is unchanged (StatusSkipped, below).
	res, runErr := app.Tools.RunOpts(ctx, toolName, mantraArgs(),
		backend.ExecOptions{Stdin: jsData})

	// WR-04, REWRITTEN ONTO THE RUNNER'S TYPED ERRORS. The requirement is
	// unchanged: a timeout, a failed launch or a crash must NEVER be swallowed as
	// "0 secrets" (XCUT-07 — we must not silently miss secrets). What changed is
	// that the Runner names each case as data instead of leaving this file to
	// infer it from an exit code and an empty buffer.
	//   - dispatch failure     → the process never started → StatusSkipped, the
	//                            same status the old exec.LookPath gate returned,
	//                            and NO staging write (F3 did-not-run).
	//   - deadline exceeded    → the tools.lock 300s bound fired → Warn.
	//   - any other tool error → Warn: results are incomplete and distinguishable
	//                            from a clean "no secrets" run, which now exits 0.
	if runErr != nil {
		switch {
		case coreerrors.IsDispatchFailure(runErr):
			if app.Log != nil {
				app.Log.Info("web.mantra: mantra unavailable — skipping")
			}
			os.Remove(jsURLsFile) //nolint:errcheck
			return task.Result{Status: task.StatusSkipped}, nil
		case errors.Is(runErr, coreerrors.ErrTimeout):
			if app.Log != nil {
				app.Log.Warn("web.mantra: timed out — JS-secret results may be incomplete",
					"err", runErr)
			}
		default:
			if app.Log != nil {
				app.Log.Warn("web.mantra: tool error — distinct from 'no secrets'", "err", runErr)
			}
		}
	}

	// Parse plain-text output.
	// XCUT-07 / T-05-13: ALL output lines written with Redacted="***".
	// The raw line content (which may contain secrets) is NEVER written to artefacts.
	var raw []byte
	if res != nil {
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
		// V-04: the tool did not finish (deadline, crash, cancellation), so this run
		// must NOT be checkpointed as done — otherwise the next run with the same
		// input hash skips it and the deadline becomes a permanent, silent hole.
		// Status stays non-error on purpose: this is best-effort and must not fail
		// the scan. See task.Result.Incomplete.
		Incomplete: res == nil,
	}, nil
}

// mantraArgs returns the mantra arg vector, VERBATIM as it stood before 18-04
// moved this dispatch onto the Runner: `mantra -ua <UA> -s` (RESEARCH §mantra,
// v1 web.sh:2329; the UA is the same one subjs uses, as in v1).
func mantraArgs() []string {
	return []string{
		"-ua", subjsUserAgent, // reuse same UA as subjs (v1 uses same HEADER)
		"-s", // silent/no-banner
	}
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
