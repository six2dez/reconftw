// jsluice.go — JsluiceTask: JS URL + secret extraction via jsluice.
//
// Name: "web.jsluice"  DependsOn: ["web.subjs", "web.sourcemapper"]
//
// JsluiceTask runs jsluice in two modes:
//   - urls mode: extracts URLs from sourcemapped JS/TS files
//   - secrets mode: extracts secrets (XCUT-07: raw values NEVER in artefacts)
//
// ARG VECTORS (RESEARCH §jsluice — verbatim v1 form, web.sh:2310, 2340):
//
//	# URLs: find .js/.ts files under raw/sourcemaps/ | jsluice urls
//	jsluice urls  (stdin: file paths)
//
//	# Secrets: find .js files under raw/sourcemaps/ | jsluice secrets -j
//	jsluice secrets -j [--patterns <file>]  (stdin: file paths)
//
// XCUT-07 / T-05-12 CRITICAL:
// jsluice secrets output contains raw credential values in the "value" field.
// JsluiceTask passes secrets JSONL through extract/js.ExtractSecrets which
// NEVER propagates the raw value. SecretRecord.Redacted is always "***".
//
// [ASSUMED A6: jsluice secrets uses "filename" field for source file path.]
// [ASSUMED A13: default patterns exist if --patterns is omitted.]
//
// Axiom: LocalBackend only (D-W13).
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
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	extractjs "github.com/six2dez/reconftw/internal/extract/js"
	extractsourcemap "github.com/six2dez/reconftw/internal/extract/sourcemap"
)

// jsSecretRecord is the D-W11 js_secrets.jsonl schema row.
// SecretRecord.Redacted is always "***" (XCUT-07).
type jsSecretRecord struct {
	URL      string `json:"url"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Redacted string `json:"secret_redacted"` // always "***"
}

// JsluiceTask runs jsluice URL + secret extraction on sourcemapped JS files.
type JsluiceTask struct{}

func (t *JsluiceTask) Name() string   { return "web.jsluice" }
func (t *JsluiceTask) Module() string { return "web" }
func (t *JsluiceTask) Description() string {
	return "JS URL + secret extraction (jsluice → urls.jsonl, js_secrets.jsonl)"
}

func (t *JsluiceTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.JS.Enabled
}
func (t *JsluiceTask) DependsOn() []string { return []string{"web.subjs", "web.sourcemapper"} }

// Run executes jsluice in urls and secrets mode against sourcemapped JS files.
func (t *JsluiceTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Find JS/TS files under raw/sourcemaps/.
	sourcemapDir := filepath.Join(app.Target.WorkDir, "raw", "sourcemaps")
	jsFiles, err := findSourcemapFiles(sourcemapDir, []string{".js", ".ts"})
	if err != nil || len(jsFiles) == 0 {
		if app.Log != nil {
			app.Log.Info("web.jsluice: no JS/TS files in raw/sourcemaps/ — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Build stdin content: one file path per line (v1: find ... | jsluice).
	fileListInput := []byte(strings.Join(jsFiles, "\n") + "\n")

	var totalURLs, totalSecrets int

	// --- Part 1: jsluice urls mode ---
	urlsOutput, urlsErr := runJsluiceWithFileList(ctx, app, "urls", fileListInput)
	if urlsErr == nil {
		// F3 (phase 15): jsluice urls mode RAN cleanly this invocation, so its
		// staging is authoritative for THIS run — stage unconditionally and let
		// StageJSONL remove the file when nothing was extracted.
		//
		// urlsErr != nil is deliberately NOT staged: it covers "jsluice is not
		// on PATH" (a dispatch failure from app.Tools.Run) as well as a non-zero
		// exit, and both mean this run did not observe the corpus. Clearing
		// there would delete a previous run's URLs on a host that simply has no
		// jsluice installed.
		entries, _ := extractsourcemap.ExtractFromJSluice(urlsOutput, app.Target.Domain)
		var lines [][]byte
		for _, e := range entries {
			b, merr := json.Marshal(e)
			if merr != nil {
				continue
			}
			lines = append(lines, b)
		}
		stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.jsluice.jsonl")
		if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
			app.Log.Debug("web.jsluice: staging write failed",
				"path", stagingPath, "err", wErr)
		}
		totalURLs = len(entries)
	}

	// --- Part 2: jsluice secrets mode (only .js files) ---
	jsOnlyFiles, _ := findSourcemapFiles(sourcemapDir, []string{".js"})
	if len(jsOnlyFiles) > 0 {
		secretsFileListInput := []byte(strings.Join(jsOnlyFiles, "\n") + "\n")
		secretsOutput, secretsErr := runJsluiceWithFileList(ctx, app, "secrets", secretsFileListInput)
		if secretsErr == nil && len(secretsOutput) > 0 {
			// XCUT-07: ExtractSecrets NEVER propagates raw value — Redacted is always "***".
			secretRecords, _ := extractjs.ExtractSecrets(secretsOutput, app.Target.Domain)
			if len(secretRecords) > 0 {
				var lines [][]byte
				for _, sr := range secretRecords {
					// Write D-W11 js_secrets.jsonl record shape.
					rec := jsSecretRecord{
						URL:      sr.URL,
						Type:     sr.Type,
						Severity: sr.Severity,
						Redacted: sr.Redacted, // always "***" from ExtractSecrets
					}
					b, merr := json.Marshal(rec)
					if merr != nil {
						continue
					}
					lines = append(lines, b)
				}
				if len(lines) > 0 {
					if appendErr := app.Tree.Append("js_secrets", lines); appendErr != nil {
						// WR-02: promote to Warn — a swallowed Append means redacted
						// secret records counted in secrets_found never reached
						// js_secrets.jsonl. Non-fatal per best_effort (D-W12).
						if app.Log != nil {
							app.Log.Warn("web.jsluice: Tree.Append(js_secrets) failed — records not persisted",
								"records", len(lines), "err", appendErr)
						}
					}
				}
				totalSecrets = len(secretRecords)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.jsluice: completed",
			"js_files", len(jsFiles),
			"urls_found", totalURLs,
			"secrets_found", totalSecrets)
	}

	return task.Result{
		Status: task.StatusDone,
		Stats: map[string]int{
			"urls_found":    totalURLs,
			"secrets_found": totalSecrets,
		},
	}, nil
}

// runJsluiceWithFileList writes fileListInput to a temp file, then invokes
// jsluice <mode> with the file list passed via stdin (using -i flag for
// FOUND-10 compliance when available; falls back to content via temp file).
//
// jsluice mode: "urls" or "secrets" (with -j for structured JSON output).
func runJsluiceWithFileList(ctx context.Context, app *appctx.AppContext,
	mode string, fileListInput []byte,
) ([]byte, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir inputs/: %w", err)
	}

	// Write file list to temp file.
	fileListPath := filepath.Join(inputsDir, fmt.Sprintf("jsluice_%s_files.txt.tmp", mode))
	if err := os.WriteFile(fileListPath, fileListInput, 0o644); err != nil { //nolint:gosec
		return nil, fmt.Errorf("write jsluice file list: %w", err)
	}
	defer os.Remove(fileListPath) //nolint:errcheck

	// Build arg vector for jsluice.
	// jsluice urls <file1> <file2> ... OR jsluice secrets -j <file1> ...
	// We pass the files as positional args (jsluice accepts file paths directly).
	var jsFiles []string
	scanner := bufio.NewScanner(bytes.NewReader(fileListInput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			jsFiles = append(jsFiles, line)
		}
	}
	if len(jsFiles) == 0 {
		return nil, nil
	}

	var args []string
	switch mode {
	case "urls":
		args = append([]string{"urls"}, jsFiles...)
	case "secrets":
		// -j for structured JSON output (RESEARCH §jsluice).
		args = append([]string{"secrets", "-j"}, jsFiles...)
	default:
		return nil, fmt.Errorf("unknown jsluice mode: %s", mode)
	}

	res, err := app.Tools.Run(ctx, "jsluice", args)
	if err != nil {
		return nil, fmt.Errorf("jsluice %s: %w", mode, err)
	}
	if res != nil && len(res.Stdout) > 0 {
		return res.Stdout, nil
	}
	return nil, nil
}

// findSourcemapFiles walks dir recursively and returns paths matching any of
// the given suffixes. Returns (nil, nil) when dir does not exist.
func findSourcemapFiles(dir string, suffixes []string) ([]string, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			return nil
		}
		lower := strings.ToLower(info.Name())
		for _, suf := range suffixes {
			if strings.HasSuffix(lower, suf) {
				files = append(files, path)
				break
			}
		}
		return nil
	})
	return files, err
}

func init() { task.Register(&JsluiceTask{}) }
