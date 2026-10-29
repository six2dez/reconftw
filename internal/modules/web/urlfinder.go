// urlfinder.go — UrlfinderTask: passive URL discovery via urlfinder.
//
// Name: "web.urlfinder"  DependsOn: ["web.httpx"]
//
// UrlfinderTask runs urlfinder against the target domain, reads its plain-text
// URL output, and writes URLRecord entries to artefacts/urls.jsonl.
//
// ARG VECTOR (verbatim v1 form, web.sh:1875):
//
//	urlfinder -d <domain> -all -o <stagingfile>
//
// The -all flag enables all passive sources. Output is a plain URL list.
// Axiom: LocalBackend only.
//
// Out-of-scope URLs filtered by extract/urls.ExtractURLs domain check.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/six2dez/reconftw/v5/internal/core/appctx"
	"github.com/six2dez/reconftw/v5/internal/core/config"
	"github.com/six2dez/reconftw/v5/internal/core/output"
	"github.com/six2dez/reconftw/v5/internal/core/task"
	urlsextract "github.com/six2dez/reconftw/v5/internal/extract/urls"
)

// UrlfinderTask runs urlfinder passive URL discovery.
type UrlfinderTask struct{}

func (t *UrlfinderTask) Name() string   { return "web.urlfinder" }
func (t *UrlfinderTask) Module() string { return "web" }
func (t *UrlfinderTask) Description() string {
	return "Passive URL discovery (urlfinder → urls.jsonl)"
}

func (t *UrlfinderTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.URLs.PassiveEnabled
}
func (t *UrlfinderTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes urlfinder and appends URL records to urls.jsonl.
func (t *UrlfinderTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "urlfinder"

	// Prepare staging file for urlfinder output.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.urlfinder: mkdir inputs/: %w", err)
	}
	stagingFile := filepath.Join(inputsDir, "urlfinder_urls.txt.tmp")

	// Build arg vector (verbatim v1 form, web.sh:1875).
	args := []string{
		"-d", app.Target.Domain,
		"-all",
		"-o", stagingFile,
	}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		// Absent-vs-failed policy (task.ClassifyToolErr): a urlfinder that never
		// started is "tool absent"; one that could not be run for any other
		// reason is degraded with its own account of why. Neither fails the
		// scan (best_effort).
		status, reason := task.ClassifyToolErr(execErr)
		app.Log.Info("web.urlfinder: urlfinder not run — skipping", "reason", reason)
		return task.Result{Status: status, Reason: reason}, nil
	}

	// Read output file; fall back to stdout.
	var raw []byte
	if data, rerr := os.ReadFile(stagingFile); rerr == nil && len(data) > 0 { //nolint:gosec
		raw = data
	} else if res != nil && len(res.Stdout) > 0 {
		raw = res.Stdout
	}

	// Extract and scope-filter URLs.
	records, _ := urlsextract.ExtractURLs(raw, "urlfinder", app.Target.Domain)

	// The old `if len(records) == 0 { return StatusDone }`
	// short-circuit here left a previous run's inputs/urls.urlfinder.jsonl on
	// disk for the urls merge to republish. urlfinder RAN (the absent-binary
	// case returned StatusSkipped above), so stage unconditionally and let
	// StageJSONL remove the file when this run found no URLs.
	var lines [][]byte
	for _, rec := range records {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.urlfinder.jsonl")
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil {
		app.Log.Debug("web.urlfinder: staging write failed",
			"path", stagingPath, "err", wErr)
	}

	// Clean up staging file.
	os.Remove(stagingFile) //nolint:errcheck

	app.Log.Debug("web.urlfinder: completed",
		"urls_found", len(records))

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"urls_found": len(records)},
	}, nil
}

func init() { task.Register(&UrlfinderTask{}) }
