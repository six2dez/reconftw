// urlfinder.go — UrlfinderTask: passive URL discovery via urlfinder.
//
// Name: "web.urlfinder"  DependsOn: ["web.httpx"]
//
// UrlfinderTask runs urlfinder against the target domain, reads its plain-text
// URL output, and writes URLRecord entries to artefacts/urls.jsonl.
//
// ARG VECTOR (RESEARCH §urlfinder — verbatim v1 form, web.sh:1875):
//
//	urlfinder -d <domain> -all -o <stagingfile>
//
// The -all flag enables all passive sources. Output is a plain URL list.
// Axiom: LocalBackend only (D-W13).
//
// T-05-15: out-of-scope URLs filtered by extract/urls.ExtractURLs domain check.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	urlsextract "github.com/six2dez/reconftw/internal/extract/urls"
)

// UrlfinderTask runs urlfinder passive URL discovery.
type UrlfinderTask struct{}

func (t *UrlfinderTask) Name() string        { return "web.urlfinder" }
func (t *UrlfinderTask) Module() string      { return "web" }
func (t *UrlfinderTask) Description() string { return "Passive URL discovery (urlfinder → urls.jsonl)" }
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

	// Build arg vector (RESEARCH §urlfinder verbatim v1 form web.sh:1875).
	args := []string{
		"-d", app.Target.Domain,
		"-all",
		"-o", stagingFile,
	}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.urlfinder: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
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

	if len(records) == 0 {
		return task.Result{Status: task.StatusDone,
			Stats: map[string]int{"urls_found": 0}}, nil
	}

	var lines [][]byte
	for _, rec := range records {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) > 0 {
		stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.urlfinder.jsonl")
		if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
			app.Log.Debug("web.urlfinder: staging write failed",
				"path", stagingPath, "err", wErr)
		}
	}

	// Clean up staging file.
	os.Remove(stagingFile) //nolint:errcheck

	if app.Log != nil {
		app.Log.Debug("web.urlfinder: completed",
			"urls_found", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"urls_found": len(records)},
	}, nil
}

func init() { task.Register(&UrlfinderTask{}) }
