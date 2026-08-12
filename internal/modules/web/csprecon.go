// csprecon.go — CspreconTask: CSP header analysis → artefacts/csprecon_hosts.jsonl.
//
// Name: "web.csprecon"  DependsOn: ["web.httpx"]
//
// CspreconTask feeds URLs from hosts.jsonl via stdin to csprecon, then parses
// the plain-text hostname output via extract/csp.Extract, writing in-scope
// hostnames to artefacts/csprecon_hosts.jsonl.
//
// NOTE: csprecon is ALREADY in tools.lock (no new entry needed per RESEARCH).
//
// Open Question 3 resolution: this Task runs csprecon against the web surface
// (artefacts/hosts.jsonl URLs). The subdomains-stage csprecon call remains in
// the subdomains module. No deduplication issue (OutputTree.Append is idempotent).
//
// ARG VECTOR (RESEARCH §csprecon — verbatim v1 form):
//
//	csprecon -s  (stdin: URL list)
//
// T-05-08: extract/csp.Extract applies anchored domain suffix filter.
// T-05-10: tool stdout routed to run.log only (never INFO terminal, GAP-3).
//
// csprecon is a LocalBackend tool only (D-W13).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-03-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/extract/csp"
)

// CspreconRecord is the csprecon_hosts.jsonl schema row.
type CspreconRecord struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
}

// CspreconTask runs csprecon CSP-header subdomain extraction.
type CspreconTask struct{}

func (t *CspreconTask) Name() string        { return "web.csprecon" }
func (t *CspreconTask) Module() string      { return "web" }
func (t *CspreconTask) Description() string { return "CSP header analysis (csprecon)" }
func (t *CspreconTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Probe.Enabled
}
func (t *CspreconTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes csprecon and writes in-scope hostnames to csprecon_hosts.jsonl.
func (t *CspreconTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "csprecon"

	urls, err := readHostURLsFromJSONL(app)
	if err != nil || len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("web.csprecon: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.csprecon: mkdir inputs/: %w", err)
	}

	urlsFile := filepath.Join(inputsDir, "csprecon.urls.txt")
	if err := os.WriteFile(urlsFile, []byte(strings.Join(urls, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.csprecon: write urls file: %w", err)
	}

	// csprecon reads URLs via -l (list file); -s = silent (suppresses banner).
	// [A15-fix: -i is not a valid flag for csprecon; -l/-list is the correct file-input flag.]
	args := []string{"-s", "-l", urlsFile}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.csprecon: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	var rawOutput []byte
	if res != nil && len(res.Stdout) > 0 {
		rawOutput = res.Stdout
	}

	// T-05-08: extract/csp.Extract applies in-scope filter.
	hostResults, _ := csp.Extract(rawOutput, app.Target.Domain)

	if len(hostResults) == 0 {
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"csp_hostnames": 0},
		}, nil
	}

	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.csprecon: mkdir artefacts/: %w", err)
	}

	var lines [][]byte
	for _, r := range hostResults {
		rec := CspreconRecord{
			Subdomain: r.Subdomain,
			Source:    r.Source,
		}
		b, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) > 0 {
		// Write to csprecon_hosts artefact (avoids collision with Phase-4 subdomains.jsonl).
		if appendErr := app.Tree.Append("csprecon_hosts", lines); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.csprecon: Tree.Append failed", "err", appendErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.csprecon: completed", "csp_hostnames", len(hostResults))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"csp_hostnames": len(hostResults)},
	}, nil
}

func init() { task.Register(&CspreconTask{}) }
