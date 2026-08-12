// favirecon.go — FaviReconTask: favicon tech recon → artefacts/favicons.jsonl.
//
// Name: "web.favirecon"  DependsOn: ["web.httpx"]
//
// CRITICAL (Pitfall 7): this Task calls favicon.ExtractWeb (JSON parser), NOT
// the Phase-4 favicon.Extract (plain-text parser). Do NOT swap these.
//
// ARG VECTOR (RESEARCH §favirecon — verbatim v1 form):
//
//	favirecon -l <urlsfile> -c 50 -t 10 -s -j -o <stagingfile>
//
// [ASSUMED A7: -l file-list flag is current favirecon for web pipeline — verify.]
//
// T-05-09: defensive JSON parsing via ExtractWeb (case-insensitive field fallback).
// T-05-10: tool stdout routed to run.log only (never INFO terminal, GAP-3).
//
// favirecon is a LocalBackend tool only (D-W13).
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
	"github.com/six2dez/reconftw/internal/extract/favicon"
)

// FaviconRecord is the favicons.jsonl schema row.
type FaviconRecord struct {
	URL    string `json:"url"`
	Tech   string `json:"tech"`
	Hash   string `json:"hash"`
	Domain string `json:"domain"`
}

// FaviReconTask runs favirecon favicon tech recon.
type FaviReconTask struct{}

func (t *FaviReconTask) Name() string   { return "web.favirecon" }
func (t *FaviReconTask) Module() string { return "web" }
func (t *FaviReconTask) Description() string {
	return "Favicon tech recon (favirecon → favicons.jsonl)"
}

func (t *FaviReconTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Favirecon.Enabled
}
func (t *FaviReconTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes favirecon and writes favicon tech records to favicons.jsonl.
func (t *FaviReconTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "favirecon"
	cfg := app.Cfg

	urls, err := readHostURLsFromJSONL(app)
	if err != nil || len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("web.favirecon: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.favirecon: mkdir inputs/: %w", err)
	}
	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.favirecon: mkdir artefacts/: %w", err)
	}

	urlsFile := filepath.Join(inputsDir, "favirecon.urls.txt")
	if err := os.WriteFile(urlsFile, []byte(strings.Join(urls, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.favirecon: write urls file: %w", err)
	}

	stagingFile := filepath.Join(artefactsDir, "favirecon.json.tmp")

	// Concurrency and timeout from config (with v1 defaults).
	concurrency := cfg.Web.Favirecon.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	timeout := cfg.Web.Favirecon.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	// RESEARCH §favirecon arg vector:
	// favirecon -l <urlsfile> -c 50 -t 10 -s -j -o <stagingfile>
	args := []string{
		"-l", urlsFile,
		"-c", fmt.Sprintf("%d", concurrency),
		"-t", fmt.Sprintf("%d", timeout),
		"-s", // silent
		"-j", // JSON output (CRITICAL: must use -j for ExtractWeb)
		"-o", stagingFile,
	}
	// Optional proxy (from config).
	if proxy := cfg.Web.Favirecon.Proxy; proxy != "" {
		args = append(args, "-px", proxy)
	}
	// Optional rate limit.
	if rl := cfg.Web.Favirecon.RateLimit; rl > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rl))
	}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.favirecon: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Parse staging file output; fall back to stdout.
	// CRITICAL (Pitfall 7): call ExtractWeb (JSON parser), NOT favicon.Extract.
	var raw []byte
	if data, rerr := os.ReadFile(stagingFile); rerr == nil { //nolint:gosec
		raw = data
	} else if res != nil && len(res.Stdout) > 0 {
		raw = res.Stdout
	}

	webResults, _ := favicon.ExtractWeb(raw, app.Target.Domain)

	if len(webResults) == 0 {
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"favicons_found": 0},
		}, nil
	}

	var lines [][]byte
	for _, r := range webResults {
		rec := FaviconRecord{
			URL:    r.URL,
			Tech:   r.Tech,
			Hash:   r.Hash,
			Domain: r.Host, // WR-03 co-change: WebResult.Domain renamed to Host; FaviconRecord.Domain kept (output schema)
		}
		b, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) > 0 {
		if appendErr := app.Tree.Append("favicons", lines); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.favirecon: Tree.Append failed", "err", appendErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.favirecon: completed", "favicons_found", len(webResults))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"favicons_found": len(webResults)},
	}, nil
}

func init() { task.Register(&FaviReconTask{}) }
