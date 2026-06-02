// wafw00f.go — Wafw00fTask: WAF detection via wafw00f → artefacts/waf.jsonl.
//
// Name: "web.wafw00f"  DependsOn: ["web.httpx"]
//
// Wafw00fTask runs wafw00f against all probed hosts, parses its text output
// via extract/waf.ExtractWafw00f, and writes WAFResult records to waf.jsonl.
//
// ARG VECTOR (RESEARCH §wafw00f — verbatim v1 form):
//
//	wafw00f -i <hostsfile> -o <stagingfile>
//
// wafw00f is in the D-W13 axiom map; app.Tools.Run dispatches transparently
// to AxiomBackend or LocalBackend based on configuration.
//
// T-05-08: wafw00f output filtered to in-scope hosts via extract/waf.ExtractWafw00f.
// T-05-10: tool stdout routed to run.log via app.Tools.Run, never terminal INFO.
//
// [ASSUMED A15: wafw00f -i/-o flags are current — verify at install (DoD-1).]
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
	"github.com/six2dez/reconftw/internal/extract/waf"
)

// WAFRecord is the D-W11 waf.jsonl schema row.
// Both wafw00f and cdncheck write into the same artefact file; fields unused
// by the producing task are written as empty strings.
type WAFRecord struct {
	Host       string `json:"host"`
	WAF        string `json:"waf"`
	CDN        string `json:"cdn"`
	DetectedBy string `json:"detected_by"`
}

// Wafw00fTask runs wafw00f WAF detection.
type Wafw00fTask struct{}

func (t *Wafw00fTask) Name() string        { return "web.wafw00f" }
func (t *Wafw00fTask) Module() string      { return "web" }
func (t *Wafw00fTask) Description() string { return "WAF detection (wafw00f → waf.jsonl)" }
func (t *Wafw00fTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.WAF.Enabled
}
func (t *Wafw00fTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes wafw00f against hosts from hosts.jsonl and writes WAF records.
func (t *Wafw00fTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "wafw00f"

	// Collect URLs from hosts.jsonl.
	urls, err := readHostURLsFromJSONL(app)
	if err != nil || len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("web.wafw00f: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.wafw00f: mkdir inputs/: %w", err)
	}
	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.wafw00f: mkdir artefacts/: %w", err)
	}

	hostsFile := filepath.Join(inputsDir, "wafw00f.hosts.txt")
	if err := os.WriteFile(hostsFile, []byte(strings.Join(urls, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.wafw00f: write hosts file: %w", err)
	}

	stagingFile := filepath.Join(artefactsDir, "wafw00f.txt.tmp")
	args := []string{"-i", hostsFile, "-o", stagingFile}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.wafw00f: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Parse staging file output; fall back to stdout.
	var raw []byte
	if data, rerr := os.ReadFile(stagingFile); rerr == nil { //nolint:gosec
		raw = data
	} else if res != nil && len(res.Stdout) > 0 {
		raw = res.Stdout
	}

	results, _ := waf.ExtractWafw00f(raw, app.Target.Domain)

	if len(results) == 0 {
		return task.Result{Status: task.StatusDone,
			Stats: map[string]int{"waf_detected": 0}}, nil
	}

	var lines [][]byte
	for _, r := range results {
		rec := WAFRecord{
			Host:       r.Host,
			WAF:        r.WAF,
			CDN:        "",
			DetectedBy: r.DetectedBy,
		}
		b, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) > 0 {
		if appendErr := app.Tree.Append("waf", lines); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.wafw00f: Tree.Append failed", "err", appendErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.wafw00f: completed", "waf_detected", len(results))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"waf_detected": len(results)},
	}, nil
}

func init() { task.Register(&Wafw00fTask{}) }
