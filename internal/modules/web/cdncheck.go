// cdncheck.go — CdnCheckTask: CDN classification via cdncheck → artefacts/waf.jsonl.
//
// Name: "web.cdncheck"  DependsOn: ["web.httpx"]
//
// CRITICAL (Pitfall 8): cdncheck reads IPs, NOT URLs.
// CdnCheckTask extracts the "ip" field from each hosts.jsonl record and feeds
// that IP list via stdin to cdncheck. Feeding URLs results in 0 output.
//
// ARG VECTOR (RESEARCH §cdncheck — verbatim v1 form):
//
//	cdncheck -silent -resp -nc  (stdin: IP list)
//
// T-05-11: IPs sourced from httpx-probed hosts.jsonl (scope-validated at write time).
//
// cdncheck is a LocalBackend tool only (D-W13).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-03-PLAN.md Task 2.
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
	"github.com/six2dez/reconftw/internal/extract/waf"
)

// CdnCheckTask runs cdncheck CDN classification.
type CdnCheckTask struct{}

func (t *CdnCheckTask) Name() string        { return "web.cdncheck" }
func (t *CdnCheckTask) Module() string      { return "web" }
func (t *CdnCheckTask) Description() string { return "CDN classification (cdncheck → waf.jsonl)" }
func (t *CdnCheckTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.WAF.Enabled
}
func (t *CdnCheckTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes cdncheck against IPs extracted from hosts.jsonl ip fields.
func (t *CdnCheckTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "cdncheck"

	// Pitfall 8: extract IP fields, not URLs, from hosts.jsonl.
	ips, err := readIPsFromHostsJSONL(app)
	if err != nil || len(ips) == 0 {
		if app.Log != nil {
			app.Log.Info("web.cdncheck: no IPs in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.cdncheck: mkdir inputs/: %w", err)
	}

	// Write IPs to a temp file then pass via stdin.
	ipsFile := filepath.Join(inputsDir, "cdncheck.ips.txt")
	if err := os.WriteFile(ipsFile, []byte(strings.Join(ips, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.cdncheck: write ips file: %w", err)
	}

	// cdncheck reads IPs via -i <file> flag.
	args := []string{"-silent", "-resp", "-nc", "-i", ipsFile}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.cdncheck: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Parse output from stdout.
	var raw []byte
	if res != nil && len(res.Stdout) > 0 {
		raw = res.Stdout
	}

	results, _ := waf.ExtractCDNCheck(raw, app.Target.Domain)

	// F3 (phase 15): the old `if len(results) == 0 { return StatusDone }`
	// short-circuit here SKIPPED the staging write below, leaving a previous
	// run's inputs/waf.cdncheck.jsonl for the waf merge to republish. cdncheck
	// RAN (absent binary returned StatusSkipped above), so fall through to the
	// unconditional StageJSONL and let it clear the file.

	var lines [][]byte
	for _, r := range results {
		rec := WAFRecord{
			Host:       r.Host,
			WAF:        "",
			CDN:        r.CDN,
			DetectedBy: r.DetectedBy,
		}
		b, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	// F3 (phase 15): staged UNCONDITIONALLY — StageJSONL removes the staging
	// file when this run detected nothing, so a previous run's CDN records
	// cannot be republished by the waf merge.
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "waf.cdncheck.jsonl")
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("web.cdncheck: staging write failed",
			"path", stagingPath, "err", wErr)
	}

	if app.Log != nil {
		app.Log.Debug("web.cdncheck: completed", "cdn_detected", len(results))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"cdn_detected": len(results)},
	}, nil
}

// readIPsFromHostsJSONL reads artefacts/hosts.jsonl and returns the list of
// non-empty IP values from the "ip" field (D-W11 HostRecord schema).
// This is the Pitfall 8 mitigation — cdncheck needs IPs not URLs.
func readIPsFromHostsJSONL(app *appctx.AppContext) ([]string, error) {
	hostsPath := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	data, err := os.ReadFile(hostsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read hosts.jsonl: %w", err)
	}
	seen := make(map[string]bool)
	var ips []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		ip := strings.TrimSpace(rec.IP)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	return ips, nil
}

func init() { task.Register(&CdnCheckTask{}) }
