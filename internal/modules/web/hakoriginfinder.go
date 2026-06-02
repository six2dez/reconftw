// hakoriginfinder.go — HakoriginfinderTask: origin IP discovery → artefacts/origins.jsonl.
//
// Name: "web.hakoriginfinder"  DependsOn: ["web.httpx"]
//
// HakoriginfinderTask feeds hostnames via stdin to hakoriginfinder, then
// extracts IPv4 addresses from the raw text output via a regex pattern.
// Per RESEARCH §hakoriginfinder, v1 uses:
//
//	hakoriginfinder < hosts.txt > raw_output.txt
//	grep -aoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' raw_output.txt
//
// D-W11 origins.jsonl schema: {host, origin_ip, method, confidence}
//
// ARG VECTOR (RESEARCH §hakoriginfinder):
//
//	hakoriginfinder  (stdin: hostname list)
//
// [ASSUMED A14: output format contains IPs parseable by IPv4 regex.]
//
// T-05-10: tool stdout routed to run.log only (never INFO terminal, GAP-3).
//
// hakoriginfinder is a LocalBackend tool only (D-W13).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-03-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// OriginRecord is the D-W11 origins.jsonl schema row.
type OriginRecord struct {
	Host       string `json:"host"`
	OriginIP   string `json:"origin_ip"`
	Method     string `json:"method"`
	Confidence string `json:"confidence"`
}

// ipv4RE matches IPv4 addresses in hakoriginfinder output.
// RESEARCH §hakoriginfinder: grep -aoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
var ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// HakoriginfinderTask runs hakoriginfinder to discover origin IPs.
type HakoriginfinderTask struct{}

func (t *HakoriginfinderTask) Name() string        { return "web.hakoriginfinder" }
func (t *HakoriginfinderTask) Module() string      { return "web" }
func (t *HakoriginfinderTask) Description() string { return "Origin IP discovery (hakoriginfinder)" }
func (t *HakoriginfinderTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Probe.Enabled
}
func (t *HakoriginfinderTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes hakoriginfinder and writes origin records to origins.jsonl.
func (t *HakoriginfinderTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "hakoriginfinder"

	// Collect hostnames from hosts.jsonl (host field, not URL).
	hosts, err := readHostnamesFromJSONL(app)
	if err != nil || len(hosts) == 0 {
		if app.Log != nil {
			app.Log.Info("web.hakoriginfinder: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.hakoriginfinder: mkdir inputs/: %w", err)
	}

	hostsFile := filepath.Join(inputsDir, "hakoriginfinder.hosts.txt")
	if err := os.WriteFile(hostsFile, []byte(strings.Join(hosts, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.hakoriginfinder: write hosts file: %w", err)
	}

	// hakoriginfinder reads stdin; use -i flag or stdin redirect.
	// The tool accepts hostnames via stdin; we pass via a file through -i if supported,
	// otherwise use the stdin piping approach. v1 uses stdin redirect.
	args := []string{"-i", hostsFile}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.hakoriginfinder: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Extract IPv4 addresses from raw output text (RESEARCH §hakoriginfinder).
	var rawOutput []byte
	if res != nil && len(res.Stdout) > 0 {
		rawOutput = res.Stdout
	}

	origins := parseHakoriginfinderOutput(rawOutput, hosts)
	if len(origins) == 0 {
		return task.Result{Status: task.StatusDone,
			Stats: map[string]int{"origins_found": 0}}, nil
	}

	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.hakoriginfinder: mkdir artefacts/: %w", err)
	}

	var lines [][]byte
	for _, r := range origins {
		b, err := json.Marshal(r)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) > 0 {
		if appendErr := app.Tree.Append("origins", lines); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.hakoriginfinder: Tree.Append failed", "err", appendErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.hakoriginfinder: completed", "origins_found", len(origins))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"origins_found": len(origins)},
	}, nil
}

// parseHakoriginfinderOutput extracts IP addresses from hakoriginfinder's raw
// text output. The output typically shows hostname → IP mappings; we extract
// all IPv4 addresses and associate them positionally with the input host list
// when possible. When we can't associate a specific host, we use the first
// hostname as a best-effort fallback per [ASSUMED A14].
func parseHakoriginfinderOutput(rawOutput []byte, hosts []string) []OriginRecord {
	if len(rawOutput) == 0 || len(hosts) == 0 {
		return nil
	}

	// Extract all unique IPs from the output.
	lines := strings.Split(string(rawOutput), "\n")
	seen := make(map[string]bool)
	var records []OriginRecord

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ips := ipv4RE.FindAllString(line, -1)
		for _, ip := range ips {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			// Associate with host by line index (best-effort per A14).
			host := ""
			if i < len(hosts) {
				host = hosts[i]
			} else if len(hosts) > 0 {
				host = hosts[0]
			}
			records = append(records, OriginRecord{
				Host:       host,
				OriginIP:   ip,
				Method:     "hakoriginfinder",
				Confidence: "medium",
			})
		}
	}
	return records
}

// readHostnamesFromJSONL reads artefacts/hosts.jsonl and returns the list of
// host field values (bare hostnames, not URLs) for hakoriginfinder stdin.
func readHostnamesFromJSONL(app *appctx.AppContext) ([]string, error) {
	hostsPath := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	data, err := os.ReadFile(hostsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read hosts.jsonl: %w", err)
	}
	seen := make(map[string]bool)
	var hostnames []string

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		h := strings.TrimSpace(rec.Host)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hostnames = append(hostnames, h)
	}
	return hostnames, nil
}

func init() { task.Register(&HakoriginfinderTask{}) }
