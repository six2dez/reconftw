// vhostfinder.go — VhostFinderTask: virtual host discovery → artefacts/vhosts.jsonl.
//
// Name: "web.vhostfinder"  DependsOn: ["web.httpx"]
//
// VhostFinderTask extracts IPs from hosts.jsonl and uses prior subdomain
// artefacts as the wordlist. It runs VhostFinder, filters lines containing "+"
// from stdout, and writes vhost records to artefacts/vhosts.jsonl.
//
// ARG VECTOR (RESEARCH §VhostFinder — verbatim v1 form):
//
//	VhostFinder -ips <ipsfile> -wordlist <subsfile> -verify
//
// Output: lines containing "+" are vhost hits.
//
// [ASSUMED A9: VhostFinder -ips/-wordlist/-verify flags are current — verify.]
//
// T-05-11: IPs sourced from httpx-probed hosts.jsonl (scope-validated at write time).
// T-05-10: tool stdout routed to run.log only (never INFO terminal, GAP-3).
//
// VhostFinder is a LocalBackend tool only (D-W13).
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
	"github.com/six2dez/reconftw/internal/core/task"
)

// VhostRecord is the vhosts.jsonl schema row.
type VhostRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

// VhostFinderTask runs VhostFinder virtual host discovery.
type VhostFinderTask struct{}

func (t *VhostFinderTask) Name() string        { return "web.vhostfinder" }
func (t *VhostFinderTask) Module() string      { return "web" }
func (t *VhostFinderTask) Description() string { return "Virtual host discovery (VhostFinder)" }
func (t *VhostFinderTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.VirtualHosts.Enabled
}
func (t *VhostFinderTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes VhostFinder and writes vhost records to vhosts.jsonl.
func (t *VhostFinderTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "VhostFinder"

	// Extract IPs from hosts.jsonl (T-05-11: scope-validated by httpx Task).
	ips, err := readIPsFromHostsJSONL(app)
	if err != nil || len(ips) == 0 {
		if app.Log != nil {
			app.Log.Info("web.vhostfinder: no IPs in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Build subdomain wordlist from prior artefacts/subdomains.jsonl or hosts.jsonl.
	wordlist, err := buildVhostWordlist(app)
	if err != nil || len(wordlist) == 0 {
		if app.Log != nil {
			app.Log.Info("web.vhostfinder: no subdomain wordlist available — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.vhostfinder: mkdir inputs/: %w", err)
	}

	ipsFile := filepath.Join(inputsDir, "vhostfinder.ips.txt")
	if err := os.WriteFile(ipsFile, []byte(strings.Join(ips, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.vhostfinder: write ips file: %w", err)
	}

	wordlistFile := filepath.Join(inputsDir, "vhostfinder.wordlist.txt")
	if err := os.WriteFile(wordlistFile, []byte(strings.Join(wordlist, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.vhostfinder: write wordlist file: %w", err)
	}

	// RESEARCH §VhostFinder: VhostFinder -ips <file> -wordlist <file> -verify
	args := []string{"-ips", ipsFile, "-wordlist", wordlistFile, "-verify"}

	res, execErr := app.Tools.Run(ctx, toolName, args)
	if execErr != nil {
		if app.Log != nil {
			app.Log.Info("web.vhostfinder: binary absent or failed — skipping",
				"err", execErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Filter stdout lines containing "+" (the hit indicator).
	var rawOutput []byte
	if res != nil && len(res.Stdout) > 0 {
		rawOutput = res.Stdout
	}

	hits := parseVhostFinderOutput(rawOutput)
	if len(hits) == 0 {
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"vhosts_found": 0},
		}, nil
	}

	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.vhostfinder: mkdir artefacts/: %w", err)
	}

	var lines [][]byte
	for _, h := range hits {
		b, err := json.Marshal(h)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) > 0 {
		if appendErr := app.Tree.Append("vhosts", lines); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.vhostfinder: Tree.Append failed", "err", appendErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.vhostfinder: completed", "vhosts_found", len(hits))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"vhosts_found": len(hits)},
	}, nil
}

// parseVhostFinderOutput filters lines containing "+" from VhostFinder output.
// RESEARCH §VhostFinder: "| grep +" is the v1 hit filter pattern.
func parseVhostFinderOutput(rawOutput []byte) []VhostRecord {
	if len(rawOutput) == 0 {
		return nil
	}
	var hits []VhostRecord
	scanner := bufio.NewScanner(bytes.NewReader(rawOutput))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "+") {
			continue
		}
		// Best-effort parse: extract host/IP from the hit line.
		// VhostFinder output format: "[+] vhostname -> ip" (assumed A9).
		fields := strings.Fields(line)
		host, ip := "", ""
		for i, f := range fields {
			if f == "+" || f == "[+]" {
				if i+1 < len(fields) {
					host = fields[i+1]
				}
			}
			if f == "->" && i+1 < len(fields) {
				ip = fields[i+1]
			}
		}
		if host == "" {
			// Fallback: use the whole line as host.
			host = strings.TrimSpace(line)
		}
		hits = append(hits, VhostRecord{Host: host, IP: ip})
	}
	return hits
}

// buildVhostWordlist builds the hostname wordlist from prior artefacts.
// Prefers artefacts/subdomains.jsonl; falls back to hostnames from hosts.jsonl.
func buildVhostWordlist(app *appctx.AppContext) ([]string, error) {
	// Try subdomains.jsonl first.
	subsPath := filepath.Join(app.Target.WorkDir, "artefacts", "subdomains.jsonl")
	if data, err := os.ReadFile(subsPath); err == nil { //nolint:gosec
		seen := make(map[string]bool)
		var names []string
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var rec struct {
				Subdomain string `json:"subdomain"`
				Host      string `json:"host"`
			}
			if jerr := json.Unmarshal(line, &rec); jerr != nil {
				continue
			}
			h := rec.Subdomain
			if h == "" {
				h = rec.Host
			}
			if h != "" && !seen[h] {
				seen[h] = true
				names = append(names, h)
			}
		}
		if len(names) > 0 {
			return names, nil
		}
	}
	// Fallback: extract hostnames from hosts.jsonl.
	return readHostnamesFromJSONL(app)
}

func init() { task.Register(&VhostFinderTask{}) }
