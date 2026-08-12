// favirecon.go — FaviReconTask: favicon-hash CMS recon via favirecon (OSINT-12).
//
// NOTE: this is osint.favirecon — DISTINCT from web.favirecon
// (internal/modules/web/favirecon.go). The osint variant folds favicon-based CMS
// fingerprinting into the OSINT findings stream (D-O3) as an OSINT-12 engine
// alongside CMSeeK; the web variant writes the favicons.jsonl artefact in the web
// pipeline. They share the LITERAL v1 favirecon arg vector but emit different
// records to different streams.
//
// FaviReconTask runs favirecon over the discovered web hosts (v1
// modules/web.sh:557 favirecon_tech: favirecon -l webs/webs_all.txt -c 50 -t 10
// -s -j -o <out>) to identify the CMS/technology behind each host by favicon hash.
// Each hit becomes an informational OSINTFindingRecord (D-O4, Category cms-favicon).
//
// OPPORTUNISTIC ENRICHMENT (D-O2): favirecon is a v1 web.sh function (host-corpus
// seeded). It reads the discovered hosts from the workspace artefacts
// (artefacts/hosts.jsonl or artefacts/urls.jsonl) IF present. When NO workspace
// hosts exist it logs an Info note and returns StatusSkipped — it NEVER fails or
// bootstraps subs/web (best_effort, D-O1/D-O2). Hosts are already scope-filtered
// by Phase 5 (T-07-05-05).
//
// SEEDING (D-O1): no DependsOn edges — the workspace-host enrichment is
// opportunistic, not a DAG edge.
// FAILURE POLICY (D-O8, ARCH-09): best_effort.
//
// Source: .planning/phases/07-osint-e2e/07-05-PLAN.md Task 1.
package osint

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

// faviReconDefaultConcurrency / faviReconDefaultTimeout are the conservative v1
// defaults (web.sh:560-561: -c 50 -t 10).
const (
	faviReconDefaultConcurrency = 50
	faviReconDefaultTimeout     = 10
)

// FaviReconTask runs favirecon for OSINT-12 (favicon CMS recon).
type FaviReconTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
// DISTINCT from web.favirecon — this is the OSINT-stream variant.
func (t *FaviReconTask) Name() string { return "osint.favirecon" }

// Module returns the owning module group.
func (t *FaviReconTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *FaviReconTask) Description() string {
	return "Favicon CMS recon (favirecon, OSINT-12)"
}

// Enabled reports whether favicon CMS recon is configured.
func (t *FaviReconTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.CMS.Enabled && cfg.OSINT.CMS.FavireconEnabled
}

// DependsOn returns nil — the workspace-host enrichment (D-O2) is OPPORTUNISTIC,
// not a DAG edge.
func (t *FaviReconTask) DependsOn() []string { return nil }

// Run executes favirecon over the workspace hosts (D-O2 opportunistic enrichment).
//
// Steps:
//  1. D-O2: read workspace hosts (artefacts/hosts.jsonl|urls.jsonl) IF present;
//     absent → log Info + StatusSkipped (best_effort, NO fail/bootstrap).
//  2. Write the host list, run favirecon (LITERAL web.sh:557 arg vector).
//  3. Parse favicon-hash CMS hits into informational records.
//  4. Write inputs/findings.favirecon.jsonl (multi-writer staging).
func (t *FaviReconTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Step 1: D-O2 opportunistic host read.
	hosts := readWorkspaceHosts(app.Target.WorkDir)
	if len(hosts) == 0 {
		// D-O2: log-skip when absent — best_effort, NOT an error/bootstrap.
		if app.Log != nil {
			app.Log.Info("osint.favirecon: no workspace hosts (artefacts/hosts.jsonl|urls.jsonl) — skipping (D-O2)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.favirecon: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	// Step 2: write the host list (favirecon -l <file>).
	hostsFile := filepath.Join(inputsDir, "favirecon.hosts.txt")
	if wErr := os.WriteFile(hostsFile, []byte(strings.Join(hosts, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.favirecon: write hosts file: %w", wErr)
	}
	favOut := filepath.Join(osintDir, "favirecon.json")

	// LITERAL v1 favirecon arg vector (web.sh:557-565):
	//   favirecon -l <hostsfile> -c 50 -t 10 -s -j -o <out>
	args := []string{
		"-l", hostsFile,
		"-c", fmt.Sprintf("%d", faviReconDefaultConcurrency),
		"-t", fmt.Sprintf("%d", faviReconDefaultTimeout),
		"-s", // silent
		"-j", // JSON output
		"-o", favOut,
	}

	res, err := app.Tools.Run(ctx, "favirecon", args)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.favirecon: favirecon run failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	// Step 3: parse favirecon JSON output (prefer the -o file, fall back to stdout).
	var raw []byte
	if data, rErr := os.ReadFile(favOut); rErr == nil && len(bytes.TrimSpace(data)) > 0 { //nolint:gosec // within WorkDir
		raw = data
	} else if res != nil {
		raw = res.Stdout
	}
	records := parseFaviReconOutput(raw)

	// Step 4: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.favirecon.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.favirecon: completed", "findings", len(records), "hosts_scanned", len(hosts))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records), "hosts_scanned": len(hosts)},
	}, nil
}

// parseFaviReconOutput parses favirecon's -j JSON-lines output (each line a JSON
// object with URL/Name/Hash fields, v1 web.sh:579 jq selector) into informational
// cms-favicon records. The matched URL + tech + hash are non-secret OSINT values.
func parseFaviReconOutput(data []byte) []OSINTFindingRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var records []OSINTFindingRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec struct {
			URL   string `json:"URL"`
			URL2  string `json:"url"`
			Name  string `json:"Name"`
			Name2 string `json:"name"`
			Hash  string `json:"Hash"`
			Hash2 string `json:"hash"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		url := firstNonEmpty(rec.URL, rec.URL2)
		if url == "" {
			continue
		}
		tech := firstNonEmpty(rec.Name, rec.Name2)
		hash := firstNonEmpty(rec.Hash, rec.Hash2)
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "favirecon",
			Category:    "cms-favicon",
			PoCRedacted: strings.TrimSpace(url + " [" + tech + "] [" + hash + "]"),
		})
	}
	return records
}

// firstNonEmpty returns the first non-empty trimmed string of its arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// init self-registers FaviReconTask with the Default task registry.
func init() { task.Register(&FaviReconTask{}) }
