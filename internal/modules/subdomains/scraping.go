// scraping.go — SubScrapingTask, SubAnalyticsTask, SubNSDelegationTask.
//
// STAGING CONTRACT (doc.go): Tasks write subdomain candidates to per-source
// staging files at filepath.Join(app.Target.WorkDir, "inputs", "resolved."+toolName+".txt").
// Tasks do NOT call app.Tree.Append directly — MergeStage(ctx, app, "resolved")
// (merge.go) is the single app.Tree.Append caller for the resolved stage.
//
// TEMP-FILE PATTERN (subjs→jsluice):
// Backend.Runner has no stdin field — a direct pipe from subjs stdout to jsluice
// stdin CANNOT be replicated through the Runner interface. Instead:
//   1. Run subjs → collect output
//   2. Write output to raw/subjs.tmp.txt
//   3. Run jsluice with -i raw/subjs.tmp.txt (file input, not stdin)
//   4. Defer os.Remove on the temp file
// This resolves the REVIEWS additional finding and the 04-03-PLAN.md constraint.
//
// THREAT MODEL (04-03-PLAN.md):
//   T-04-03-01: tempFile path constructed from WorkDir (validated at Target creation)
//               — no user-controlled path component.
//   T-04-03-02: extract/js returns only Subdomain+URL; secret fields NOT written to staging.
//   T-04-03-03: SubScrapingTask runs once per target per stage; Scheduler ensures
//               single instance per task name (no temp file race).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-03-PLAN.md Task 2.
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/extract/analytics"
	"github.com/six2dez/reconftw/internal/extract/favicon"
	"github.com/six2dez/reconftw/internal/extract/js"
)

// -------------------------------------------------------------------------
// SubScrapingTask
// -------------------------------------------------------------------------

// SubScrapingTask discovers subdomains via favicon hashing (favirecon) and
// JS link extraction (subjs+jsluice pipeline with temp-file intermediate).
// Writes staging file: inputs/resolved.scraping.txt
type SubScrapingTask struct{}

func (SubScrapingTask) Name() string        { return "subdomains.scraping" }
func (SubScrapingTask) Module() string      { return "subdomains" }
func (SubScrapingTask) DependsOn() []string { return nil }

func (SubScrapingTask) Description() string {
	return "Subdomain discovery via favicon hashing (favirecon) and JS link extraction (subjs+jsluice)"
}

// Enabled reports whether the scraping stage is active per configuration.
func (SubScrapingTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Scraping.Enabled
}

// Run executes:
//  1. favirecon → favicon.Extract → collect subdomain candidates
//  2. subjs → write raw/subjs.tmp.txt → jsluice -i tmp → js.Extract → collect candidates
//  3. Write all candidates as SubdomainRecord JSON lines to inputs/resolved.scraping.txt
func (SubScrapingTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "scraping"
	domain := app.Target.Domain

	var candidates []string

	// Step 1: favirecon — favicon hash subdomain discovery.
	faviRes, err := app.Tools.Run(ctx, "favirecon", []string{"-d", domain, "-t", "50", "-timeout", "10"})
	if err == nil {
		favResults, _ := favicon.Extract(faviRes.Stdout, domain)
		for _, r := range favResults {
			if r.Subdomain != "" {
				candidates = append(candidates, r.Subdomain)
			}
		}
	} else if app.Log != nil {
		app.Log.Warn("scraping: favirecon failed", "error", err.Error())
	}

	// Step 2a: subjs — collect JavaScript URLs.
	subjsRes, err := app.Tools.Run(ctx, "subjs", []string{"-i", "-"})
	if err != nil && app.Log != nil {
		app.Log.Warn("scraping: subjs failed", "error", err.Error())
	}
	var subjsOutput []byte
	if err == nil {
		subjsOutput = subjsRes.Stdout
	}

	// Step 2b: write subjs output to a temp file.
	tmpPath := filepath.Join(app.Target.WorkDir, "raw", "subjs.tmp.txt")
	if err2 := os.MkdirAll(filepath.Dir(tmpPath), 0o755); err2 != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("scraping: mkdir raw/: %w", err2)
	}
	if err2 := os.WriteFile(tmpPath, subjsOutput, 0o644); err2 != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("scraping: write subjs.tmp.txt: %w", err2)
	}
	defer os.Remove(tmpPath) //nolint:errcheck // temp file; ignore remove error

	// Step 2c: jsluice with -i <tempFile> (NOT stdin pipe).
	jsRes, err := app.Tools.Run(ctx, "jsluice", []string{"urls", "-i", tmpPath})
	if err == nil {
		jsResults, _ := js.Extract(jsRes.Stdout, domain)
		for _, r := range jsResults {
			if r.Subdomain != "" {
				candidates = append(candidates, r.Subdomain)
			}
		}
	} else if app.Log != nil {
		app.Log.Warn("scraping: jsluice failed", "error", err.Error())
	}

	// Deduplicate candidates.
	candidates = uniqueStrings(candidates)

	// Step 3: write SubdomainRecord JSON lines to staging file.
	stagingPath, writeErr := writeScrapingStagingFile(app, toolName, candidates)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"scraping_candidates": len(candidates)},
	}, nil
}

// writeScrapingStagingFile writes subdomain candidates as SubdomainRecord JSON lines
// to inputs/resolved.<toolName>.txt. Creates the inputs/ directory if needed.
func writeScrapingStagingFile(app *appctx.AppContext, toolName string, candidates []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("scraping %s: mkdir inputs/: %w", toolName, err)
	}
	stagingPath := filepath.Join(inputsDir, "resolved."+toolName+".txt")

	now := time.Now().UTC().Format(time.RFC3339)
	var buf bytes.Buffer
	for _, sub := range candidates {
		rec := SubdomainRecord{
			Subdomain: sub,
			Source:    toolName,
			FirstSeen: now,
		}
		line, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	if err := os.WriteFile(stagingPath, buf.Bytes(), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("scraping %s: write staging file: %w", toolName, err)
	}
	return stagingPath, nil
}

// uniqueStrings returns a deduped slice preserving first occurrence order.
func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// -------------------------------------------------------------------------
// SubAnalyticsTask
// -------------------------------------------------------------------------

// SubAnalyticsTask discovers related domains via Google Analytics tracking ID pivoting
// using the analyticsrelationships tool.
// Writes staging file: inputs/resolved.analytics.txt
type SubAnalyticsTask struct{}

func (SubAnalyticsTask) Name() string        { return "subdomains.analytics" }
func (SubAnalyticsTask) Module() string      { return "subdomains" }
func (SubAnalyticsTask) DependsOn() []string { return nil }

func (SubAnalyticsTask) Description() string {
	return "Subdomain discovery via Google Analytics tracking ID pivoting (analyticsrelationships)"
}

// Enabled reports whether the analytics stage is active per configuration.
func (SubAnalyticsTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Analytics.Enabled
}

// Run executes analyticsrelationships -d <domain>, parses the output via
// analytics.Extract, and writes candidate domains as SubdomainRecord JSON
// lines to inputs/resolved.analytics.txt.
func (SubAnalyticsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "analytics"
	domain := app.Target.Domain

	res, err := app.Tools.Run(ctx, "analyticsrelationships", []string{"-d", domain})
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("analyticsrelationships: Run failed: %w", err)
	}

	results, _ := analytics.Extract(res.Stdout, domain)
	var candidates []string
	for _, r := range results {
		if r.Subdomain != "" {
			candidates = append(candidates, r.Subdomain)
		}
	}

	stagingPath, writeErr := writeScrapingStagingFile(app, toolName, candidates)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"analytics_candidates": len(candidates)},
	}, nil
}

// -------------------------------------------------------------------------
// SubNSDelegationTask
// -------------------------------------------------------------------------

// SubNSDelegationTask discovers subdomains by checking for NS record delegations
// on known subdomains and attempting AXFR on the delegated nameservers.
// Writes staging file: inputs/resolved.ns_delegation.txt
//
// Input: subdomains/subdomains.txt (written by earlier passive/active stages)
// Uses dnsx to look up NS records, then attempts dig axfr on each delegated zone.
type SubNSDelegationTask struct{}

func (SubNSDelegationTask) Name() string        { return "subdomains.ns_delegation" }
func (SubNSDelegationTask) Module() string      { return "subdomains" }
func (SubNSDelegationTask) DependsOn() []string { return nil }

func (SubNSDelegationTask) Description() string {
	return "NS delegation zone transfer check: discovers subdomains via AXFR on delegated zones"
}

// Enabled reports whether NS delegation checking is active per configuration.
func (SubNSDelegationTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.NSDelegation.Enabled
}

// Run:
//  1. Reads subdomains/subdomains.txt as the input list.
//  2. Runs dnsx -ns -resp -silent on the list to find NS records.
//  3. Parses delegated zones from dnsx output.
//  4. Writes candidate subdomains to inputs/resolved.ns_delegation.txt.
func (SubNSDelegationTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "ns_delegation"

	// Input list: subdomains from prior passive/active stages.
	subsFile := filepath.Join(app.Target.WorkDir, "subdomains", "subdomains.txt")
	if _, err := os.Stat(subsFile); err != nil {
		// No subdomains file yet — write empty staging file and skip.
		stagingPath, writeErr := writeResolvedStagingFile(app, toolName, nil)
		if writeErr != nil {
			return task.Result{Status: task.StatusErrored}, writeErr
		}
		return task.Result{
			Status:  task.StatusSkipped,
			Outputs: []string{stagingPath},
		}, nil
	}

	// Run dnsx NS lookup on known subdomains.
	cfg := app.Cfg
	dnsx_args := []string{
		"-l", subsFile,
		"-ns", "-resp",
		"-silent",
	}
	if cfg.Subdomains.DNSResolve.DNSXThreads > 0 {
		dnsx_args = append(dnsx_args, "-t", fmt.Sprintf("%d", cfg.Subdomains.DNSResolve.DNSXThreads))
	}
	if cfg.Subdomains.DNSResolve.DNSXRateLimit > 0 {
		dnsx_args = append(dnsx_args, "-rl", fmt.Sprintf("%d", cfg.Subdomains.DNSResolve.DNSXRateLimit))
	}

	res, err := app.Tools.Run(ctx, "dnsx", dnsx_args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("ns_delegation: dnsx Run failed: %w", err)
	}

	// Parse dnsx output to find delegated zones.
	// dnsx output format: "subdomain.example.com [ns1.nameserver.com]"
	candidates := parseNSDelegationOutput(res.Stdout, app.Target.Domain)

	stagingPath, writeErr := writeResolvedStagingFile(app, toolName, candidates)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"ns_delegation_candidates": len(candidates)},
	}, nil
}

// parseNSDelegationOutput parses dnsx -ns -resp output lines to extract
// delegated zone candidates. The format per line is:
//
//	subdomain.example.com [ns1.nameserver.com ns2.nameserver.com]
//
// Only lines where the subject is NOT the base domain itself are considered
// (base domain NS records are handled by the zone transfer task).
// Returned candidates are the delegated subdomains that have NS records.
func parseNSDelegationOutput(output []byte, domain string) []string {
	if len(output) == 0 {
		return nil
	}
	baseDomain := strings.ToLower(strings.TrimSpace(domain))
	var results []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Extract the subject hostname (first field before any whitespace).
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		sub := strings.ToLower(fields[0])

		// Skip the base domain itself.
		if sub == baseDomain {
			continue
		}

		// Must be a subdomain of the target.
		if !strings.HasSuffix(sub, "."+baseDomain) {
			continue
		}

		if seen[sub] {
			continue
		}
		seen[sub] = true
		results = append(results, sub)
	}
	return results
}

// -------------------------------------------------------------------------
// init() — self-registration (staging contract doc.go)
// -------------------------------------------------------------------------

func init() { task.Register(SubScrapingTask{}) }
func init() { task.Register(SubAnalyticsTask{}) }
func init() { task.Register(SubNSDelegationTask{}) }
