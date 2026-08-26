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
//  0. Write the workspace's scheme-bearing URLs to inputs/scraping_subjs_urls.txt.tmp
//     and pass THAT to subjs -i. subjs has no stdin sentinel: `-i -` fails with
//     `Could not open input file: open -: no such file or directory`, and nothing
//     was ever piped to it either (fixed 17-04).
//  1. Run subjs → collect output
//  2. Write output to raw/subjs.tmp.txt
//  3. Run jsluice with -i raw/subjs.tmp.txt (file input, not stdin)
//  4. Defer os.Remove on the temp file
//
// This resolves the REVIEWS additional finding and the 04-03-PLAN.md constraint.
//
// THREAT MODEL (04-03-PLAN.md):
//
//	T-04-03-01: tempFile path constructed from WorkDir (validated at Target creation)
//	            — no user-controlled path component.
//	T-04-03-02: extract/js returns only Subdomain+URL; secret fields NOT written to staging.
//	T-04-03-03: SubScrapingTask runs once per target per stage; Scheduler ensures
//	            single instance per task name (no temp file race).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-03-PLAN.md Task 2.
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
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
	// favirecon takes the domain via -u (NOT -d, which does not exist → exit 2)
	// and -t is an ALIAS for -timeout (not a thread count). Verified against the
	// installed favirecon CLI.
	faviRes, err := app.Tools.Run(ctx, "favirecon", []string{"-u", domain, "-timeout", "10"})
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
	//
	// A REAL FILE, not a stdin sentinel. subjs has no `-` convention — `-i`
	// names a file and nothing else:
	//
	//	$ subjs -i - < /dev/null
	//	Error running subjs: Could not open input file: open -: no such file …  (exit 1)
	//	$ subjs -i urls.txt
	//	                                                                       (exit 0)
	//
	// `subjs -h` (v1.0.1) lists exactly five flags — `-c -i -t -ua -version` —
	// and `-i` is documented as "Input file containing URLS". The old vector was
	// broken twice over: the sentinel is not a file, AND nothing was ever piped
	// to it, so this leg contributed nothing. Written the same way the file-fed
	// jsluice call below and web/subjs.go both do it.
	subjsInputURLs, subjsDropped := scrapingSubjsInput(app)
	if subjsDropped > 0 && app.Log != nil {
		app.Log.Debug("scraping: workspace entries without a scheme skipped for subjs",
			"dropped", subjsDropped)
	}
	var subjsOutput []byte
	if len(subjsInputURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("scraping: no workspace URLs for subjs — skipping JS URL collection",
				"source", "artefacts/hosts.jsonl|urls.jsonl")
		}
	} else {
		subjsInputPath := filepath.Join(app.Target.WorkDir, "inputs", "scraping_subjs_urls.txt.tmp")
		if wErr := os.MkdirAll(filepath.Dir(subjsInputPath), 0o755); wErr != nil {
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("scraping: mkdir inputs/: %w", wErr)
		}
		if wErr := os.WriteFile(subjsInputPath,
			[]byte(strings.Join(subjsInputURLs, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("scraping: write subjs input: %w", wErr)
		}
		subjsRes, sErr := app.Tools.Run(ctx, "subjs", []string{"-i", subjsInputPath})
		if sErr != nil {
			if app.Log != nil {
				app.Log.Warn("scraping: subjs failed", "error", sErr.Error())
			}
		} else {
			subjsOutput = subjsRes.Stdout
		}
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

// writeScrapingStagingFile writes subdomain candidates as PLAIN hostnames
// (one per line) to inputs/resolved.<toolName>.txt. Creates the inputs/
// directory if needed.
//
// STAGING CONTRACT (doc.go): staging files are plain newline-delimited
// hostnames — MergeStage's readStagingFile reads them line-by-line. This
// MUST match writeStagingFile (passive) and writeResolvedStagingFile
// (resolve); writing JSON SubdomainRecord lines here (the prior behavior)
// made MergeStage treat each JSON blob as a single bogus "hostname", which
// the scope filter then rejected — losing every scraping/analytics result
// and (with the old whole-batch-reject Append) the rest of the merge too.
func writeScrapingStagingFile(app *appctx.AppContext, toolName string, candidates []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("scraping %s: mkdir inputs/: %w", toolName, err)
	}
	stagingPath := filepath.Join(inputsDir, "resolved."+toolName+".txt")

	// F3 (phase 15): write-or-REMOVE via output.StageLines. Calling this asserts
	// "this scraping source RAN and found exactly these candidates", so a
	// zero-result run clears the previous run's file instead of leaving it for
	// MergeAllSubdomains (which globs inputs/resolved.*.txt) to republish.
	if err := output.StageLines(stagingPath, candidates); err != nil {
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

// Run executes analyticsrelationships against the target, parses the output via
// analytics.Extract, and writes candidate domains as SubdomainRecord JSON
// lines to inputs/resolved.analytics.txt.
//
// CLI contract (verified against the installed binary): the tool is
// `analyticsrelationships -u <URL> [--chain-mode]`. There is NO -d flag —
// passing `-d <domain>` prints usage and exits 2, which previously aborted the
// whole resolve stage. `--chain-mode` is required so stdout is undecorated
// (one bare related-domain per line) instead of the banner/">> "/"|__ "
// decorations that analytics.Extract cannot parse.
//
// The tool also panics (exit 2) on transient builtwith.com server errors even
// with valid args, so a non-zero exit is treated as a non-fatal degrade: log a
// warning and write whatever (possibly empty) candidate set was parsed. The
// task never returns StatusErrored for a tool failure — it is an independent
// best-effort discovery source (see the resolve-stage failure-policy split).
func (SubAnalyticsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "analytics"
	domain := app.Target.Domain
	targetURL := "https://" + domain

	res, err := app.Tools.Run(ctx, "analyticsrelationships", []string{"-u", targetURL, "--chain-mode"})
	var stdout []byte
	if err != nil {
		if app.Log != nil {
			app.Log.Warn("analytics: analyticsrelationships failed (non-fatal)", "error", err.Error())
		}
	} else {
		stdout = res.Stdout
	}

	results, _ := analytics.Extract(stdout, domain)
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

// scrapingSubjsInput returns the workspace URLs to hand subjs, and the number of
// scheme-less entries dropped.
//
// v1's sub_scraping pipes webs_all.txt — httpx's scheme-bearing URL list — into
// subjs (web.sh). The v2 equivalent is artefacts/hosts.jsonl's "url" field,
// which HTTPXTask writes from httpx's own JSONL output, with urls.jsonl as a
// second source.
//
// Scheme-less entries are COUNTED AND DROPPED rather than repaired: subjs
// fetches each line, and a bare host is not something to guess a scheme for.
func scrapingSubjsInput(app *appctx.AppContext) (urls []string, droppedNoScheme int) {
	seen := make(map[string]struct{})
	for _, src := range []string{"hosts.jsonl", "urls.jsonl"} {
		path := filepath.Join(app.Target.WorkDir, "artefacts", src)
		f, err := os.Open(path) //nolint:gosec // within WorkDir
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			raw := line
			if strings.HasPrefix(line, "{") {
				var rec struct {
					URL string `json:"url"`
				}
				if json.Unmarshal([]byte(line), &rec) != nil || rec.URL == "" {
					continue
				}
				raw = rec.URL
			}
			u, uErr := url.Parse(raw)
			if uErr != nil || u.Scheme == "" || u.Host == "" {
				droppedNoScheme++
				continue
			}
			if _, ok := seen[raw]; ok {
				continue
			}
			seen[raw] = struct{}{}
			urls = append(urls, raw)
		}
		_ = f.Close()
	}
	return urls, droppedNoScheme
}
