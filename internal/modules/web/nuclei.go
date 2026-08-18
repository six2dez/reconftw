// nuclei.go — NucleiTask: templated scanner → artefacts/findings.jsonl.
//
// NucleiTask runs nuclei against probed hosts, writes findings to the
// SARIF-compatible findings.jsonl artefact (unchanged schema from Phase 4).
//
// DEPENDENCY (D-W12): DependsOn ["web.httpx", "web.wafw00f"] so that
// waf.jsonl exists for WAF rate-halving (v1 web.sh:969→1149 sequencing).
// best_effort: a disabled/empty wafw00f still lets nuclei run — the step-b
// fallback runs all hosts at normal rate when waf.jsonl is absent or empty.
//
// WAF RATE-HALVING (web.sh:1121 behaviour preserved):
// WAF hosts detected in artefacts/waf.jsonl run at rl = NucleiRateLimit/3.
// Non-WAF hosts run at rl = NucleiRateLimit (default 150).
//
// ARG VECTOR (RESEARCH §nuclei — verbatim v1 form):
//
//	nuclei -l <hostsfile> -severity <sev> -nh -rl <n> -silent -retries 2
//	       -t <templates> -j -o <stagingFile>
//
// T-05-04 mitigation: nuclei stdout routed to run.log via app.Tools.Stream;
// never logged at INFO terminal (GAP-3 pattern).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-02-PLAN.md Task 1.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// nucleiLine is the subset of nuclei JSONL output fields we parse.
// Source: RESEARCH §Code Examples: nucleiLine struct.
type nucleiLine struct {
	TemplateID  string `json:"template-id"`
	MatcherName string `json:"matcher-name"`
	Type        string `json:"type"`
	Info        struct {
		Severity string `json:"severity"`
	} `json:"info"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Host             string   `json:"host"`
}

// FindingRecord is the SARIF-compatible findings.jsonl schema for Phase 5.
// Extends the Phase-4 TakeoverRecord shape with nuclei-specific fields.
// D-W11: findings.jsonl schema is UNCHANGED (extends Phase 4, never removes).
type FindingRecord struct {
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	TemplateID       string   `json:"template_id,omitempty"`
	MatcherName      string   `json:"matcher_name,omitempty"`
	Severity         string   `json:"severity"`
	MatchedAt        string   `json:"matched_at,omitempty"`
	ExtractedResults []string `json:"extracted_results,omitempty"`
	Confidence       string   `json:"confidence"`
	Service          string   `json:"service,omitempty"`
	Refs             []string `json:"refs"`
}

// NucleiTask runs nuclei and writes SARIF-compatible findings to
// artefacts/findings.jsonl.
type NucleiTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *NucleiTask) Name() string { return "web.nuclei" }

// Module returns the owning module group.
func (t *NucleiTask) Module() string { return "web" }

// Description returns a human-readable one-line description.
func (t *NucleiTask) Description() string { return "Nuclei templated scanner (findings.jsonl)" }

// Enabled reports whether this task should run.
func (t *NucleiTask) Enabled(cfg *config.Config) bool { return cfg.Web.Nuclei.Enabled }

// DependsOn returns the DAG edges. Depends on web.httpx (input) and
// web.wafw00f (WAF rate-halving). best_effort: wafw00f absence is handled
// via the step-b fallback in Run.
func (t *NucleiTask) DependsOn() []string { return []string{"web.httpx", "web.wafw00f"} }

// Run executes nuclei against probed hosts and writes findings to
// artefacts/findings.jsonl via app.Tree.Append.
func (t *NucleiTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "nuclei"
	cfg := app.Cfg

	// Resolve templates path from config: cfg.Web.Nuclei.TemplatesPath falls
	// back to cfg.Paths.NucleiTemplates (ADR §2 legacy alias pattern).
	templatesPath := cfg.Web.Nuclei.TemplatesPath
	if templatesPath == "" {
		templatesPath = cfg.Paths.NucleiTemplates
	}

	// Pitfall 3: check templates path before invoking nuclei.
	if templatesPath == "" {
		if app.Log != nil {
			app.Log.Info("web.nuclei: templates path not configured — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if _, err := os.Stat(templatesPath); err != nil {
		if app.Log != nil {
			app.Log.Info("web.nuclei: templates path not accessible — skipping",
				"path", templatesPath, "err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read all probed hosts from artefacts/hosts.jsonl.
	allHosts, err := readHostURLsFromJSONL(app)
	if err != nil || len(allHosts) == 0 {
		if app.Log != nil {
			app.Log.Info("web.nuclei: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read WAF hosts from artefacts/waf.jsonl (step-b fallback: none if absent).
	wafHosts := readWAFHostsSet(app)

	// Prepare host file directories.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.nuclei: mkdir inputs/: %w", err)
	}
	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.nuclei: mkdir artefacts/: %w", err)
	}

	// Rate limits.
	rl := cfg.Web.Nuclei.RateLimit
	if rl <= 0 {
		rl = 150 // v1 default NUCLEI_RATELIMIT
	}
	wafRL := rl / 3

	// Severity.
	severity := cfg.Web.Nuclei.Severity
	if severity == "" {
		severity = "info,low,medium,high,critical"
	}

	// Extra args.
	var extraArgs []string
	if cfg.Web.Nuclei.ExtraArgs != "" {
		extraArgs = strings.Fields(cfg.Web.Nuclei.ExtraArgs)
	}

	// Separate WAF hosts from normal hosts.
	var normalHosts, wafHostList []string
	for _, h := range allHosts {
		if len(wafHosts) > 0 {
			if _, isWAF := wafHosts[normalizeHost(h)]; isWAF {
				wafHostList = append(wafHostList, h)
				continue
			}
		}
		normalHosts = append(normalHosts, h)
	}

	var allFindings []FindingRecord

	// Run nuclei for normal hosts.
	if len(normalHosts) > 0 {
		findings, err := runNucleiGroup(ctx, app, toolName, normalHosts,
			severity, rl, templatesPath, extraArgs, "normal", inputsDir, artefactsDir)
		if err != nil && app.Log != nil {
			app.Log.Debug("web.nuclei: normal group error", "err", err)
		}
		allFindings = append(allFindings, findings...)
	}

	// Run nuclei for WAF hosts at reduced rate (web.sh:1121 behaviour).
	if len(wafHostList) > 0 {
		findings, err := runNucleiGroup(ctx, app, toolName, wafHostList,
			severity, wafRL, templatesPath, extraArgs, "waf", inputsDir, artefactsDir)
		if err != nil && app.Log != nil {
			app.Log.Debug("web.nuclei: waf group error", "err", err)
		}
		allFindings = append(allFindings, findings...)
	}

	// Stage findings into inputs/findings.nuclei.jsonl (staging contract).
	// MergeAllWebArtefacts is the single app.Tree.Append caller for findings.
	//
	// F3 (phase 15): staged UNCONDITIONALLY — StageJSONL removes the staging
	// file when this scan produced no findings, so a remediated vulnerability
	// from a previous run cannot reappear in the merged findings artefact.
	// Reaching here means nuclei RAN; every "not configured / no hosts" path
	// returns StatusSkipped above and stages nothing.
	var lines [][]byte
	for _, rec := range allFindings {
		b, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.nuclei.jsonl")
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("web.nuclei: staging write failed",
			"path", stagingPath, "err", wErr)
	}

	if app.Log != nil {
		app.Log.Debug("web.nuclei: completed", "findings", len(allFindings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(allFindings)},
	}, nil
}

// runNucleiGroup runs nuclei for a host group, returning parsed FindingRecords.
// Uses Backend.Stream (XCUT-09 heartbeat — nuclei can run 30+ minutes).
func runNucleiGroup(ctx context.Context, app *appctx.AppContext, toolName string,
	hosts []string, severity string, rateLimit int, templatesPath string,
	extraArgs []string, groupLabel, inputsDir, artefactsDir string,
) ([]FindingRecord, error) {
	// Write hosts to a temporary input file.
	hostsFile := filepath.Join(inputsDir, "nuclei."+groupLabel+".hosts.txt")
	content := strings.Join(hosts, "\n") + "\n"
	if err := os.WriteFile(hostsFile, []byte(content), 0o644); err != nil { //nolint:gosec
		return nil, fmt.Errorf("write nuclei hosts file %s: %w", groupLabel, err)
	}

	stagingFile := filepath.Join(artefactsDir, "nuclei."+groupLabel+".jsonl.tmp")

	// Build arg vector (RESEARCH §nuclei verbatim v1 form).
	args := []string{
		"-l", hostsFile,
		"-severity", severity,
		"-nh", // no-httpx: skip probe, already probed via HTTPXTask
		"-rl", strconv.Itoa(rateLimit),
		"-silent",
		"-retries", "2",
	}
	args = append(args, extraArgs...)
	args = append(args,
		"-t", templatesPath,
		"-j",              // JSONL output
		"-o", stagingFile, // write to staging file
	)

	// Use Backend.Stream for XCUT-09 heartbeat (T-05-04 mitigation: raw
	// nuclei output routed to run.log via stream drain, never to terminal).
	eventCh, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		return nil, fmt.Errorf("nuclei stream %s: %w", groupLabel, err)
	}
	// Drain stream (Backend contract: caller MUST drain until closed).
	for range eventCh { //nolint:revive // intentional drain
	}

	// Parse staging file.
	data, err := os.ReadFile(stagingFile) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no findings produced
		}
		return nil, fmt.Errorf("read nuclei staging %s: %w", groupLabel, err)
	}

	return parseNucleiOutput(data), nil
}

// parseNucleiOutput parses nuclei JSONL output into FindingRecord slice.
// Lines that fail to parse are silently skipped (passive parsing).
func parseNucleiOutput(data []byte) []FindingRecord {
	if len(data) == 0 {
		return nil
	}
	var records []FindingRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var nl nucleiLine
		if err := json.Unmarshal(line, &nl); err != nil {
			continue
		}
		refs := nl.ExtractedResults
		if refs == nil {
			refs = []string{}
		}
		records = append(records, FindingRecord{
			Type: "nuclei-finding",
			// normalizeHost, not nl.Host raw: nuclei reports the full origin
			// for HTTP templates ("https://target.example.com"), and the
			// findings scope gate matches host values as hostnames — a raw
			// origin is rejected and takes the whole merged batch with it.
			Host:             normalizeHost(nl.Host),
			TemplateID:       nl.TemplateID,
			MatcherName:      nl.MatcherName,
			Severity:         nl.Info.Severity,
			MatchedAt:        nl.MatchedAt,
			ExtractedResults: nl.ExtractedResults,
			Confidence:       "high",
			Refs:             refs,
		})
	}
	return records
}

// readHostURLsFromJSONL reads artefacts/hosts.jsonl and returns the list of
// host URLs for nuclei input (url field from D-W11 HostRecord schema).
func readHostURLsFromJSONL(app *appctx.AppContext) ([]string, error) {
	hostsPath := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	data, err := os.ReadFile(hostsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read hosts.jsonl: %w", err)
	}
	var hosts []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			URL  string `json:"url"`
			Host string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		h := rec.URL
		if h == "" {
			h = rec.Host
		}
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

// readWAFHostsSet reads artefacts/waf.jsonl and returns a set of WAF hosts
// (keyed by normalised host string). Returns empty map when file is absent.
func readWAFHostsSet(app *appctx.AppContext) map[string]struct{} {
	wafPath := filepath.Join(app.Target.WorkDir, "artefacts", "waf.jsonl")
	data, err := os.ReadFile(wafPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return map[string]struct{}{} // step-b fallback: treat as no WAF data
	}
	set := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err == nil && rec.Host != "" {
			set[normalizeHost(rec.Host)] = struct{}{}
		}
	}
	return set
}

// normalizeHost strips scheme, path, and port from a URL/host string for WAF
// set lookup.
//
// IN-04: kept byte-for-byte behavior-equivalent to extract/waf.normalizeHost
// (waf.go:131) — including port stripping with an IPv6 guard. nuclei keys the
// WAF-host set produced from waf.jsonl with this function; if those two
// implementations diverged on port handling, WAF rate-halving would
// mis-classify any host that ever carried an explicit port. (waf records are
// port-free today, so this aligns behavior pre-emptively rather than fixing a
// present bug; the two functions live in different packages, so they are not
// yet consolidated into one shared helper.)
func normalizeHost(h string) string {
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if idx := strings.IndexByte(h, '/'); idx >= 0 {
		h = h[:idx]
	}
	// Strip port (IPv6 guard: only strip when the remaining host has no other
	// colon, i.e. it is not a bare IPv6 literal).
	if idx := strings.LastIndex(h, ":"); idx >= 0 {
		if !strings.Contains(h[:idx], ":") {
			h = h[:idx]
		}
	}
	return strings.ToLower(h)
}

// init self-registers NucleiTask with the Default task registry.
func init() { task.Register(&NucleiTask{}) }
