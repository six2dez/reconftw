// ssti.go — SSTITask: TInjA / SSTImap engine-switch SSTI scanner (VULN-05).
//
// SSTITask reads inputs/gf/ssti.txt produced by GFTask, passes each URL
// through a qsreplace FUZZ pipeline to generate one-param-at-a-time candidates,
// then dispatches to either TInjA (default) or SSTImap depending on
// cfg.Vulns.SSTI.Engine. Findings are stored in inputs/findings.ssti.jsonl.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — reads inputs/gf/ssti.txt bucket.
//
// ENGINE SELECTION (Claude's Discretion, 06-CONTEXT.md §SSTI engine selection):
//
//	cfg.Vulns.SSTI.Engine == "TInjA"   (default) → run TInjA url subcommand
//	cfg.Vulns.SSTI.Engine == "SSTImap" → run SSTImap via python3 sstimap.py
//
// TInjA ARG VECTOR (v1 vulns.sh:461-468):
//
//	TInjA url --reportpath <dir>/ --ratelimit <r> --timeout <t> --verbosity 0
//	         [-H <header>] [--url <u1>] [--url <u2>] ...
//
// SSTImap ARG VECTOR (v1 vulns.sh:438-449):
//
//	python3 <sstimap_dir>/sstimap.py --level <l> --no-color [--legacy]
//	        [--generic] [--delay <d>] [-H <header>] --load-urls <tmpfile>
//
// PAYLOAD REDACTION (XCUT-07, T-06-04-02):
// SSTI confirmation output may contain template evaluation results (e.g., "49"
// from {{7*7}}). MUST NEVER be logged. Only "confirmed/not" count at Info.
// PayloadRedacted and PoCRedacted are always "***" in every VulnFindingRecord.
//
// RATE LIMITING / DELAY (D-V6 / T-06-04-03 DoS mitigation):
// TInjA: cfg.Advanced.Tools.TInjA.RateLimit (default 0 = unlimited; omit -r),
//
//	cfg.Advanced.Tools.TInjA.Timeout (default 15s).
//
// SSTImap: cfg.Advanced.Tools.SSTImap.Level (default 1),
//
//	cfg.Advanced.Tools.SSTImap.Delay (default 0 = no delay; omit when 0),
//	cfg.Advanced.Tools.SSTImap.Legacy,
//	cfg.Advanced.Tools.SSTImap.Generic.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-04-PLAN.md Task 2.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// SSTITask runs the TInjA or SSTImap SSTI scanner for VULN-05.
type SSTITask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SSTITask) Name() string { return "vulns.ssti" }

// Module returns the owning module group.
func (t *SSTITask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *SSTITask) Description() string {
	return "SSTI scanner (TInjA or SSTImap per config)"
}

// Enabled reports whether SSTI scanning is configured.
func (t *SSTITask) Enabled(cfg *config.Config) bool { return cfg.Vulns.SSTI.Enabled }

// DependsOn returns the DAG edges — SSTITask reads gf/ssti.txt from GFTask.
func (t *SSTITask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the SSTI scan pipeline.
//
// Steps:
//  1. Read inputs/gf/ssti.txt — skip if empty.
//  2. qsreplace FUZZ in pure Go: for each URL with params, emit per-param variants;
//     keep only URLs containing "FUZZ"; write inputs/tmp_ssti.txt.
//  3. Deep-limit gate: skip if URL count > DeepLimit and !Deep.
//  4. Dispatch to TInjA or SSTImap based on cfg.Vulns.SSTI.Engine.
//  5. Parse engine output for SSTI confirmation (XCUT-07: never log payloads).
//  6. Write inputs/findings.ssti.jsonl via output.WriteJSONL.
func (t *SSTITask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg

	// Step 1: Read inputs/gf/ssti.txt bucket.
	gfBucket := filepath.Join(app.Target.WorkDir, "inputs", "gf", "ssti.txt")
	bucketData, err := os.ReadFile(gfBucket) //nolint:gosec // path within WorkDir
	if err != nil || len(bytes.TrimSpace(bucketData)) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.ssti: gf/ssti bucket empty — SSTI skipped", "bucket", gfBucket)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.ssti: mkdir inputs/: %w", err)
	}

	// Step 2: qsreplace FUZZ in pure Go — one variant per param, filter to FUZZ lines.
	// Mirrors v1: qsreplace "FUZZ" <gf/ssti.txt | sed '/FUZZ/!d' | anew -q .tmp/tmp_ssti.txt
	fuzzLines := sstiReplaceParams(bucketData)
	if len(fuzzLines) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.ssti: no FUZZ candidates after qsreplace — SSTI skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Write inputs/tmp_ssti.txt for SSTImap --load-urls and inspection.
	tmpSSTIFile := filepath.Join(inputsDir, "tmp_ssti.txt")
	if wErr := os.WriteFile(tmpSSTIFile,
		[]byte(strings.Join(fuzzLines, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.ssti: write tmp_ssti.txt: %w", wErr)
	}

	// Step 3: Deep-limit gate (mirrors v1 vulns.sh:424).
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 500 // v1 DEEP_LIMIT default
	}
	if !cfg.Advanced.Deep && len(fuzzLines) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.ssti: too many URLs — skipped (use --deep to override)",
				"url_count", len(fuzzLines), "deep_limit", deepLimit)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 4: Resolve engine and dispatch.
	engine := cfg.Vulns.SSTI.Engine
	if engine == "" {
		engine = "TInjA" // default (D-V6 / 06-CONTEXT.md §SSTI engine selection)
	}

	var findings []VulnFindingRecord
	var scanErr error

	switch engine {
	case "SSTImap":
		findings, scanErr = runSSTImap(ctx, app, tmpSSTIFile, cfg)
	default:
		// "TInjA" or any unrecognised value → TInjA (safe fallback).
		engine = "TInjA"
		findings, scanErr = runTInjA(ctx, app, fuzzLines, cfg)
	}

	if scanErr != nil && app.Log != nil {
		app.Log.Debug("vulns.ssti: engine error (best_effort)", "engine", engine, "err", scanErr)
	}

	// Step 6: Write inputs/findings.ssti.jsonl.
	if len(findings) > 0 {
		var lines [][]byte
		for _, rec := range findings {
			b, mErr := json.Marshal(rec)
			if mErr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			stagingPath := filepath.Join(inputsDir, "findings.ssti.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.ssti: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	// XCUT-07 (T-06-04-02): log only count; NEVER log template evaluation results
	// (e.g., "49" from {{7*7}}).
	if app.Log != nil {
		app.Log.Info("vulns.ssti: completed", "engine", engine, "findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"ssti_findings": len(findings)},
	}, nil
}

// runTInjA runs TInjA with the url subcommand for all FUZZ candidates.
//
// v1 arg vector (modules/vulns.sh:461-468):
//
//	TInjA url --reportpath <dir>/ --ratelimit <r> --timeout <t> --verbosity 0
//	         [-H <header>] [--url <u1>] [--url <u2>] ...
//
// Confirmation parsing: TInjA writes a JSONL report to the reportpath.
// We parse it for isWebpageVulnerable==true or any parameter where
// isParameterVulnerable==true (v1 jq filter vulns.sh:477-479).
//
// XCUT-07 (T-06-04-02): TInjA output may contain template eval results.
// NEVER log at Info/Warn. Only confirmed count at Debug.
func runTInjA(ctx context.Context, app *appctx.AppContext,
	fuzzLines []string, cfg *config.Config,
) ([]VulnFindingRecord, error) {
	const toolName = "TInjA"

	rateLimit := cfg.Advanced.Tools.TInjA.RateLimit
	timeout := cfg.Advanced.Tools.TInjA.Timeout
	if timeout <= 0 {
		timeout = 15 // v1 TInjA_TIMEOUT default
	}
	header := cfg.Advanced.Header

	// Create report dir inside inputs/ so it stays within WorkDir.
	reportDir := filepath.Join(app.Target.WorkDir, "inputs", "TInjA_reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return nil, fmt.Errorf("vulns.ssti: mkdir TInjA_reports: %w", err)
	}

	// v1 TInjA arg vector: url subcommand + all --url flags in one invocation.
	args := []string{
		"url",
		"--reportpath", reportDir + "/",
		"--timeout", strconv.Itoa(timeout),
		"--verbosity", "0",
	}
	if rateLimit > 0 {
		args = append(args, "--ratelimit", strconv.Itoa(rateLimit))
	}
	if header != "" {
		args = append(args, "-H", header)
	}
	// Append all URLs as --url flags (v1 pattern: while read u; TInjA_cmd+=(--url "$u")).
	for _, u := range fuzzLines {
		u = strings.TrimSpace(u)
		if u != "" {
			args = append(args, "--url", u)
		}
	}

	// Run TInjA. TInjA is fast enough to use Run (not Stream) for small URL
	// sets; use Stream to provide XCUT-09 heartbeat for larger sets.
	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	if streamErr != nil {
		return nil, fmt.Errorf("vulns.ssti: TInjA stream error: %w", streamErr)
	}

	// Drain stream — Backend contract requires full drain.
	// XCUT-07 (T-06-04-02): NEVER log raw TInjA stdout (template eval results).
	for range eventCh { //nolint:revive // intentional drain — template eval not logged
	}

	// Parse TInjA JSONL report(s) from reportDir.
	return parseTInjAReports(reportDir, app)
}

// tinjAReport is the TInjA JSONL report structure (simplified — fields we parse).
// Full structure per v1 jq filter (vulns.sh:477): isWebpageVulnerable,
// url, certainty, parameters[].isParameterVulnerable.
type tinjAReport struct {
	URL                 string           `json:"url"`
	IsWebpageVulnerable bool             `json:"isWebpageVulnerable"`
	Certainty           string           `json:"certainty"`
	Parameters          []tinjAParameter `json:"parameters"`
}

type tinjAParameter struct {
	IsParameterVulnerable bool `json:"isParameterVulnerable"`
}

// parseTInjAReports reads all JSONL files in reportDir, parses for vulnerability
// confirmation, and returns VulnFindingRecord slice.
//
// XCUT-07 (T-06-04-02): certainty string and URL may appear in TInjA output;
// we only log the hostname (not the full URL or certainty expression).
func parseTInjAReports(reportDir string, app *appctx.AppContext) ([]VulnFindingRecord, error) {
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		return nil, fmt.Errorf("parseTInjAReports: readdir %q: %w", reportDir, err)
	}

	var records []VulnFindingRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		fpath := filepath.Join(reportDir, e.Name())
		data, rerr := os.ReadFile(fpath) //nolint:gosec // path within WorkDir
		if rerr != nil || len(data) == 0 {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var rep tinjAReport
			if err := json.Unmarshal(line, &rep); err != nil {
				continue
			}
			// Confirm: isWebpageVulnerable OR any parameter isParameterVulnerable.
			confirmed := rep.IsWebpageVulnerable
			if !confirmed {
				for _, p := range rep.Parameters {
					if p.IsParameterVulnerable {
						confirmed = true
						break
					}
				}
			}
			if !confirmed {
				continue
			}

			// XCUT-07: extract host only — never write raw URL or template result.
			host := sstiExtractHost(rep.URL)
			if app.Log != nil {
				// XCUT-07: only log the hostname, not the certainty string or URL.
				app.Log.Debug("vulns.ssti: TInjA SSTI confirmed", "host", host)
			}
			records = append(records, VulnFindingRecord{
				// Phase 4/5 inherited SARIF-compatible fields.
				Severity:   "critical",
				Confidence: "high",
				// Phase 6 vuln-class fields.
				VulnClass:       "ssti",
				MatchedParam:    host,  // hostname only — no raw payload (XCUT-07)
				PayloadRedacted: "***", // XCUT-07: raw SSTI payload never written
				PoCRedacted:     "***", // XCUT-07: template eval result never written
				Engine:          "TInjA",
			})
		}
	}
	return records, nil
}

// runSSTImap runs SSTImap via python3 sstimap.py with --load-urls for all
// FUZZ candidates.
//
// v1 arg vector (modules/vulns.sh:438-449):
//
//	python3 <sstimap_dir>/sstimap.py --level <l> --no-color [--legacy]
//	        [--generic] [--delay <d>] [-H <header>] --load-urls <tmpfile>
//
// SSTImap path is sourced from cfg.Paths.DataDir+"/../tools/SSTImap" as the
// canonical v2 tool installation path (T-06-04-04 — sstiMapPath sourced from
// trusted config, not user input). Falls back to "sstimap.py" on PATH if
// configured path is absent (best_effort).
//
// XCUT-07 (T-06-04-02): SSTImap stdout may contain template evaluation probes
// and results. NEVER log raw output at Info/Warn. Only count at Info.
func runSSTImap(ctx context.Context, app *appctx.AppContext,
	tmpSSTIFile string, cfg *config.Config,
) ([]VulnFindingRecord, error) {
	// Locate SSTImap installation (T-06-04-04 — trusted config path, not user input).
	sstiMapScript, sstiMapPython, found := resolveSSTImapPath(cfg)

	level := cfg.Advanced.Tools.SSTImap.Level
	if level <= 0 {
		level = 1 // v1 SSTIMAP_LEVEL default
	}
	delay := cfg.Advanced.Tools.SSTImap.Delay
	legacy := cfg.Advanced.Tools.SSTImap.Legacy
	generic := cfg.Advanced.Tools.SSTImap.Generic
	header := cfg.Advanced.Header

	var toolName string
	var args []string

	if found {
		// SSTImap installed in canonical path — use venv python3.
		toolName = sstiMapPython
		args = []string{
			sstiMapScript,
			"--level", strconv.Itoa(level),
			"--no-color",
		}
	} else {
		// Fallback: invoke sstimap directly if on PATH (best_effort).
		toolName = "sstimap"
		args = []string{
			"--level", strconv.Itoa(level),
			"--no-color",
		}
		if app.Log != nil {
			app.Log.Debug("vulns.ssti: SSTImap canonical path not found — trying PATH fallback")
		}
	}

	if legacy {
		args = append(args, "--legacy")
	}
	if generic {
		args = append(args, "--generic")
	}
	if delay > 0 {
		args = append(args, "--delay", strconv.Itoa(delay))
	}
	if header != "" {
		args = append(args, "-H", header)
	}
	args = append(args, "--load-urls", tmpSSTIFile)

	// XCUT-09: Backend.Stream for heartbeat (SSTImap can run >5 min on large input).
	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	if streamErr != nil {
		return nil, fmt.Errorf("vulns.ssti: SSTImap stream error: %w", streamErr)
	}

	// Drain stream; parse for confirmation indicators.
	// XCUT-07 (T-06-04-02): SSTImap output may contain template eval results (e.g.,
	// "49" from {{7*7}}). NEVER log raw lines at Info/Warn.
	var confirmedURLs []string
	for ev := range eventCh {
		line := strings.ToLower(string(ev.Line))
		// SSTImap prints "confirmed" or "identified" on SSTI confirmation.
		// Extract only the URL from the line for XCUT-07-safe storage.
		if strings.Contains(line, "confirmed") || strings.Contains(line, "identified") {
			if app.Log != nil {
				// XCUT-07: never log the raw confirmation line (may contain eval result).
				app.Log.Debug("vulns.ssti: SSTImap confirmation indicator detected")
			}
			// Extract URL from the line (SSTImap prints "URL: http://..." on confirm).
			// We parse the raw (not lowercased) event line for URL extraction.
			rawLine := strings.TrimSpace(string(ev.Line))
			if u := extractSSTImapURL(rawLine); u != "" {
				confirmedURLs = append(confirmedURLs, u)
			} else {
				// Confirmation detected but URL extraction failed — still record a finding.
				confirmedURLs = append(confirmedURLs, "")
			}
		}
	}

	if len(confirmedURLs) == 0 {
		return nil, nil
	}

	var records []VulnFindingRecord
	for _, rawURL := range confirmedURLs {
		host := sstiExtractHost(rawURL)
		records = append(records, VulnFindingRecord{
			// Phase 4/5 inherited SARIF-compatible fields.
			Severity:   "critical",
			Confidence: "high",
			// Phase 6 vuln-class fields.
			VulnClass:       "ssti",
			MatchedParam:    host,  // hostname only — no raw payload (XCUT-07)
			PayloadRedacted: "***", // XCUT-07: raw SSTI payload never written
			PoCRedacted:     "***", // XCUT-07: template eval result never written
			Engine:          "SSTImap",
		})
	}
	return records, nil
}

// resolveSSTImapPath locates the SSTImap script and venv python3.
//
// Canonical installation path (T-06-04-04 — sourced from trusted config):
//   - cfg.Paths.DataDir/../tools/SSTImap/sstimap.py (script)
//   - cfg.Paths.DataDir/../tools/SSTImap/venv/bin/python3 (venv python)
//
// Returns (scriptPath, pythonPath, found). If found==false, the caller should
// fall back to invoking "sstimap" directly from PATH.
func resolveSSTImapPath(cfg *config.Config) (scriptPath, pythonPath string, found bool) {
	// Derive tools base dir from DataDir (mirrors v1 $tools var).
	dataDir := cfg.Paths.DataDir
	if dataDir == "" {
		return "", "", false
	}
	// v1 $tools is adjacent to $SCRIPTPATH (typically $HOME/Tools or similar).
	// In v2, DataDir stores reconftw state; tools are relative to its parent.
	// Best-effort: try DataDir/../tools/SSTImap/.
	toolsDir := filepath.Join(filepath.Dir(dataDir), "tools")
	script := filepath.Join(toolsDir, "SSTImap", "sstimap.py")
	python := filepath.Join(toolsDir, "SSTImap", "venv", "bin", "python3")

	if _, err := os.Stat(script); err != nil {
		return "", "", false
	}
	if _, err := os.Stat(python); err != nil {
		// Script exists but venv python absent — return script path only;
		// caller can try "python3 <script>" with system python3.
		return script, "python3", true
	}
	return script, python, true
}

// sstiReplaceParams implements qsreplace FUZZ in pure Go for the SSTI pipeline.
//
// For each URL with query params, emits one variant per parameter with all
// parameter values replaced by "FUZZ". Keeps only variants that contain "FUZZ"
// (mirrors v1: qsreplace FUZZ | sed '/FUZZ/!d').
//
// Note: unlike LFI's per-param replacement (one param at a time), SSTI uses
// qsreplace which replaces ALL param values with FUZZ in one pass — matching
// v1 vulns.sh:420 which runs qsreplace once (not per-param).
func sstiReplaceParams(data []byte) []string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	seen := make(map[string]struct{})
	var lines []string

	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		parsed, pErr := parseURLForSSTI(raw)
		if pErr != nil || parsed == "" {
			continue
		}
		if !strings.Contains(parsed, "FUZZ") {
			continue
		}
		if _, exists := seen[parsed]; !exists {
			seen[parsed] = struct{}{}
			lines = append(lines, parsed)
		}
	}
	return lines
}

// parseURLForSSTI replaces all query parameter values with "FUZZ" in a URL
// (mirrors qsreplace FUZZ for SSTI).
func parseURLForSSTI(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.RawQuery == "" {
		return "", nil // no query params → not a FUZZ candidate
	}
	vals := u.Query()
	for k := range vals {
		vals[k] = []string{"FUZZ"}
	}
	u.RawQuery = vals.Encode()
	return u.String(), nil
}

// extractSSTImapURL tries to extract a URL from a SSTImap confirmation line.
// SSTImap typically prints "URL: http://..." or includes the URL in the line.
// Returns "" if extraction fails (best_effort — XCUT-07: raw line never stored).
func extractSSTImapURL(line string) string {
	// Look for "http://" or "https://" in the confirmation line.
	for _, prefix := range []string{"https://", "http://"} {
		idx := strings.Index(line, prefix)
		if idx < 0 {
			continue
		}
		rest := line[idx:]
		// Trim at first whitespace.
		if end := strings.IndexAny(rest, " \t\r\n"); end >= 0 {
			rest = rest[:end]
		}
		return rest
	}
	return ""
}

// sstiExtractHost extracts the hostname from a URL for XCUT-07-safe record storage.
// The full URL with SSTI payload is never written to any VulnFindingRecord.
func sstiExtractHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers SSTITask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&SSTITask{}) }
