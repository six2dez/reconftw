// sqli.go — SQLiTask: dual-engine sqlmap + ghauri SQL injection scanner (VULN-02).
//
// SQLiTask reads inputs/gf/sqli.txt produced by GFTask, runs the URL set
// through a qsreplace FUZZ pipeline, then dispatches to sqlmap (default-on)
// and/or ghauri (default-off) based on per-engine config flags (D-V6).
//
// DEPENDENCY: DependsOn ["vulns.gf"] — reads inputs/gf/sqli.txt bucket.
//
// ENGINE SELECTION (D-V6 conservative defaults):
//
//	cfg.Vulns.SQLi.SQLMap (default true)  — run sqlmap
//	cfg.Vulns.SQLi.Ghauri (default false) — run ghauri (opt-in)
//
// At least one engine must be enabled, else StatusSkipped.
//
// DEEP LIMIT GATE (T-06-03-03):
// If URL count > cfg.Advanced.DeepLimit and !cfg.Advanced.Deep → StatusSkipped.
// Mirrors v1 sqli() DEEP_LIMIT check (vulns.sh:528-529).
//
// ARG VECTOR (v1 vulns.sh:533-534 verbatim):
//
//	sqlmap: python3 ${tools}/sqlmap/sqlmap.py -m <tmpFile> -b -o --smart
//	        --batch --disable-coloring --random-agent --output-dir=<dir>
//	ghauri: ghauri -u <url> --batch -H <header> --force-ssl
//
// PAYLOAD REDACTION (XCUT-07, T-06-03-01):
// sqlmap/ghauri stdout contains raw SQL payloads — NEVER logged at Info/Warn.
// PayloadRedacted and PoCRedacted are always "***" in every VulnFindingRecord.
//
// HEARTBEAT (XCUT-09):
// Backend.Stream used for BOTH sqlmap and ghauri — sqlmap can run for hours
// per URL set against complex targets; ghauri per URL can run >10 min.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-03-PLAN.md Task 1.
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
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// SQLiTask runs the dual-engine sqlmap + ghauri SQLi scanner for VULN-02.
type SQLiTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SQLiTask) Name() string { return "vulns.sqli" }

// Module returns the owning module group.
func (t *SQLiTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *SQLiTask) Description() string {
	return "SQL injection scanner (sqlmap + ghauri dual-engine)"
}

// Enabled reports whether SQLi scanning is configured.
func (t *SQLiTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.SQLi.Enabled }

// DependsOn returns the DAG edges — SQLiTask reads gf/sqli.txt from GFTask.
func (t *SQLiTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the sqlmap and/or ghauri SQLi scan pipeline.
//
// Steps:
//  1. Check engine selection — at least one of sqlmap/ghauri must be enabled.
//  2. Read inputs/gf/sqli.txt — skip if empty (no sqli gf candidates).
//  3. qsreplace FUZZ pipeline: pipe through qsreplace FUZZ; filter "FUZZ" lines;
//     write to inputs/tmp_sqli.txt.
//  4. Deep-limit gate (T-06-03-03): skip if URL count > DeepLimit and !Deep.
//  5. If SQLMapEnabled: Stream sqlmap with -m flag; drain; parse sqlmapOutDir.
//  6. If GhauriEnabled: for each URL, Stream ghauri; drain; parse output lines.
//  7. Write inputs/findings.sqli.jsonl via output.WriteJSONL.
func (t *SQLiTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg

	// Step 1: Engine selection — at least one must be enabled (D-V6 / T-06-03-03).
	sqlmapEnabled := cfg.Vulns.SQLi.SQLMap
	ghauriEnabled := cfg.Vulns.SQLi.Ghauri
	if !sqlmapEnabled && !ghauriEnabled {
		if app.Log != nil {
			app.Log.Info("vulns.sqli: no engine enabled (sqlmap=false, ghauri=false) — SQLi skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 2: Read gf/sqli.txt bucket.
	gfBucket := filepath.Join(app.Target.WorkDir, "inputs", "gf", "sqli.txt")
	bucketData, err := os.ReadFile(gfBucket) //nolint:gosec // path within WorkDir
	if err != nil || len(bytes.TrimSpace(bucketData)) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.sqli: gf/sqli bucket empty — SQLi skipped",
				"bucket", gfBucket)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.sqli: mkdir inputs/: %w", err)
	}

	// Step 3: qsreplace FUZZ pipeline — filter lines containing FUZZ.
	// v1: qsreplace "FUZZ" <gf/sqli.txt | sed '/FUZZ/!d' | anew -q .tmp/tmp_sqli.txt
	fuzzed := sqliReplaceParams(bucketData)
	var fuzzLines []string
	if len(fuzzed) > 0 {
		sc := bufio.NewScanner(bytes.NewReader(fuzzed))
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, "FUZZ") {
				fuzzLines = append(fuzzLines, line)
			}
		}
	}
	if len(fuzzLines) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.sqli: no FUZZ candidates after qsreplace — SQLi skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Write inputs/tmp_sqli.txt (the -m input file for sqlmap).
	tmpSQLiFile := filepath.Join(inputsDir, "tmp_sqli.txt")
	if wErr := os.WriteFile(tmpSQLiFile,
		[]byte(strings.Join(fuzzLines, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.sqli: write tmp_sqli.txt: %w", wErr)
	}

	// Step 4: Deep-limit gate (T-06-03-03 — DoS mitigation).
	// v1: if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 500 // v1 default DEEP_LIMIT
	}
	if !cfg.Advanced.Deep && len(fuzzLines) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.sqli: too many URLs — skipped (use --deep to override)",
				"url_count", len(fuzzLines), "deep_limit", deepLimit)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	sqlmapOutDir := filepath.Join(app.Target.WorkDir, "inputs", "sqlmap_output")
	if err := os.MkdirAll(sqlmapOutDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.sqli: mkdir sqlmap_output: %w", err)
	}

	var findings []VulnFindingRecord

	// Step 5: sqlmap (XCUT-09 — Backend.Stream heartbeat; can run hours).
	if sqlmapEnabled {
		recs, sqlmapErr := runSQLMap(ctx, app, tmpSQLiFile, sqlmapOutDir)
		if sqlmapErr != nil && app.Log != nil {
			app.Log.Debug("vulns.sqli: sqlmap error (best_effort)", "err", sqlmapErr)
		}
		findings = append(findings, recs...)
	}

	// Step 6: ghauri per-URL (XCUT-09 — Backend.Stream heartbeat per URL).
	if ghauriEnabled {
		recs, ghauriErr := runGhauriPerURL(ctx, app, fuzzLines)
		if ghauriErr != nil && app.Log != nil {
			app.Log.Debug("vulns.sqli: ghauri error (best_effort)", "err", ghauriErr)
		}
		findings = append(findings, recs...)
	}

	// Step 7: Write inputs/findings.sqli.jsonl.
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
			stagingPath := filepath.Join(inputsDir, "findings.sqli.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.sqli: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	// XCUT-07: log only count, never raw SQLi payloads.
	if app.Log != nil {
		app.Log.Info("vulns.sqli: completed", "findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"sqli_findings": len(findings)},
	}, nil
}

// runSQLMap runs sqlmap via Backend.Stream (XCUT-09) and parses the output
// directory for injection confirmations.
//
// v1 arg vector (vulns.sh:533):
//
//	python3 ${tools}/sqlmap/sqlmap.py -m <tmpFile> -b -o --smart
//	         --batch --disable-coloring --random-agent --output-dir=<dir>
//
// XCUT-07: sqlmap stdout contains raw SQL payloads — NEVER logged at Info/Warn.
func runSQLMap(ctx context.Context, app *appctx.AppContext,
	tmpSQLiFile, sqlmapOutDir string,
) ([]VulnFindingRecord, error) {
	const toolName = "sqlmap"

	// v1 arg vector verbatim (vulns.sh:533-534).
	args := []string{
		"-m", tmpSQLiFile,
		"-b",                 // banner grab
		"-o",                 // optimize (safe-union, heuristic, predict-output)
		"--smart",            // heuristic shortcuts
		"--batch",            // never prompt
		"--disable-coloring", // plain output
		"--random-agent",     // rotate user-agent
		"--output-dir", sqlmapOutDir,
	}

	// XCUT-09: Backend.Stream so UI never appears stuck (sqlmap can run hours).
	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	if streamErr != nil {
		// Non-fatal per best_effort policy.
		return nil, fmt.Errorf("vulns.sqli: sqlmap stream error: %w", streamErr)
	}

	// Drain stream — Backend contract: caller MUST drain until closed.
	// XCUT-07: each event.Line may contain raw SQL payloads; NEVER log at Info/Warn.
	var injectable int
	for ev := range eventCh {
		// Parse stream for "injectable" confirmation indicators.
		// XCUT-07: raw line content NEVER forwarded to Info/Warn logs.
		line := strings.ToLower(string(ev.Line))
		if strings.Contains(line, "injectable") || strings.Contains(line, "is vulnerable") {
			injectable++
			if app.Log != nil {
				app.Log.Debug("vulns.sqli: sqlmap injectable indicator detected")
			}
		}
	}

	// Also scan the output dir for sqlmap result files (*.log, *.csv) that
	// confirm injection. This supplements the stream count (sqlmap writes results
	// to the output-dir even when they are not printed to stdout).
	dirFindings := parseSQLMapOutputDir(sqlmapOutDir)
	if len(dirFindings) == 0 && injectable == 0 {
		return nil, nil
	}

	// Build VulnFindingRecord entries, one per injectable TARGET.
	//
	// parseSQLMapOutputDir returns the per-target subdirectory names sqlmap
	// creates, which are the target hostnames — real per-finding identity.
	// This used to take len(dirFindings) and emit that many records all
	// stamped with app.Target.Domain: an injection on shop.example.com was
	// attributed to example.com, and because the merger deduplicates by raw
	// JSON bytes, N byte-identical records collapsed into a single finding.
	newRec := func(host string) VulnFindingRecord {
		return VulnFindingRecord{
			Host:            host, // scope-gate locator
			Severity:        "critical",
			Confidence:      "high",
			VulnClass:       "sqli",
			PayloadRedacted: "***", // XCUT-07: raw SQL payload never written
			PoCRedacted:     "***", // XCUT-07: raw sqlmap PoC never written
			Engine:          "sqlmap",
		}
	}

	var records []VulnFindingRecord
	for _, target := range dirFindings {
		records = append(records, newRec(findingHost(target)))
	}

	// Fallback: sqlmap printed injectable indicators to the stream but wrote no
	// per-target output dir. That path carries NO identity, only a count, so
	// emit ONE record against the scan target rather than `injectable` copies
	// of it — identical records convey nothing extra and collapse in the merge
	// anyway. The count stays in the log.
	if len(records) == 0 && injectable > 0 {
		if app.Log != nil {
			app.Log.Debug("vulns.sqli: sqlmap stream reported injections with no "+
				"per-target output dir — recording one finding against the scan target",
				"indicators", injectable)
		}
		records = append(records, newRec(app.Target.Domain))
	}
	return records, nil
}

// parseSQLMapOutputDir scans the sqlmap output directory for injectable target
// subdirectories. sqlmap creates a subdirectory per target hostname; a
// "dump" or "log" file inside confirms exploitation/injection.
func parseSQLMapOutputDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var confirmed []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// sqlmap creates one sub-dir per target; any non-empty subdir signals activity.
		subDir := filepath.Join(dir, e.Name())
		subEntries, rerr := os.ReadDir(subDir)
		if rerr != nil || len(subEntries) == 0 {
			continue
		}
		// Look for log files containing injection confirmation.
		for _, sf := range subEntries {
			name := strings.ToLower(sf.Name())
			if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".csv") {
				data, rerr := os.ReadFile(filepath.Join(subDir, sf.Name())) //nolint:gosec
				if rerr != nil {
					continue
				}
				lower := strings.ToLower(string(data))
				if strings.Contains(lower, "injectable") || strings.Contains(lower, "parameter") {
					confirmed = append(confirmed, e.Name())
					break
				}
			}
		}
	}
	return confirmed
}

// runGhauriPerURL runs ghauri per URL via Backend.Stream (XCUT-09).
// v1 pattern (vulns.sh:546-547): ghauri -u "$_sqli_target" --batch -H "$HEADER" --force-ssl
//
// XCUT-07: ghauri stdout contains raw SQL payloads — NEVER logged at Info/Warn.
func runGhauriPerURL(ctx context.Context, app *appctx.AppContext,
	urls []string,
) ([]VulnFindingRecord, error) {
	const toolName = "ghauri"

	header := app.Cfg.Advanced.Header

	var records []VulnFindingRecord
	for _, rawURL := range urls {
		// Check for context cancellation between URLs.
		select {
		case <-ctx.Done():
			return records, fmt.Errorf("vulns.sqli: ghauri cancelled: %w", ctx.Err())
		default:
		}

		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}

		// v1 arg vector: ghauri -u "$_sqli_target" --batch -H "$HEADER" --force-ssl
		args := []string{"-u", rawURL, "--batch", "--force-ssl"}
		if header != "" {
			args = append(args, "-H", header)
		}

		// XCUT-09: Backend.Stream for heartbeat (ghauri per URL can run >10 min).
		eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
		if streamErr != nil {
			// Non-fatal per best_effort — log at Debug only, continue to next URL.
			if app.Log != nil {
				app.Log.Debug("vulns.sqli: ghauri stream error (best_effort, continuing)",
					"err", streamErr)
			}
			continue
		}

		// Drain stream — check for injection confirmation.
		// XCUT-07: raw line content NEVER forwarded to Info/Warn.
		var confirmed bool
		for ev := range eventCh {
			line := strings.ToLower(string(ev.Line))
			// ghauri prints "parameter ... appears to be ... injectable" on confirm.
			if strings.Contains(line, "injectable") || strings.Contains(line, "identified") {
				confirmed = true
				if app.Log != nil {
					app.Log.Debug("vulns.sqli: ghauri injectable indicator detected")
				}
			}
		}

		if confirmed {
			// Extract host only (XCUT-07: no raw payload or PoC URL written).
			host := sqliExtractHost(rawURL)
			records = append(records, VulnFindingRecord{
				Host: host, // scope-gate locator (findings:host|url)
				// Phase 4/5 inherited SARIF-compatible fields.
				Severity:   "critical",
				Confidence: "high",
				// Phase 6 vuln-class fields.
				VulnClass:       "sqli",
				MatchedParam:    host,
				PayloadRedacted: "***", // XCUT-07: raw ghauri payload never written
				PoCRedacted:     "***", // XCUT-07: raw PoC URL never written
				Engine:          "ghauri",
			})
		}
	}
	return records, nil
}

// sqliReplaceParams replaces all query-parameter values with "FUZZ" in each
// URL line of the input byte slice. Lines without query params are dropped.
// Implements the qsreplace FUZZ step in pure Go (T-05-17 shell-injection mitigation).
func sqliReplaceParams(data []byte) []byte {
	sc := bufio.NewScanner(bytes.NewReader(data))
	var out bytes.Buffer
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		parsed, pErr := url.Parse(raw)
		if pErr != nil || parsed.RawQuery == "" {
			// Drop lines without query params (v1: sed '/FUZZ/!d').
			continue
		}
		vals := parsed.Query()
		for k := range vals {
			vals[k] = []string{"FUZZ"}
		}
		parsed.RawQuery = vals.Encode()
		out.WriteString(parsed.String())
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// sqliExtractHost extracts a hostname from a URL for XCUT-07-safe record storage.
// The full URL with injected SQLi payload must never appear in records.
func sqliExtractHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers SQLiTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&SQLiTask{}) }
