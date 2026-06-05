// cmdi.go — CMDITask: commix command injection scanner (VULN-08).
//
// CMDITask reads inputs/gf/rce.txt produced by GFTask, runs the URL set
// through a qsreplace FUZZ pipeline, then dispatches to commix --batch.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — reads inputs/gf/rce.txt bucket.
//
// ARG VECTOR (v1 vulns.sh:718 verbatim):
//
//	commix --batch -m <tmpRceFile> --output-dir <commixOutDir>
//
// DEEP LIMIT GATE (T-06-03-03):
// If URL count > cfg.Advanced.DeepLimit and !cfg.Advanced.Deep → StatusSkipped.
// Mirrors v1 command_injection() DEEP_LIMIT check (vulns.sh:713).
//
// PAYLOAD REDACTION (XCUT-07, T-06-03-02):
// commix stdout contains shell command output from the target — NEVER logged at
// Info/Warn. Only finding count is logged. PayloadRedacted and PoCRedacted are
// always "***" in every VulnFindingRecord.
//
// HEARTBEAT (XCUT-09):
// Backend.Stream used for commix — can run >10 min per URL set against complex
// targets; the UI must never appear stuck.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-03-PLAN.md Task 2.
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

// CMDITask runs the commix command injection scanner for VULN-08.
type CMDITask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *CMDITask) Name() string { return "vulns.cmdi" }

// Module returns the owning module group.
func (t *CMDITask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *CMDITask) Description() string {
	return "Command injection scanner (commix)"
}

// Enabled reports whether command injection scanning is configured.
func (t *CMDITask) Enabled(cfg *config.Config) bool { return cfg.Vulns.CMDi.Enabled }

// DependsOn returns the DAG edges — CMDITask reads gf/rce.txt from GFTask.
func (t *CMDITask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the commix command injection scan pipeline.
//
// Steps:
//  1. Read inputs/gf/rce.txt — skip if empty (no rce gf candidates).
//  2. qsreplace FUZZ pipeline: pipe through qsreplace FUZZ; filter "FUZZ" lines;
//     write to inputs/tmp_rce.txt.
//  3. Deep-limit gate (T-06-03-03): skip if URL count > DeepLimit and !Deep.
//  4. Run commix --batch -m <tmpRceFile> --output-dir via Backend.Stream (XCUT-09).
//  5. Parse commix output for "[+]" injection confirmation lines.
//  6. Write inputs/findings.cmdi.jsonl via output.WriteJSONL.
func (t *CMDITask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "commix"
	cfg := app.Cfg

	// Step 1: Read gf/rce.txt bucket.
	gfBucket := filepath.Join(app.Target.WorkDir, "inputs", "gf", "rce.txt")
	bucketData, err := os.ReadFile(gfBucket) //nolint:gosec // path within WorkDir
	if err != nil || len(bytes.TrimSpace(bucketData)) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.cmdi: gf/rce bucket empty — CMDi skipped",
				"bucket", gfBucket)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.cmdi: mkdir inputs/: %w", err)
	}

	// Step 2: qsreplace FUZZ pipeline — filter lines containing FUZZ.
	// v1: qsreplace "FUZZ" <gf/rce.txt | sed '/FUZZ/!d' | anew -q .tmp/tmp_rce.txt
	fuzzed := cmdiReplaceParams(bucketData)
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
			app.Log.Info("vulns.cmdi: no FUZZ candidates after qsreplace — CMDi skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Write inputs/tmp_rce.txt (the -m input file for commix).
	tmpRceFile := filepath.Join(inputsDir, "tmp_rce.txt")
	if wErr := os.WriteFile(tmpRceFile,
		[]byte(strings.Join(fuzzLines, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.cmdi: write tmp_rce.txt: %w", wErr)
	}

	// Step 3: Deep-limit gate (T-06-03-03 — DoS mitigation).
	// v1: if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 500 // v1 default DEEP_LIMIT
	}
	if !cfg.Advanced.Deep && len(fuzzLines) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.cmdi: too many URLs — skipped (use --deep to override)",
				"url_count", len(fuzzLines), "deep_limit", deepLimit)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// commix output directory — within workDir (T-06-03-04 path containment).
	commixOutDir := filepath.Join(app.Target.WorkDir, "inputs", "commix_output")
	if err := os.MkdirAll(commixOutDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.cmdi: mkdir commix_output: %w", err)
	}

	// Step 4: Run commix via Backend.Stream (XCUT-09 heartbeat).
	// v1 arg vector (vulns.sh:718): commix --batch -m <file> --output-dir <dir>
	args := []string{
		"--batch",
		"-m", tmpRceFile,
		"--output-dir", commixOutDir,
	}

	var confirmedCount int

	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	if streamErr != nil {
		// Non-fatal per best_effort policy — commix may not be installed.
		if app.Log != nil {
			app.Log.Debug("vulns.cmdi: commix stream error (best_effort)", "err", streamErr)
		}
	} else {
		// Step 5: Drain event channel; detect injection confirmation lines.
		// XCUT-07 / T-06-03-02: commix stdout may contain shell output from target.
		// NEVER log raw lines at Info/Warn. Only count at Debug.
		for ev := range eventCh {
			line := strings.TrimSpace(string(ev.Line))
			if line == "" {
				continue
			}
			// commix prints "[+]" prefix on confirmed injections.
			// Check for both "[+]" and "injectable" to catch all confirmation forms.
			lower := strings.ToLower(line)
			if strings.HasPrefix(line, "[+]") &&
				(strings.Contains(lower, "injectable") ||
					strings.Contains(lower, "parameter") ||
					strings.Contains(lower, "vulnerable")) {
				confirmedCount++
				// XCUT-07: raw line content NEVER logged; only count.
				if app.Log != nil {
					app.Log.Debug("vulns.cmdi: commix injection confirmed", "count", confirmedCount)
				}
			}
		}
	}

	// Also scan the commix output directory for session files that indicate
	// successful exploitation (commix writes per-target session files on confirm).
	dirCount := parseCommixOutputDir(commixOutDir)
	if dirCount > confirmedCount {
		confirmedCount = dirCount
	}

	// Build VulnFindingRecord entries.
	var findings []VulnFindingRecord
	for i := 0; i < confirmedCount; i++ {
		findings = append(findings, VulnFindingRecord{
			// Phase 4/5 inherited SARIF-compatible fields.
			Severity:   "critical",
			Confidence: "high",
			// Phase 6 vuln-class fields.
			VulnClass:       "rce",
			PayloadRedacted: "***", // XCUT-07: raw commix payload never written
			PoCRedacted:     "***", // XCUT-07: raw commix PoC never written
			Engine:          "commix",
		})
	}

	// Step 6: Write inputs/findings.cmdi.jsonl.
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
			stagingPath := filepath.Join(inputsDir, "findings.cmdi.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.cmdi: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	// XCUT-07: log only count, never raw RCE payloads or target shell output.
	if app.Log != nil {
		app.Log.Info("vulns.cmdi: completed", "cmdi_findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"cmdi_findings": len(findings)},
	}, nil
}

// parseCommixOutputDir scans the commix output directory for session files
// that indicate confirmed command injection exploits. commix creates a
// subdirectory per target hostname containing a "session" file on success.
func parseCommixOutputDir(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var count int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subDir := filepath.Join(dir, e.Name())
		subEntries, rerr := os.ReadDir(subDir)
		if rerr != nil || len(subEntries) == 0 {
			continue
		}
		for _, sf := range subEntries {
			name := strings.ToLower(sf.Name())
			// commix writes session files (e.g. "results.csv", "logs/*.txt") on success.
			if strings.HasSuffix(name, ".csv") ||
				strings.HasSuffix(name, ".log") ||
				name == "session" {
				// Any session or result file in a per-target subdir signals a confirmed find.
				count++
				break
			}
		}
	}
	return count
}

// cmdiReplaceParams replaces all query-parameter values with "FUZZ" in each
// URL line of the input byte slice. Lines without query params are dropped.
// Implements the qsreplace FUZZ step in pure Go (T-05-17 shell-injection mitigation).
// Mirrors sqliReplaceParams — same logic, separate function for clarity.
func cmdiReplaceParams(data []byte) []byte {
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

// cmdiExtractHost extracts a hostname from a URL for XCUT-07-safe record storage.
// Kept as a helper for potential per-URL cmdi extensions; not used in -m batch mode.
func cmdiExtractHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers CMDITask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&CMDITask{}) }
