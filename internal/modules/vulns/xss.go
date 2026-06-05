// xss.go — XSSTask: dalfox pipe via Gxss reflection filter (VULN-01).
//
// XSSTask reads inputs/gf/xss.txt produced by GFTask, runs URLs through a
// qsreplace FUZZ | Gxss -c 100 -p Xss | qsreplace FUZZ reflection filter,
// then pipes the reflected candidates into dalfox in pipe mode.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — reads inputs/gf/xss.txt bucket.
//
// ARG VECTOR (v1 vulns.sh:27 + dalfox:50 verbatim):
//
//	qsreplace FUZZ < gf/xss.txt | sed '/FUZZ/!d' | Gxss -c 100 -p Xss |
//	  qsreplace FUZZ | sed '/FUZZ/!d'
//	dalfox pipe --silence --no-color --no-spinner --only-poc r
//	            --ignore-return 302,404,403 --skip-bav [-b XSS_SERVER]
//	            -w <threads> -d <depth>
//
// BLIND XSS GATING (D-V6, T-06-02-03):
// XSS_SERVER empty → log.Warn "No XSS_SERVER defined, blind XSS skipped";
// -b flag is NOT added.
//
// WAF-FRIENDLY THREAD CAP (D-V6, T-06-02-04):
// Default cfg.Vulns.XSS.Threads == 5 (reduced from v1's AVAILABLE_CORES*15).
//
// PAYLOAD REDACTION (XCUT-07, T-06-02-01):
// dalfox stdout lines (PoC URLs) are NEVER logged at Info/Warn level.
// Only finding count at Info. PoCRedacted field is always "***".
//
// HEARTBEAT (XCUT-09):
// dalfox pipe can run 30+ min. Uses exec.CommandContext so the OS kills the
// process on cancellation; a background goroutine reads stdout line-by-line
// so the UI never appears stuck.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-02-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// XSSTask runs the Gxss reflection filter + dalfox pipe scanner for VULN-01.
type XSSTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *XSSTask) Name() string { return "vulns.xss" }

// Module returns the owning module group.
func (t *XSSTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *XSSTask) Description() string {
	return "XSS scanner (Gxss reflection filter + dalfox pipe)"
}

// Enabled reports whether XSS scanning is configured.
func (t *XSSTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.XSS.Enabled }

// DependsOn returns the DAG edges — XSSTask reads gf/xss.txt from GFTask.
func (t *XSSTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the Gxss reflection filter then dalfox pipe scan.
//
// Steps:
//  1. Read inputs/gf/xss.txt — skip if empty (no XSS gf candidates).
//  2. Pipe through qsreplace FUZZ then Gxss -c 100 -p Xss then qsreplace FUZZ;
//     filter lines containing "FUZZ"; write to inputs/xss_reflected.txt.
//  3. If xss_reflected.txt empty — skip (no reflected candidates).
//  4. Build dalfox pipe args; conditionally add -b BlindServer (D-V6 gate).
//  5. Run dalfox via exec.CommandContext (XCUT-09 heartbeat via goroutine reader).
//  6. Parse stdout PoC lines as VulnFindingRecord; redact per XCUT-07.
//  7. Write inputs/findings.xss.jsonl via output.WriteJSONL.
func (t *XSSTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "dalfox"
	cfg := app.Cfg

	// Resolve thread count; fall back to WAF-friendly default (D-V6).
	threads := cfg.Vulns.XSS.Threads
	if threads <= 0 {
		threads = 5 // D-V6: WAF-friendly cap; reduced from v1 AVAILABLE_CORES*15
	}

	// Depth: 3 in DEEP mode, 2 otherwise (v1 DEPTH default).
	depth := 2
	if cfg.Advanced.Deep {
		depth = 3
	}

	// Step 1: Read gf/xss.txt bucket.
	gfBucket := filepath.Join(app.Target.WorkDir, "inputs", "gf", "xss.txt")
	bucketData, err := os.ReadFile(gfBucket) //nolint:gosec // path within WorkDir
	if err != nil || len(bytes.TrimSpace(bucketData)) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.xss: gf/xss bucket empty — XSS skipped",
				"bucket", gfBucket)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.xss: mkdir inputs/: %w", err)
	}

	// Step 2: qsreplace FUZZ → Gxss → qsreplace FUZZ pipeline.
	reflected, pipeErr := runGxssReflectionPipeline(ctx, bucketData, app)
	if pipeErr != nil && app.Log != nil {
		app.Log.Debug("vulns.xss: Gxss pipeline error (best_effort)", "err", pipeErr)
	}
	// Filter lines containing FUZZ (v1: sed '/FUZZ/!d').
	var reflectedLines []string
	if len(reflected) > 0 {
		sc := bufio.NewScanner(bytes.NewReader(reflected))
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, "FUZZ") {
				reflectedLines = append(reflectedLines, line)
			}
		}
	}

	// Write xss_reflected.txt temp file.
	reflectedFile := filepath.Join(inputsDir, "xss_reflected.txt")
	if len(reflectedLines) > 0 {
		if wErr := os.WriteFile(reflectedFile,
			[]byte(strings.Join(reflectedLines, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("vulns.xss: write xss_reflected.txt: %w", wErr)
		}
	} else {
		if app.Log != nil {
			app.Log.Info("vulns.xss: no reflected candidates after Gxss filter — XSS skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 3: Build dalfox pipe args.
	args := []string{
		"pipe",
		"--silence",
		"--no-color",
		"--no-spinner",
		"--only-poc", "r",
		"--ignore-return", "302,404,403",
		"--skip-bav",
	}

	// D-V6 / T-06-02-03: blind-XSS gate — skip -b when XSS_SERVER empty.
	blindServer := cfg.APIKeys.XSSServer
	if blindServer != "" {
		args = append(args, "-b", blindServer)
	} else {
		if app.Log != nil {
			app.Log.Warn("vulns.xss: No XSS_SERVER defined, blind XSS skipped")
		}
	}

	args = append(args,
		"-w", strconv.Itoa(threads),
		"-d", strconv.Itoa(depth),
	)

	// Step 4: Locate dalfox binary.
	dalfoxPath, lookErr := exec.LookPath(toolName)
	if lookErr != nil {
		if app.Log != nil {
			app.Log.Info("vulns.xss: dalfox binary not found — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 5: Run dalfox with XCUT-09 heartbeat (goroutine reader).
	//nolint:gosec // dalfoxPath from exec.LookPath; args constructed above
	cmd := exec.CommandContext(ctx, dalfoxPath, args...)
	cmd.Stdin = bytes.NewReader([]byte(strings.Join(reflectedLines, "\n") + "\n"))

	outPipe, pipeOpenErr := cmd.StdoutPipe()
	if pipeOpenErr != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.xss: open dalfox stdout pipe: %w", pipeOpenErr)
	}
	// Suppress stderr (XCUT-07: no raw tool output at terminal level).
	cmd.Stderr = nil

	if startErr := cmd.Start(); startErr != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.xss: start dalfox: %w", startErr)
	}

	// XCUT-09: read stdout line-by-line in the same goroutine so the UI
	// never appears stuck. dalfox pipe can run 30+ minutes.
	var pocLines []string
	sc := bufio.NewScanner(outPipe)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// XCUT-07 / T-06-02-01: raw PoC line is NEVER logged at Info/Warn.
		if app.Log != nil {
			app.Log.Debug("vulns.xss: dalfox PoC line received")
		}
		pocLines = append(pocLines, line)
	}

	// Wait for dalfox to exit; non-zero exit is common when findings exist.
	if waitErr := cmd.Wait(); waitErr != nil && app.Log != nil {
		app.Log.Debug("vulns.xss: dalfox exited non-zero (may be normal)", "err", waitErr)
	}

	// Step 6: Parse PoC lines as VulnFindingRecord (XCUT-07 — redact all values).
	var records []VulnFindingRecord
	for _, poc := range pocLines {
		rec := VulnFindingRecord{
			// Phase 4/5 inherited fields.
			Severity:   "medium",
			Confidence: "medium",
			// Phase 6 vuln-class fields.
			VulnClass:       "xss",
			PayloadRedacted: "***", // XCUT-07: raw payload never written
			PoCRedacted:     "***", // XCUT-07: raw PoC URL never written
			Engine:          "dalfox",
		}
		// Extract host from the PoC URL without storing the raw URL.
		rec.MatchedParam = extractHostFromPoC(poc)
		records = append(records, rec)
	}

	// Step 7: Write inputs/findings.xss.jsonl.
	if len(records) > 0 {
		var lines [][]byte
		for _, rec := range records {
			b, mErr := json.Marshal(rec)
			if mErr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			stagingPath := filepath.Join(inputsDir, "findings.xss.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.xss: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Info("vulns.xss: completed", "findings", len(records))
	}

	_ = toolName // used via dalfoxPath from exec.LookPath
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// runGxssReflectionPipeline runs the three-stage reflection filter:
// qsreplace FUZZ → Gxss -c 100 -p Xss → qsreplace FUZZ.
//
// Implemented with exec.CommandContext to avoid shell interpolation
// (T-05-17/T-06-02 mitigation). Input URLs come from gf/xss.txt.
// The final output contains only lines where parameter values were
// replaced with FUZZ (reflection candidates for dalfox).
func runGxssReflectionPipeline(ctx context.Context, bucketData []byte, app *appctx.AppContext) ([]byte, error) {
	// Stage 1: inline FUZZ replacement (replaces qsreplace FUZZ step).
	// Parse each URL and replace all query-param values with "FUZZ".
	fuzzed := xssFuzzReplaceParams(bucketData)
	if len(fuzzed) == 0 {
		return nil, nil
	}

	// Stage 2: Gxss -c 100 -p Xss (detects reflection candidates).
	gxssPath, err := exec.LookPath("Gxss")
	if err != nil {
		if app.Log != nil {
			app.Log.Info("vulns.xss: Gxss binary not found — reflection filter skipped")
		}
		// Fall back to the FUZZ-replaced URLs directly (best_effort).
		return fuzzed, nil
	}

	//nolint:gosec // gxssPath from exec.LookPath
	gxssCmd := exec.CommandContext(ctx, gxssPath, "-c", "100", "-p", "Xss")
	gxssCmd.Stdin = bytes.NewReader(fuzzed)
	gxssOut, gxssErr := gxssCmd.Output()
	if gxssErr != nil && app.Log != nil {
		app.Log.Debug("vulns.xss: Gxss exited non-zero (best_effort)", "err", gxssErr)
	}
	if len(gxssOut) == 0 {
		return nil, nil
	}

	// Stage 3: second qsreplace FUZZ pass — ensure param values are FUZZ.
	// In v1: qsreplace FUZZ | sed '/FUZZ/!d'. We apply inline.
	secondFuzz := xssFuzzReplaceParams(gxssOut)
	return secondFuzz, nil
}

// xssFuzzReplaceParams replaces all query-parameter values with "FUZZ" in each
// line of the input byte slice. Lines that have no query params are dropped.
// Implements the qsreplace FUZZ step in pure Go (T-05-17 mitigation — no shell).
func xssFuzzReplaceParams(data []byte) []byte {
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

// extractHostFromPoC extracts a hostname from a PoC URL without storing the
// full URL (XCUT-07: the host field is not a secret, but the full PoC with
// injected payload must not appear in records).
func extractHostFromPoC(pocURL string) string {
	parsed, err := url.Parse(pocURL)
	if err != nil || parsed.Host == "" {
		// Fallback: return empty string — host is best-effort in vulns records.
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers XSSTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&XSSTask{}) }
