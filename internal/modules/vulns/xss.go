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
// dalfox pipe can run 30+ min, so its stdout is consumed line-by-line as it
// arrives and the UI never appears stuck.
//
// 18-04: THIS FILE NO LONGER BYPASSES THE SEAM — BOTH of its shapes came home.
// Its only manifest reason was `stdin`, which 18-01's ExecOptions.Stdin serves.
//
//   - dalfox pipe mode now goes through app.Tools.StreamOpts, NOT RunOpts. This
//     is not a stylistic choice: the buffered path returns a *ToolError with NO
//     Result on a non-zero exit, and dalfox routinely exits non-zero WHEN IT HAS
//     FINDINGS — the very line below says so. Buffering would therefore have
//     thrown away exactly the PoC lines this task exists to collect, and would
//     also have held 30+ minutes of output in memory instead of streaming it.
//     StreamOpts delivers each line as it arrives and carries the terminal error
//     on the final Event, so the heartbeat and the findings both survive.
//   - the Gxss reflection pre-pass goes through app.Tools.RunOpts with stdin.
//     It used gxssCmd.Output(), which is NOT one of the FOUND-10 walker's
//     forbidden patterns — so that dispatch was uncounted by the bypass census
//     even while this file was declared (18-03-SUMMARY records the gap). It is
//     moved anyway: an uncounted bypass is still a bypass.
//
// TIMEOUT: dalfox carries timeout_seconds = 0 in tools.lock and this file
// applied NO deadline of its own — the two AGREE, and the agreement is stated
// here rather than left for a reader to infer. dalfox pipe is unbounded by
// design (a 30+ minute scan is normal) and the scan's own context still bounds
// it. Gxss carries timeout_seconds = 120, which the Runner now applies to the
// pre-pass; that call previously had NO bound at all, so this is a bound gained,
// not one lost.
//
// DEFAULT ARGS: both rows carry default_args = [], so both argvs are
// byte-for-byte the pre-move ones.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-02-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
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
//  5. Run dalfox via Runner.StreamOpts (XCUT-09 heartbeat via streamed events).
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

	// Step 4+5: stream dalfox through backend.Runner with the reflected
	// candidates on stdin (XCUT-09 heartbeat: each line is consumed as it
	// arrives, so a 30+ minute scan never looks stuck).
	//
	// NO exec.LookPath GATE. An unresolvable dalfox now returns a typed dispatch
	// failure and is RECORDED as dispatch_failed instead of vanishing; the task's
	// status on an absent binary is unchanged (StatusSkipped), and no staging
	// write happens on that path (F3 did-not-run).
	events, streamErr := app.Tools.StreamOpts(ctx, toolName, args, backend.ExecOptions{
		Stdin: []byte(strings.Join(reflectedLines, "\n") + "\n"),
	})
	if streamErr != nil {
		if coreerrors.IsDispatchFailure(streamErr) {
			if app.Log != nil {
				app.Log.Info("vulns.xss: dalfox unavailable — skipping")
			}
			return task.Result{Status: task.StatusSkipped}, nil
		}
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.xss: start dalfox: %w", streamErr)
	}

	var pocLines []string
	// Collect drains to completion and returns the stream's terminal error, so a
	// dalfox that exits non-zero AFTER printing PoC lines keeps those lines —
	// which is the routine case, not the exceptional one.
	if collectErr := backend.Collect(events, func(ev backend.Event) {
		// Stderr is not a finding (XCUT-07: no raw tool output at terminal level).
		if ev.IsErr {
			return
		}
		line := strings.TrimSpace(string(ev.Line))
		if line == "" {
			return
		}
		// XCUT-07 / T-06-02-01: raw PoC line is NEVER logged at Info/Warn.
		if app.Log != nil {
			app.Log.Debug("vulns.xss: dalfox PoC line received")
		}
		pocLines = append(pocLines, line)
	}); collectErr != nil && app.Log != nil {
		app.Log.Debug("vulns.xss: dalfox exited non-zero (may be normal)", "err", collectErr)
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
		// Host is the scope-gate locator; MatchedParam is kept for
		// backwards compatibility with existing findings consumers.
		rec.MatchedParam = extractHostFromPoC(poc)
		rec.Host = rec.MatchedParam
		records = append(records, rec)
	}

	// Step 7: Write inputs/findings.xss.jsonl.
	//
	// F3 (phase 15): staged UNCONDITIONALLY. dalfox RAN — an absent binary
	// returned StatusSkipped at the dispatch-failure arm above and a failed
	// stream open returned StatusErrored, so reaching here means the scan
	// completed and zero PoC lines is a real observation.
	stagingPath := filepath.Join(inputsDir, "findings.xss.jsonl")
	stageVulnFindings(app, "vulns.xss", stagingPath, true, records)

	if app.Log != nil {
		app.Log.Info("vulns.xss: completed", "findings", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// runGxssReflectionPipeline runs the three-stage reflection filter:
// qsreplace FUZZ → Gxss -c 100 -p Xss → qsreplace FUZZ.
//
// Implemented with inline URL rewriting plus Runner.RunOpts, without shell
// interpolation (T-05-17/T-06-02 mitigation). Input URLs come from gf/xss.txt.
// The final output contains only lines where parameter values were
// replaced with FUZZ (reflection candidates for dalfox).
func runGxssReflectionPipeline(ctx context.Context, bucketData []byte, app *appctx.AppContext) ([]byte, error) {
	// Stage 1: inline FUZZ replacement (replaces qsreplace FUZZ step).
	// Parse each URL and replace all query-param values with "FUZZ".
	fuzzed := xssFuzzReplaceParams(bucketData)
	if len(fuzzed) == 0 {
		return nil, nil
	}

	// Stage 2: Gxss -c 100 -p Xss (detects reflection candidates), through the
	// Runner with the FUZZ-replaced corpus on stdin. This site used
	// gxssCmd.Output(), a dispatch shape the FOUND-10 walker does not even count
	// — moved anyway, because an uncounted bypass is still a bypass.
	if app == nil || app.Tools == nil {
		return fuzzed, nil
	}
	gxssRes, gxssErr := app.Tools.RunOpts(ctx, xssGxssToolName, xssGxssArgs(),
		backend.ExecOptions{Stdin: fuzzed})
	if gxssErr != nil {
		if coreerrors.IsDispatchFailure(gxssErr) {
			if app.Log != nil {
				app.Log.Info("vulns.xss: Gxss unavailable — reflection filter skipped")
			}
			// Fall back to the FUZZ-replaced URLs directly (best_effort) —
			// byte-for-byte the old exec.LookPath fallback.
			return fuzzed, nil
		}
		// WR-05: ANY other failure gets the SAME fallback, not silence.
		//
		// This site used gxssCmd.Output(), which returns captured stdout even on a
		// non-zero exit or a cancelled context. RunOpts discards it, so after the
		// move a Gxss deadline produced zero reflected lines, the caller saw an
		// empty candidate list and returned StatusSkipped — the WHOLE XSS scan went
		// silent, with an Info line indistinguishable from a genuine zero-reflection
		// result. The 120s bound the file header calls "a bound gained, not one
		// lost" is exactly what makes this reachable.
		//
		// Gxss is a best-effort NARROWING pre-pass. Failing to narrow means testing
		// the unfiltered corpus — more work, same coverage. It never means testing
		// nothing.
		if app.Log != nil {
			app.Log.Warn("vulns.xss: Gxss did not complete — proceeding with the UNFILTERED "+
				"corpus rather than skipping the scan (WR-05)",
				"candidates", len(fuzzed), "err", gxssErr)
		}
		return fuzzed, nil
	}
	var gxssOut []byte
	if gxssRes != nil {
		gxssOut = gxssRes.Stdout
	}
	if len(gxssOut) == 0 {
		return nil, nil
	}

	// Stage 3: second qsreplace FUZZ pass — ensure param values are FUZZ.
	// In v1: qsreplace FUZZ | sed '/FUZZ/!d'. We apply inline.
	secondFuzz := xssFuzzReplaceParams(gxssOut)
	return secondFuzz, nil
}

// xssGxssToolName is the tools.lock registry key for the reflection pre-pass.
const xssGxssToolName = "Gxss"

// xssGxssArgs returns the reflection pre-pass arg vector, VERBATIM as it stood
// before 18-04 moved this dispatch onto the Runner: `Gxss -c 100 -p Xss`
// (v1 vulns.sh:27). Identical to web/gxss.go's vector, and deliberately declared
// separately: the two sites are independent and must each be pinned.
func xssGxssArgs() []string { return []string{"-c", "100", "-p", "Xss"} }

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
