// lfi.go — LFITask: ffuf parameter fuzz with lfi_wordlist (VULN-04).
//
// LFITask reads inputs/gf/lfi.txt produced by GFTask, generates single-param
// candidate URLs (one FUZZ slot per query parameter, other params preserved),
// caps candidates at LFI_MAX_URLS (default 150, D-V6 WAF-friendly posture),
// runs ffuf -w lfi_wordlist:LFI per candidate, and stores findings in
// inputs/findings.lfi.jsonl per the multi-writer staging contract (doc.go).
//
// DEPENDENCY: DependsOn ["vulns.gf"] — reads inputs/gf/lfi.txt bucket.
//
// CANDIDATE PREPARATION (ports v1 _lfi_emit_single_param_candidates +
// _lfi_prepare_candidates from modules/vulns.sh:241-311):
// For each URL with a query string, one variant is emitted per parameter with
// that parameter's value replaced by "LFI" (all other parameters preserved).
// Duplicates are dropped. If len(candidates) > MaxURLs, the list is truncated.
//
// ARG VECTOR (v1 vulns.sh:355-366 verbatim):
//
//	ffuf -v -noninteractive -t <threads> -rate <rate>
//	     -timeout <timeout> -maxtime <maxtime>
//	     -H <header> -w lfi_wordlist:LFI
//	     -mr "root:" -u <candidateURL-with-LFI-slot>
//
// PAYLOAD REDACTION (XCUT-07, T-06-04-01):
// ffuf verbose output may contain file contents (e.g., /etc/passwd lines).
// Raw ffuf output lines MUST NEVER appear in logs at Info/Warn.
// Only status code + response count logged at Debug. PayloadRedacted="***".
//
// DEEP LIMIT GATE (mirrors v1 vulns.sh:337 DEEP/DEEP_LIMIT check):
// If cfg.Advanced.Deep is false AND candidate count > cfg.Advanced.DeepLimit,
// the scan is skipped with an Info log suggesting --deep.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-04-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// LFITask runs ffuf parameter fuzzing with lfi_wordlist for VULN-04.
type LFITask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *LFITask) Name() string { return "vulns.lfi" }

// Module returns the owning module group.
func (t *LFITask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *LFITask) Description() string {
	return "LFI parameter fuzzing (ffuf + lfi_wordlist)"
}

// Enabled reports whether LFI scanning is configured.
func (t *LFITask) Enabled(cfg *config.Config) bool { return cfg.Vulns.LFI.Enabled }

// DependsOn returns the DAG edges — LFITask reads gf/lfi.txt from GFTask.
func (t *LFITask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the LFI ffuf parameter fuzz pipeline.
//
// Steps:
//  1. Check lfi_wordlist path — skip if not configured or not accessible.
//  2. Read inputs/gf/lfi.txt bucket — skip if empty.
//  3. prepareLFICandidates: expand each URL into per-param FUZZ variants;
//     deduplicate; cap at LFI_MAX_URLS; write inputs/tmp_lfi_candidates.txt.
//  4. Deep-limit gate: skip if count > DeepLimit and !Deep.
//  5. For each candidate URL, run ffuf -w lfi_wordlist:LFI -u <candidate>
//     via Backend.Stream (XCUT-09 heartbeat for potentially slow runs).
//  6. Collect hits; write inputs/findings.lfi.jsonl via output.WriteJSONL.
func (t *LFITask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "ffuf"
	cfg := app.Cfg

	// Step 1: Resolve lfi_wordlist path.
	lfiWordlist := cfg.Paths.LFIWordlist
	if lfiWordlist == "" {
		if app.Log != nil {
			app.Log.Info("vulns.lfi: lfi_wordlist not configured — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if _, err := os.Stat(lfiWordlist); err != nil {
		if app.Log != nil {
			app.Log.Info("vulns.lfi: lfi_wordlist not accessible — skipping",
				"path", lfiWordlist, "err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 2: Read inputs/gf/lfi.txt bucket.
	gfBucket := filepath.Join(app.Target.WorkDir, "inputs", "gf", "lfi.txt")
	bucketData, err := os.ReadFile(gfBucket) //nolint:gosec // path within WorkDir
	if err != nil || len(bytes.TrimSpace(bucketData)) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.lfi: gf/lfi bucket empty — LFI skipped", "bucket", gfBucket)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Ensure inputs/ dir exists.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.lfi: mkdir inputs/: %w", err)
	}

	// Step 3: Generate single-param FUZZ candidates (D-V6 cap at LFI_MAX_URLS).
	maxURLs := cfg.Vulns.LFI.MaxURLs
	if maxURLs <= 0 {
		maxURLs = 150 // v1 LFI_MAX_URLS default
	}
	candidates := prepareLFICandidates(bucketData, maxURLs)
	if len(candidates) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.lfi: no per-parameter LFI candidates generated — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Write candidates to inputs/tmp_lfi_candidates.txt (for inspection).
	candidatesFile := filepath.Join(inputsDir, "tmp_lfi_candidates.txt")
	if wErr := os.WriteFile(candidatesFile,
		[]byte(strings.Join(candidates, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		if app.Log != nil {
			app.Log.Debug("vulns.lfi: write candidates file failed (continuing)",
				"path", candidatesFile, "err", wErr)
		}
	}

	if app.Log != nil {
		app.Log.Info("vulns.lfi: candidate URLs prepared",
			"count", len(candidates), "cap", maxURLs)
	}

	// Step 4: Deep-limit gate (mirrors v1 vulns.sh:337).
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 500 // v1 DEEP_LIMIT default
	}
	if !cfg.Advanced.Deep && len(candidates) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.lfi: too many candidates — skipped (use --deep to override)",
				"candidate_count", len(candidates), "deep_limit", deepLimit)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Resolve ffuf knobs from config (mirrors v1 vulns.sh:341-346).
	threads := resolveLFIThreads(cfg)
	rateLimit := cfg.Advanced.Tools.FFUF.RateLimit
	if rateLimit <= 0 {
		rateLimit = 50 // v1 LFI_FFUF_RATELIMIT default
	}
	timeoutSeconds := 10 // v1 LFI_FFUF_TIMEOUT default
	maxTimeSeconds := 90 // v1 LFI_FFUF_MAXTIME default
	header := cfg.Advanced.Header

	// Step 5: Run ffuf per candidate URL.
	var findings []VulnFindingRecord
	// ffufRan records whether AT LEAST ONE candidate was actually probed. If
	// ffuf is absent every dispatch fails, the task observed nothing, and it
	// must not clear a previous run's staging (F3 did-not-run — staging.go).
	ffufRan := false
	// cancelled records that the loop stopped early on context cancellation, so
	// a partially-probed corpus is not mistaken for a completed clean run.
	cancelled := false

	for i, candidate := range candidates {
		// Stop early on context cancellation (SA4011: a bare break inside a
		// select would only exit the select, not this loop).
		if ctx.Err() != nil {
			if app.Log != nil {
				app.Log.Debug("vulns.lfi: cancelled", "processed", i, "total", len(candidates))
			}
			cancelled = true
			break
		}

		hits, ffufErr := runLFIFFUF(ctx, app, toolName, candidate, lfiWordlist,
			threads, rateLimit, timeoutSeconds, maxTimeSeconds, header)
		// F6 (phase 15): ffuf RAN and ended badly on this candidate. The corpus is
		// only partly probed, so escalate and discard rather than let the
		// remaining candidates read as clean. A DISPATCH error (ffuf absent) keeps
		// its best-effort path and simply leaves ffufRan false.
		if isTerminalStreamError(ffufErr) {
			return task.Result{Status: task.StatusErrored}, ffufErr
		}
		if ffufErr == nil {
			ffufRan = true
		}
		findings = append(findings, hits...)
	}

	// Step 6: Write inputs/findings.lfi.jsonl.
	//
	// F3 (phase 15): staged through stageVulnFindings so a run in which ffuf
	// matched nothing REMOVES the previous run's staging. A CANCELLED run only
	// probed part of the corpus, so it is treated as did-not-run: an interrupted
	// scan must never be the reason a finding disappears.
	//
	// NOTE inputs/tmp_lfi_candidates.txt above is a scratch/inspection file, not
	// staging, and keeps its raw unconditional write.
	stagingPath := filepath.Join(inputsDir, "findings.lfi.jsonl")
	stageVulnFindings(app, "vulns.lfi", stagingPath, ffufRan && !cancelled, findings)

	// XCUT-07: log only count, never raw LFI payload or file contents.
	if app.Log != nil {
		app.Log.Info("vulns.lfi: completed", "findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"lfi_findings": len(findings)},
	}, nil
}

// prepareLFICandidates ports v1 _lfi_emit_single_param_candidates +
// _lfi_prepare_candidates (modules/vulns.sh:241-311).
//
// For each URL line with a query string:
//   - For each unique query parameter key K, emit a variant URL where K's value
//     is set to "LFI" and all other parameters are left unchanged.
//
// The resulting slice is deduplicated. If maxURLs > 0 and len > maxURLs,
// the slice is truncated to maxURLs (D-V6 WAF-friendly cap, T-06-04-03).
//
// NOTE: The placeholder is "LFI" (used as the ffuf keyword -w wordlist:LFI).
// This mirrors v1's qsreplace pattern where ffuf receives the wordlist as
// -w lfi_wordlist:LFI and the candidate URL already contains the LFI keyword.
func prepareLFICandidates(data []byte, maxURLs int) []string {
	seen := make(map[string]struct{})
	var ordered []string

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		rawLine := strings.TrimSpace(sc.Text())
		if rawLine == "" {
			continue
		}
		// Only process URLs with query parameters.
		parsed, err := url.Parse(rawLine)
		if err != nil || parsed.RawQuery == "" {
			continue
		}

		vals := parsed.Query()
		if len(vals) == 0 {
			continue
		}

		// For each unique parameter key, emit one variant with that param=LFI.
		seenKeys := make(map[string]struct{})
		for key := range vals {
			if _, already := seenKeys[key]; already {
				continue
			}
			seenKeys[key] = struct{}{}

			// Build the variant: all params preserved, target param = LFI.
			variantVals := make(url.Values)
			for k, vs := range vals {
				if k == key {
					variantVals[k] = []string{"LFI"}
				} else {
					variantVals[k] = vs
				}
			}
			variant := *parsed
			variant.RawQuery = variantVals.Encode()
			candidateURL := variant.String()

			if _, exists := seen[candidateURL]; !exists {
				seen[candidateURL] = struct{}{}
				ordered = append(ordered, candidateURL)
			}
		}
	}

	// Cap at maxURLs (v1 head -n LFI_MAX_URLS equivalent).
	if maxURLs > 0 && len(ordered) > maxURLs {
		ordered = ordered[:maxURLs]
	}
	return ordered
}

// runLFIFFUF runs ffuf for a single LFI candidate URL and returns any findings.
//
// The error return distinguishes the two ffuf failure channels. A DISPATCH
// error (ffuf absent) is returned bare and means this candidate was never
// probed — the caller must not count it as an observation (F3 did-not-run).
//
// v1 arg vector (modules/vulns.sh:355-366):
//
//	ffuf -v -noninteractive -t <threads> -rate <rate>
//	     -timeout <timeout> -maxtime <maxtime>
//	     -H <header> -w <lfi_wordlist>:LFI -mr "root:" -u <candidateURL>
//
// XCUT-07 (T-06-04-01): ffuf verbose output may contain raw file content lines.
// Raw output MUST NOT be logged at Info/Warn. Only status count at Debug.
// The LFI keyword in the candidate URL and wordlist entries are NEVER written
// to any VulnFindingRecord field.
func runLFIFFUF(ctx context.Context, app *appctx.AppContext,
	toolName, candidateURL, lfiWordlist string,
	threads, rateLimit, timeoutSeconds, maxTimeSeconds int,
	header string,
) ([]VulnFindingRecord, error) {
	// v1 arg vector: ffuf -v -noninteractive -t <t> -rate <r>
	//                     -timeout <to> -maxtime <mt> -H <h>
	//                     -w lfi_wordlist:LFI -mr "root:" -u <candidate>
	args := []string{
		"-v",
		"-noninteractive",
	}
	if threads > 0 {
		args = append(args, "-t", strconv.Itoa(threads))
	}
	if rateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(rateLimit))
	}
	args = append(args, "-timeout", strconv.Itoa(timeoutSeconds))
	args = append(args, "-maxtime", strconv.Itoa(maxTimeSeconds))
	if header != "" {
		args = append(args, "-H", header)
	}
	// Wordlist with LFI keyword (ffuf substitutes LFI placeholder in URL).
	args = append(args, "-w", lfiWordlist+":LFI")
	// Match on "root:" pattern — typical /etc/passwd first line (v1 -mr "root:").
	args = append(args, "-mr", "root:")
	args = append(args, "-u", candidateURL)

	// XCUT-09: Backend.Stream for heartbeat; ffuf per URL can run up to maxtime.
	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	if streamErr != nil {
		// DISPATCH failure — ffuf is not on PATH; this candidate never ran.
		if app.Log != nil {
			app.Log.Debug("vulns.lfi: ffuf stream error (best_effort, continuing)",
				"err", streamErr)
		}
		return nil, fmt.Errorf("vulns.lfi: ffuf stream: %w", streamErr)
	}

	// Drain stream — Backend contract requires full drain.
	// XCUT-07 (T-06-04-01): raw ffuf output may contain file contents (e.g.,
	// /etc/passwd lines). NEVER log at Info/Warn. Count matches only at Debug.
	//
	// F6 (phase 15) accumulator shape: latch the TERMINAL error inside the loop
	// and check it after.
	var matchCount int
	var termErr error
	for ev := range eventCh {
		if ev.Err != nil {
			termErr = ev.Err
		}
		line := strings.ToLower(string(ev.Line))
		// ffuf -v output includes "| URL |" lines for matches; -mr means only
		// lines matching "root:" are printed at all. Count presence.
		if strings.Contains(line, "url") && strings.Contains(line, "lfi") {
			matchCount++
			if app.Log != nil {
				// XCUT-07: NEVER log the matched URL or payload content.
				app.Log.Debug("vulns.lfi: ffuf match indicator detected")
			}
		}
	}

	// F6: ffuf ended badly, so this candidate was only partially probed. Report
	// it rather than let a partial probe read as "no LFI on this URL".
	if termErr != nil {
		return nil, terminalStreamError(toolName, termErr)
	}

	if matchCount == 0 {
		return nil, nil
	}

	// Extract host for XCUT-07-safe record storage (no raw payload).
	host := lfiExtractHost(candidateURL)

	var records []VulnFindingRecord
	for i := 0; i < matchCount; i++ {
		records = append(records, VulnFindingRecord{
			Host: host, // scope-gate locator (findings:host|url)
			// Phase 4/5 inherited SARIF-compatible fields.
			Severity:   "high",
			Confidence: "medium",
			// Phase 6 vuln-class fields.
			VulnClass:       "lfi",
			MatchedParam:    host,  // hostname only — no raw payload (XCUT-07)
			PayloadRedacted: "***", // XCUT-07: raw LFI path never written
			PoCRedacted:     "***", // XCUT-07: raw matching URL never written
			Engine:          "ffuf",
		})
	}
	return records, nil
}

// resolveLFIThreads computes the effective ffuf thread count for LFI.
// v1 default: LFI_FFUF_THREADS=20; cap with cfg.Advanced.Tools.FFUF.Threads.
func resolveLFIThreads(cfg *config.Config) int {
	computed := 20 // v1 LFI_FFUF_THREADS default
	cap := cfg.Advanced.Tools.FFUF.Threads
	if cap > 0 && computed > cap {
		computed = cap
	}
	_ = runtime.NumCPU() // available for future AVAILABLE_CORES-based scaling
	return computed
}

// lfiExtractHost extracts the hostname from a candidate URL for XCUT-07-safe
// storage. The full URL with LFI payload slot is never written to records.
func lfiExtractHost(candidateURL string) string {
	parsed, err := url.Parse(candidateURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers LFITask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&LFITask{}) }
