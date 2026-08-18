// webcache.go — WebCacheTask: web cache poisoning scanner (WCVS + toxicache, VULN-09).
//
// WebCacheTask reads the web host URL list from artefacts/urls.jsonl, writes a
// temp host file, runs Web-Cache-Vulnerability-Scanner (primary engine) and
// optionally toxicache (secondary engine), and stores merged findings in
// inputs/findings.webcache.jsonl per the multi-writer staging contract.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — webcache() v1 runs after the URL corpus
// is ready; the gf DAG root ensures that corpus is finalized before this task.
//
// INPUT: artefacts/urls.jsonl — host URL list from Phase 5 web probe (D-V5).
// WCVS does NOT need gf-pattern-filtered input; it tests all web hosts
// (v1 webcache() reads webs/webs_all.txt, the unfiltered host list).
//
// ARG VECTORS (v1 vulns.sh:879 + :894 verbatim):
//
//	Web-Cache-Vulnerability-Scanner -u "file:<hostsFile>" -v 0
//	toxicache -i <hostsFile> -o <outFile> -t <threads> -ua <userAgent>
//
// PAYLOAD REDACTION (XCUT-07, T-06-06-02):
// WCVS stdout contains raw cache poisoning PoC headers (X-Forwarded-Host etc.)
// and injected cache directives. These MUST NOT appear in logs. Only finding
// count is logged at Info. PayloadRedacted and PoCRedacted are always "***".
//
// SUBPROCESS SAFETY (FOUND-09, T-06-06-01):
// Backend.Stream uses LocalBackend which sets SysProcAttr.Setpgid=true and
// WaitDelay for all subprocess invocations — orphan processes are kill-tree safe.
// No raw exec.Command calls in WebCacheTask code.
//
// HEARTBEAT (XCUT-09):
// Backend.Stream used for WCVS — can be slow on large host sets; the UI must
// never appear stuck. toxicache uses Backend.Run (finite output).
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-06-PLAN.md Task 1.
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
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// WebCacheTask runs the web cache poisoning scanner (WCVS + toxicache) for VULN-09.
type WebCacheTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *WebCacheTask) Name() string { return "vulns.webcache_wcvs" }

// Module returns the owning module group.
func (t *WebCacheTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *WebCacheTask) Description() string {
	return "Web cache poisoning scanner (WCVS + toxicache)"
}

// Enabled reports whether web cache poisoning scanning is configured.
func (t *WebCacheTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.Cache.Enabled }

// DependsOn returns the DAG edges — WebCacheTask consumes the URL corpus
// prepared by the vulns pipeline after GFTask (mirrors v1 sequencing where
// webcache() runs after url_gf() in the vulns pipeline).
func (t *WebCacheTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes web cache poisoning scanning against the probed host URL list.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract URL strings — skip if empty.
//  2. Write host URLs to inputs/webcache_hosts.txt temp file.
//  3. Deep-limit gate: skip if URL count > DeepLimit and !Deep (mirrors v1).
//  4. Stream("Web-Cache-Vulnerability-Scanner", ["-u", "file:hostsFile", "-v", "0"]);
//     drain event channel for XCUT-09 heartbeat; parse stdout for confirmed poisoning.
//  5. If cfg.Vulns.Cache.Toxicache: Run("toxicache", ["-i", hostsFile, "-o", outFile,
//     "-t", threads, "-ua", userAgent]); parse outFile plain text.
//  6. Merge WCVS + toxicache findings; write inputs/findings.webcache.jsonl.
func (t *WebCacheTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const (
		wcvsToolName      = "Web-Cache-Vulnerability-Scanner"
		toxicacheToolName = "toxicache"
	)
	cfg := app.Cfg

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	hostURLs, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.webcache: read URL corpus error (best_effort)", "err", err)
	}
	if len(hostURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.webcache: no host URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.webcache: mkdir inputs/: %w", err)
	}

	// Step 2: Write host URLs to temp file.
	hostsFile := filepath.Join(inputsDir, "webcache_hosts.txt")
	if wErr := os.WriteFile(hostsFile,
		[]byte(strings.Join(hostURLs, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.webcache: write webcache_hosts.txt: %w", wErr)
	}

	// Step 3: Deep-limit gate (mirrors v1 webcache() DEEP_LIMIT check, vulns.sh:872).
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 500 // v1 default DEEP_LIMIT
	}
	if !cfg.Advanced.Deep && len(hostURLs) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.webcache: too many URLs — skipped (use --deep to override)",
				"url_count", len(hostURLs), "deep_limit", deepLimit)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	var allFindings []VulnFindingRecord
	// termErr latches a TERMINAL stream error — WCVS RAN and ended badly.
	var termErr error

	// Step 4: Run WCVS via Backend.Stream (XCUT-09 heartbeat).
	// v1 arg vector (vulns.sh:879): Web-Cache-Vulnerability-Scanner -u "file:hostsFile" -v 0
	wcvsArgs := []string{"-u", "file:" + hostsFile, "-v", "0"}

	eventCh, streamErr := app.Tools.Stream(ctx, wcvsToolName, wcvsArgs)
	// engineRan records whether EITHER engine was actually dispatched. If neither
	// WCVS nor toxicache is installed the task observed nothing and must not
	// clear a previous run's staging (F3 did-not-run — staging.go).
	engineRan := streamErr == nil
	if streamErr != nil {
		// Non-fatal per best_effort policy — WCVS may not be installed.
		if app.Log != nil {
			app.Log.Debug("vulns.webcache: WCVS stream error (best_effort)", "err", streamErr)
		}
	} else {
		// Drain event channel for XCUT-09 heartbeat; collect WCVS confirmed findings.
		// XCUT-07 / T-06-06-02: raw WCVS output lines contain cache poisoning PoC
		// headers (X-Forwarded-Host etc.). NEVER log raw lines at Info/Warn.
		// F6 (phase 15) accumulator shape: latch the TERMINAL error inside the
		// loop and act on it after. `streamErr` is the DISPATCH error and keeps
		// its untouched best-effort branch above.
		for ev := range eventCh {
			if ev.Err != nil {
				termErr = ev.Err
			}
			line := strings.TrimSpace(string(ev.Line))
			if line == "" {
				continue
			}
			// WCVS outputs "Web Cache Poisoning Found!" or "[VULN]" prefixes on confirmed
			// poisoning. Collect the finding but NEVER store raw poison headers.
			if wcvsIsConfirmedPoison(line) {
				host := wcvsExtractHost(line)
				allFindings = append(allFindings, VulnFindingRecord{
					Host:            host, // scope-gate locator (findings:host|url)
					Severity:        "high",
					Confidence:      "high",
					VulnClass:       "webcache",
					MatchedParam:    host,  // hostname only — no raw poison headers
					PayloadRedacted: "***", // XCUT-07: raw poison header never written
					PoCRedacted:     "***", // XCUT-07: raw PoC request never written
					Engine:          "wcvs",
				})
			}
		}
		// F6: WCVS exited non-zero, so the poisoning verdicts collected above are
		// a partial scan. Return before toxicache and before the staging write —
		// publishing a crashed scanner's partial result as this run's
		// cache-poisoning verdict is exactly what gate 5 exists to stop.
		if termErr != nil {
			return task.Result{Status: task.StatusErrored}, terminalStreamError(wcvsToolName, termErr)
		}
	}

	// Step 5: Optionally run toxicache (secondary engine).
	// v1: if [[ ${WEBCACHE_TOXICACHE:-true} == true ]]; then toxicache -i hostsFile ...
	// v2: cfg.Vulns.Cache.Toxicache (mapped from WEBCACHE_TOXICACHE, default true).
	if cfg.Vulns.Cache.Toxicache {
		toxicacheOut := filepath.Join(inputsDir, "webcache_toxicache.txt")

		// Toxicache config from cfg.Advanced.Tools.Toxicache (threads, user_agent).
		threads := cfg.Advanced.Tools.Toxicache.Threads
		if threads <= 0 {
			threads = 70 // v1 default TOXICACHE_THREADS=70
		}
		userAgent := cfg.Advanced.Tools.Toxicache.UserAgent
		if userAgent == "" {
			userAgent = "Mozilla/5.0 (X11; Linux x86_64)" // v1 default TOXICACHE_USER_AGENT
		}

		// v1 arg vector (vulns.sh:894):
		// toxicache -i hostsFile -o outFile -t threads -ua userAgent
		toxArgs := []string{
			"-i", hostsFile,
			"-o", toxicacheOut,
			"-t", strconv.Itoa(threads),
			"-ua", userAgent,
		}

		_, toxErr := app.Tools.Run(ctx, toxicacheToolName, toxArgs)
		if toxErr != nil {
			// Non-fatal per best_effort policy — toxicache may not be installed.
			if app.Log != nil {
				app.Log.Debug("vulns.webcache: toxicache run error (best_effort)", "err", toxErr)
			}
		} else {
			engineRan = true
			// Parse toxicache plain-text output for additional findings.
			if toxData, rErr := os.ReadFile(toxicacheOut); rErr == nil { //nolint:gosec
				toxFindings := parseToxicacheOutput(toxData)
				allFindings = append(allFindings, toxFindings...)
			}
		}
	}

	// Step 6: Write inputs/findings.webcache.jsonl (merged WCVS + toxicache).
	//
	// F3 (phase 15): staged through stageVulnFindings so a run in which neither
	// engine confirmed poisoning REMOVES the previous run's staging instead of
	// republishing a cache-poisoning vector that has since been fixed.
	//
	// NOTE inputs/webcache_hosts.txt is a TOOL-INPUT list and
	// inputs/webcache_toxicache.txt is toxicache's own -o output — neither is
	// staging.
	stagingPath := filepath.Join(inputsDir, "findings.webcache.jsonl")
	stageVulnFindings(app, "vulns.webcache", stagingPath, engineRan, allFindings)

	// XCUT-07: log only count, never raw cache poisoning PoC headers.
	if app.Log != nil {
		app.Log.Info("vulns.webcache: completed", "webcache_findings", len(allFindings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"webcache_findings": len(allFindings)},
	}, nil
}

// wcvsIsConfirmedPoison returns true if the WCVS output line indicates a
// confirmed cache poisoning finding.
//
// WCVS outputs confirmation markers like "[VULN]", "[VULNERABLE]",
// "Web Cache Poisoning Found", or "poisoning confirmed" on successful findings.
func wcvsIsConfirmedPoison(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "[vuln]") ||
		strings.Contains(lower, "[vulnerable]") ||
		strings.Contains(lower, "poisoning found") ||
		strings.Contains(lower, "poisoning confirmed") ||
		strings.Contains(lower, "cache poison")
}

// wcvsExtractHost extracts the hostname from a WCVS output line for XCUT-07-safe
// record storage. WCVS output lines may contain the target URL; we extract only
// the hostname, never storing raw injected headers.
func wcvsExtractHost(line string) string {
	// WCVS typically includes the target URL in confirmation lines.
	// Extract the first http(s):// URL and return its hostname only.
	fields := strings.Fields(line)
	for _, f := range fields {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			parsed, err := url.Parse(f)
			if err == nil && parsed.Host != "" {
				return strings.ToLower(parsed.Hostname())
			}
		}
	}
	return ""
}

// parseToxicacheOutput parses toxicache plain-text output into VulnFindingRecord
// slice. toxicache writes confirmed poisoning lines to a plain-text output file.
//
// XCUT-07: raw injected cache headers NEVER written to records or logs.
// Only the hostname is extracted for MatchedParam.
func parseToxicacheOutput(data []byte) []VulnFindingRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var records []VulnFindingRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// toxicache writes one confirmed-poisoning URL per line.
		// XCUT-07: extract hostname only; raw poison header never stored.
		host := toxicacheExtractHost(line)
		records = append(records, VulnFindingRecord{
			Host:            host, // scope-gate locator (findings:host|url)
			Severity:        "high",
			Confidence:      "medium",
			VulnClass:       "webcache",
			MatchedParam:    host,  // hostname only — no raw poison headers
			PayloadRedacted: "***", // XCUT-07: raw toxicache payload never written
			PoCRedacted:     "***", // XCUT-07: raw PoC never written
			Engine:          "toxicache",
		})
	}
	return records
}

// toxicacheExtractHost extracts the hostname from a toxicache output line.
func toxicacheExtractHost(line string) string {
	// toxicache output lines are typically "https://host.example.com [VULN]" or similar.
	fields := strings.Fields(line)
	if len(fields) > 0 {
		parsed, err := url.Parse(fields[0])
		if err == nil && parsed.Host != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}
	return ""
}

// init self-registers WebCacheTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&WebCacheTask{}) }
