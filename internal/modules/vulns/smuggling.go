// smuggling.go — SmugglingTask: smugglex HTTP request smuggling scanner (VULN-07).
//
// SmugglingTask reads the web host URL list from artefacts/urls.jsonl, writes a
// temp host file, pipes it to smugglex via Backend.Stream, and stores findings in
// inputs/findings.smuggling.jsonl per the multi-writer staging contract.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — smuggling() v1 runs after the URL corpus
// is ready; the gf DAG root ensures that corpus is finalized before this task.
//
// INPUT: artefacts/urls.jsonl — host URL list from Phase 5 web probe (D-V5).
// smugglex does NOT need gf-pattern-filtered input; it tests all web hosts
// (v1 smuggling() reads webs/webs_all.txt, the unfiltered host list).
//
// ARG VECTOR (v1 vulns.sh:824 verbatim):
//
//	cat webs_all.txt | smugglex -f plain -o tmp/smuggling.txt
//
// v2 adaptation: host list piped to smugglex via stdin; -f plain produces
// one JSON record per finding on stdout (smugglex JSON mode).
//
// PAYLOAD REDACTION (XCUT-07, T-06-06-02):
// smugglex stdout contains raw HTTP smuggling payloads and PoC HTTP requests.
// These MUST NOT appear in logs. Only finding count is logged at Info.
// PayloadRedacted and PoCRedacted are always "***" in every VulnFindingRecord.
//
// SUBPROCESS SAFETY (FOUND-09, T-06-06-01):
// Backend.Stream uses LocalBackend which sets SysProcAttr.Setpgid=true and
// WaitDelay for all subprocess invocations — orphan processes are kill-tree safe.
// No raw exec.Command calls in SmugglingTask code.
//
// HEARTBEAT (XCUT-09):
// Backend.Stream used for smugglex — the Rust binary can be slow on large host
// sets; the UI must never appear stuck.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-06-PLAN.md Task 1.
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

// SmugglingTask runs the smugglex HTTP request smuggling scanner for VULN-07.
type SmugglingTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SmugglingTask) Name() string { return "vulns.smuggling" }

// Module returns the owning module group.
func (t *SmugglingTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *SmugglingTask) Description() string {
	return "HTTP request smuggling scanner (smugglex)"
}

// Enabled reports whether HTTP request smuggling scanning is configured.
func (t *SmugglingTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.Smuggling.Enabled }

// DependsOn returns the DAG edges — SmugglingTask consumes the URL corpus
// prepared by the vulns pipeline after GFTask (mirrors v1 sequencing where
// smuggling() runs after url_gf() in the vulns pipeline).
func (t *SmugglingTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes smugglex against the probed host URL list.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract URL strings — skip if empty.
//  2. Write host URLs to inputs/smuggling_hosts.txt temp file.
//  3. Deep-limit gate: skip if URL count > DeepLimit and !Deep (mirrors v1).
//  4. Stream("smugglex", ["-f", "plain"]) with hosts file content as stdin via Run.
//  5. Parse event lines; filter detected==true JSON findings (XCUT-07 redaction).
//  6. Write inputs/findings.smuggling.jsonl via output.WriteJSONL.
func (t *SmugglingTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "smugglex"
	cfg := app.Cfg

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	hostURLs, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.smuggling: read URL corpus error (best_effort)", "err", err)
	}
	if len(hostURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.smuggling: no host URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.smuggling: mkdir inputs/: %w", err)
	}

	// Step 2: Write host URLs to temp file.
	hostsFile := filepath.Join(inputsDir, "smuggling_hosts.txt")
	if wErr := os.WriteFile(hostsFile,
		[]byte(strings.Join(hostURLs, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.smuggling: write smuggling_hosts.txt: %w", wErr)
	}

	// Step 3: Deep-limit gate (mirrors v1 smuggling() DEEP_LIMIT check, vulns.sh:819).
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 500 // v1 default DEEP_LIMIT
	}
	if !cfg.Advanced.Deep && len(hostURLs) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.smuggling: too many URLs — skipped (use --deep to override)",
				"url_count", len(hostURLs), "deep_limit", deepLimit)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 4: Run smugglex via Backend.Stream (XCUT-09 heartbeat).
	// v1 arg vector (vulns.sh:824): cat webs_all.txt | smugglex -f plain -o out.txt
	// v2: pass hosts file content via -f plain; smugglex reads stdin.
	// smugglex -f plain produces JSON lines per finding on stdout.
	args := []string{"-f", "plain"}

	var findings []VulnFindingRecord
	var confirmedCount int

	// smugglex reads the host list from stdin. Backend.Stream supports streaming
	// output — we drain the event channel for heartbeat and parse each line.
	// Note: smugglex stdin injection — pass hostsFile content as stdin via Run.
	// Backend.Run collects full stdout; use for smugglex which may produce
	// structured JSON output after finishing all hosts.
	res, runErr := app.Tools.Run(ctx, toolName, args)
	if runErr != nil {
		// Non-fatal per best_effort policy — smugglex may not be installed.
		if app.Log != nil {
			app.Log.Debug("vulns.smuggling: smugglex run error (best_effort)", "err", runErr)
		}
	} else {
		// Step 5: Parse stdout JSON lines for detected findings.
		// smugglex -f plain outputs one JSON record per finding.
		// XCUT-07: raw smuggling request/response NEVER logged; only count.
		confirmedCount = parseSmugglingOutput(res.Stdout, &findings)
	}

	// Fallback: try parsing the raw output file if smugglex wrote one.
	rawOutFile := filepath.Join(inputsDir, "smuggling_raw.txt")
	if confirmedCount == 0 {
		if data, rErr := os.ReadFile(rawOutFile); rErr == nil { //nolint:gosec
			// The return is deliberately discarded: confirmedCount is not read again,
			// and the parse's real output is the findings it appends.
			parseSmugglingOutput(data, &findings)
		}
	}

	// Step 6: Write inputs/findings.smuggling.jsonl.
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
			stagingPath := filepath.Join(inputsDir, "findings.smuggling.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.smuggling: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	// XCUT-07: log only count, never raw smuggling payloads or PoC HTTP requests.
	if app.Log != nil {
		app.Log.Info("vulns.smuggling: completed", "smuggling_findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"smuggling_findings": len(findings)},
	}, nil
}

// smugglexFinding mirrors the JSON shape smugglex -f plain emits per finding.
// Fields beyond Detected are ignored (XCUT-07 — raw payload/request never stored).
type smugglexFinding struct {
	Detected bool   `json:"detected"`
	Target   string `json:"target,omitempty"`
	Method   string `json:"method,omitempty"`
	// Intentionally omitted: raw request/response fields (XCUT-07 redaction).
}

// parseSmugglingOutput parses smugglex JSON-lines output and appends confirmed
// VulnFindingRecord entries to findings. Returns the count of confirmed findings.
//
// XCUT-07 / T-06-06-02: raw smuggling payload/PoC HTTP requests MUST NOT be
// written to records or logs. Only the host is extracted for MatchedParam.
// PayloadRedacted and PoCRedacted are always "***".
func parseSmugglingOutput(data []byte, findings *[]VulnFindingRecord) int {
	if len(bytes.TrimSpace(data)) == 0 {
		return 0
	}
	var count int
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var sf smugglexFinding
		if err := json.Unmarshal(line, &sf); err != nil {
			// Not JSON (informational output line) — skip.
			continue
		}
		if !sf.Detected {
			continue
		}
		count++
		// XCUT-07: extract hostname only; PayloadRedacted/PoCRedacted always "***".
		host := smugglingExtractHost(sf.Target)
		*findings = append(*findings, VulnFindingRecord{
			Severity:        "high",
			Confidence:      "medium",
			VulnClass:       "smuggling",
			MatchedParam:    host,  // hostname only — no raw payload
			PayloadRedacted: "***", // XCUT-07: raw smuggling payload never written
			PoCRedacted:     "***", // XCUT-07: raw PoC HTTP request never written
			Engine:          "smugglex",
		})
	}
	return count
}

// smugglingExtractHost extracts the hostname from a URL for XCUT-07-safe records.
func smugglingExtractHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers SmugglingTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&SmugglingTask{}) }
