// crlf.go — CRLFTask: crlfuzz scanner (VULN-06).
//
// CRLFTask reads the probed host URL list from artefacts/urls.jsonl (Phase 5
// web output), writes a temp host file, runs crlfuzz, and stores findings in
// inputs/findings.crlf.jsonl per the multi-writer staging contract.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — v1 crlf_checks() runs after url_gf()
// in the vulns pipeline; the gf DAG root ensures the URL corpus is ready.
//
// INPUT: artefacts/urls.jsonl — host URL list from Phase 5 web probe (D-V5).
// crlfuzz does NOT need gf-pattern-filtered input; it tests all web hosts
// (v1 crlf_checks reads webs/webs_all.txt, the unfiltered host list).
//
// ARG VECTOR (v1 vulns.sh:223 verbatim):
//
//	crlfuzz -l <hostsFile> -o <stagingTxt>
//
// PAYLOAD REDACTION (XCUT-07, T-06-02-02):
// crlfuzz output lines contain raw CRLF injection sequences (\r\n).
// These MUST NOT appear in logs. Only finding count is logged at Info.
// MatchedAt and PoCRedacted fields are always "***".
//
// HEARTBEAT (XCUT-09):
// crlfuzz on a large host set can run >5 min. Backend.Stream is used for the
// heartbeat — the event channel is drained in a goroutine so the UI never
// appears stuck.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-02-PLAN.md Task 2.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// CRLFTask runs the crlfuzz CRLF injection scanner for VULN-06.
type CRLFTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *CRLFTask) Name() string { return "vulns.crlf" }

// Module returns the owning module group.
func (t *CRLFTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *CRLFTask) Description() string {
	return "CRLF injection scanner (crlfuzz)"
}

// Enabled reports whether CRLF scanning is configured.
func (t *CRLFTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.CRLF.Enabled }

// DependsOn returns the DAG edges — CRLFTask consumes the URL corpus prepared
// by the vulns pipeline after GFTask (mirrors v1 sequencing where crlf_checks
// runs after url_gf in the vulns pipeline).
func (t *CRLFTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes crlfuzz against the probed host URL list.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract URL strings — skip if empty.
//  2. Write host URLs to inputs/crlfuzz_hosts.txt temp file.
//  3. Run crlfuzz -l <hostsFile> -o <stagingTxt> via Backend.Stream (XCUT-09).
//  4. Read stagingTxt; parse lines as VulnFindingRecord (XCUT-07 redaction).
//  5. Write inputs/findings.crlf.jsonl via output.WriteJSONL.
func (t *CRLFTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "crlfuzz"

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	hostURLs, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.crlf: read URL corpus error (best_effort)", "err", err)
	}
	if len(hostURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.crlf: no host URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.crlf: mkdir inputs/: %w", err)
	}

	// Step 2: Write host URLs to temp file for crlfuzz -l flag.
	hostsFile := filepath.Join(inputsDir, "crlfuzz_hosts.txt")
	if wErr := os.WriteFile(hostsFile,
		[]byte(strings.Join(hostURLs, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.crlf: write crlfuzz_hosts.txt: %w", wErr)
	}

	// stagingTxt is crlfuzz's plain-text output file (vulnerable URLs, one per line).
	stagingTxt := filepath.Join(inputsDir, "findings.crlfuzz.txt")

	// Step 3: Run crlfuzz via Backend.Stream (XCUT-09 heartbeat).
	// v1 arg vector: crlfuzz -l <file> -o <stagingTxt>
	args := []string{"-l", hostsFile, "-o", stagingTxt}

	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	// crlfuzzRan records whether crlfuzz was actually DISPATCHED. A dispatch
	// failure means the binary is absent: the task observed nothing and must not
	// clear a previous run's staging (F3 did-not-run — staging.go).
	crlfuzzRan := streamErr == nil
	if streamErr != nil {
		if app.Log != nil {
			app.Log.Debug("vulns.crlf: crlfuzz stream error (best_effort)", "err", streamErr)
		}
		// Non-fatal per best_effort policy — proceed; stagingTxt may still have output
		// if crlfuzz wrote it before exiting, or be absent (handled below).
	} else {
		// Drain the event channel — Backend contract requires full drain.
		// XCUT-07 / T-06-02-02: events contain raw CRLF sequences; NEVER log at Info.
		for range eventCh { //nolint:revive // intentional drain — raw CRLF not logged
		}
	}

	// Step 4: Read and parse crlfuzz staging output.
	//
	// F3 (phase 15): both read-failure paths used to `return StatusDone` HERE,
	// one statement before the staging write. That is the same run-isolation bug
	// as an unconditional write, and no AST guard can see it — the detector
	// reports raw WRITES, not a return placed in front of a correct one. A clean
	// target (no output file at all) therefore republished the previous run's
	// CRLF injections forever. Both paths now fall through to the staging call
	// with zero records, which CLEARS the file.
	stagingData, readErr := os.ReadFile(stagingTxt) //nolint:gosec // path within WorkDir
	if readErr != nil && app.Log != nil {
		if os.IsNotExist(readErr) {
			// No output file — normal for a clean target.
			app.Log.Debug("vulns.crlf: no crlfuzz output file — zero findings this run")
		} else {
			app.Log.Debug("vulns.crlf: read staging file error (best_effort)", "err", readErr)
		}
	}

	records := parseCRLFuzzOutput(stagingData)

	// Step 5: Write inputs/findings.crlf.jsonl.
	//
	// NOTE the OTHER inputs/ writes in this function — inputs/crlfuzz_hosts.txt
	// (the -l TOOL-INPUT list) and inputs/findings.crlfuzz.txt (crlfuzz's own -o
	// plain-text output, which the subdomains .txt merger globs do not cover) —
	// are not staging and keep their existing handling.
	stagingPath := filepath.Join(inputsDir, "findings.crlf.jsonl")
	stageVulnFindings(app, "vulns.crlf", stagingPath, crlfuzzRan, records)

	// XCUT-07: log only the count, never the raw CRLF payload lines.
	if app.Log != nil {
		app.Log.Info("vulns.crlf: completed", "findings", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// parseCRLFuzzOutput parses crlfuzz plain-text output into VulnFindingRecord slice.
// Each non-empty line is a vulnerable URL (containing injected \r\n sequences).
//
// XCUT-07 / T-06-02-02: raw CRLF payload lines (which contain injected CR/LF
// chars) MUST NOT appear in logs or records. MatchedAt and PoCRedacted are "***".
// Only the host (extracted from the URL) is written to the record.
func parseCRLFuzzOutput(data []byte) []VulnFindingRecord {
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
		// XCUT-07: extract hostname only; do NOT write raw vulnerable URL to record.
		host := extractCRLFHost(line)
		records = append(records, VulnFindingRecord{
			Host: host, // scope-gate locator (findings:host|url)
			// Phase 4/5 inherited SARIF-compatible fields.
			Severity:   "medium",
			Confidence: "high",
			// Phase 6 vuln-class fields.
			VulnClass:       "crlf",
			PayloadRedacted: "***", // XCUT-07: raw CRLF payload never written
			PoCRedacted:     "***", // XCUT-07: raw vulnerable URL never written
			MatchedParam:    host,  // hostname only — no payload
			Engine:          "crlfuzz",
		})
	}
	return records
}

// extractCRLFHost extracts the hostname from a crlfuzz output URL.
// crlfuzz outputs vulnerable URLs; we extract the hostname to avoid
// storing injected CRLF sequences in records (XCUT-07).
func extractCRLFHost(rawURL string) string {
	// Trim any CRLF sequences that may have leaked into the URL line.
	rawURL = strings.TrimRight(rawURL, "\r\n")
	// Take only the part before any injected CR or LF.
	if idx := strings.IndexAny(rawURL, "\r\n"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers CRLFTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&CRLFTask{}) }
