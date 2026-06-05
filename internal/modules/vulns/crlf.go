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

	// Step 1: Read artefacts/urls.jsonl — host URL list from Phase 5.
	hostURLs, err := readURLsForCRLF(app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.crlf: read urls.jsonl error (best_effort)", "err", err)
	}
	if len(hostURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.crlf: no host URLs in artefacts/urls.jsonl — skipping")
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
	stagingData, readErr := os.ReadFile(stagingTxt) //nolint:gosec // path within WorkDir
	if readErr != nil {
		if os.IsNotExist(readErr) {
			// No findings — normal for a clean target.
			if app.Log != nil {
				app.Log.Info("vulns.crlf: completed", "findings", 0)
			}
			return task.Result{
				Status: task.StatusDone,
				Stats:  map[string]int{"findings": 0},
			}, nil
		}
		if app.Log != nil {
			app.Log.Debug("vulns.crlf: read staging file error (best_effort)", "err", readErr)
		}
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"findings": 0},
		}, nil
	}

	records := parseCRLFuzzOutput(stagingData)

	// Step 5: Write inputs/findings.crlf.jsonl.
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
			stagingPath := filepath.Join(inputsDir, "findings.crlf.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.crlf: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

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

// readURLsForCRLF reads artefacts/urls.jsonl and returns all URL strings.
// Returns nil when the file is absent or empty (non-error for CRLFTask).
func readURLsForCRLF(app *appctx.AppContext) ([]string, error) {
	urlsPath := filepath.Join(app.Target.WorkDir, "artefacts", "urls.jsonl")
	data, err := os.ReadFile(urlsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // urls.jsonl not yet produced — non-error
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var urls []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.URL != "" {
			urls = append(urls, rec.URL)
		}
	}
	return urls, nil
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
