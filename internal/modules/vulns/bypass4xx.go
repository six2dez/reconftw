// bypass4xx.go — Bypass4xxTask: nomore403 4xx bypass scanner (VULN-13).
//
// Bypass4xxTask reads artefacts/fuzz.jsonl (Phase 5 ffuf output), filters for
// 4xx responses excluding 404, and runs nomore403 to discover bypass techniques.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — follows the vulns DAG root; inputs
// come from Phase 5 web run (artefacts/fuzz.jsonl), not from GFTask directly.
//
// REPO-CLONE BINARY (mirrors web/nomore403.go Pitfall 2):
// nomore403 is NOT a `go install` tool. It is cloned from GitHub and built
// locally. The binary is resolved via os.Stat (not exec.LookPath) at:
//
//	<tools_dir>/nomore403/nomore403
//
// CRITICAL (T-05-16 mitigation carried to vulns phase):
// nomore403 must run with cmd.Dir = <tools_dir>/nomore403 because it resolves
// wordlists at paths relative to its own directory. exec.CommandContext is used
// directly (same sanctioned pattern as web/nomore403.go). This file is in the
// FOUND-10 allowlist.
//
// INPUT FILTER (mirrors web/nomore403.go):
// Only 4xx responses excluding 404 are meaningful bypass candidates.
// v1 reference: vulns.sh:762 — grep 4xx not 404, awk $3.
//
// STAGING: inputs/bypass4xx_targets.txt (URL list written before nomore403 call).
// OUTPUT:  inputs/findings.bypass4xx.jsonl (staging contract — doc.go).
//
// PAYLOAD REDACTION (XCUT-07):
// nomore403 stdout bypass lines contain target URL path info.
// PayloadRedacted = "***" always. PoCRedacted = "***" always.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-07-PLAN.md Task 2.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// fuzzJSONLRecord is the minimal fuzz.jsonl record shape for 4xx URL extraction.
// Matches the FuzzRecord schema from internal/modules/web/ffuf.go (D-W11).
type fuzzJSONLRecord struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// Bypass4xxTask runs nomore403 against 4xx URLs from fuzz.jsonl (VULN-13).
type Bypass4xxTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *Bypass4xxTask) Name() string { return "vulns.bypass4xx" }

// Module returns the owning module group.
func (t *Bypass4xxTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *Bypass4xxTask) Description() string {
	return "4xx bypass (nomore403 on fuzz.jsonl 4xx URLs)"
}

// Enabled reads cfg.Vulns.Bypass4xx.Enabled.
func (t *Bypass4xxTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.Bypass4xx.Enabled }

// DependsOn returns the DAG edges — Bypass4xxTask follows the vulns DAG root.
// The fuzz.jsonl input comes from Phase 5 (artefacts/fuzz.jsonl); vulns.gf
// ensures the DAG sequencing contract is honoured.
func (t *Bypass4xxTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the nomore403 4xx bypass pipeline:
//  1. Check nomore403 binary exists (repo-clone tool).
//  2. Read artefacts/fuzz.jsonl; filter 4xx excluding 404; collect URLs.
//  3. Skip if no 4xx bypass candidates.
//  4. Write inputs/bypass4xx_targets.txt.
//  5. Run nomore403 with collected URLs as stdin.
//  6. Parse stdout for bypass lines.
//  7. Write inputs/findings.bypass4xx.jsonl.
func (t *Bypass4xxTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	workDir := app.Target.WorkDir

	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.bypass4xx: mkdir inputs/: %w", err)
	}

	// Step 1: Check nomore403 binary (repo-clone — os.Stat, not exec.LookPath).
	// T-05-16 / Pitfall 2 mitigation: repo-clone tools use os.Stat for binary check.
	toolsDir := resolveToolsDirVulns(cfg)
	binaryPath := filepath.Join(toolsDir, "nomore403", "nomore403")
	if _, err := os.Stat(binaryPath); err != nil {
		if app.Log != nil {
			app.Log.Info("vulns.bypass4xx: nomore403 binary not found — run reconftw install",
				"path", binaryPath)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 2: Read fuzz.jsonl; collect 4xx URLs excluding 404.
	fuzzURLs, err := read4xxURLsFromVulnsFuzzJSONL(workDir)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.bypass4xx: read fuzz.jsonl error", "err", err)
	}
	// Step 3: Skip if no 4xx bypass candidates.
	if len(fuzzURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.bypass4xx: no 4xx URLs in fuzz.jsonl — bypass4xx skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 4: Write inputs/bypass4xx_targets.txt.
	targetsFile := filepath.Join(inputsDir, "bypass4xx_targets.txt")
	if wErr := os.WriteFile(targetsFile,
		[]byte(strings.Join(fuzzURLs, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.bypass4xx: write bypass4xx_targets.txt: %w", wErr)
	}

	// Step 5: Run nomore403 with collected URLs piped as stdin.
	//
	// nomore403 is a repo-clone tool with relative-path wordlist dependencies.
	// Backend.Stream/Run does not expose cmd.Dir or stdin injection; exec.Cmd
	// is used directly (same sanctioned pattern as web/nomore403.go — FOUND-10
	// allowlist: internal/modules/vulns/bypass4xx.go).
	inputData := []byte(strings.Join(fuzzURLs, "\n") + "\n")
	toolDir := filepath.Join(toolsDir, "nomore403")

	// Bounded context: nomore403.timeout_seconds=300 (mirrors web/nomore403.go CR-07).
	toolTimeout := 300 * time.Second
	cmdCtx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()

	//nolint:gosec // binaryPath validated by os.Stat above; toolDir from validated config
	cmd := exec.CommandContext(cmdCtx, binaryPath)
	cmd.Dir = toolDir // CRITICAL: nomore403 resolves wordlists relative to its own dir
	cmd.Stdin = bytes.NewReader(inputData)

	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	if runErr := cmd.Run(); runErr != nil {
		// nomore403 may exit non-zero when no bypasses are found; treat as empty result.
		if app.Log != nil {
			app.Log.Debug("vulns.bypass4xx: nomore403 exited non-zero (may be normal)",
				"err", runErr)
		}
	}

	// Step 6: Parse stdout for bypass lines.
	findings := parseBypass4xxOutput(outBuf.Bytes())

	// Step 7: Write inputs/findings.bypass4xx.jsonl (staging contract — doc.go).
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
			stagingPath := filepath.Join(inputsDir, "findings.bypass4xx.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.bypass4xx: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Info("vulns.bypass4xx: completed",
			"input_urls", len(fuzzURLs),
			"bypasses", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"bypasses": len(findings)},
	}, nil
}

// read4xxURLsFromVulnsFuzzJSONL reads artefacts/fuzz.jsonl and returns URLs with
// status codes 400-499 excluding 404 (bypass candidates per v1 vulns.sh:762).
// Mirrors web/nomore403.go read4xxURLsFromFuzzJSONL but operates from workDir
// directly (not through AppContext to avoid cross-package dependency).
func read4xxURLsFromVulnsFuzzJSONL(workDir string) ([]string, error) {
	fuzzPath := filepath.Join(workDir, "artefacts", "fuzz.jsonl")
	data, err := os.ReadFile(fuzzPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read fuzz.jsonl: %w", err)
	}
	var urls []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec fuzzJSONLRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		// Filter: 4xx excluding 404 (status >= 400 AND <= 499 AND != 404).
		if rec.Status >= 400 && rec.Status <= 499 && rec.Status != 404 && rec.URL != "" {
			urls = append(urls, rec.URL)
		}
	}
	return urls, sc.Err()
}

// parseBypass4xxOutput parses nomore403 stdout.
// Each non-empty line is a potential bypass result — either a URL or a status indicator.
// XCUT-07: PayloadRedacted = "***"; PoCRedacted = "***" always.
func parseBypass4xxOutput(data []byte) []VulnFindingRecord {
	if len(data) == 0 {
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
		// nomore403 outputs bypass results as plain text lines.
		// A successful bypass typically shows "200 <url>" or similar.
		lower := strings.ToLower(line)
		isBypass := strings.Contains(lower, "200") ||
			strings.Contains(lower, "bypass") ||
			strings.Contains(lower, "ok")
		if !isBypass {
			continue
		}
		records = append(records, VulnFindingRecord{
			// Scope-gate locator: nomore403 prints the bypassed URL inside the
			// result line (e.g. "200 https://host/path"), so the per-finding
			// host is recoverable without falling back to the scan target.
			Host: bypass4xxExtractHost(line),
			// Phase 4/5 SARIF-compatible fields.
			Severity:   "low",
			Confidence: "medium",
			// Phase 6 vuln-class fields.
			VulnClass:       "4xx-bypass",
			PayloadRedacted: "***", // XCUT-07
			PoCRedacted:     "***", // XCUT-07
			Engine:          "nomore403",
		})
	}
	return records
}

// bypass4xxExtractHost pulls the hostname out of a nomore403 result line.
// The tool prints free-form text with the tested URL embedded (e.g.
// "200 https://api.example.com/admin"), so the first URL-looking token wins.
// Returns "" when no token carries a scheme — the caller then has no
// per-finding locator and the record is dropped by the merge scope filter
// rather than poisoning the batch.
func bypass4xxExtractHost(line string) string {
	for _, tok := range strings.Fields(line) {
		if strings.Contains(tok, "://") {
			return findingHost(tok)
		}
	}
	return ""
}

// init self-registers Bypass4xxTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&Bypass4xxTask{}) }
