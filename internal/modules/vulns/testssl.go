// testssl.go — TestSSLTask: testssl.sh TLS misconfiguration scanner (D-V3).
//
// TestSSLTask is a D-V3 fold-in from vulns.sh test_ssl(), per plan 06-08
// (VULN-14 parity completeness gate).
//
// INPUT PRECEDENCE (mirrors v1 test_ssl() lines 594-597):
//  1. artefacts/ips_nocdn.txt — non-CDN IPs preferred (avoids testing CDN TLS)
//  2. artefacts/hosts.jsonl   — hostname fallback
//  3. StatusSkipped if neither exists or both are empty
//
// ARG VECTOR (v1 vulns.sh:599 verbatim):
//
//	testssl.sh --quiet --color 0 -U -iL <targetsFile>
//
// testssl.sh is a bash script invoked via app.Tools.Run as "testssl.sh".
// The binary must be on PATH or configured via cfg.Advanced.Tools.<entry>.
//
// XCUT-07 / T-06-08-03:
// testssl.sh output may include certificate details in error cases. Raw stdout
// is NEVER logged at Info/Warn. Only severity category counts at Info.
//
// OUTPUT: artefacts/testssl.jsonl — single-writer; direct app.Tree.Append OK
// (doc.go: single-writer artefacts do NOT go through the staging+merge pipeline).
//
// NOTE: testssl.sh produces plain-text output, not JSON. v2 records each
// finding as a structured tsslRecord (severity + description from the output
// line). Raw lines NEVER reach Info logging (XCUT-07 / T-06-08-03).
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-08-PLAN.md Task 2.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// TestSSLTask runs testssl.sh TLS misconfiguration scanner (D-V3, VULN-14).
type TestSSLTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *TestSSLTask) Name() string { return "vulns.testssl" }

// Module returns the owning module group.
func (t *TestSSLTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *TestSSLTask) Description() string {
	return "TLS misconfiguration scanner (testssl.sh)"
}

// Enabled reads cfg.Vulns.SSL.Enabled.
func (t *TestSSLTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.SSL.Enabled }

// DependsOn declares GFTask as the DAG root dependency.
func (t *TestSSLTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes testssl.sh against the IP/host target list.
//
// Steps:
//  1. Resolve input: prefer artefacts/ips_nocdn.txt → artefacts/hosts.jsonl.
//     StatusSkipped if neither exists or is empty.
//  2. Write target list to inputs/testssl_targets.txt.
//  3. Run testssl.sh --quiet --color 0 -U -iL <targetsFile> via app.Tools.Run.
//     On error → log.Debug (best_effort).
//  4. Parse stdout for TLS finding lines (XCUT-07: raw lines NOT logged at Info).
//  5. Write artefacts/testssl.jsonl via app.Tree.Append (single-writer).
func (t *TestSSLTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "testssl.sh"
	workDir := app.Target.WorkDir

	// Step 1: Resolve input file (mirrors v1 test_ssl() precedence).
	targetsData, err := resolveTestSSLInput(workDir)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.testssl: input resolution error (best_effort)", "err", err)
	}
	if len(targetsData) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.testssl: no IP/host targets — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.testssl: mkdir inputs/: %w", err)
	}

	// Step 2: Write target list to inputs/testssl_targets.txt.
	targetsFile := filepath.Join(inputsDir, "testssl_targets.txt")
	if wErr := os.WriteFile(targetsFile, targetsData, 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.testssl: write testssl_targets.txt: %w", wErr)
	}

	// Context cancellation check.
	select {
	case <-ctx.Done():
		return task.Result{Status: task.StatusCancelled},
			fmt.Errorf("vulns.testssl: cancelled: %w", ctx.Err())
	default:
	}

	// Step 3: Run testssl.sh --quiet --color 0 -U -iL <targetsFile>.
	// v1 arg vector (vulns.sh:599): testssl.sh --quiet --color 0 -U -iL "$testssl_input"
	args := []string{"--quiet", "--color", "0", "-U", "-iL", targetsFile}

	res, runErr := app.Tools.Run(ctx, toolName, args)
	if runErr != nil && app.Log != nil {
		// testssl.sh may exit non-zero even when it produces findings.
		// Non-fatal per best_effort policy — parse whatever stdout was produced.
		app.Log.Debug("vulns.testssl: testssl.sh exit error (best_effort — parsing output)",
			"err", runErr)
	}

	// Step 4: Parse stdout for TLS finding lines.
	// XCUT-07 / T-06-08-03: raw testssl.sh stdout NEVER logged at Info/Warn.
	// Only category counts are surfaced.
	records := parseTestSSLOutput(res.Stdout)

	// Step 5: Write artefacts/testssl.jsonl via direct app.Tree.Append (single-writer).
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
			if wErr := app.Tree.Append("testssl", lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.testssl: Tree.Append failed",
					"records", len(lines), "err", wErr)
			}
		}
	}

	// XCUT-07 / T-06-08-03: log only finding count, never raw testssl output.
	if app.Log != nil {
		app.Log.Info("vulns.testssl: completed", "findings", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// tsslRecord is the artefacts/testssl.jsonl schema for a TLS misconfiguration finding.
// XCUT-07 / T-06-08-03: no raw certificate content or key material is stored.
type tsslRecord struct {
	Severity    string `json:"severity"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
	Engine      string `json:"engine"` // "testssl.sh"
}

// testSSLSeverityPrefixes maps testssl.sh output line prefixes to severity labels.
// testssl.sh uses colour codes and bracket markers in its output.
// These are the plain-text (--color 0) severity indicators.
var testSSLSeverityPrefixes = []struct {
	prefix   string
	severity string
}{
	{"CRITICAL", "critical"},
	{"HIGH", "high"},
	{"MEDIUM", "medium"},
	{"LOW", "low"},
	{"INFO", "info"},
	{"OK", "info"},
	{"WARN", "warn"},
	{"NOT OK", "medium"}, // testssl.sh "NOT ok" lines indicate issues
	{"not ok", "medium"},
}

// parseTestSSLOutput parses testssl.sh plain-text output (--color 0) into
// tsslRecord slice. Only vulnerability/misconfiguration finding lines are
// retained (lines containing severity indicators).
//
// XCUT-07 / T-06-08-03: raw certificate details and key material NEVER stored.
// Only the severity category + a sanitized description fragment are written.
func parseTestSSLOutput(data []byte) []tsslRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var records []tsslRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		// Only process lines that indicate a finding (severity prefix present).
		severity, category, desc, ok := classifyTestSSLLine(line)
		if !ok {
			continue
		}

		// XCUT-07: sanitize description to remove potential key/cert content.
		// Truncate to 200 chars and strip any PEM-like content.
		desc = sanitizeTestSSLDesc(desc)

		records = append(records, tsslRecord{
			Severity:    severity,
			Category:    category,
			Description: desc,
			Engine:      "testssl.sh",
		})
	}
	return records
}

// classifyTestSSLLine inspects a testssl.sh plain-text output line and extracts
// severity, category, and sanitized description. Returns ok=false for non-finding lines.
func classifyTestSSLLine(line string) (severity, category, desc string, ok bool) {
	upper := strings.ToUpper(line)

	// Check for known severity/finding markers in the line.
	for _, sp := range testSSLSeverityPrefixes {
		if strings.Contains(upper, strings.ToUpper(sp.prefix)) {
			// Extract a category from the first token of the line.
			parts := strings.Fields(line)
			cat := ""
			if len(parts) > 0 {
				cat = parts[0]
				if len(cat) > 50 { // cap category token length
					cat = cat[:50]
				}
			}
			// Description: everything after the category token.
			d := ""
			if len(parts) > 1 {
				d = strings.Join(parts[1:], " ")
			}
			return sp.severity, cat, d, true
		}
	}
	return "", "", "", false
}

// sanitizeTestSSLDesc removes PEM-like content and truncates to 200 chars.
// XCUT-07: prevents private key material or certificate data from being stored.
func sanitizeTestSSLDesc(desc string) string {
	// Remove anything that looks like PEM content.
	if strings.Contains(desc, "-----BEGIN") || strings.Contains(desc, "-----END") {
		return "[certificate-data-redacted]"
	}
	// Truncate to a safe maximum length.
	const maxLen = 200
	if len(desc) > maxLen {
		return desc[:maxLen] + "..."
	}
	return desc
}

// resolveTestSSLInput implements the v1 test_ssl() input precedence:
//  1. artefacts/ips_nocdn.txt — non-CDN IPs preferred (avoids testing CDN TLS)
//  2. artefacts/hosts.jsonl — hostname fallback
//
// Returns the file contents as a []byte ready to write to inputs/testssl_targets.txt.
// Returns nil when no suitable input is found (caller emits StatusSkipped).
func resolveTestSSLInput(workDir string) ([]byte, error) {
	// Priority 1: artefacts/ips_nocdn.txt (non-CDN IPs).
	noCDNPath := filepath.Join(workDir, "artefacts", "ips_nocdn.txt")
	if data, err := os.ReadFile(noCDNPath); err == nil && len(bytes.TrimSpace(data)) > 0 { //nolint:gosec
		return data, nil
	}

	// Priority 2: artefacts/hosts.jsonl — extract hostnames.
	hostsPath := filepath.Join(workDir, "artefacts", "hosts.jsonl")
	data, err := os.ReadFile(hostsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	// hosts.jsonl may be JSON-per-line or plain hostnames.
	var hosts []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		// Try JSON with "host" field.
		var rec struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err == nil && rec.Host != "" {
			hosts = append(hosts, rec.Host)
			continue
		}
		// Plain hostname line.
		h := strings.TrimSpace(string(line))
		if h != "" && !strings.HasPrefix(h, "{") {
			hosts = append(hosts, h)
		}
	}

	if len(hosts) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(hosts, "\n") + "\n"), nil
}

// init self-registers TestSSLTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&TestSSLTask{}) }
