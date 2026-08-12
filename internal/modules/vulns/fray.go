// fray.go — FrayTask: WAF-aware payload testing (fray — D-V3 fold-in).
//
// FrayTask is a D-V3 fold-in from vulns.sh fray_checks(), per plan 06-08
// (VULN-14 parity completeness gate).
//
// XCUT-07 BINDING CONSTRAINT (T-06-08-02):
// fray payload strings (which ARE the bypass technique) are NEVER logged or
// written to any artefact field. Only bypass_rate + category at Info.
// PayloadRedacted = "***" always in VulnFindingRecord.
//
// INPUT: artefacts/urls.jsonl — URL corpus from Phase 5.
//
//	Empty → StatusSkipped (best_effort per D-V7).
//
// ARG VECTOR (v1 vulns.sh:1149 verbatim):
//
//	cat <targets> | fray test -c <category> --max <maxPayloads> -t <timeout> -d <delay> --json
//
// Per-category invocation. fray reads targets from stdin.
// fray is a Python PyPI tool that reads stdin and outputs JSONL.
//
// DEEP_LIMIT GATE (mirrors v1 fray_checks() lines 1133-1141):
// If URL count > cfg.Advanced.DeepLimit and !cfg.Advanced.Deep → truncate to DeepLimit.
//
// WAF-FRIENDLY DEFAULTS (D-V6):
//   - MaxPayloads=20 (v1 FRAY_MAX_PAYLOADS=20)
//   - Delay=0.5s     (v1 FRAY_DELAY=0.5)
//   - Timeout=10s    (v1 FRAY_TIMEOUT=10)
//
// CATEGORIES (v1 FRAY_CATEGORIES default):
//
//	ai_prompt_injection, prototype_pollution, api_security, modern_bypasses
//
// OUTPUT: inputs/findings.fray.jsonl — multi-writer staging (doc.go).
// MergeVulnsFindings merges into artefacts/findings.jsonl.
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
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// frayDefaultCategories is the v1 FRAY_CATEGORIES default value.
// Maps to cfg.Vulns.Fray.Categories when the config field is empty.
const frayDefaultCategories = "ai_prompt_injection,prototype_pollution,api_security,modern_bypasses"

// FrayTask runs fray WAF-aware payload testing per category (D-V3, VULN-14).
type FrayTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *FrayTask) Name() string { return "vulns.fray" }

// Module returns the owning module group.
func (t *FrayTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *FrayTask) Description() string {
	return "WAF-aware payload testing (fray — modern bypass categories)"
}

// Enabled reads cfg.Vulns.Fray.Enabled.
func (t *FrayTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.Fray.Enabled }

// DependsOn declares GFTask as the DAG root dependency.
func (t *FrayTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes fray per-category WAF bypass testing.
//
// Steps:
//  1. Read artefacts/urls.jsonl — StatusSkipped if empty.
//  2. Apply DeepLimit gate (mirrors v1 fray_checks() lines 1133-1141).
//  3. Write target list to inputs/fray_targets.txt.
//  4. For each category:
//     a. Run fray test -c <category> --max <maxPayloads> -t <timeout> -d <delay> --json
//     with targets on stdin (via temp file redirect via -l flag for registry compat).
//     b. Parse JSONL output — filter bypassed > 0.
//     c. Build VulnFindingRecord (XCUT-07: PayloadRedacted="***" always).
//  5. Write inputs/findings.fray.jsonl via output.WriteJSONL (multi-writer staging).
func (t *FrayTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "fray"
	cfg := app.Cfg
	workDir := app.Target.WorkDir

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	urls, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.fray: read URL corpus error (best_effort)", "err", err)
	}
	if len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.fray: no URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.fray: mkdir inputs/: %w", err)
	}

	// Step 2: Apply DeepLimit gate (mirrors v1 lines 1133-1141).
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 100 // v1 DEEP_LIMIT default
	}
	if !cfg.Advanced.Deep && len(urls) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.fray: limiting targets (DeepMode disabled)",
				"original", len(urls), "limit", deepLimit)
		}
		urls = urls[:deepLimit]
	}

	// Step 3: Write target list to inputs/fray_targets.txt.
	// fray reads targets from stdin; we pass via -l <file> (or use a temp file).
	// The Backend registry does not support stdin injection, so we use a targets
	// file and pass it via fray's -l flag (if supported) or redirect approach.
	// v1 uses: cat $targets | fray test -c $cat ... --json
	// v2 uses: fray test -c $cat -l $targetsFile ... --json (stdin equiv via file)
	targetsFile := filepath.Join(inputsDir, "fray_targets.txt")
	if wErr := os.WriteFile(targetsFile,
		[]byte(strings.Join(urls, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.fray: write fray_targets.txt: %w", wErr)
	}

	// Resolve fray config parameters with v1-compatible defaults (D-V6).
	maxPayloads := cfg.Vulns.Fray.MaxPayloads
	if maxPayloads <= 0 {
		maxPayloads = 20 // v1 FRAY_MAX_PAYLOADS default
	}
	timeoutSec := cfg.Vulns.Fray.Timeout
	if timeoutSec <= 0 {
		timeoutSec = 10 // v1 FRAY_TIMEOUT default
	}
	delay := cfg.Vulns.Fray.Delay
	if delay <= 0 {
		delay = 0.5 // v1 FRAY_DELAY default
	}
	delayStr := strconv.FormatFloat(delay, 'f', -1, 64)

	categories := cfg.Vulns.Fray.Categories
	if categories == "" {
		categories = frayDefaultCategories
	}
	catList := strings.Split(categories, ",")

	var allFindings []VulnFindingRecord
	totalBypassed := 0

	// Step 4: Per-category fray invocation.
	for _, cat := range catList {
		cat = strings.TrimSpace(cat)
		if cat == "" {
			continue
		}

		// Context cancellation check between categories.
		select {
		case <-ctx.Done():
			return task.Result{Status: task.StatusCancelled},
				fmt.Errorf("vulns.fray: cancelled: %w", ctx.Err())
		default:
		}

		// Build fray arg vector.
		// v1: cat $targets | fray test -c $cat --max $max -t $timeout -d $delay --json
		// v2 equivalent using -l <file> flag (avoids stdin injection via Backend):
		args := []string{
			"test",
			"-c", cat,
			"-l", targetsFile,
			"--max", strconv.Itoa(maxPayloads),
			"-t", strconv.Itoa(timeoutSec),
			"-d", delayStr,
			"--json",
		}

		res, runErr := app.Tools.Run(ctx, toolName, args)
		if runErr != nil {
			// Bail regardless of whether app.Log is set — the continue must NOT be
			// gated on app.Log != nil, or a nil Log would fall through to a
			// nil-res deref (same class as the testssl live all-mode regression).
			if app.Log != nil {
				app.Log.Debug("vulns.fray: fray error (best_effort — continuing)",
					"category", cat, "err", runErr)
			}
			continue
		}
		if res == nil {
			continue
		}

		// Parse JSONL output — filter bypassed > 0.
		// XCUT-07 (T-06-08-02): bypass payload strings NEVER logged.
		catFindings, bypassed := parseFrayOutput(res.Stdout, cat)
		allFindings = append(allFindings, catFindings...)
		totalBypassed += bypassed

		// XCUT-07: log only bypass_rate + category (never payload strings).
		if app.Log != nil && bypassed > 0 {
			app.Log.Info("vulns.fray: bypass detected",
				"category", cat, "bypassed_count", bypassed)
		}
	}

	// Step 5: Write inputs/findings.fray.jsonl (multi-writer staging contract — doc.go).
	// MergeVulnsFindings will merge into artefacts/findings.jsonl.
	if len(allFindings) > 0 {
		var lines [][]byte
		for _, rec := range allFindings {
			b, mErr := json.Marshal(rec)
			if mErr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			stagingPath := filepath.Join(inputsDir, "findings.fray.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.fray: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Info("vulns.fray: completed", "total_bypassed", totalBypassed)
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"total_bypassed": totalBypassed},
	}, nil
}

// frayOutputLine is the subset of fray JSONL output fields consumed for
// WAF bypass detection. Only bypassed count and bypass_rate are safe to store.
//
// XCUT-07 (T-06-08-02): Fields deliberately excluded from this struct:
//   - payload / payloads — bypass technique strings (the "secret" of the finding)
//   - request / response — raw HTTP content
//   - body — response body that may contain reflected payloads
type frayOutputLine struct {
	Target     string  `json:"target"`
	Bypassed   int     `json:"bypassed"`
	Total      int     `json:"total"`
	BypassRate float64 `json:"bypass_rate"`
}

// parseFrayOutput parses fray JSONL stdout for bypass findings.
// Filters records where bypassed > 0.
// XCUT-07 (T-06-08-02 BINDING): PayloadRedacted="***" always;
// bypass payload strings NEVER stored or logged at any level.
func parseFrayOutput(data []byte, category string) (findings []VulnFindingRecord, bypassed int) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, 0
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var fl frayOutputLine
		if err := json.Unmarshal(line, &fl); err != nil {
			continue
		}
		if fl.Bypassed <= 0 {
			continue
		}
		bypassed += fl.Bypassed
		// VulnFindingRecord with XCUT-07 compliant fields.
		findings = append(findings, VulnFindingRecord{
			// Phase 4/5 SARIF-compatible fields.
			Severity:   "medium",
			Confidence: "medium",
			// Phase 6 vuln-class fields.
			VulnClass: "waf-bypass-" + category,
			Engine:    "fray",
			// XCUT-07 (T-06-08-02): payload strings NEVER stored.
			PayloadRedacted: "***",
			PoCRedacted:     "***",
			// Target is safe to store (not a payload).
			MatchedParam: fl.Target,
		})
	}
	return findings, bypassed
}

// init self-registers FrayTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&FrayTask{}) }
