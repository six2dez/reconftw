// second_order.go — SecondOrderTask: second-order injection / broken-link scanner (VULN-12).
//
// SecondOrderTask absorbs v1's brokenLinks() function (web.sh:2839) into the
// vulns pipeline as VULN-12. It reads the web host URL list from artefacts/urls.jsonl,
// runs the second-order tool per-target, and stores findings in
// inputs/findings.second_order.jsonl per the multi-writer staging contract.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — second-order depends on the URL corpus
// being ready; the gf DAG root ensures that corpus is finalized before this task.
//
// INPUT: artefacts/urls.jsonl — host URL list from Phase 5 web probe (D-V5).
// second-order does NOT need gf-pattern-filtered input; it tests all web hosts
// (v1 brokenLinks() reads webs/webs_all.txt, the unfiltered host list).
//
// ARG VECTOR (v1 web.sh:2873-2888 verbatim per host):
//
//	second-order -target <url> -config <configFile> -depth <n> -threads <n> [-insecure] [-header <header>]
//
// Output: second-order writes non-200-url-attributes.json to an -output directory.
// v2: parse JSON to extract dangling link URLs → VulnFindingRecord.
//
// PAYLOAD REDACTION (XCUT-07, T-06-06-03):
// second-order discovers dangling/broken link URLs. Raw dangling link URLs
// MUST NOT be logged at Info/Warn. Only finding count is logged. MatchedParam
// stores the hostname only. PayloadRedacted and PoCRedacted are always "***".
//
// SUBPROCESS SAFETY (FOUND-09, T-06-06-01):
// Backend.Run uses LocalBackend which sets SysProcAttr.Setpgid=true and
// WaitDelay for all subprocess invocations — orphan processes are kill-tree safe.
// No raw exec.Command calls in SecondOrderTask code.
//
// PATH CONTAINMENT (T-06-06-03):
// configFile is derived from cfg.Paths (trusted config value); validated via
// os.Stat before use. Path traversal in operator-supplied config is blocked by
// the config validator (validate:"omitempty,nopath_traversal" in config.go).
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-06-PLAN.md Task 2.
package vulns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// SecondOrderTask runs the second-order injection / broken-link scanner for VULN-12.
// Absorbs v1 brokenLinks() (web.sh:2839) — uses only the "second-order" engine path.
type SecondOrderTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SecondOrderTask) Name() string { return "vulns.second_order" }

// Module returns the owning module group.
func (t *SecondOrderTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *SecondOrderTask) Description() string {
	return "Second-order injection / broken link scanner (second-order)"
}

// Enabled reports whether second-order scanning is configured.
// Uses VulnBrokenLinks.Enabled — the config key that v1's BROKENLINKS=true maps to.
func (t *SecondOrderTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.BrokenLinks.Enabled }

// DependsOn returns the DAG edges — SecondOrderTask consumes the URL corpus
// prepared by the vulns pipeline after GFTask.
func (t *SecondOrderTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes second-order scanning against each host URL.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract URL strings — StatusSkipped if empty.
//  2. Resolve config file from cfg.Advanced.SecondOrder.Config
//     (defaults to cfg.Paths.ToolsDir/second-order/config/takeover.json).
//  3. For each base host URL: build args; Run("second-order", args);
//     parse output JSON (non-200-url-attributes.json); collect dangling URLs.
//  4. Convert dangling URLs to VulnFindingRecord (XCUT-07 redaction).
//  5. Write inputs/findings.second_order.jsonl via output.WriteJSONL.
func (t *SecondOrderTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "second-order"
	cfg := app.Cfg

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	hostURLs, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.second_order: read URL corpus error (best_effort)", "err", err)
	}
	if len(hostURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.second_order: no host URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.second_order: mkdir inputs/: %w", err)
	}

	// Step 2: Resolve the second-order config file path (T-06-06-03 containment).
	// v1: SECOND_ORDER_CONFIG="${tools}/second-order/config/takeover.json"
	// v2: cfg.Advanced.Tools.SecondOrder.Config (maps from SECOND_ORDER_CONFIG legacy alias).
	configFile := cfg.Advanced.Tools.SecondOrder.Config
	if configFile == "" {
		// Fallback to the canonical v1 default path.
		// v1 uses ${tools} which defaults to $HOME/Tools.
		toolsDir := filepath.Join(os.Getenv("HOME"), "Tools")
		configFile = filepath.Join(toolsDir, "second-order", "config", "takeover.json")
	}
	// Validate config file exists (T-06-06-03 — path traversal via os.Stat check).
	// If not found, omit the -config flag rather than failing (best_effort, D-V7).
	configFileValid := false
	if info, statErr := os.Stat(configFile); statErr == nil && info.Mode().IsRegular() {
		configFileValid = true
	}

	// Resolve depth and thread settings from cfg.Advanced.Tools.SecondOrder.
	// v1 defaults: SECOND_ORDER_DEPTH=1, SECOND_ORDER_THREADS=10.
	depth := cfg.Advanced.Tools.SecondOrder.Depth
	if depth <= 0 {
		depth = 1
	}
	// v1: if [[ $DEEP == true ]]; then so_depth=$((so_depth + 1))
	if cfg.Advanced.Deep {
		depth++
	}
	threads := cfg.Advanced.Tools.SecondOrder.Threads
	if threads <= 0 {
		threads = 10
	}
	insecure := cfg.Advanced.Tools.SecondOrder.Insecure

	// Scratch directory for per-target second-order output.
	scratchDir := filepath.Join(inputsDir, "second_order_out")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.second_order: mkdir second_order_out: %w", err)
	}

	var allFindings []VulnFindingRecord
	var processedTargets int
	// toolRan records whether AT LEAST ONE second-order invocation succeeded, and
	// cancelled records that the loop was interrupted. Neither an uninstalled
	// second-order nor a cancelled run observed the corpus, so neither may clear
	// a previous run's staging (F3 did-not-run — staging.go).
	toolRan := false
	cancelled := false

	// Step 3: For each base host URL, run second-order.
	// v1 mirrors: while IFS= read -r target; do second-order -target "$target" ...
	for _, targetURL := range hostURLs {
		// Check for context cancellation between targets.
		select {
		case <-ctx.Done():
			if app.Log != nil {
				app.Log.Debug("vulns.second_order: context cancelled", "processed", processedTargets)
			}
			cancelled = true
			goto writefindings
		default:
		}

		targetURL = strings.TrimSpace(targetURL)
		if targetURL == "" {
			continue
		}

		// Create a per-target output directory using a sanitized name.
		// v1: safe_target=$(echo "$target" | sed 's|https\?://||; s|[^A-Za-z0-9._-]|_|g')
		safeTarget := soSanitizeTargetName(targetURL)
		outDir := filepath.Join(scratchDir, safeTarget)
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			if app.Log != nil {
				app.Log.Debug("vulns.second_order: mkdir outDir (best_effort)",
					"target", targetURL, "err", err)
			}
			continue
		}

		// Build arg vector.
		// v1 (web.sh:2873-2888):
		//   second-order -target "$target" -config <cfg> -depth <n> -threads <n> -output <dir>
		args := []string{
			"-target", targetURL,
			"-depth", strconv.Itoa(depth),
			"-threads", strconv.Itoa(threads),
			"-output", outDir,
		}
		if configFileValid {
			args = append(args, "-config", configFile)
		}
		if insecure {
			args = append(args, "-insecure")
		}

		_, runErr := app.Tools.Run(ctx, toolName, args)
		if runErr != nil {
			// Non-fatal per best_effort policy — second-order may not be installed
			// or may fail on a particular target.
			if app.Log != nil {
				app.Log.Debug("vulns.second_order: run error (best_effort)",
					"target", targetURL, "err", runErr)
			}
			processedTargets++
			continue
		}
		toolRan = true

		// Parse second-order JSON output: non-200-url-attributes.json.
		// v1 (web.sh:2890-2893):
		//   jq -r 'to_entries[]?.value | to_entries[]?.value[]? // empty' .json | grep '^https?://'
		findings := parseSecondOrderOutput(outDir, targetURL)
		allFindings = append(allFindings, findings...)

		// XCUT-07: log only count per target, never raw dangling link URLs.
		if app.Log != nil {
			app.Log.Debug("vulns.second_order: processed target",
				"target", safeTarget, "new_findings", len(findings))
		}
		processedTargets++
	}

writefindings:
	// Step 5: Write inputs/findings.second_order.jsonl.
	//
	// F3 (phase 15): staged through stageVulnFindings so a run that found no
	// dangling links REMOVES the previous run's staging instead of republishing
	// links that have since been fixed. The `goto writefindings` cancellation
	// path lands here too, which is exactly why `cancelled` is part of the
	// did-not-run test: an interrupted scan must not delete findings.
	stagingPath := filepath.Join(inputsDir, "findings.second_order.jsonl")
	stageVulnFindings(app, "vulns.second_order", stagingPath, toolRan && !cancelled, allFindings)

	// XCUT-07: log only count, never raw dangling link URLs.
	if app.Log != nil {
		app.Log.Info("vulns.second_order: completed",
			"targets", processedTargets,
			"second_order_findings", len(allFindings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats: map[string]int{
			"targets":               processedTargets,
			"second_order_findings": len(allFindings),
		},
	}, nil
}

// soSanitizeTargetName converts a URL to a filesystem-safe name.
// Mirrors v1: sed 's|https\?://||; s|[^A-Za-z0-9._-]|_|g'
func soSanitizeTargetName(rawURL string) string {
	// Strip scheme.
	name := rawURL
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimPrefix(name, "http://")
	// Replace unsafe chars with underscore.
	re := regexp.MustCompile(`[^A-Za-z0-9._-]`)
	name = re.ReplaceAllString(name, "_")
	if name == "" {
		return "unknown"
	}
	// Limit length to avoid filesystem issues.
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

// secondOrderNon200 mirrors the shape of second-order's non-200-url-attributes.json.
// The tool writes a nested map: outer key = attribute type, inner key = URL,
// inner value = list of dangling URLs found in that attribute.
// e.g.: {"src": {"https://example.com/page": ["https://dangling.example.com"]}}
type secondOrderNon200 map[string]map[string][]string

// parseSecondOrderOutput reads the second-order output directory and returns
// VulnFindingRecord entries for all dangling link URLs found.
//
// XCUT-07: raw dangling link URLs MUST NOT be logged at Info/Warn. Only count
// is logged. MatchedParam contains the hostname only (not the full URL).
func parseSecondOrderOutput(outDir, sourceURL string) []VulnFindingRecord {
	outputFile := filepath.Join(outDir, "non-200-url-attributes.json")
	data, err := os.ReadFile(outputFile) //nolint:gosec // path within WorkDir
	if err != nil {
		if !os.IsNotExist(err) {
			// File exists but unreadable — non-fatal.
			return nil
		}
		return nil
	}

	var non200 secondOrderNon200
	if jsonErr := json.Unmarshal(data, &non200); jsonErr != nil {
		return nil
	}

	// Extract hostname of the source target for XCUT-07-safe record storage.
	sourceHost := soExtractHost(sourceURL)

	var records []VulnFindingRecord
	// Flatten: iterate outer map (attribute type) → inner map (page URL) → dangling URLs.
	// v1: jq -r 'to_entries[]?.value | to_entries[]?.value[]? // empty' | grep '^https?://'
	for _, innerMap := range non200 {
		for _, danglingURLs := range innerMap {
			for _, du := range danglingURLs {
				du = strings.TrimSpace(du)
				if du == "" {
					continue
				}
				// Must match ^https?:// (mirrors v1 grep filter).
				if !strings.HasPrefix(du, "http://") && !strings.HasPrefix(du, "https://") {
					continue
				}
				// XCUT-07: extract dangling hostname only; never store full dangling URL.
				danglingHost := soExtractHost(du)
				records = append(records, VulnFindingRecord{
					Host:       sourceHost, // scope-gate locator: the in-scope source, not the dangling target
					Severity:   "medium",
					Confidence: "medium",
					// VulnClass reflects second-order / broken-link category.
					VulnClass:    "second-order",
					MatchedParam: sourceHost + "->" + danglingHost, // host pair; no raw URLs
					// XCUT-07: dangling link URLs NEVER stored in payload/PoC fields.
					PayloadRedacted: "***",
					PoCRedacted:     "***",
					Engine:          "second-order",
				})
			}
		}
	}
	return records
}

// soExtractHost extracts the hostname from a URL for XCUT-07-safe records.
func soExtractHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	return strings.ToLower(parsed.Hostname())
}

// init self-registers SecondOrderTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&SecondOrderTask{}) }
