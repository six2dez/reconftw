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
// locally, at <tools_dir>/nomore403/nomore403.
//
// 18-05: IT COMES HOME, ALONGSIDE web/nomore403.go AND BY THE SAME PATH. That
// sameness is the point of doing the two together. Both files used to join the
// tools root THEMSELVES — this one through resolveToolsDirVulns, the other
// through web.resolveToolsDir — so two modules independently decided where one
// binary lives, which is how they drift. Both now ask the registry, and
// TestBypass4xxAndNomore403ResolveTheSameBinary asserts they get the same
// answer.
//
// CRITICAL (T-05-16 mitigation carried to vulns phase), unchanged as a
// REQUIREMENT: nomore403 must run with its own directory as cwd because it
// resolves its payload wordlists relative to it. That cwd now comes from
// Tool.WorkDir (tools.lock clone_workdir = true), NOT from an ExecOptions.Dir
// built here — passing it from the module would rebuild the module-side notion
// of where the clone lives that this change removes.
//
// DEADLINE: the local 300s context.WithTimeout is GONE; tools.lock's
// timeout_seconds = 300 is now the single owner (the two agreed).
//
// PARTIAL OUTPUT ON A NON-ZERO EXIT IS NO LONGER PARSED. Measured against the
// real binary on 2026-08-26: it exits 0 on a reachable target, with findings
// and without, and exits 2 only when it cannot reach the target at all — on
// which path its stdout is error prose, not bypasses.
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
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/task"
)

// bypass4xxToolName is the tools.lock entry this task dispatches — the SAME row
// web/nomore403.go dispatches.
const bypass4xxToolName = "nomore403"

// bypass4xxArgs is the arg vector: EMPTY, the captured pre-move value. nomore403
// takes its targets from standard input and the pre-18-05 call was
// exec.CommandContext(cmdCtx, binaryPath) with no arguments. tools.lock declares
// default_args = [] for the row, so applyToolContract prepends nothing.
func bypass4xxArgs() []string { return nil }

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
	workDir := app.Target.WorkDir

	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.bypass4xx: mkdir inputs/: %w", err)
	}

	// Step 1 is GONE: no os.Stat probe and no module-side join into the tools
	// root. The registry resolves nomore403 from its declared clone coordinates,
	// and an unresolvable one becomes a recorded dispatch_failed rather than a
	// silent absence. The task's STATUS on an absent binary is unchanged.

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

	// Step 5: Run nomore403 with collected URLs piped as stdin, THROUGH THE SEAM.
	// The cwd comes from Tool.WorkDir (clone_workdir), not from here.
	inputData := []byte(strings.Join(fuzzURLs, "\n") + "\n")

	res, runErr := app.Tools.RunOpts(ctx, bypass4xxToolName, bypass4xxArgs(),
		backend.ExecOptions{Stdin: inputData})
	if runErr != nil {
		// Unresolvable tool: the SAME graceful skip the os.Stat gate gave, and
		// crucially WITHOUT staging — a run in which nomore403 never dispatched
		// must not clear a previous run's bypasses (F3 did-not-run).
		if coreerrors.IsDispatchFailure(runErr) {
			if app.Log != nil {
				app.Log.Info("vulns.bypass4xx: nomore403 unavailable — run reconftw install")
			}
			return task.Result{Status: task.StatusSkipped}, nil
		}
		if app.Log != nil {
			app.Log.Debug("vulns.bypass4xx: nomore403 exited non-zero (no partial output on this path)",
				"err", runErr)
		}
	}

	// Step 6: Parse stdout for bypass lines.
	var outBytes []byte
	if res != nil {
		outBytes = res.Stdout
	}
	findings := parseBypass4xxOutput(outBytes)

	// Step 7: Write inputs/findings.bypass4xx.jsonl (staging contract — doc.go).
	//
	// F3 (phase 15): staged UNCONDITIONALLY, and reaching here now MEANS the
	// tool ran — the dispatch-failure arm above returns before this point, so
	// zero findings is a real observation and stageVulnFindings removes the
	// previous run's staging file rather than leaving a bypass that no longer
	// exists to be republished. Before 18-05 that guarantee rested on an os.Stat
	// probe that could succeed while the process still failed to start.
	// F3 DID-NOT-RUN, deadline arm (18-06 code review, CR-03). Reaching here with
	// res == nil means the tool did NOT complete — a tools.lock deadline, a crash,
	// or a cancelled context. Before the move each of these files applied its own
	// context.WithTimeout and PARSED the partially-filled buffer, so a timeout
	// still staged what it had seen. The move removed both, so res is nil and
	// findings is empty — and StageJSONL implements an empty input as os.Remove.
	// A run that never observed the corpus has no standing to delete what a
	// previous run did observe, which is exactly what the F3 comment below claims
	// and, on this path, did not deliver.
	stagingPath := filepath.Join(inputsDir, "findings.bypass4xx.jsonl")
	if res == nil {
		if app.Log != nil {
			app.Log.Warn("vulns.bypass4xx: incomplete run — previous staging preserved",
				"err", runErr)
		}
	} else {
		stageVulnFindings(app, "vulns.bypass4xx", stagingPath, true, findings)
	}

	if app.Log != nil {
		app.Log.Info("vulns.bypass4xx: completed",
			"input_urls", len(fuzzURLs),
			"bypasses", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"bypasses": len(findings)},
		// V-04: the tool did not finish (deadline, crash, cancellation), so this run
		// must NOT be checkpointed as done — otherwise the next run with the same
		// input hash skips it and the deadline becomes a permanent, silent hole.
		// Status stays non-error on purpose: this is best-effort and must not fail
		// the scan. See task.Result.Incomplete.
		Incomplete: res == nil,
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
