// nuclei_dast.go — NucleiDASTTask: nuclei DAST mode on full URL+gf corpus (VULN-11).
//
// NucleiDASTTask collects targets from artefacts/urls.jsonl AND all
// inputs/gf/*.txt buckets, deduplicates them, and runs nuclei in DAST mode.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — reads inputs/gf/*.txt buckets (all classes).
//
// INPUT CONTRACT:
//   - artefacts/urls.jsonl   (deduped URL corpus from Phase 5)
//   - inputs/gf/*.txt        (per-class buckets from GFTask)
//   - Both merged+deduped into inputs/nuclei_dast_targets.txt
//
// ARG VECTOR (v1 vulns.sh:1037-1055 verbatim):
//
//	nuclei -l <targetsFile> -dast -nh -rl <rateLimit> -silent -retries 2
//	       -duc -t <dastTemplatesPath> -j -o <stagingFile>
//	       [ExtraArgs fields...]
//
// -duc: disable update check — mandatory on dev Mac where UDP/53 is blocked
// (memory/project_local_dns_block; matches v1 "pass -duc or PD tools hang").
//
// HEARTBEAT (XCUT-09):
// Backend.Stream used — nuclei DAST can run for hours on large URL corpora.
// The UI must never appear stuck.
//
// DEEP_LIMIT2 GATE (T-06-07-03):
// If URL count > cfg.Advanced.DeepLimit2 and !cfg.Advanced.Deep → StatusSkipped.
// Mirrors v1 nuclei_dast() DEEP_LIMIT2 check (vulns.sh:1041).
//
// PAYLOAD REDACTION (XCUT-07, T-06-07-01):
// nuclei DAST matched-at and extracted-results contain raw payload/response
// data — NEVER logged at Info/Warn. Only template-id + severity + count.
// PayloadRedacted = "***" always.
//
// Config: cfg.Vulns.NucleiDAST (VulnNucleiDAST) — NOT cfg.Web.NucleiDAST.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-07-PLAN.md Task 1.
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

// NucleiDASTTask runs nuclei in DAST mode against the full URL+gf corpus (VULN-11).
type NucleiDASTTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *NucleiDASTTask) Name() string { return "vulns.nuclei_dast" }

// Module returns the owning module group.
func (t *NucleiDASTTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *NucleiDASTTask) Description() string {
	return "Nuclei DAST mode (HTTP traffic replay on gf+url corpus)"
}

// Enabled reads cfg.Vulns.NucleiDAST.Enabled — the vulns-pipeline DAST gate,
// distinct from cfg.Web.NucleiDAST which is the web-phase gate.
func (t *NucleiDASTTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.NucleiDAST.Enabled }

// DependsOn declares GFTask as the DAG dependency — NucleiDASTTask reads all
// inputs/gf/*.txt buckets produced by GFTask.
func (t *NucleiDASTTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the nuclei DAST pipeline:
//  1. Collect targets: merge artefacts/urls.jsonl + inputs/gf/*.txt; dedup.
//  2. Write inputs/nuclei_dast_targets.txt.
//  3. Deep-limit gate (T-06-07-03).
//  4. Resolve dastTemplatesPath from cfg.Vulns.NucleiDAST.TemplatesPath (fallback cfg.Paths.NucleiTemplates+"/dast").
//  5. Run nuclei -dast via Backend.Stream (XCUT-09 heartbeat).
//  6. Drain stream; parse staging file; build VulnFindingRecord slice (XCUT-07 redaction).
//  7. Write inputs/findings.nuclei_dast.jsonl.
func (t *NucleiDASTTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "nuclei"
	cfg := app.Cfg
	workDir := app.Target.WorkDir

	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.nuclei_dast: mkdir inputs/: %w", err)
	}

	// Step 1: Collect targets — artefacts/urls.jsonl + inputs/gf/*.txt.
	targetURLs, err := collectNucleiDASTTargets(workDir)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.nuclei_dast: target collection error (best_effort)", "err", err)
	}
	if len(targetURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.nuclei_dast: no targets from urls.jsonl + gf buckets — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 2: Write deduped target list.
	targetsFile := filepath.Join(inputsDir, "nuclei_dast_targets.txt")
	if err := writeURLList(targetsFile, targetURLs); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.nuclei_dast: write targets file: %w", err)
	}

	// Step 3: Deep-limit gate (T-06-07-03, mirrors v1 DEEP_LIMIT2 check).
	deepLimit2 := cfg.Advanced.DeepLimit2
	if deepLimit2 <= 0 {
		deepLimit2 = 5000 // v1 default DEEP_LIMIT2
	}
	if !cfg.Advanced.Deep && len(targetURLs) > deepLimit2 {
		if app.Log != nil {
			app.Log.Info("vulns.nuclei_dast: too many URLs — skipped (use --deep to override)",
				"url_count", len(targetURLs), "deep_limit2", deepLimit2)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 4: Resolve templates path.
	// cfg.Vulns.NucleiDAST.TemplatesPath (VulnNucleiDAST.TemplatesPath) is the
	// primary source — distinct from cfg.Web.NucleiDAST or any web-phase field.
	dastTemplates := cfg.Vulns.NucleiDAST.TemplatesPath
	if dastTemplates == "" {
		dastTemplates = filepath.Join(cfg.Paths.NucleiTemplates, "dast")
	}
	if _, statErr := os.Stat(dastTemplates); statErr != nil {
		if app.Log != nil {
			app.Log.Info("vulns.nuclei_dast: dast templates path not accessible — skipping",
				"path", dastTemplates, "err", statErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Rate limit (default 150 = v1 NUCLEI_RATELIMIT).
	rl := cfg.Web.Nuclei.RateLimit
	if rl <= 0 {
		rl = 150
	}

	// Staging file — distinct from fuzzparams staging.
	stagingFile := filepath.Join(inputsDir, "findings.nuclei_dast_raw.jsonl")

	// Step 5: Build arg vector and run via Backend.Stream.
	// -duc: disable update check (T-06-07-02 — mandatory; dev Mac DNS block).
	args := []string{
		"-l", targetsFile,
		"-dast",
		"-nh",
		"-rl", strconv.Itoa(rl),
		"-silent",
		"-retries", "2",
		"-duc", // disable update check — always present (XCUT memory/project_local_dns_block)
		"-t", dastTemplates,
		"-j",
		"-o", stagingFile,
	}
	// Append ExtraArgs fields if configured.
	if cfg.Vulns.NucleiDAST.ExtraArgs != "" {
		args = append(args, strings.Fields(cfg.Vulns.NucleiDAST.ExtraArgs)...)
	}

	// Backend.Stream for XCUT-09 heartbeat (nuclei DAST can run hours).
	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	if streamErr != nil {
		if app.Log != nil {
			app.Log.Debug("vulns.nuclei_dast: stream error (best_effort)", "err", streamErr)
		}
		// Non-fatal per best_effort policy.
	} else {
		// Drain stream — Backend contract: caller MUST drain until closed.
		// XCUT-07: raw nuclei output routed to run.log only; never to Info terminal.
		for range eventCh { //nolint:revive // intentional drain
		}
	}

	// Step 6: Parse staging file → VulnFindingRecord slice.
	data, readErr := os.ReadFile(stagingFile) //nolint:gosec // path within WorkDir
	if readErr != nil && !os.IsNotExist(readErr) {
		if app.Log != nil {
			app.Log.Debug("vulns.nuclei_dast: read staging file error", "err", readErr)
		}
	}
	findings := parseNucleiDAST(data)

	// Step 7: Write inputs/findings.nuclei_dast.jsonl (staging contract — doc.go).
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
			stagingPath := filepath.Join(inputsDir, "findings.nuclei_dast.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.nuclei_dast: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	// XCUT-07: log only template-id + severity + count, never raw matched-at / extracted-results.
	if app.Log != nil {
		app.Log.Info("vulns.nuclei_dast: completed", "findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(findings)},
	}, nil
}

// collectNucleiDASTTargets merges artefacts/urls.jsonl (raw URL lines from the
// Phase 5 deduped corpus) with all inputs/gf/*.txt bucket files, deduplicating
// entries. Returns a sorted-stable slice of unique URLs.
//
// This mirrors v1 _nuclei_dast_collect_targets() (vulns.sh:1016-1036):
// reads webs/webs_all.txt + webs/url_extract_nodupes.txt + all gf/*.txt.
func collectNucleiDASTTargets(workDir string) ([]string, error) {
	seen := make(map[string]struct{})
	var urls []string

	addURL := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, exists := seen[u]; !exists {
			seen[u] = struct{}{}
			urls = append(urls, u)
		}
	}

	// Source 1: artefacts/urls.jsonl — read raw lines (each line is a URL string).
	urlsJSONL := filepath.Join(workDir, "artefacts", "urls.jsonl")
	if data, err := os.ReadFile(urlsJSONL); err == nil { //nolint:gosec // path within WorkDir
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			addURL(sc.Text())
		}
	}

	// Source 2: all inputs/gf/*.txt buckets from GFTask.
	gfDir := filepath.Join(workDir, "inputs", "gf")
	buckets, globErr := filepath.Glob(filepath.Join(gfDir, "*.txt"))
	if globErr == nil {
		for _, bucket := range buckets {
			data, err := os.ReadFile(bucket) //nolint:gosec // path within WorkDir
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(bytes.NewReader(data))
			sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
			for sc.Scan() {
				addURL(sc.Text())
			}
		}
	}

	return urls, nil
}

// dastNucleiLine is the subset of nuclei JSONL output fields parsed for DAST findings.
type dastNucleiLine struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Info       struct {
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

// parseNucleiDAST parses nuclei DAST JSONL output into VulnFindingRecord slice.
// XCUT-07: extracted-results and matched-at values are NEVER logged at Info/Warn;
// the MatchedAt field carries the finding URL but is not echoed to the terminal.
// PayloadRedacted is always "***" (nuclei DAST sends crafted HTTP payloads).
func parseNucleiDAST(data []byte) []VulnFindingRecord {
	if len(data) == 0 {
		return nil
	}
	var records []VulnFindingRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var nl dastNucleiLine
		if err := json.Unmarshal(line, &nl); err != nil {
			continue
		}
		// VulnClass inferred from first template tag (if any).
		vulnClass := "nuclei-dast"
		if len(nl.Info.Tags) > 0 {
			vulnClass = nl.Info.Tags[0]
		}
		records = append(records, VulnFindingRecord{
			// Phase 4/5 SARIF-compatible fields.
			Severity:   nl.Info.Severity,
			Confidence: "high",
			// Phase 6 vuln-class fields.
			VulnClass:       vulnClass,
			PayloadRedacted: "***", // XCUT-07: raw DAST payload never stored
			Engine:          "nuclei-dast",
		})
	}
	return records
}

// init self-registers NucleiDASTTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&NucleiDASTTask{}) }
