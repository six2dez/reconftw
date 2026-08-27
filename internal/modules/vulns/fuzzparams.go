// fuzzparams.go — FuzzparamsTask: nuclei DAST parameter fuzzing on deduped URL corpus.
//
// FuzzparamsTask reads artefacts/urls.jsonl ONLY (the deduped URL corpus from
// Phase 5 — equivalent to v1 webs/url_extract_nodupes.txt). It does NOT
// aggregate gf buckets or webs_all (unlike NucleiDASTTask which merges both).
//
// The distinction: NucleiDASTTask runs DAST templates on the full gf+url corpus;
// FuzzparamsTask runs DAST templates on the narrow deduped URL corpus only —
// the parameterized fuzzing pass focuses on URLs with query parameters.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — follows the GFTask DAG root.
//
// ARG VECTOR (v1 vulns.sh:918-1014 verbatim):
//
//	nuclei -l <urlsPath> -dast -nh -rl <rateLimit> -silent -retries 2
//	       -duc -t <fuzzTemplatesPath> -j -o <stagingFile>
//
// -duc: disable update check — mandatory (dev Mac DNS block; mirrors NucleiDASTTask).
//
// CONFIG: cfg.Vulns.FuzzParams (VulnFuzzParams) — a DISTINCT struct from
// cfg.Vulns.NucleiDAST. TemplatesPath is VulnFuzzParams.TemplatesPath
// (koanf "fuzz_params.templates_path"), NOT VulnNucleiDAST.TemplatesPath
// (koanf "nuclei_dast.templates_path"). Both default to NucleiTemplates+"/dast"
// but are independently configurable TOML keys (B-new-1/B-new-2 fix).
//
// STAGING: inputs/fuzzparams_raw.jsonl (distinct staging path from nuclei_dast).
// OUTPUT:  inputs/findings.fuzzparams.jsonl (staging contract — doc.go).
//
// HEARTBEAT (XCUT-09): Backend.Stream — nuclei fuzz runs can be lengthy.
//
// PAYLOAD REDACTION (XCUT-07):
// nuclei DAST stdout contains matched payload/response data — NEVER logged at
// Info/Warn. Only template-id + severity + count. PayloadRedacted = "***".
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

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// FuzzparamsTask runs nuclei DAST parameter fuzzing against the deduped URL corpus.
type FuzzparamsTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *FuzzparamsTask) Name() string { return "vulns.fuzzparams" }

// Module returns the owning module group.
func (t *FuzzparamsTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *FuzzparamsTask) Description() string {
	return "Parameter fuzzing via nuclei DAST on deduped URL corpus (FUZZPARAMS)"
}

// Enabled reads cfg.Vulns.FuzzParams.Enabled — gated independently of NucleiDAST.
func (t *FuzzparamsTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.FuzzParams.Enabled }

// DependsOn declares GFTask as the DAG dependency (follows the vulns DAG root).
func (t *FuzzparamsTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the nuclei DAST fuzzparams pipeline:
//  1. Resolve urlsPath = artefacts/urls.jsonl (ONLY — no gf bucket aggregation).
//  2. Skip if absent or empty.
//  3. Resolve fuzzTemplatesPath from cfg.Vulns.FuzzParams.TemplatesPath
//     (DISTINCT field from cfg.Vulns.NucleiDAST.TemplatesPath).
//  4. Run nuclei -dast via Backend.Stream (XCUT-09 heartbeat).
//  5. Drain stream; parse staging file (inputs/fuzzparams_raw.jsonl).
//  6. Write inputs/findings.fuzzparams.jsonl.
func (t *FuzzparamsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "nuclei"
	cfg := app.Cfg
	workDir := app.Target.WorkDir

	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.fuzzparams: mkdir inputs/: %w", err)
	}

	// Step 1 & 2: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	// FuzzparamsTask does NOT aggregate gf buckets (distinct from NucleiDASTTask).
	// Equivalent to v1 fuzzparams() reading webs/url_extract_nodupes.txt.
	urlsPath, resolveErr := resolveURLInput(ctx, app)
	if resolveErr != nil || urlsPath == "" {
		if app.Log != nil {
			app.Log.Info("vulns.fuzzparams: no URL corpus available — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if info, statErr := os.Stat(urlsPath); statErr != nil || info.Size() == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.fuzzparams: URL corpus absent or empty — skipping", "path", urlsPath)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 3: Resolve templates path.
	// cfg.Vulns.FuzzParams.TemplatesPath is the primary source —
	// VulnFuzzParams.TemplatesPath (koanf "fuzz_params.templates_path"),
	// DISTINCT from VulnNucleiDAST.TemplatesPath (koanf "nuclei_dast.templates_path").
	fuzzTemplates := cfg.Vulns.FuzzParams.TemplatesPath
	if fuzzTemplates == "" {
		fuzzTemplates = filepath.Join(cfg.Paths.NucleiTemplates, "dast")
	}
	if _, statErr := os.Stat(fuzzTemplates); statErr != nil {
		if app.Log != nil {
			app.Log.Info("vulns.fuzzparams: fuzz templates path not accessible — skipping",
				"path", fuzzTemplates, "err", statErr)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Rate limit (default 150 = v1 NUCLEI_RATELIMIT).
	rl := cfg.Web.Nuclei.RateLimit
	if rl <= 0 {
		rl = 150
	}

	// Staging file — DISTINCT path from nuclei_dast staging (inputs/findings.nuclei_dast_raw.jsonl).
	stagingFile := filepath.Join(inputsDir, "fuzzparams_raw.jsonl")

	// Step 4: Build arg vector and run via Backend.Stream.
	// -duc: disable update check (mandatory — dev Mac DNS block; XCUT-09 heartbeat).
	args := []string{
		"-l", urlsPath,
		"-dast",
		"-nh",
		"-rl", strconv.Itoa(rl),
		"-silent",
		"-retries", "2",
		"-duc", // disable update check — always present (memory/project_local_dns_block)
		"-t", fuzzTemplates,
		"-j",
		"-o", stagingFile,
	}

	// Backend.Stream for XCUT-09 heartbeat.
	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	// nucleiRan records whether nuclei was actually DISPATCHED. A dispatch
	// failure means the binary is absent: the task observed nothing and must not
	// clear a previous run's staging (F3 did-not-run — staging.go).
	nucleiRan := streamErr == nil
	if streamErr != nil {
		if app.Log != nil {
			app.Log.Debug("vulns.fuzzparams: stream error (best_effort)", "err", streamErr)
		}
		// Non-fatal per best_effort policy.
	} else {
		// F6 (phase 15): consume the TERMINAL error before reading stagingFile —
		// a nuclei that exited non-zero leaves a truncated file, or none at all,
		// in which case the read would return the PREVIOUS run's output.
		// XCUT-07: raw nuclei output routed to run.log only; never to Info terminal.
		if drainErr := backend.Drain(eventCh); drainErr != nil {
			return task.Result{Status: task.StatusErrored},
				terminalStreamError(toolName, drainErr)
		}
	}

	// Step 5: Parse staging file → VulnFindingRecord slice.
	data, readErr := os.ReadFile(stagingFile) //nolint:gosec // path within WorkDir
	if readErr != nil && !os.IsNotExist(readErr) {
		if app.Log != nil {
			app.Log.Debug("vulns.fuzzparams: read staging file error", "err", readErr)
		}
	}
	findings := parseFuzzparamsOutput(data)

	// Step 6: Write inputs/findings.fuzzparams.jsonl (staging contract — doc.go).
	//
	// F3 (phase 15): staged through stageVulnFindings so a clean run REMOVES the
	// previous run's staging rather than republishing DAST findings that have
	// since been fixed.
	//
	// NOTE inputs/fuzzparams_raw.jsonl is nuclei's own -o output in nuclei's
	// native schema — raw tool output this task parses, not staging. It is
	// deliberately named OUTSIDE the inputs/findings.*.jsonl merge glob.
	stagingPath := filepath.Join(inputsDir, "findings.fuzzparams.jsonl")
	stageVulnFindings(app, "vulns.fuzzparams", stagingPath, nucleiRan, findings)

	// XCUT-07: log only template-id + severity + count, never raw matched-at / extracted-results.
	if app.Log != nil {
		app.Log.Info("vulns.fuzzparams: completed", "findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(findings)},
	}, nil
}

// fuzzparamsNucleiLine is the subset of nuclei JSONL output fields parsed for fuzzparams findings.
type fuzzparamsNucleiLine struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Info       struct {
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

// parseFuzzparamsOutput parses nuclei DAST JSONL output into VulnFindingRecord slice.
// XCUT-07: extracted-results and matched-at values are NEVER logged at Info/Warn.
// PayloadRedacted is always "***" (nuclei sends crafted DAST payloads).
// Only template-id + severity + count are reported.
func parseFuzzparamsOutput(data []byte) []VulnFindingRecord {
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
		var nl fuzzparamsNucleiLine
		if err := json.Unmarshal(line, &nl); err != nil {
			continue
		}
		// VulnClass inferred from first template tag (if any).
		vulnClass := "fuzzparams"
		if len(nl.Info.Tags) > 0 {
			vulnClass = nl.Info.Tags[0]
		}
		records = append(records, VulnFindingRecord{
			// Scope-gate locator, normalised through findingHost: nuclei's
			// "host" is the full origin for HTTP templates
			// ("https://target.example.com"), which the hostname-matching
			// scope gate would reject outright.
			Host: findingHost(nl.Host),
			// Phase 4/5 SARIF-compatible fields.
			Severity:   nl.Info.Severity,
			Confidence: "medium",
			// Phase 6 vuln-class fields.
			VulnClass:       vulnClass,
			PayloadRedacted: "***", // XCUT-07: raw DAST payload never stored
			Engine:          "nuclei-fuzzparams",
		})
	}
	return records
}

// init self-registers FuzzparamsTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&FuzzparamsTask{}) }

// resolveToolsDirVulns is GONE (18-05 Task 2). It existed solely so bypass4xx.go
// could join the tools root itself and reach ~/Tools/nomore403/nomore403, and
// bypass4xx.go now asks the registry instead. It was one of THREE hand-rolled
// copies of the same resolver, and — like web.resolveToolsDir — it read
// cfg.Paths.DataDir, which 17-06 recorded as the hazard: data_dir already meant
// the workspace root. The tools root is named once, at config.Config.ToolsRoot()
// over paths.tools_dir (18-02).

// (host-extraction helper removed — unused; the web package owns the canonical
// implementation if FuzzparamsTask ever needs per-URL host attribution.)
