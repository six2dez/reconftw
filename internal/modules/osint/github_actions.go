// github_actions.go — GitHubActionsTask: GitHub Actions audit via gato (OSINT-06).
//
// GitHubActionsTask runs gato over the company org (v1 osint.sh:307
// github_actions_audit), enumerating workflow artefacts and self-hosted-runner
// exposure. gato output can SURFACE WORKFLOW SECRETS, so this Task applies
// XCUT-07 field-level redaction: any entry that exposes a secret is recorded
// with ValueRedacted="***" and the non-secret locator only — the raw secret
// value is NEVER written to a record, log, or artefact (mantra.go:162-193).
//
// KEY GATE (D-O8): reads cfg.Paths.GitHubTokens (the v1 $GITHUB_TOKENS file).
// Empty path / empty file → logged Info (naming the var, not the value) +
// StatusSkipped (logged-never-silent, web/nuclei.go:108-128).
//
// SECRET HANDLING (XCUT-07 / T-07-03-01, T-07-03-02): the GitHub token is read
// from disk and exported to gato via the GH_TOKEN child-process environment
// variable (Runner.RunEnv → Backend env seam → cmd.Env) — NEVER placed on argv
// and NEVER logged. The token value is registered with the slog Redactor before
// any subsequent log line. Surfaced workflow secrets are stripped to "***" before
// any write, AND the raw gato JSON side-file is NOT persisted (gato writes to a
// temp file inside WorkDir; only the redacted findings.jsonl survives) — XCUT-07
// holds at EVERY sink, not just the canonical findings stream.
//
// SEEDING (D-O1): company-org-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — tool failure / empty output logs Debug
// and returns StatusDone with findings:0.
//
// Source: .planning/phases/07-osint-e2e/07-03-PLAN.md Task 1.
package osint

import (
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

// GitHubActionsTask runs gato for OSINT-06 (key-gated, secret-redacting).
type GitHubActionsTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GitHubActionsTask) Name() string { return "osint.github_actions" }

// Module returns the owning module group.
func (t *GitHubActionsTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *GitHubActionsTask) Description() string {
	return "GitHub Actions audit (gato, OSINT-06) — key-gated, XCUT-07 redacted"
}

// Enabled reports whether the GitHub Actions audit is configured.
func (t *GitHubActionsTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GitHub.ActionsAudit.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *GitHubActionsTask) DependsOn() []string { return nil }

// Run executes gato over the company org.
//
// Steps:
//  1. Derive + validate the root domain → company name.
//  2. Key gate (D-O8): require a non-empty cfg.Paths.GitHubTokens file.
//  3. Write the org list; run gato with GH_TOKEN exported (never logged).
//  4. Parse gato JSON; redact any surfaced secret (ValueRedacted="***").
//  5. Write inputs/findings.github_actions.jsonl (multi-writer staging).
func (t *GitHubActionsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.github_actions: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	company := companyName(root)

	// Step 2: GITHUB_TOKEN key gate (D-O8, logged-never-silent).
	token, ok := readGitHubToken(app)
	if !ok {
		if app.Log != nil {
			app.Log.Info("osint.github_actions: no GITHUB_TOKEN (cfg.paths.github_tokens) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	// XCUT-07 / T-07-09-01: register the LIVE token with the slog Redactor BEFORE
	// any subsequent log line, so it can never leak into structured output. The
	// token is passed to gato ONLY via the GH_TOKEN child-env entry (never argv).
	registerSecret(app.Log, token)

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_actions: mkdir inputs/: %w", err)
	}
	// GAP-03: no osint/ side-file is written (the raw gato JSON would embed live
	// secrets), so we no longer create osint/. Only redacted findings.jsonl is
	// persisted (via the multi-writer staging contract under inputs/).

	// Step 3: write the org list (gato -O <file>), run gato writing JSON output.
	orgsFile := filepath.Join(inputsDir, "gato_orgs.txt")
	if wErr := os.WriteFile(orgsFile, []byte(company+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_actions: write gato_orgs.txt: %w", wErr)
	}
	// GAP-03 (XCUT-07 / T-07-09-03): gato's raw -oJ output can embed live workflow
	// secrets, so we NEVER persist it to osint/github_actions_audit.json. gato writes
	// to a temp file inside WorkDir which we parse (redacting surfaced secrets) and
	// then DELETE — only the redacted findings.jsonl survives. No raw-secret sink.
	gatoTmp, tmpErr := os.CreateTemp(app.Target.WorkDir, ".gato_audit_*.json")
	if tmpErr != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_actions: create gato temp output: %w", tmpErr)
	}
	gatoJSON := gatoTmp.Name()
	_ = gatoTmp.Close()
	// Best-effort cleanup: the raw gato JSON must not outlive this Task.
	defer func() { _ = os.Remove(gatoJSON) }()

	// v1 arg vector (osint.sh:330): e --enum_wf_artifacts --skip_sh_runner_enum
	//                               -O <orgs> -oJ <json>
	args := []string{
		"e", "--enum_wf_artifacts", "--skip_sh_runner_enum",
		"-O", orgsFile, "-oJ", gatoJSON,
	}
	if app.Cfg != nil && app.Cfg.OSINT.GitHub.ActionsAudit.IncludeAllArtifactSecrets {
		args = append(args, "--include_all_artifact_secrets")
	}

	// gato authenticates via the GH_TOKEN env var (v1 osint.sh:341), delivered
	// through the kernel env seam (RunEnv → Backend.ExecEnv → cmd.Env). The token
	// is exported to the child process ONLY; it is NEVER placed in argv or logged.
	if _, err := app.Tools.RunEnv(ctx, "gato", args, []string{"GH_TOKEN=" + token}); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_actions: gato run failed (best_effort)", "err", err)
		}
		// Fall through — gato may have written partial JSON before exiting.
	}

	// Step 4: parse gato JSON; redact any surfaced secret.
	gatoData, readErr := os.ReadFile(gatoJSON) //nolint:gosec // temp file within WorkDir
	if readErr != nil {
		if app.Log != nil {
			app.Log.Info("osint.github_actions: completed", "findings", 0)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}
	records := parseGatoOutput(gatoData)

	// Step 5: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.github_actions.jsonl", records)

	// XCUT-07: log ONLY the count, never the raw gato output.
	if app.Log != nil {
		app.Log.Info("osint.github_actions: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// secretExposureKeywords are the case-insensitive markers that, when present in
// a gato JSON string value, indicate a surfaced workflow secret / sensitive
// artefact. Mirrors v1's jq filter (osint.sh:349 — artifact|workflow|runner|secret).
var secretExposureKeywords = []string{"secret", "artifact", "workflow", "runner", "token", "credential", "password"}

// parseGatoOutput walks gato's JSON output and emits OSINTFindingRecords.
//
// XCUT-07 / T-07-03-01: gato output may embed live workflow secrets. We extract
// ONLY a non-secret locator (the JSON key path) and ALWAYS set ValueRedacted to
// "***" for any secret-exposure entry — the raw value is NEVER propagated.
func parseGatoOutput(data []byte) []OSINTFindingRecord {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var records []OSINTFindingRecord
	walkGato(root, "", seen, &records)
	return records
}

// walkGato recursively scans the gato JSON tree. For every string leaf whose
// key path or surrounding key matches a secret-exposure keyword, it emits a
// REDACTED record keyed on the non-secret locator (the JSON path), never the
// raw value.
func walkGato(node interface{}, keyPath string, seen map[string]struct{}, out *[]OSINTFindingRecord) {
	switch v := node.(type) {
	case map[string]interface{}:
		for k, child := range v {
			childPath := k
			if keyPath != "" {
				childPath = keyPath + "." + k
			}
			// A key whose NAME signals a secret marks an exposure regardless of value.
			if isSecretExposureKey(k) {
				addGatoRecord(childPath, seen, out)
			}
			walkGato(child, childPath, seen, out)
		}
	case []interface{}:
		for i, child := range v {
			childPath := fmt.Sprintf("%s[%d]", keyPath, i)
			walkGato(child, childPath, seen, out)
		}
	case string:
		// A string VALUE that names a secret-bearing artefact is an exposure.
		if isSecretExposureKey(v) {
			addGatoRecord(keyPath, seen, out)
		}
	}
}

// addGatoRecord appends a deduped REDACTED workflow-secret-exposure record.
// The locator (JSON path) is non-secret; ValueRedacted is always "***".
func addGatoRecord(locator string, seen map[string]struct{}, out *[]OSINTFindingRecord) {
	if locator == "" {
		return
	}
	if _, ok := seen[locator]; ok {
		return
	}
	seen[locator] = struct{}{}
	*out = append(*out, OSINTFindingRecord{
		Severity:      "high",
		Confidence:    "medium",
		Class:         "osint",
		Source:        "github_actions",
		Category:      "workflow-secret-exposure",
		ValueRedacted: "***", // XCUT-07: raw workflow secret NEVER propagated
		PoCRedacted:   locator,
	})
}

// isSecretExposureKey reports whether s contains a secret-exposure keyword
// (case-insensitive).
func isSecretExposureKey(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range secretExposureKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// init self-registers GitHubActionsTask with the Default task registry.
func init() { task.Register(&GitHubActionsTask{}) }
