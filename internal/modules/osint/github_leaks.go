// github_leaks.go — GitHubLeaksTask: GitHub-wide secret scan (OSINT-05).
//
// *** HIGHEST-SECRET-LEAK-RISK TASK OF THE PHASE ***
//
// GitHubLeaksTask runs BOTH leak engines per OSINT-05 (v1 osint.sh:266 github_leaks
// + osint.sh:220 trufflehog enrichment) over the repositories enumerated by
// GitHubReposTask:
//   - ghleaks    — GitHub-wide secret search by query (`-q <domain>`)
//   - trufflehog — per-repo git secret scan (`git <repoURL> -j`)
//
// Both engines emit LIVE CREDENTIALS in their output. XCUT-07 three-layer
// redaction is the #1 correctness requirement (07-PATTERNS.md §"Secret redaction
// at the sink", mantra.go:162-193):
//
//	L1 (type-level): the GitHub token is read via readGitHubToken and passed to
//	    the subprocess only — never logged (T-07-03-02).
//	L2 (runtime registry): for every surfaced secret VALUE, app.Log's Redactor
//	    .Register(rawValue) is called BEFORE any log line so the substring is
//	    scrubbed from ALL subsequent slog output (redactor.go:35-58).
//	L3 (field-level): the OSINTFindingRecord carries ONLY the non-secret locator
//	    (repo/file/line/detector); ValueRedacted="***". The raw secret is NEVER
//	    written to a record, log, or artefact.
//
// Logs report ONLY counts, never raw matches (crlf.go:171-173).
//
// KEY GATE (D-O8): reads cfg.Paths.GitHubTokens (the v1 $GITHUB_TOKENS file).
// Empty path / empty file → logged Info + StatusSkipped (logged-never-silent).
//
// DEPENDENCY (D-O10 fold): DependsOn ["osint.github_repos"] — the enumerated
// repo list (inputs/github_repos.txt) feeds the per-repo trufflehog scan.
//
// FAILURE POLICY (D-O8): best_effort — engine failure / empty output logs Debug
// and returns StatusDone.
//
// Source: .planning/phases/07-osint-e2e/07-03-PLAN.md Task 2.
package osint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/task"
)

// GitHubLeaksTask runs ghleaks + trufflehog for OSINT-05 (secret-emitting).
type GitHubLeaksTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GitHubLeaksTask) Name() string { return "osint.github_leaks" }

// Module returns the owning module group.
func (t *GitHubLeaksTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *GitHubLeaksTask) Description() string {
	return "GitHub-wide secret scan (ghleaks + trufflehog, OSINT-05) — XCUT-07 redacted"
}

// Enabled reports whether GitHub leak scanning is configured.
func (t *GitHubLeaksTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GitHub.LeaksEnabled
}

// DependsOn returns the DAG edge to github_repos — the enumerated repo list
// feeds the per-repo trufflehog scan (D-O10 fold).
func (t *GitHubLeaksTask) DependsOn() []string { return []string{"osint.github_repos"} }

// Run executes ghleaks + trufflehog over the enumerated repos with full
// XCUT-07 redaction.
func (t *GitHubLeaksTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.github_leaks: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Key gate (D-O8, logged-never-silent).
	token, ok := readGitHubToken(app)
	if !ok {
		if app.Log != nil {
			app.Log.Info("osint.github_leaks: no GITHUB_TOKEN (cfg.paths.github_tokens) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_leaks: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	var records []OSINTFindingRecord

	// --- Engine 1: ghleaks (GitHub-wide secret search by query) ---------------
	// v1 arg vector (osint.sh:272): -q <domain> --token <tok> --report <json>
	//                               --threads <n> --no-banner
	ghReport := filepath.Join(osintDir, "github_leaks.json")
	ghArgs := []string{
		"-q", root,
		"--token", token, // L1: token to subprocess only; never logged
		"--report", ghReport,
		"--no-banner",
	}
	// XCUT-09 heartbeat: ghleaks can run long — use Stream and drain.
	// The event lines may embed raw secrets, so they are NEVER logged here.
	if ev, sErr := app.Tools.Stream(ctx, "ghleaks", ghArgs); sErr != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_leaks: ghleaks stream error (best_effort)", "err", sErr)
		}
	} else {
		for range ev { //nolint:revive // intentional drain — raw secret lines NOT logged
		}
	}
	if ghData, rErr := os.ReadFile(ghReport); rErr == nil { //nolint:gosec // within WorkDir
		records = append(records, parseGhleaksReport(ghData, app.Log)...)
	}

	// --- Engine 2: trufflehog (per-repo git scan) -----------------------------
	repos := readRepoList(inputsDir)
	for _, repoURL := range repos {
		// v1 arg vector (osint.sh:230): trufflehog git <repoURL> -j
		res, rErr := app.Tools.Run(ctx, "trufflehog", []string{"git", repoURL, "-j"})
		if rErr != nil {
			if app.Log != nil {
				app.Log.Debug("osint.github_leaks: trufflehog run failed (best_effort)", "repo", repoURL, "err", rErr)
			}
			continue
		}
		records = append(records, parseTrufflehogOutput(res.Stdout, app.Log)...)
	}

	// Write staging JSONL — every record is already REDACTED (ValueRedacted="***").
	writeOSINTStaging(app, inputsDir, "findings.github_leaks.jsonl", records)

	// XCUT-07: log ONLY the count, never the raw matches.
	if app.Log != nil {
		app.Log.Info("osint.github_leaks: completed",
			"secrets_found", len(records), "repos_scanned", len(repos))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"secrets_found": len(records), "repos_scanned": len(repos)},
	}, nil
}

// readRepoList reads the single-writer repo list produced by GitHubReposTask
// (inputs/github_repos.txt). Returns nil when absent (best_effort).
func readRepoList(inputsDir string) []string {
	data, err := os.ReadFile(filepath.Join(inputsDir, "github_repos.txt")) //nolint:gosec // within WorkDir
	if err != nil {
		return nil
	}
	return splitNonEmptyLines(data)
}

// registerSecret feeds a surfaced raw secret value into the slog Redactor (L2)
// so it is scrubbed from ALL subsequent log output (redactor.go:35-58). The
// app logger's handler IS a RedactingHandler wrapping a shared *Redactor; we
// reach it via the package-level helper. This MUST be called BEFORE any log
// line that could reference the value. Values ≤4 chars are ignored by Register.
func registerSecret(logger *slog.Logger, raw string) {
	if raw == "" {
		return
	}
	log.RegisterHandlerSecret(logger, raw)
}

// trufflehogResult is the subset of trufflehog -j JSON we read. We deliberately
// IGNORE the Raw / RawV2 secret fields for the record — only the non-secret
// locator (detector + source metadata) survives. Raw IS read transiently to
// register it with the Redactor (L2), then discarded.
type trufflehogResult struct {
	DetectorName   string          `json:"DetectorName"`
	Verified       bool            `json:"Verified"`
	Raw            string          `json:"Raw"`
	RawV2          string          `json:"RawV2"`
	Redacted       string          `json:"Redacted"`
	SourceMetadata json.RawMessage `json:"SourceMetadata"`
}

// parseTrufflehogOutput parses trufflehog -j JSONL output (one JSON object per
// line) into REDACTED OSINTFindingRecords.
//
// XCUT-07: the raw secret (Raw/RawV2/Redacted) is registered with the Redactor
// (L2) then DROPPED. The record carries only the detector + a non-secret source
// locator and ValueRedacted="***" (L3).
func parseTrufflehogOutput(data []byte, logger *slog.Logger) []OSINTFindingRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var records []OSINTFindingRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r trufflehogResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if r.DetectorName == "" && r.Raw == "" && r.RawV2 == "" {
			continue
		}
		// L2: register any raw secret value BEFORE building/logging the record.
		registerSecret(logger, r.Raw)
		registerSecret(logger, r.RawV2)
		registerSecret(logger, r.Redacted)

		severity := "high"
		if r.Verified {
			severity = "critical"
		}
		locator := trufflehogLocator(r)
		records = append(records, OSINTFindingRecord{
			Severity:      severity,
			Confidence:    confidenceFor(r.Verified),
			Class:         "osint",
			Source:        "github_leaks",
			Category:      "leaked-secret",
			ValueRedacted: "***", // L3: raw secret NEVER propagated
			PoCRedacted:   locator,
		})
	}
	return records
}

// trufflehogLocator builds a NON-SECRET locator string (detector + git path /
// commit / file from SourceMetadata) for a trufflehog finding. It NEVER includes
// the secret value. SourceMetadata shape varies by source; we extract the common
// git fields (repository, file, commit, line) best-effort.
func trufflehogLocator(r trufflehogResult) string {
	parts := []string{r.DetectorName}
	if len(r.SourceMetadata) > 0 {
		var meta map[string]interface{}
		if err := json.Unmarshal(r.SourceMetadata, &meta); err == nil {
			parts = append(parts, extractGitLocator(meta)...)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// extractGitLocator pulls non-secret git locator fields (repository/file/commit/
// line) from a decoded trufflehog SourceMetadata map. Only these whitelisted,
// non-secret keys are returned — arbitrary string values are NOT harvested
// (which could leak a secret embedded elsewhere in the metadata).
func extractGitLocator(node interface{}) []string {
	var out []string
	wanted := map[string]struct{}{
		"repository": {}, "file": {}, "commit": {}, "line": {},
		"email": {}, "timestamp": {},
	}
	var walk func(interface{})
	walk = func(n interface{}) {
		switch v := n.(type) {
		case map[string]interface{}:
			for k, child := range v {
				if _, ok := wanted[strings.ToLower(k)]; ok {
					switch cv := child.(type) {
					case string:
						if cv != "" {
							out = append(out, cv)
						}
					case float64:
						out = append(out, fmt.Sprintf("%v", cv))
					}
					continue
				}
				walk(child)
			}
		case []interface{}:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(node)
	return out
}

// ghleaksReportEntry is the subset of a ghleaks report record we read. As with
// trufflehog, the raw secret is registered (L2) then dropped; only the
// non-secret locator survives (L3).
type ghleaksReportEntry struct {
	Repository  string `json:"repository"`
	Repo        string `json:"repo"`
	File        string `json:"file"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	LineNumber  int    `json:"lineNumber"`
	RuleID      string `json:"ruleID"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Secret      string `json:"secret"`
	Match       string `json:"match"`
}

// parseGhleaksReport parses the ghleaks JSON report (an array of entries, or a
// JSONL stream) into REDACTED OSINTFindingRecords. The raw secret (Secret/Match)
// is registered (L2) then dropped; ValueRedacted="***" (L3).
func parseGhleaksReport(data []byte, logger *slog.Logger) []OSINTFindingRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var entries []ghleaksReportEntry
	// Try a JSON array first.
	if err := json.Unmarshal(data, &entries); err != nil {
		// Fall back to JSONL (one object per line).
		entries = entries[:0]
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var e ghleaksReportEntry
			if uErr := json.Unmarshal(line, &e); uErr == nil {
				entries = append(entries, e)
			}
		}
	}

	var records []OSINTFindingRecord
	for _, e := range entries {
		// L2: register the raw secret BEFORE building/logging anything.
		registerSecret(logger, e.Secret)
		registerSecret(logger, e.Match)

		locator := ghleaksLocator(e)
		if locator == "" && e.Secret == "" && e.Match == "" {
			continue
		}
		records = append(records, OSINTFindingRecord{
			Severity:      "high",
			Confidence:    "medium",
			Class:         "osint",
			Source:        "github_leaks",
			Category:      "leaked-secret",
			ValueRedacted: "***", // L3: raw secret NEVER propagated
			PoCRedacted:   locator,
		})
	}
	return records
}

// ghleaksLocator builds a non-secret locator (repo + file + line + rule) for a
// ghleaks entry. It NEVER includes the secret value.
func ghleaksLocator(e ghleaksReportEntry) string {
	repo := e.Repository
	if repo == "" {
		repo = e.Repo
	}
	file := e.File
	if file == "" {
		file = e.Path
	}
	line := e.Line
	if line == 0 {
		line = e.LineNumber
	}
	rule := e.RuleID
	if rule == "" {
		rule = e.Rule
	}
	var parts []string
	if repo != "" {
		parts = append(parts, repo)
	}
	if file != "" {
		if line > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", file, line))
		} else {
			parts = append(parts, file)
		}
	}
	if rule != "" {
		parts = append(parts, rule)
	}
	return strings.Join(parts, " ")
}

// confidenceFor maps a verified flag to a confidence string.
func confidenceFor(verified bool) string {
	if verified {
		return "high"
	}
	return "medium"
}

// init self-registers GitHubLeaksTask with the Default task registry.
func init() { task.Register(&GitHubLeaksTask{}) }
