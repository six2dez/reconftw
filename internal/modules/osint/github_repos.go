// github_repos.go — GitHubReposTask: org repo enumeration via enumerepo (OSINT-05).
//
// GitHubReposTask runs enumerepo over the company org (v1 osint.sh:68
// github_repos), producing the repository list that feeds the leak scan
// (GitHubLeaksTask, D-O10 fold: github_repos + github_leaks → OSINT-05).
//
// The repo list is written to inputs/github_repos.txt as a SINGLE-WRITER
// artefact (D-O5) — one URL per line — which GitHubLeaksTask reads via its
// DependsOn edge. Discovered repos are emitted as informational OSINTFindingRecords.
//
// KEY GATE (D-O8): reads cfg.Paths.GitHubTokens (the v1 $GITHUB_TOKENS file).
// Empty path / empty file → logged Info (naming the var, not the value) +
// StatusSkipped (logged-never-silent).
//
// SECRET HANDLING (XCUT-07 / T-07-03-02): the token is written to a 0600 temp
// file and passed via enumerepo's -token-file flag (v1 osint.sh:80-85) so it is
// NEVER placed on argv or in a log line; the temp file is removed after the run.
//
// SEEDING (D-O1): company-org-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — tool failure / empty output logs Debug
// and returns StatusDone with findings:0.
//
// Source: .planning/phases/07-osint-e2e/07-03-PLAN.md Task 2.
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

// GitHubReposTask runs enumerepo for OSINT-05 (key-gated, feeds github_leaks).
type GitHubReposTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GitHubReposTask) Name() string { return "osint.github_repos" }

// Module returns the owning module group.
func (t *GitHubReposTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *GitHubReposTask) Description() string {
	return "GitHub org repo enumeration (enumerepo, OSINT-05) — feeds github_leaks"
}

// Enabled reports whether GitHub repo enumeration is configured.
func (t *GitHubReposTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GitHub.Enabled
}

// DependsOn returns nil — enumerepo is the DAG root for the leak scan; it is
// company-org-seeded (D-O1) with no upstream edges of its own.
func (t *GitHubReposTask) DependsOn() []string { return nil }

// Run executes enumerepo over the company org and writes the repo list.
//
// Steps:
//  1. Derive + validate the root domain → company name.
//  2. Key gate (D-O8): require a non-empty cfg.Paths.GitHubTokens file.
//  3. Write a 0600 temp token file; run enumerepo -token-file -usernames -o.
//  4. Parse the enumerepo output into a repo URL list.
//  5. Write inputs/github_repos.txt (single-writer artefact, feeds leaks).
//  6. Emit informational records; write staging JSONL.
func (t *GitHubReposTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.github_repos: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	company := companyName(root)

	// Step 2: GITHUB_TOKEN key gate (D-O8, logged-never-silent).
	token, ok := readGitHubToken(app)
	if !ok {
		if app.Log != nil {
			app.Log.Info("osint.github_repos: no GITHUB_TOKEN (cfg.paths.github_tokens) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_repos: mkdir inputs/: %w", err)
	}

	// Step 3: write a 0600 temp token file (T-07-03-02 — token off argv).
	tokenFile, err := writeTokenFile(token)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_repos: write token file failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"repos": 0}}, nil
	}
	defer os.Remove(tokenFile) //nolint:errcheck

	usernamesFile := filepath.Join(inputsDir, "github_company_name.txt")
	if wErr := os.WriteFile(usernamesFile, []byte(company+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_repos: write usernames file: %w", wErr)
	}
	enumOut := filepath.Join(inputsDir, "company_repos.json")

	// v1 arg vector (osint.sh:83): -token-file <f> -usernames <file> -o <out>.
	args := []string{"-token-file", tokenFile, "-usernames", usernamesFile, "-o", enumOut}
	if _, err := app.Tools.Run(ctx, "enumerepo", args); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_repos: enumerepo run failed (best_effort)", "err", err)
		}
		// Fall through — enumerepo may have written partial output.
	}

	// Step 4: parse the enumerepo output into a repo URL list.
	repos := parseEnumerepoOutput(enumOut)

	// Step 5: write inputs/github_repos.txt — the SINGLE-WRITER artefact that
	// GitHubLeaksTask consumes (D-O5 / D-O10 fold).
	reposListPath := filepath.Join(inputsDir, "github_repos.txt")
	if len(repos) > 0 {
		if wErr := os.WriteFile(reposListPath,
			[]byte(strings.Join(repos, "\n")+"\n"), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.github_repos: write github_repos.txt failed", "err", wErr)
		}
	}

	// Step 6: informational records (repo URLs are non-secret OSINT output).
	var records []OSINTFindingRecord
	for _, r := range repos {
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "github_repos",
			Category:    "repo",
			PoCRedacted: r,
		})
	}
	writeOSINTStaging(app, inputsDir, "findings.github_repos.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.github_repos: completed", "repos", len(repos))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"repos": len(repos)},
	}, nil
}

// parseEnumerepoOutput extracts the deduped list of repo clone URLs from
// enumerepo's JSON output. enumerepo emits a JSON array of objects keyed by
// username, each carrying a "repos" array of repo metadata. We tolerate several
// shapes (object-keyed map, array of {repos:[{url|html_url|clone_url|full_name}]})
// and also fall back to plain-text lines (one repo per line).
func parseEnumerepoOutput(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // within WorkDir
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}

	var generic interface{}
	if jErr := json.Unmarshal(data, &generic); jErr == nil {
		collectRepoURLs(generic, add)
		if len(out) > 0 {
			return out
		}
	}

	// Plain-text fallback: one repo URL / full_name per line.
	for _, line := range splitNonEmptyLines(data) {
		add(line)
	}
	return out
}

// collectRepoURLs walks a decoded enumerepo JSON tree, adding any repo URL or
// full_name leaf via add.
func collectRepoURLs(node interface{}, add func(string)) {
	switch v := node.(type) {
	case map[string]interface{}:
		for k, child := range v {
			switch strings.ToLower(k) {
			case "url", "html_url", "clone_url", "ssh_url", "full_name":
				if s, ok := child.(string); ok {
					add(s)
					continue
				}
			}
			collectRepoURLs(child, add)
		}
	case []interface{}:
		for _, child := range v {
			collectRepoURLs(child, add)
		}
	}
}

// init self-registers GitHubReposTask with the Default task registry.
func init() { task.Register(&GitHubReposTask{}) }
