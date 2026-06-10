// github_dorks.go — GitHubDorksTask: dork automation via dorks_hunter (OSINT-04).
//
// GitHubDorksTask runs dorks_hunter seeded by the company name (the registrable
// label of the root domain — the `unfurl format %r` analog, v1 osint.sh:23).
//
// KEY GATE (D-O8): GitHub OSINT sources are key-gated. The gate reads the
// cfg.Paths.GitHubTokens token FILE (v1 $GITHUB_TOKENS is a path to a file of
// tokens, one per line). When that path is empty or the file is empty/absent,
// the Task logs an Info line naming the variable (NEVER the value) and returns
// StatusSkipped — logged, never silent (mirrors web/nuclei.go:108-128).
//
// SECRET HANDLING (XCUT-07 / T-07-03-02): the token is read from disk and passed
// to the subprocess via a 0600 temp token-file (never argv, never logged). The
// raw token value is NEVER written to a log line.
//
// SEEDING (D-O1): root-domain / company-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — tool failure / empty output logs Debug
// and returns StatusDone with findings:0.
//
// Source: .planning/phases/07-osint-e2e/07-03-PLAN.md Task 1.
package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// GitHubDorksTask runs dorks_hunter for OSINT-04 (key-gated).
type GitHubDorksTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GitHubDorksTask) Name() string { return "osint.github_dorks" }

// Module returns the owning module group.
func (t *GitHubDorksTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *GitHubDorksTask) Description() string {
	return "dork automation (dorks_hunter, OSINT-04) — key-gated"
}

// Enabled reports whether dork automation is configured.
func (t *GitHubDorksTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GoogleDorks.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *GitHubDorksTask) DependsOn() []string { return nil }

// Run executes dorks_hunter against the company / root domain.
//
// Steps:
//  1. Derive + validate the root domain.
//  2. Key gate (D-O8): require a non-empty cfg.Paths.GitHubTokens file →
//     logged StatusSkipped when absent.
//  3. Run dorks_hunter (-d <domain> -o <out>) — conservative defaults (D-O8).
//  4. Parse hits into informational records; write staging JSONL.
func (t *GitHubDorksTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.github_dorks: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 2: GITHUB_TOKEN key gate (D-O8, logged-never-silent).
	if _, ok := readGitHubToken(app); !ok {
		if app.Log != nil {
			app.Log.Info("osint.github_dorks: no GITHUB_TOKEN (cfg.paths.github_tokens) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_dorks: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_dorks: mkdir osint/ failed (best_effort)", "err", err)
		}
	}

	// Step 3: dorks_hunter — v1 arg vector (osint.sh:23): -d <domain> -o <out>.
	// Conservative defaults; no rate flags beyond the tool's built-in throttle (D-O8).
	dorksOut := filepath.Join(osintDir, "dorks.txt")
	res, err := app.Tools.Run(ctx, "dorks_hunter", []string{"-d", root, "-o", dorksOut})
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_dorks: dorks_hunter run failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	// Step 4: parse hits. dorks_hunter writes osint/dorks.txt; also parse stdout
	// in case the build streams hits there. Each hit is an informational dork URL.
	hits := splitNonEmptyLines(res.Stdout)
	if fileHits, rErr := os.ReadFile(dorksOut); rErr == nil { //nolint:gosec // within WorkDir
		hits = append(hits, splitNonEmptyLines(fileHits)...)
	}
	records := dorkRecords(hits, "github_dorks", "github-dork")

	writeOSINTStaging(app, inputsDir, "findings.github_dorks.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.github_dorks: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// dorkRecords builds deduped informational OSINTFindingRecords from dork hit
// lines. The hit (a public dork URL / result line) is non-secret OSINT output
// and survives as PoCRedacted; no live secret value is ever propagated.
func dorkRecords(hits []string, source, category string) []OSINTFindingRecord {
	seen := make(map[string]struct{})
	var records []OSINTFindingRecord
	for _, h := range hits {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      source,
			Category:    category,
			PoCRedacted: h,
		})
	}
	return records
}

// init self-registers GitHubDorksTask with the Default task registry.
func init() { task.Register(&GitHubDorksTask{}) }
