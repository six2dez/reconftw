// gitdorks.go — GitDorksTask: GitHub dork search via gitdorks_go (OSINT-04).
//
// GitDorksTask runs gitdorks_go seeded by the company / root domain (v1
// osint.sh:44). gitdorks_go searches GitHub code for leaked-secret dork
// patterns; it REQUIRES a GitHub token file (-tf), so this Task is key-gated.
//
// KEY GATE (D-O8): reads cfg.Paths.GitHubTokens (the v1 $GITHUB_TOKENS file
// path). Empty path / empty file → logged Info (naming the var, not the value)
// + StatusSkipped (logged-never-silent, mirrors web/nuclei.go:108-128).
//
// SECRET HANDLING (XCUT-07 / T-07-03-02): the token file path is passed via the
// -tf flag exactly as v1 does (the file already holds the token; we never read
// the raw token into a log line, never place it in argv). Dork hits are public
// code-search result locators (repo/path), not the secrets themselves — they
// survive as PoCRedacted; no live secret value is propagated.
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

// GitDorksTask runs gitdorks_go for OSINT-04 (key-gated).
type GitDorksTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GitDorksTask) Name() string { return "osint.gitdorks" }

// Module returns the owning module group.
func (t *GitDorksTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *GitDorksTask) Description() string {
	return "GitHub dork search (gitdorks_go, OSINT-04) — key-gated"
}

// Enabled reports whether GitHub dork search is configured.
func (t *GitDorksTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GoogleDorks.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *GitDorksTask) DependsOn() []string { return nil }

// Run executes gitdorks_go against the company / root domain.
//
// Steps:
//  1. Derive + validate the root domain.
//  2. Key gate (D-O8): require a non-empty cfg.Paths.GitHubTokens file.
//  3. Run gitdorks_go (-target <domain> -tf <tokenFile>, conservative -nws/-ew).
//  4. Parse hits into informational records; write staging JSONL.
func (t *GitDorksTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.gitdorks: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 2: GITHUB_TOKEN key gate (D-O8, logged-never-silent). gitdorks_go
	// needs the token FILE path (v1 -tf "$GITHUB_TOKENS").
	tokenFile := gitHubTokenFile(app)
	if tokenFile == "" {
		if app.Log != nil {
			app.Log.Info("osint.gitdorks: no GITHUB_TOKEN (cfg.paths.github_tokens) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.gitdorks: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.gitdorks: mkdir osint/ failed (best_effort)", "err", err)
		}
	}

	// Step 3: gitdorks_go — v1 arg vector (osint.sh:44/49, small dorks default).
	// -nws 20 -ew 3 are conservative v1 throttle defaults (D-O8). The token is
	// passed by file path (-tf), never on the command line as a raw value.
	args := []string{"-nws", "20", "-target", root, "-tf", tokenFile, "-ew", "3"}
	res, err := app.Tools.Run(ctx, "gitdorks_go", args)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.gitdorks: gitdorks_go run failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	// Step 4: parse hits (public code-search result locators).
	records := dorkRecords(splitNonEmptyLines(res.Stdout), "gitdorks", "github-dork")

	// Preserve osint/gitdorks.txt (D-O5 single-writer human file).
	if len(records) > 0 {
		gitdorksFile := filepath.Join(osintDir, "gitdorks.txt")
		if wErr := os.WriteFile(gitdorksFile, res.Stdout, 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.gitdorks: write gitdorks.txt failed", "err", wErr)
		}
	}

	writeOSINTStaging(app, inputsDir, "findings.gitdorks.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.gitdorks: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// init self-registers GitDorksTask with the Default task registry.
func init() { task.Register(&GitDorksTask{}) }
