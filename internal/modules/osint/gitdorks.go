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
// ARG VECTOR (v1 osint.sh:44/49 verbatim):
//
//	gitdorks_go -gd <tools>/gitdorks_go/Dorks/{medium_dorks|smalldorks}.txt
//	            -nws 20 -target <domain> -tf <tokenFile> -ew 3
//
// `-gd` is the dorks file (medium in DEEP mode, small otherwise). Without it
// — and without `-gk` — gitdorks_go prints "require keyword or dorkfile" and
// exits 0 having searched NOTHING, which is what this task did until 21-07a
// (the v1 vector was copied minus its first flag). The dorks files ship in
// the gitdorks_go clone under the tools root (install.sh), the same place v1
// read them from.
//
// SEEDING (D-O1): root-domain / company-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — a run in which the tool did not run
// is StatusSkipped with a Reason that says whether it was absent or failed
// (task.ClassifyToolErr); it never fails the scan.
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
//  3. Run gitdorks_go (-gd <dorks> -nws 20 -target <domain> -tf <tokenFile> -ew 3).
//  4. Parse hits into informational records; write staging JSONL.
func (t *GitDorksTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		app.Log.Info("osint.gitdorks: no valid root domain — skipping")
		return task.NothingProduced("no valid root domain"), nil
	}

	// Step 2: GITHUB_TOKEN key gate (D-O8, logged-never-silent). gitdorks_go
	// needs the token FILE path (v1 -tf "$GITHUB_TOKENS").
	tokenFile := gitHubTokenFile(app)
	if tokenFile == "" {
		app.Log.Info("osint.gitdorks: no GITHUB_TOKEN (cfg.paths.github_tokens) — skipping")
		return task.NothingProduced("no GITHUB_TOKEN (cfg.paths.github_tokens)"), nil
	}

	// The dorks file (v1 -gd). Its absence is a broken install, not a
	// zero-result search, and is reported as such rather than handed to the tool
	// to fail on.
	dorksFile := gitDorksFile(app.Cfg)
	if _, statErr := os.Stat(dorksFile); statErr != nil {
		app.Log.Warn("osint.gitdorks: dorks file missing — skipping", "path", dorksFile, "err", statErr)
		return task.NothingProduced("dorks file missing: " + dorksFile), nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.gitdorks: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		app.Log.Debug("osint.gitdorks: mkdir osint/ failed (best_effort)", "err", err)
	}

	// Step 3: gitdorks_go — v1 arg vector (osint.sh:44/49), flag order kept.
	// -nws 20 -ew 3 are conservative v1 throttle defaults (D-O8). The token is
	// passed by file path (-tf), never on the command line as a raw value.
	args := []string{"-gd", dorksFile, "-nws", "20", "-target", root, "-tf", tokenFile, "-ew", "3"}
	res, err := app.Tools.Run(ctx, "gitdorks_go", args)
	if err != nil {
		// Absent-vs-failed (task.ClassifyToolErr). Before 21-07a this arm
		// returned StatusDone with findings:0 — a silent success for a tool that
		// never ran.
		status, reason := task.ClassifyToolErr(err)
		app.Log.Info("osint.gitdorks: gitdorks_go not run — skipping", "reason", reason)
		return task.Result{Status: status, Reason: reason}, nil
	}

	// Step 4: parse hits (public code-search result locators).
	records := dorkRecords(splitNonEmptyLines(res.Stdout), "gitdorks", "github-dork")

	// Preserve osint/gitdorks.txt (D-O5 single-writer human file).
	if len(records) > 0 {
		gitdorksFile := filepath.Join(osintDir, "gitdorks.txt")
		if wErr := os.WriteFile(gitdorksFile, res.Stdout, 0o644); wErr != nil { //nolint:gosec
			app.Log.Debug("osint.gitdorks: write gitdorks.txt failed", "err", wErr)
		}
	}

	writeOSINTStaging(app, inputsDir, "findings.gitdorks.jsonl", records)

	app.Log.Info("osint.gitdorks: completed", "findings", len(records))
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// gitDorksFile is the v1 dorks file path: <tools>/gitdorks_go/Dorks/
// medium_dorks.txt in DEEP mode, smalldorks.txt otherwise (osint.sh:43-49).
func gitDorksFile(cfg *config.Config) string {
	name := "smalldorks.txt"
	if cfg.Advanced.Deep {
		name = "medium_dorks.txt"
	}
	return filepath.Join(cfg.ToolsRoot(), "gitdorks_go", "Dorks", name)
}

// init self-registers GitDorksTask with the Default task registry.
func init() { task.Register(&GitDorksTask{}) }
