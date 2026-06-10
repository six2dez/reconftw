// xnldorker.go — XnldorkerTask: Google dorking via xnldorker (OSINT-15).
//
// XnldorkerTask runs xnldorker (the v2 Google-dorking engine for OSINT-15; v1's
// google_dorks at osint.sh:17 used dorks_hunter — xnldorker is the named OSINT-15
// engine per the phase plan) seeded by the company name to surface indexed,
// publicly-dorkable assets (exposed files, login panels, config leaks) across
// search engines. Each dork hit becomes an informational OSINTFindingRecord (D-O4).
//
// KEY GATE (D-O8, logged-never-silent): Google dorking through search-engine APIs
// requires a credential. The only dork-related credential configured in v2 is the
// GitHub-tokens file (the same credential the GitHub-dork engines use); xnldorker
// gates on it as the dork-credential proxy. Absent → log.Info naming the var +
// StatusSkipped (NEVER a silent skip — web/nuclei.go:108-128). The run COMPLETES.
//
// CONSERVATIVE RATE LIMITS (D-O8): Google dorking is a noisy/abuse-prone source.
// It ships with a conservative per-engine cap and the company seed only — no
// aggressive multi-engine fan-out.
//
// SEEDING (D-O1): company-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8, ARCH-09): best_effort.
//
// THREAT MODEL (T-07-05-04): the dork credential stays log.Secret-typed; xnldorker
// reads it only as a gate signal here (never passes the raw token to argv — the
// credential is consumed by the GitHub-dork engines). The company string crosses
// into xnldorker argv via Backend.Run's []string arg-vector (never a shell string).
//
// Source: .planning/phases/07-osint-e2e/07-05-PLAN.md Task 2.
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

// XnldorkerTask runs xnldorker for OSINT-15 (Google dorking, key-gated).
type XnldorkerTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *XnldorkerTask) Name() string { return "osint.xnldorker" }

// Module returns the owning module group.
func (t *XnldorkerTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *XnldorkerTask) Description() string {
	return "Google dorking (xnldorker, OSINT-15) — key-gated"
}

// Enabled reports whether Google dorking is configured.
func (t *XnldorkerTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GoogleDorks.Enabled && cfg.OSINT.GoogleDorks.XnldorkerEnabled
}

// DependsOn returns nil — OSINT is root-domain/company-seeded (D-O1), no DAG edges.
func (t *XnldorkerTask) DependsOn() []string { return nil }

// Run executes xnldorker seeded by the company name (key-gated D-O8).
//
// Steps:
//  1. Derive + validate the root domain → company name (T-07-05-04).
//  2. Key gate (D-O8): require a configured dork credential (GitHub tokens file).
//     Absent → log Info naming the var + StatusSkipped (logged-never-silent).
//  3. Run xnldorker seeded by company (conservative caps).
//  4. Parse dork hits into informational records.
//  5. Write inputs/findings.xnldorker.jsonl (multi-writer staging).
func (t *XnldorkerTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.xnldorker: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	company := companyName(root)

	// Step 2: key gate (D-O8, logged-never-silent). The GitHub-tokens file is the
	// configured dork credential proxy; absent → logged skip naming the var.
	if gitHubTokenFile(app) == "" {
		if app.Log != nil {
			app.Log.Info("osint.xnldorker: no dork credential (cfg.paths.github_tokens) — skipping (D-O8)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.xnldorker: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	// Step 3: xnldorker seeded by the company name, writing to osint/xnldorker.txt.
	// Conservative single-seed invocation (D-O8) — no aggressive engine fan-out.
	dorkOut := filepath.Join(osintDir, "xnldorker.txt")
	res, err := app.Tools.Run(ctx, "xnldorker", []string{"-q", company, "-o", dorkOut})
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.xnldorker: xnldorker run failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	// Step 4: parse dork hits. xnldorker writes osint/xnldorker.txt; also parse
	// stdout in case the build streams hits there. Each hit is a public dork URL.
	hits := splitNonEmptyLines(res.Stdout)
	if fileHits, rErr := os.ReadFile(dorkOut); rErr == nil { //nolint:gosec // within WorkDir
		hits = append(hits, splitNonEmptyLines(fileHits)...)
	}
	records := dorkRecords(hits, "xnldorker", "google-dork")

	// Step 5: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.xnldorker.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.xnldorker: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// init self-registers XnldorkerTask with the Default task registry.
func init() { task.Register(&XnldorkerTask{}) }
