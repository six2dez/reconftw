// emails.go — EmailsTask: email harvesting via EmailHarvester (OSINT-03).
//
// EmailsTask runs EmailHarvester on the root domain (v1 modules/osint.sh:535),
// parses harvested addresses, emits one informational OSINTFindingRecord per
// email to inputs/findings.emails.jsonl (multi-writer staging, D-O3), and
// preserves the v1 human file osint/emails.txt as a single-writer artefact
// (D-O5).
//
// SEEDING (D-O1): root-domain-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — tool failure / empty output logs Debug
// and returns StatusDone with findings:0.
//
// THREAT MODEL (T-07-02-01): domain crosses into EmailHarvester argv via
// Backend.Run's []string arg-vector. T-07-02-03 (accept): harvested emails are
// the intended OSINT output (informational, non-secret).
//
// Source: .planning/phases/07-osint-e2e/07-02-PLAN.md Task 2.
package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// EmailsTask runs EmailHarvester for OSINT-03.
type EmailsTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *EmailsTask) Name() string { return "osint.emails" }

// Module returns the owning module group.
func (t *EmailsTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *EmailsTask) Description() string { return "email harvesting (EmailHarvester, OSINT-03)" }

// Enabled reports whether email harvesting is configured.
func (t *EmailsTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Emails.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *EmailsTask) DependsOn() []string { return nil }

// Run executes EmailHarvester against the root domain.
//
// Steps:
//  1. Derive + validate the root domain.
//  2. Run EmailHarvester (-d <domain> -e all -l 20, v1 osint.sh:535).
//  3. Parse harvested emails; emit informational records.
//  4. Preserve osint/emails.txt (D-O5 single-writer).
//  5. Write inputs/findings.emails.jsonl (multi-writer staging).
func (t *EmailsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.emails: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.emails: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.emails: mkdir osint/ failed (best_effort)", "err", err)
		}
	}

	// Step 2: EmailHarvester — v1 arg vector: -d <domain> -e all -l 20.
	res, err := app.Tools.Run(ctx, "EmailHarvester", []string{"-d", root, "-e", "all", "-l", "20"})
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.emails: EmailHarvester run failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	// Step 3: parse harvested emails (lines containing "@", v1 grep "@").
	emails := parseHarvestedEmails(res.Stdout)
	var records []OSINTFindingRecord
	for _, e := range emails {
		records = append(records, OSINTFindingRecord{
			Severity: "informational",
			Class:    "osint",
			Source:   "emails",
			Category: "email",
			PoCRedacted: e, // email address (intended OSINT output, T-07-02-03 accept)
		})
	}

	// Step 4: preserve osint/emails.txt (D-O5 single-writer).
	if len(emails) > 0 {
		emailsFile := filepath.Join(osintDir, "emails.txt")
		if wErr := os.WriteFile(emailsFile,
			[]byte(strings.Join(emails, "\n")+"\n"), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.emails: write emails.txt failed", "err", wErr)
		}
	}

	// Step 5: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.emails.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.emails: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// parseHarvestedEmails returns deduped, lower-cased email addresses from the
// EmailHarvester output (lines containing "@", mirroring v1 grep "@").
func parseHarvestedEmails(data []byte) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, line := range splitNonEmptyLines(data) {
		// EmailHarvester emits one address per line; some lines have surrounding
		// markup — keep only the token that looks like an email.
		for _, tok := range strings.Fields(line) {
			tok = strings.Trim(tok, "<>,;\"'()[]")
			if !strings.Contains(tok, "@") {
				continue
			}
			at := strings.IndexByte(tok, '@')
			if at <= 0 || at == len(tok)-1 || strings.Contains(tok, "://") {
				continue
			}
			lower := strings.ToLower(tok)
			if _, ok := seen[lower]; ok {
				continue
			}
			seen[lower] = struct{}{}
			out = append(out, lower)
		}
	}
	return out
}

// init self-registers EmailsTask with the Default task registry.
func init() { task.Register(&EmailsTask{}) }
