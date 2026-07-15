// emails.go — EmailsTask: email harvesting (EmailHarvester) + password-leak
// search (LeakSearch) (OSINT-03 / PAR-03).
//
// EmailsTask runs EmailHarvester on the root domain (v1 modules/osint.sh:535),
// parses harvested addresses, emits one informational OSINTFindingRecord per
// email to inputs/findings.emails.jsonl (multi-writer staging, D-O3), and
// preserves the v1 human file osint/emails.txt as a single-writer artefact
// (D-O5).
//
// It then runs LeakSearch AFTER EmailHarvester (v1 emails() ordering,
// osint.sh:552-561) to surface leaked passwords → osint/passwords.txt. This
// restored a PAR-03 gap: the Go task previously ran only EmailHarvester, so no
// passwords.txt / password findings were produced. LeakSearch is a python-venv
// repo-clone tool invoked by name through app.Tools (mirroring EmailHarvester).
//
// SEEDING (D-O1): root-domain-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — a failing tool / empty output logs Debug
// and STILL returns StatusDone (a LeakSearch failure never breaks the emails
// path, and vice-versa).
//
// THREAT MODEL: T-07-02-01 — the domain crosses into EmailHarvester/LeakSearch
// argv via Backend.Run's []string arg-vector. T-07-02-03 (accept): harvested
// emails are the intended OSINT output (informational, non-secret). T-13-05-02
// (mitigate): leaked passwords are secrets — the raw value is registered with
// the log Redactor and confined to the single-writer osint/passwords.txt human
// file; the findings.passwords.jsonl stream carries only ValueRedacted="***"
// (XCUT-07 — the raw password NEVER reaches the JSONL stream or a log line).
//
// Source: .planning/phases/07-osint-e2e/07-02-PLAN.md Task 2;
//
//	.planning/phases/13-domain-parity/13-05-PLAN.md Task 1 (LeakSearch fold).
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

// Run executes EmailHarvester + LeakSearch against the root domain.
//
// Steps:
//  1. Derive + validate the root domain.
//  2. Run EmailHarvester (-d <domain> -e all -l 20, v1 osint.sh:545).
//  3. Parse harvested emails; emit informational records.
//  4. Preserve osint/emails.txt (D-O5 single-writer).
//  5. Write inputs/findings.emails.jsonl (multi-writer staging).
//  6. Run LeakSearch (-k <domain> -o <tmp>, v1 osint.sh:552-561) → osint/passwords.txt
//     (plaintext, D-O5) + inputs/findings.passwords.jsonl (redacted, XCUT-07).
//
// A failure in EITHER tool is best_effort (D-O8): it logs Debug and the OTHER
// step still runs — mirroring bash, where LeakSearch runs in its own subshell
// regardless of the EmailHarvester result.
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

	// Step 2: EmailHarvester — v1 arg vector: -d <domain> -e all -l 20. A failure
	// is best_effort and does NOT short-circuit the LeakSearch step below (bash
	// runs LeakSearch in its own subshell regardless — osint.sh:552).
	var emails []string
	if res, err := app.Tools.Run(ctx, "EmailHarvester", []string{"-d", root, "-e", "all", "-l", "20"}); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.emails: EmailHarvester run failed (best_effort)", "err", err)
		}
	} else {
		// Step 3: parse harvested emails (lines containing "@", v1 grep "@").
		emails = parseHarvestedEmails(res.Stdout)
	}

	var records []OSINTFindingRecord
	for _, e := range emails {
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "emails",
			Category:    "email",
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

	// Step 5: write emails staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.emails.jsonl", records)

	// Step 6: LeakSearch password-leak search (v1 emails() osint.sh:552-561).
	pwCount := t.runLeakSearch(ctx, app, root, inputsDir, osintDir)

	if app.Log != nil {
		app.Log.Info("osint.emails: completed", "emails", len(records), "passwords", pwCount)
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records) + pwCount, "emails": len(records), "passwords": pwCount},
	}, nil
}

// runLeakSearch runs LeakSearch after EmailHarvester (v1 emails() osint.sh:552-561).
// LeakSearch WRITES discovered leaked passwords to its -o path (like enumerepo
// -o), so we read the file back. The plaintext passwords are preserved ONLY in
// the single-writer human file osint/passwords.txt (D-O5, bash parity); the
// findings.passwords.jsonl stream carries REDACTED records (ValueRedacted="***")
// and each raw password is registered with the log Redactor BEFORE any log line
// (XCUT-07 / T-13-05-02 — the raw value never reaches the JSONL or a log).
//
// Best_effort (D-O8): a missing tool / venv / empty output logs Debug and returns
// 0 without disturbing the emails path. Returns the count of leaked passwords.
func (t *EmailsTask) runLeakSearch(ctx context.Context, app *appctx.AppContext, root, inputsDir, osintDir string) int {
	// v1 scratch path: ${dir}/.tmp/passwords.txt (osint.sh:555).
	tmpDir := filepath.Join(app.Target.WorkDir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.emails: mkdir .tmp/ failed (best_effort)", "err", err)
		}
		return 0
	}
	pwTmp := filepath.Join(tmpDir, "passwords.txt")

	// v1 arg vector (osint.sh:555): LeakSearch.py -k <domain> -o <tmp passwords>.
	if _, err := app.Tools.Run(ctx, "LeakSearch", []string{"-k", root, "-o", pwTmp}); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.emails: LeakSearch run failed (best_effort)", "err", err)
		}
		return 0
	}

	data, err := os.ReadFile(pwTmp) //nolint:gosec // within WorkDir
	if err != nil {
		// No output file → LeakSearch found nothing / is not installed. best_effort.
		if app.Log != nil {
			app.Log.Debug("osint.emails: no LeakSearch passwords output (best_effort)", "err", err)
		}
		return 0
	}
	passwords := parseLeakSearchPasswords(data)
	if len(passwords) == 0 {
		return 0
	}

	// D-O5 single-writer human file: osint/passwords.txt (PLAINTEXT, bash parity).
	// The plaintext is CONFINED here (T-13-05-02); the JSONL below is redacted.
	// 0600 — this file holds leaked credentials.
	pwFile := filepath.Join(osintDir, "passwords.txt")
	if wErr := os.WriteFile(pwFile, []byte(strings.Join(passwords, "\n")+"\n"), 0o600); wErr != nil && app.Log != nil {
		app.Log.Debug("osint.emails: write passwords.txt failed", "err", wErr)
	}

	// XCUT-07: register every raw password with the Redactor (L2) BEFORE any log
	// line, then emit REDACTED records only (raw NEVER placed in the JSONL — L3).
	var records []OSINTFindingRecord
	for _, pw := range passwords {
		registerSecret(app.Log, pw)
		records = append(records, OSINTFindingRecord{
			Severity:      "medium",
			Confidence:    "medium",
			Class:         "osint",
			Source:        "passwords",
			Category:      "leaked-password",
			ValueRedacted: "***", // L3: raw password NEVER propagated to artefacts
		})
	}
	writeOSINTStaging(app, inputsDir, "findings.passwords.jsonl", records)
	return len(passwords)
}

// parseLeakSearchPasswords returns the deduped, non-empty password lines from a
// LeakSearch -o output file (v1 anew → osint/passwords.txt). One leaked
// credential per line; order is preserved and blank lines are dropped.
func parseLeakSearchPasswords(data []byte) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, line := range splitNonEmptyLines(data) {
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
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
