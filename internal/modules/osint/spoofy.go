// spoofy.go — SpoofyTask: email spoofing posture (OSINT-10, mail_hygiene fold).
//
// SpoofyTask runs Spoofy on the root domain (v1 modules/osint.sh:658 spoof),
// parsing the SPF/DMARC/DKIM posture. Per D-O10, the v1 mail_hygiene function
// (osint.sh:687 — also SPF/DMARC posture via dig TXT) is FOLDED into this Task:
// SpoofyTask.Enabled gates on Spoofy.Enabled || MailHygiene.Enabled.
//
// Posture records (SPF/DMARC/DKIM present-or-absent) are informational (D-O4).
// A reported-spoofable domain is a GENUINE security finding (T-07-02-04: never
// silently informational) and is emitted with "medium" / "high" severity.
//
// Records are written to inputs/findings.spoofy.jsonl per the multi-writer
// staging contract (D-O3).
//
// SEEDING (D-O1): root-domain-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — tool failure / empty output logs Debug
// and returns StatusDone with findings:0.
//
// THREAT MODEL (T-07-02-01): domain crosses into Spoofy argv via Backend.Run's
// []string arg-vector. T-07-02-04 (mitigate): spoofable verdict → security
// severity, parsed per-record into a typed Category, never silently dropped.
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

// SpoofyTask runs Spoofy SPF/DMARC/DKIM posture for OSINT-10 (mail_hygiene fold).
type SpoofyTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SpoofyTask) Name() string { return "osint.spoofy" }

// Module returns the owning module group.
func (t *SpoofyTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *SpoofyTask) Description() string {
	return "email spoofing posture SPF/DMARC/DKIM (Spoofy + mail_hygiene, OSINT-10)"
}

// Enabled gates on EITHER Spoofy or MailHygiene (D-O10 fold — both are SPF/DMARC
// posture). Either flag enabling triggers the Spoofy run.
func (t *SpoofyTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Spoofy.Enabled || cfg.OSINT.MailHygiene.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *SpoofyTask) DependsOn() []string { return nil }

// Run executes Spoofy against the root domain.
//
// Steps:
//  1. Derive + validate the root domain.
//  2. Run Spoofy (-d <domain>, v1 osint.sh:671).
//  3. Parse SPF/DMARC/DKIM posture + spoofable verdict into records.
//  4. Preserve osint/spoof.txt (D-O5 single-writer).
//  5. Write inputs/findings.spoofy.jsonl (multi-writer staging).
func (t *SpoofyTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.spoofy: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.spoofy: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.spoofy: mkdir osint/ failed (best_effort)", "err", err)
		}
	}

	// Step 2: Spoofy — v1 arg vector: -d <domain>.
	res, err := app.Tools.Run(ctx, "Spoofy", []string{"-d", root})
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.spoofy: Spoofy run failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	// Step 3: parse posture + spoofable verdict.
	records := parseSpoofyOutput(res.Stdout)

	// Step 4: preserve osint/spoof.txt (D-O5 single-writer).
	if len(strings.TrimSpace(string(res.Stdout))) > 0 {
		spoofFile := filepath.Join(osintDir, "spoof.txt")
		if wErr := os.WriteFile(spoofFile, res.Stdout, 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.spoofy: write spoof.txt failed", "err", wErr)
		}
	}

	// Step 5: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.spoofy.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.spoofy: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// parseSpoofyOutput parses Spoofy's SPF/DMARC/DKIM posture lines into
// OSINTFindingRecords. Posture records (the presence/absence of each mechanism)
// are informational; a reported-spoofable domain is a security finding
// (T-07-02-04) emitted with medium/high severity — never silently informational.
//
// Spoofy output is line-oriented and includes a final spoofing verdict (e.g.
// "Spoofing possible for <domain>!" / "SPOOFING POSSIBLE"). The exact wording
// varies by version, so detection is keyword-based and case-insensitive.
func parseSpoofyOutput(data []byte) []OSINTFindingRecord {
	var records []OSINTFindingRecord
	for _, line := range splitNonEmptyLines(data) {
		lower := strings.ToLower(line)

		// Category classification (posture, informational by default).
		category := ""
		switch {
		case strings.Contains(lower, "dmarc"):
			category = "dmarc"
		case strings.Contains(lower, "dkim"):
			category = "dkim"
		case strings.Contains(lower, "spf"):
			category = "spf"
		}

		// Spoofable verdict — a genuine security finding (T-07-02-04).
		if isSpoofableVerdict(lower) {
			sev := "medium"
			// A definitively spoofable domain (no SPF/DMARC at all) is high.
			if strings.Contains(lower, "no protection") ||
				strings.Contains(lower, "not protected") ||
				strings.Contains(lower, "highly") {
				sev = "high"
			}
			records = append(records, OSINTFindingRecord{
				Severity:    sev,
				Confidence:  "high",
				Class:       "osint",
				Source:      "spoofy",
				Category:    "spoofable",
				PoCRedacted: line,
			})
			continue
		}

		if category == "" {
			continue
		}
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "spoofy",
			Category:    category,
			PoCRedacted: line,
		})
	}
	return records
}

// isSpoofableVerdict reports whether a (lower-cased) Spoofy output line indicates
// the domain is spoofable. Keyword-based + version-tolerant.
func isSpoofableVerdict(lower string) bool {
	if strings.Contains(lower, "not spoofable") || strings.Contains(lower, "spoofing not possible") {
		return false
	}
	return strings.Contains(lower, "spoofable") ||
		strings.Contains(lower, "spoofing possible") ||
		strings.Contains(lower, "spoofing is possible")
}

// init self-registers SpoofyTask with the Default task registry.
func init() { task.Register(&SpoofyTask{}) }
