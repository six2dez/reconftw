// misconfig.go — MisconfigTask: third-party misconfiguration OSINT (fold-in D-O10).
//
// MisconfigTask runs misconfig-mapper (v1 modules/osint.sh:622 third_party_misconfigs)
// over the company name to surface third-party SaaS misconfigurations (exposed
// dashboards, public boards, mis-scoped integrations across "*" services). This
// is the D-O10 third_party_misconfigs fold-in — the v1 function folds into the
// OSINT pipeline rather than being silently dropped.
//
// SEEDING (D-O1): company/root-domain-seeded — no DependsOn edges. The target
// domain crosses into misconfig-mapper's []string argv via -target (never a
// shell string — T-07-04-04).
//
// FINDINGS: each surfaced misconfiguration becomes an OSINTFindingRecord
// (Source third_party_misconfig, Category misconfig) with a per-finding severity.
// The discovered list is preserved as osint/3rdparts_misconfigurations.txt
// (v1 osint.sh:632 anew target, D-O5 single-writer).
//
// FAILURE POLICY (D-O8): best_effort — tool failure / empty output logs Debug and
// returns StatusDone with findings:0.
//
// Source: .planning/phases/07-osint-e2e/07-04-PLAN.md Task 1.
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

// MisconfigTask runs misconfig-mapper for the D-O10 third-party misconfig fold-in.
type MisconfigTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *MisconfigTask) Name() string { return "osint.misconfig" }

// Module returns the owning module group.
func (t *MisconfigTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *MisconfigTask) Description() string {
	return "Third-party misconfigurations (misconfig-mapper, D-O10 fold-in)"
}

// Enabled reports whether third-party misconfig scanning is configured.
func (t *MisconfigTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Misconfig.Enabled
}

// DependsOn returns nil — misconfig-mapper is company/root-domain-seeded (D-O1).
func (t *MisconfigTask) DependsOn() []string { return nil }

// Run executes misconfig-mapper over the company/domain.
//
// Steps:
//  1. Derive + validate the root domain (T-07-04-04).
//  2. Run misconfig-mapper -target <domain> -service "*" (v1 osint.sh:625).
//  3. Preserve osint/3rdparts_misconfigurations.txt (D-O5 single-writer).
//  4. Parse misconfigurations into OSINTFindingRecords.
//  5. Write inputs/findings.misconfig.jsonl (multi-writer staging).
func (t *MisconfigTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.misconfig: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.misconfig: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	// v1 arg vector (osint.sh:625): misconfig-mapper -target <domain>
	//   -as-domain true -permutations false -skip-ssl -service "*" -verbose 0.
	args := []string{
		"-target", root,
		"-as-domain", "true",
		"-permutations", "false",
		"-skip-ssl",
		"-service", "*",
		"-verbose", "0",
	}
	var outLines []string
	if res, err := app.Tools.Run(ctx, "misconfig-mapper", args); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.misconfig: misconfig-mapper run failed (best_effort)", "err", err)
		}
	} else {
		outLines = splitNonEmptyLines(res.Stdout)
	}

	// Step 3: preserve the discovered list (D-O5 single-writer).
	if len(outLines) > 0 {
		listPath := filepath.Join(osintDir, "3rdparts_misconfigurations.txt")
		if wErr := os.WriteFile(listPath,
			[]byte(strings.Join(outLines, "\n")+"\n"), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.misconfig: write 3rdparts_misconfigurations.txt failed", "err", wErr)
		}
	}

	// Step 4: parse misconfigurations into records.
	records := parseMisconfigLines(outLines)

	// Step 5: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.misconfig.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.misconfig: completed", "misconfigs", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"misconfigs": len(records)},
	}, nil
}

// parseMisconfigLines maps misconfig-mapper output lines to OSINTFindingRecords.
// A line that reports a detected/vulnerable third-party integration becomes a
// medium-severity finding (or high when the line marks it exploitable/public);
// banner/progress lines are skipped. Misconfig locators are non-secret OSINT
// output, carried in PoCRedacted.
func parseMisconfigLines(lines []string) []OSINTFindingRecord {
	var records []OSINTFindingRecord
	for _, line := range lines {
		lower := strings.ToLower(line)
		// Only keep lines that look like a positive detection (a URL, or an
		// explicit detected/vulnerable/misconfigured marker). misconfig-mapper
		// emits progress/banner noise we do not want as findings.
		isURL := strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
		// NOTE: deliberately exclude the bare "misconfig" keyword — the tool's
		// own name/banner ("misconfig-mapper") contains it and would produce
		// false-positive findings.
		isHit := strings.Contains(lower, "detected") || strings.Contains(lower, "vulnerable") ||
			strings.Contains(lower, "exposed") || strings.Contains(lower, "exploitable")
		if !isURL && !isHit {
			continue
		}
		severity := "medium"
		if strings.Contains(lower, "exploitable") || strings.Contains(lower, "public") ||
			strings.Contains(lower, "vulnerable") {
			severity = "high"
		}
		records = append(records, OSINTFindingRecord{
			Severity:    severity,
			Confidence:  "medium",
			Class:       "osint",
			Source:      "third_party_misconfig",
			Category:    "misconfig",
			PoCRedacted: line, // misconfig locator — non-secret OSINT output
		})
	}
	return records
}

// init self-registers MisconfigTask with the Default task registry.
func init() { task.Register(&MisconfigTask{}) }
