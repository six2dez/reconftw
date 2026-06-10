// msftrecon.go — MSFTReconTask: Microsoft tenant recon via msftrecon (OSINT-11).
//
// MSFTReconTask runs msftrecon over the root domain (v1 modules/osint.sh:589,
// inside domain_info: msftrecon.py -d <domain>) to enumerate the target's Azure
// AD / Microsoft 365 tenant — the associated/federated domains, tenant ID, and
// configuration that map the organisation's Microsoft footprint. Each surfaced
// tenant domain becomes an informational OSINTFindingRecord (D-O4).
//
// HIGH-VALUE LIST (D-O5): the tenant-domain list is preserved as the single-writer
// human file osint/azure_tenant_domains.txt — exactly as v1 osint.sh:598 writes it
// (the output-tree name is a public contract). On tool failure the file is left
// empty (v1 osint.sh:602), never partially written.
//
// SEEDING (D-O1): root-domain-seeded — runs from app.Target.Domain alone, no URL
// corpus, no DependsOn edges, never bootstraps subs/web.
//
// FAILURE POLICY (D-O8, ARCH-09): best_effort. msftrecon failing / finding nothing
// logs Debug and returns StatusDone with findings:0 — the run COMPLETES.
//
// THREAT MODEL (T-07-05-01): the domain string crosses into msftrecon argv via
// Backend.Run's []string arg-vector (never a shell string); rootDomain validates a
// registrable-domain shape before use.
//
// Source: .planning/phases/07-osint-e2e/07-05-PLAN.md Task 1.
package osint

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// MSFTReconTask runs msftrecon for OSINT-11 (Microsoft tenant recon).
type MSFTReconTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *MSFTReconTask) Name() string { return "osint.msftrecon" }

// Module returns the owning module group.
func (t *MSFTReconTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *MSFTReconTask) Description() string {
	return "Microsoft tenant recon (msftrecon, OSINT-11)"
}

// Enabled reports whether Microsoft tenant recon is configured.
func (t *MSFTReconTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.MSFT.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *MSFTReconTask) DependsOn() []string { return nil }

// Run executes msftrecon against the root domain and preserves the tenant-domain
// list as osint/azure_tenant_domains.txt (D-O5 single-writer).
//
// Steps:
//  1. Derive + validate the root domain (T-07-05-01).
//  2. Initialise osint/azure_tenant_domains.txt empty (v1 osint.sh:588).
//  3. Run msftrecon (-d <domain>); on success overwrite the txt with raw stdout
//     (v1 osint.sh:597-603), on failure leave it empty.
//  4. Parse tenant domains into informational records.
//  5. Write inputs/findings.msftrecon.jsonl (multi-writer staging).
func (t *MSFTReconTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.msftrecon: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.msftrecon: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.msftrecon: mkdir osint/ failed (best_effort)", "err", err)
		}
	}

	// Step 2: initialise the tenant-domains artefact empty (v1 osint.sh:588).
	azureFile := filepath.Join(osintDir, "azure_tenant_domains.txt")
	if wErr := os.WriteFile(azureFile, nil, 0o644); wErr != nil && app.Log != nil { //nolint:gosec
		app.Log.Debug("osint.msftrecon: init azure_tenant_domains.txt failed", "err", wErr)
	}

	// Step 3: msftrecon — v1 arg vector (osint.sh:592): -d <domain>.
	res, err := app.Tools.Run(ctx, "msftrecon", []string{"-d", root})
	if err != nil {
		// v1 osint.sh:600-602: log and continue with the empty artefact.
		if app.Log != nil {
			app.Log.Debug("osint.msftrecon: msftrecon failed (best_effort) — empty tenant list", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	// Step 3 (cont.): on success, preserve the raw stdout as the human artefact
	// (D-O5 single-writer, v1 osint.sh:598: cat msftrecon_output > azure_tenant_domains.txt).
	if len(bytes.TrimSpace(res.Stdout)) > 0 {
		if wErr := os.WriteFile(azureFile, res.Stdout, 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.msftrecon: write azure_tenant_domains.txt failed", "err", wErr)
		}
	}

	// Step 4: parse tenant domains into informational records. msftrecon emits
	// the associated/federated domain list; each line is a non-secret OSINT value.
	var records []OSINTFindingRecord
	for _, line := range splitNonEmptyLines(res.Stdout) {
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "msftrecon",
			Category:    "azure-tenant",
			PoCRedacted: line, // tenant domain — non-secret OSINT output (T-07-05-02 accept)
		})
	}

	// Step 5: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.msftrecon.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.msftrecon: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// init self-registers MSFTReconTask with the Default task registry.
func init() { task.Register(&MSFTReconTask{}) }
