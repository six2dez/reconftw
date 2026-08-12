// zonetransfer.go — ZoneTransferTask: AXFR zone transfer enumeration.
//
// AllowTransfer safety gate (SUBD-10):
// cfg.Subdomains.ZoneTransfer.Enabled is checked TWICE:
//  1. In Enabled() — used by filterByModuleAndEnabled in the command layer.
//  2. In Run() — defense in depth because Scheduler does NOT call Enabled()
//     before Run (REVIEWS finding #4). Run() returns StatusSkipped immediately
//     if Enabled is false, preventing accidental AXFR without user consent.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-05-PLAN.md Task 2.
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// ZoneTransferTask attempts AXFR zone transfers against all authoritative
// nameservers for the target domain. Writes discovered subdomains to
// inputs/resolved.zonetransfer.txt for consumption by the final MergeStage.
//
// The task is explicitly opt-in: cfg.Subdomains.ZoneTransfer.Enabled must
// be true. This is checked in BOTH Enabled() and Run() (REVIEWS finding #4).
type ZoneTransferTask struct{}

// Name returns the task identifier.
func (ZoneTransferTask) Name() string { return "subdomains.zonetransfer" }

// Module returns the owning module.
func (ZoneTransferTask) Module() string { return "subdomains" }

// Description returns a short description.
func (ZoneTransferTask) Description() string {
	return "DNS zone transfer (AXFR) subdomain enumeration — explicit opt-in required"
}

// Enabled returns cfg.Subdomains.ZoneTransfer.Enabled.
// Used by filterByModuleAndEnabled in the command layer.
func (ZoneTransferTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.ZoneTransfer.Enabled
}

// DependsOn returns nil — sequential RunStage ordering in command layer.
func (ZoneTransferTask) DependsOn() []string { return nil }

// Run attempts AXFR zone transfers and writes found subdomains to
// inputs/resolved.zonetransfer.txt.
//
// GATE: Re-checks cfg.Subdomains.ZoneTransfer.Enabled in Run() body.
// Returns StatusSkipped if false (defense in depth — Scheduler does not
// call Enabled() per REVIEWS finding #4).
func (ZoneTransferTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// In-Run gate (REVIEWS finding #4 fix): re-check even if Enabled() was called.
	if !app.Cfg.Subdomains.ZoneTransfer.Enabled {
		if app.Log != nil {
			app.Log.Info("zone_transfer_skipped_not_enabled",
				"domain", app.Target.Domain)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	domain := app.Target.Domain

	// Look up NS records for the target domain.
	nsRecords, err := lookupNS(ctx, domain)
	if err != nil || len(nsRecords) == 0 {
		if app.Log != nil {
			app.Log.Debug("zonetransfer: no NS records found or lookup failed",
				"domain", domain, "err", func() string {
					if err != nil {
						return err.Error()
					}
					return "no records"
				}())
		}
		// Write empty staging file and return done.
		stagingPath, wErr := writeZoneTransferStagingFile(app, nil)
		if wErr != nil {
			return task.Result{Status: task.StatusDone, Stats: map[string]int{"subdomains_found": 0}}, nil
		}
		return task.Result{
			Status:  task.StatusDone,
			Outputs: []string{stagingPath},
			Stats:   map[string]int{"subdomains_found": 0},
		}, nil
	}

	// Attempt AXFR against each NS server.
	var allSubdomains []string
	seen := make(map[string]struct{})

	for _, ns := range nsRecords {
		if ctx.Err() != nil {
			break
		}
		subs := attemptAXFR(ctx, app, domain, ns)
		for _, sub := range subs {
			lower := strings.ToLower(strings.TrimSpace(sub))
			if lower == "" {
				continue
			}
			if _, exists := seen[lower]; !exists {
				seen[lower] = struct{}{}
				allSubdomains = append(allSubdomains, lower)
			}
		}
	}

	stagingPath, wErr := writeZoneTransferStagingFile(app, allSubdomains)
	if wErr != nil {
		if app.Log != nil {
			app.Log.Debug("zonetransfer: write staging file failed", "err", wErr.Error())
		}
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"subdomains_found": len(allSubdomains)},
		}, nil
	}

	if app.Log != nil && len(allSubdomains) > 0 {
		app.Log.Debug("zonetransfer: AXFR succeeded",
			"domain", domain, "subdomains_found", len(allSubdomains))
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"subdomains_found": len(allSubdomains)},
	}, nil
}

// lookupNS resolves NS records for domain using the standard library.
// Falls back to trying dnsx via app.Tools if net.LookupNS fails.
func lookupNS(_ context.Context, domain string) ([]string, error) {
	nsEntries, err := net.LookupNS(domain)
	if err != nil {
		return nil, err
	}
	var ns []string
	for _, entry := range nsEntries {
		host := strings.TrimSuffix(entry.Host, ".")
		if host != "" {
			ns = append(ns, host)
		}
	}
	return ns, nil
}

// attemptAXFR tries to perform an AXFR zone transfer from the given NS server.
// Returns a list of subdomain hostnames found in the AXFR response.
// Uses app.Tools.Run(ctx, "dnsx") for zone transfer if available.
func attemptAXFR(ctx context.Context, app *appctx.AppContext, domain, nsServer string) []string {
	// Try dnsx AXFR.
	args := []string{
		"-d", domain,
		"-axfr",
		"-ns", nsServer,
		"-silent",
	}

	res, err := app.Tools.Run(ctx, "dnsx", args)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("zonetransfer: dnsx AXFR failed",
				"ns", nsServer, "domain", domain, "err", err.Error())
		}
		return nil
	}

	// Parse dnsx output (one hostname per line).
	var subs []string
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || line == domain {
			continue
		}
		// Only keep subdomains of the target domain.
		if strings.HasSuffix(line, "."+domain) || line == domain {
			subs = append(subs, line)
		}
	}
	return subs
}

// writeZoneTransferStagingFile writes discovered subdomains (one per line) to
// inputs/resolved.zonetransfer.txt for consumption by the final MergeStage.
func writeZoneTransferStagingFile(app *appctx.AppContext, subdomains []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", err
	}

	stagingPath := filepath.Join(inputsDir, "resolved.zonetransfer.txt")
	content := strings.Join(subdomains, "\n")
	if len(subdomains) > 0 {
		content += "\n"
	}

	if err := os.WriteFile(stagingPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", err
	}
	return stagingPath, nil
}

// -------------------------------------------------------------------------
// init() — Task self-registration
// -------------------------------------------------------------------------

func init() { task.Register(ZoneTransferTask{}) }
