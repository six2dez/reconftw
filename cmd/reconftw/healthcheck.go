// healthcheck.go — `reconftw health-check` subcommand (working per CONTEXT D-04).
//
// Source: ADR 0002 §8.1 (health-check subcommand inventory) + 03-CONTEXT.md D-04
// + REQUIREMENTS.md FOUND-08 (Blocker 5 — two-tier missing-tool handling).
//
// Three checks emitted as ui.Printer dot-fill lines:
//
//	1. config.parse        — cfg non-nil (parsed by main STEP 5)
//	2. backend.local       — LocalBackend.HealthCheck(ctx) returns nil
//	3. tool.<name>         — backend.Default registered tools:
//	                            present-and-PATHed     → [OK  ] tool.<name>
//	                            missing-but-required   → [WARN] tool.<name> (required)
//	                            missing-and-critical   → [FAIL] tool.<name> (critical)
//
// Blocker 5 semantics:
//   - Missing critical tools → FAIL line + overall exit 1 (*exitCodeError{code:1}).
//   - Missing required tools (Critical=false) → WARN line + overall exit 0.
//   - No tools registered (Phase 3 baseline before Plan 07 seeds tools.lock)
//     → single OK line stating "0 tools registered (Phase 3 baseline)".
//
// The Printer is constructed locally (not pulled from app.UI) because
// health-check is callable WITHOUT --target — app may be nil.

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/ui"
)

// newHealthCheckCmd creates the working health-check subcommand per D-04.
//
// app may be nil — health-check runs without --target. cfg is the resolved
// Config from main.run STEP 5 (always non-nil under normal invocation).
//
// For testability the function captures app + cfg by closure; tests use
// runHealthCheck() directly with synthetic registry / cfg.
func newHealthCheckCmd(app *appctx.AppContext, cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "health-check",
		Short: "Verify tool binaries reachable + backend operational + config parses",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHealthCheck(cmd, app, cfg, backend.Default)
		},
	}
}

// runHealthCheck is the testable kernel of the health-check subcommand.
// Tests inject a fresh *ToolRegistry (Blocker 7 — never reuse backend.Default
// across tests) to get deterministic results.
//
// Returns *exitCodeError{code:1} when any critical tool is missing or any
// foundational check fails. Returns nil on success.
func runHealthCheck(cmd *cobra.Command, app *appctx.AppContext, cfg *config.Config, reg *backend.ToolRegistry) error {
	w := cmd.OutOrStdout()
	if w == nil {
		w = os.Stdout
	}
	verbosity := ui.VerbosityNormal
	if cfg != nil {
		verbosity = ui.Verbosity(cfg.Output.Verbosity)
	}
	printer := ui.NewPrinter(w, verbosity)

	// criticalFailures names every critical check that failed, so the closing
	// message can report what actually broke. It used to be a bool paired with
	// missingCriticalCount, and the message printed the COUNT — so a config or
	// backend failure exited 1 while announcing "0 critical health checks
	// failed", which reads as success.
	var criticalFailures []string
	missingCriticalCount := 0

	// Check 1: config parse.
	start := time.Now()
	if cfg == nil {
		printer.Status(ui.BadgeFAIL, "config.parse", time.Since(start))
		criticalFailures = append(criticalFailures, "config.parse")
	} else {
		printer.Status(ui.BadgeOK, "config.parse", time.Since(start))
	}

	// Check 2: backend.local HealthCheck.
	start = time.Now()
	killGrace := time.Duration(5) * time.Second
	if cfg != nil {
		killGrace = time.Duration(cfg.Concurrency.KillGraceSeconds) * time.Second
		if killGrace <= 0 {
			killGrace = time.Duration(5) * time.Second
		}
	}
	local := backend.NewLocalBackend(killGrace)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = cmd.Root().Context()
	}
	if err := local.HealthCheck(ctx); err != nil {
		printer.Status(ui.BadgeFAIL, "backend.local", time.Since(start))
		criticalFailures = append(criticalFailures, "backend.local")
	} else {
		printer.Status(ui.BadgeOK, "backend.local", time.Since(start))
	}

	// Check 3: ToolRegistry per-tool exec.LookPath via Discover, then iterate.
	if reg == nil {
		reg = backend.Default
	}
	_ = reg.Discover(ctx)
	missingCritical := reg.MissingCritical()
	missingRequired := reg.MissingRequired()
	missingCritSet := map[string]bool{}
	for _, n := range missingCritical {
		missingCritSet[n] = true
	}
	missingReqSet := map[string]bool{}
	for _, n := range missingRequired {
		missingReqSet[n] = true
	}

	all := reg.All()
	if len(all) == 0 {
		// Phase 3 baseline — Plan 07's tools.lock seed populates real entries.
		printer.Status(ui.BadgeOK, "tools (0 registered — Phase 3 baseline)", 0)
	}
	okCount, missingNames := 0, []string(nil)
	for _, t := range all {
		start = time.Now()
		switch {
		case missingCritSet[t.Name]:
			// Blocker 5: missing-and-critical → FAIL + overall exit 1.
			printer.Status(ui.BadgeFAIL, "tool."+t.Name+" (critical)", time.Since(start))
			criticalFailures = append(criticalFailures, "tool."+t.Name)
			missingCriticalCount++
			missingNames = append(missingNames, t.Name)
		case missingReqSet[t.Name]:
			// Blocker 5: missing-but-required (Critical=false) → WARN, exit 0.
			printer.Status(ui.BadgeWARN, "tool."+t.Name+" (required)", time.Since(start))
			missingNames = append(missingNames, t.Name)
		default:
			printer.Status(ui.BadgeOK, "tool."+t.Name, time.Since(start))
			okCount++
		}
	}

	// Closing summary. Without it the interesting lines — a handful of WARN/FAIL —
	// are buried in a hundred [OK] rows scrolled off the top of the terminal, and
	// the operator has to eyeball every line to learn what is actually missing.
	if len(all) > 0 {
		_, _ = fmt.Fprintf(w, "\n  %d tools: %d present, %d missing (%d critical)\n",
			len(all), okCount, len(missingNames), missingCriticalCount)
		if len(missingNames) > 0 {
			_, _ = fmt.Fprintf(w, "  missing: %s\n", strings.Join(missingNames, " "))
			_, _ = fmt.Fprintf(w, "  install them with: reconftw install\n")
		}
	}

	// Use app only to surface that AppContext booted successfully (informational).
	if app != nil {
		printer.Status(ui.BadgeOK, "appctx (target booted)", 0)
	}

	if len(criticalFailures) > 0 {
		return &exitCodeError{
			code: 1,
			msg: fmt.Sprintf("%d critical health check(s) failed: %s",
				len(criticalFailures), strings.Join(criticalFailures, ", ")),
		}
	}
	return nil
}
