// loglevel.go — makes the ADR §8.2 global flags --log-level / --quiet / --verbose
// actually take effect.
//
// THE BUG THIS FIXES: the three flags were declared on the root command
// (root.go addPersistentGlobalFlags) but NOTHING ever read them. main.run builds
// the process logger at STEP 6 from cfg.Output.LogLevel — which happens BEFORE
// cobra parses argv at STEP 10 — so `--log-level debug` was a silent no-op for
// every subcommand. Composite modes (recon/all/passive/zen/deep) are worse still:
// handlers.BootReconApp re-loads config from scratch, so even a post-parse
// slog.SetDefault would be ignored by the config the scan actually runs on.
//
// Both halves below are required:
//
//  1. root.PersistentPreRunE → applyCLILogLevel resolves the effective level,
//     writes it onto the already-loaded *config.Config, and rebuilds slog.Default
//     so every line from cobra dispatch onward honours it.
//  2. cliLogLevel + cliLogger are carried into handlers.RunOptions by every
//     subcommand, so BootReconApp applies the same override to ITS freshly-loaded
//     config and hands the same logger to appctx.Boot and NewAxiomBackend (which
//     otherwise logged through slog.Default() at whatever level STEP 6 had set —
//     making AxiomBackend's dispatch diagnostics invisible).
//
// Precedence: --verbose (debug) > --quiet (error) > --log-level <lvl>. An unset
// --log-level leaves cfg.Output.LogLevel untouched, so a config-file level still
// wins over the flag's "info" default.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
)

// cliLogLevel is the operator-requested level ("" when no flag was supplied).
// Subcommands pass it through handlers.RunOptions.LogLevel so the composite
// path's own config.Load result honours the flag too.
var cliLogLevel string

// cliLogger is the logger rebuilt at that level (nil when no flag was supplied).
// Subcommands pass it through handlers.RunOptions.Logger so AppContext.Log and
// AxiomBackend share one explicitly-levelled, redacting logger.
var cliLogger *slog.Logger

// cliOutputDir is the operator-supplied -o/--output workspace root ("" when the
// flag was not given, so a configured paths.data_dir keeps winning over the
// flag's own "workspaces" default). Subcommands pass it through
// handlers.RunOptions.OutputDir.
var cliOutputDir string

// warnIfAxiom tells the operator, once, what --axiom currently is.
//
// Live testing across eight paid fleets showed axiom-scan frequently never returns
// in a healthy environment: the fleet deploys, the remote tools run and produce
// correct results, and the scan-side poll hangs. v2 now degrades safely (each
// dispatch is capped, failures re-run locally, a dead fleet is abandoned), so
// --axiom cannot damage a scan — but it does not reliably speed one up either, and
// it provisions BILLABLE cloud instances. Silence would be the wrong default for a
// flag that costs money; `-v` is also the v1 alias for it, which is easy to hit by
// reflex when reaching for verbose (that is -V).
func warnIfAxiom(root *cobra.Command) {
	if root == nil {
		return
	}
	f := root.PersistentFlags().Lookup("axiom")
	if f == nil || !f.Changed || f.Value.String() != "true" {
		return
	}
	fmt.Fprintln(os.Stderr,
		"Warning: --axiom is EXPERIMENTAL and provisions billable cloud instances.\n"+
			"         Distribution is unreliable (axiom-scan often does not return); the scan\n"+
			"         falls back to local execution and results stay correct, but expect no\n"+
			"         speed-up. Fleets are removed at end of scan when shutdown_on_end = true.")
}

// applyCLIOutputDir records -o/--output when the operator actually supplied it.
// Reading the value unconditionally would push the flag default ("workspaces")
// over any configured paths.data_dir on every single run.
func applyCLIOutputDir(root *cobra.Command) {
	if root == nil {
		return
	}
	if f := root.PersistentFlags().Lookup("output"); f != nil && f.Changed {
		cliOutputDir = f.Value.String()
	}
}

// applyCLILogLevel resolves --log-level / --quiet / --verbose into a slog level,
// applies it to cfg, and rebuilds the process-default logger.
//
// No-op when none of the three flags was supplied: the config-file / env level
// (already baked into the STEP 6 logger) stays authoritative. An unrecognised
// --log-level value is ignored here — config validation owns that error path.
func applyCLILogLevel(root *cobra.Command, cfg *config.Config) {
	if root == nil {
		return
	}
	pf := root.PersistentFlags()

	level := ""
	if f := pf.Lookup("log-level"); f != nil && f.Changed {
		level = f.Value.String()
	}
	if quiet, err := pf.GetBool("quiet"); err == nil && quiet {
		level = "error"
	}
	if verbose, err := pf.GetBool("verbose"); err == nil && verbose {
		level = "debug"
	}

	switch level {
	case "debug", "info", "warn", "error":
	default:
		return // unset or unrecognised — leave the STEP 6 logger alone
	}

	cliLogLevel = level
	if cfg == nil {
		return
	}
	cfg.Output.LogLevel = level

	// Rebuild through log.New so the RedactingHandler chain (XCUT-07) survives.
	//
	// THIS IS A FOURTH REDACTOR INSTANCE, AND DELIBERATELY SO. applyCLILogLevel
	// runs in PersistentPreRun, before any subcommand body has built the run's
	// shared redactor (newRunRedactor is called in the RunOptions literal, which
	// is evaluated later). There is nothing here to share, so a fresh instance is
	// the only option — but it is seeded from registerSecrets, the SAME single
	// enumeration every other sink is seeded from, so the two can never know
	// different CONFIG secrets.
	//
	// NAMED RESIDUAL (see the sink table in internal/core/backend/recorder.go):
	// this instance does NOT learn RUNTIME-registered secrets — a GitHub/GitLab
	// token whose file contents a module registers on the run redactor before
	// dispatch (plan 16-01's pattern). cliLogger is passed as RunOptions.Logger
	// and can become app.Log, so on a NON-TTY run with an explicit
	// --log-level/--quiet/--verbose, a runtime-registered token echoed by a tool
	// would reach stderr unredacted. Config secrets are covered; runtime ones are
	// not. Closing it means re-routing app.Log onto the shared instance once cfg
	// and the run redactor both exist, which is a logging-routing change with its
	// own reproduction to build and is deliberately NOT smuggled into 17-01.
	rdct := &log.Redactor{}
	registerSecrets(cfg, rdct)
	cliLogger = log.New(cfg.AsLoggerConfig(), rdct)
	slog.SetDefault(cliLogger)
}
