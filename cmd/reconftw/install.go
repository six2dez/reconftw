// install.go — the real `reconftw install` subcommand (Phase 11 plan 03),
// replacing the exit-64 stub. It is a thin Cobra adapter over the
// internal/installer package: parse flags → build installer.Options → Run.
//
// The `--health-check` path reuses runHealthCheck() from healthcheck.go (same
// package) so `reconftw install --health-check` and `reconftw health-check`
// share one implementation (INST-10, no duplication). It passes nil for both
// the AppContext and the resolved config — install runs as a standalone
// operation before config is loaded, and runHealthCheck already nil-guards both
// (confirmed in healthcheck.go:68/144). No config value is referenced here.
package main

import (
	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/installer"
)

type installFlags struct {
	profile        string
	without        []string
	healthCheck    bool
	nonInteractive bool
	updateLock     bool
}

// newInstallCmd builds the `reconftw install` subcommand (INST-01).
func newInstallCmd() *cobra.Command {
	f := &installFlags{}
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install or update reconFTW tool dependencies (per tools.lock)",
		Long: "Install every orchestrated tool from the pinned tools.lock manifest " +
			"via the native toolchains (go install / uv tool install / system package " +
			"manager), bootstrapping Go + uv (and Rust when needed) on a clean machine. " +
			"Idempotent: re-running installs only missing or outdated tools.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.healthCheck {
				// Reuse the health-check kernel; nil app + nil config are
				// intentional and nil-guarded in runHealthCheck (BLOCKER 3).
				return runHealthCheck(cmd, nil, nil, backend.Default)
			}
			if f.updateLock {
				cmd.Println("tools.lock version pins are updated via the XCUT-08 quarantine workflow:")
				cmd.Println("  scripts/update-tools-lock.sh --all          # list candidate updates")
				cmd.Println("  scripts/update-tools-lock.sh --tool <name> --apply   # after the 24-72h quarantine window")
				return nil
			}
			opts := installer.Options{
				Profile:        f.profile,
				Without:        f.without,
				NonInteractive: f.nonInteractive,
				Registry:       backend.Default,
			}
			if err := installer.New(opts).Run(cmd.Context()); err != nil {
				return &exitCodeError{code: 1, msg: err.Error()}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.profile, "profile", "full", "install profile: full|core (core = critical tier only, per D-03)")
	cmd.Flags().StringSliceVar(&f.without, "without", nil, "skip tool groups by name or kind, e.g. --without rust --without python")
	cmd.Flags().BoolVar(&f.healthCheck, "health-check", false, "probe installed tools instead of installing (INST-10; same as the health-check subcommand)")
	cmd.Flags().BoolVar(&f.nonInteractive, "non-interactive", false, "suppress spinners/prompts (for CI and the Docker builder stage)")
	cmd.Flags().BoolVar(&f.updateLock, "update-lock", false, "print the XCUT-08 workflow for resolving @latest pins into tools.lock")
	return cmd
}
