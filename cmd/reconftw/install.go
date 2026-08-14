// install.go — the real `reconftw install` subcommand (Phase 11 plan 03),
// replacing the exit-64 stub. It is a thin Cobra adapter over the
// internal/installer package: parse flags → build installer.Options → Run.
//
// The `--health-check` path reuses runHealthCheck() from healthcheck.go (same
// package) so `reconftw install --health-check` and `reconftw health-check`
// share one implementation (INST-10, no duplication). It loads the config the
// same way the standalone subcommand does: passing nil made runHealthCheck's
// first check report `[FAIL] config.parse` on a perfectly healthy machine, so
// `install --health-check` always exited 1 while `health-check` exited 0.
// nil was nil-guarded, but "guarded" meant "reported as a failure".
package main

import (
	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
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
				// Load the config so config.parse reflects reality. A genuine
				// parse failure still surfaces as [FAIL] — which is the point;
				// what must not happen is reporting failure because the caller
				// never tried to load it. app stays nil: health-check runs
				// without --target and runHealthCheck treats app as optional.
				cfg, err := config.Load(config.LoadOptions{})
				if err != nil {
					cfg = nil // real failure — runHealthCheck reports config.parse FAIL
				}
				return runHealthCheck(cmd, nil, cfg, backend.Default)
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
