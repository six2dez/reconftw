// migrate.go — the real `reconftw migrate` subcommand (Phase 14 plan 14-01),
// replacing the exit-64 stub. It is a thin Cobra adapter over the
// internal/core/config migrator engine: parse a v1 reconftw.cfg → emit v2 TOML.
//
// migrate PRODUCES config; it does NOT consume it — so, unlike newReportCmd, it
// never calls config.Load. All parsing/evaluation/disposition lives in the
// engine (config.Migrate / config.MigrateFile), keeping this file a thin adapter.
//
// SECURITY: secret-typed values (SHODAN/WHOISXML/PDCP, slack/telegram/discord
// tokens) are written verbatim ONLY to the target .toml. The --dry-run table and
// all stderr summaries are secret-redacted by the engine (threat T-14-02).
package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/config"
)

type migrateFlags struct {
	fromBash string
	to       string
	dryRun   bool
}

// newMigrateCmd builds the `reconftw migrate` subcommand (CUT-01/02/05/06).
func newMigrateCmd() *cobra.Command {
	f := &migrateFlags{}
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate a v1 reconftw.cfg to a v2 reconftw.toml",
		Long: "Translate a v1 bash reconftw.cfg into a v2-native TOML config. Every v1 " +
			"value is evaluated to a concrete TOML value at migrate-time using the Go " +
			"standard library (arithmetic via go/constant, $(nproc) via runtime.NumCPU) — " +
			"NEVER by shelling out. Mapped keys become live v2-native keys; keys v2 " +
			"auto-computes or supersedes become # SUPERSEDED comments; genuinely unknown " +
			"keys become # UNKNOWN comments AND emit a loud stderr warning (never silently " +
			"dropped). The output loads with zero unknown-key warnings.\n\n" +
			"Use --dry-run to preview the disposition table without writing a file.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrateCmd(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.fromBash, "from-bash", "./reconftw.cfg", "path to the v1 reconftw.cfg to migrate")
	cmd.Flags().StringVar(&f.to, "to", "./reconftw.toml", "destination v2 reconftw.toml ('-' or empty = stdout)")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "preview the disposition table; write no file (CUT-05)")
	return cmd
}

func runMigrateCmd(cmd *cobra.Command, f *migrateFlags) error {
	opts := config.MigrateOptions{
		WarnSink: cmd.ErrOrStderr(), // loud ⚠ unknown-key lines land here (CUT-06)
		DryRun:   f.dryRun,
	}
	res, err := config.MigrateFile(f.fromBash, f.to, opts)
	if err != nil {
		return &exitCodeError{code: 1, msg: err.Error()}
	}

	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	if f.dryRun {
		// Secret-safe: DispositionTable redacts secret values to ***.
		_, _ = fmt.Fprint(out, res.DispositionTable())
		_, _ = fmt.Fprintln(errOut, "[dry-run] no file written.")
		return nil
	}

	if f.to == "" || f.to == "-" {
		// The user explicitly directed the migrated config to stdout — this IS the
		// chosen target, so the real values (incl. secrets) belong here.
		if _, werr := out.Write(res.TOML); werr != nil {
			return &exitCodeError{code: 1, msg: werr.Error()}
		}
	} else {
		_, _ = fmt.Fprintf(out, "migrated %s → %s\n", f.fromBash, f.to)
	}

	// Secret-safe summary: counts only, no values.
	_, _ = fmt.Fprintf(errOut, "disposition: %d mapped, %d superseded, %d unknown\n",
		res.MappedCount, res.SupersededCount, res.UnknownCount)
	if res.UnknownCount > 0 {
		_, _ = fmt.Fprintf(errOut, "⚠ %d unknown key(s) need human review — see the # UNKNOWN comments in the output\n", res.UnknownCount)
	}
	return nil
}
