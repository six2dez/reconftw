// config_subcommand.go — `reconftw config` : show the EFFECTIVE configuration.
//
// Why this exists: config is assembled from an 8-source precedence chain (defaults →
// system → user → project → --config → secrets → RECONFTW_* env → CLI flags). When a
// setting does not behave as expected there was previously no way to ask the binary
// what it actually resolved to — operators had to reason about the chain by hand. The
// review that added this found two real consequences of that blindness: `./reconftw.toml`
// was never being read at all, and `-o/--output` was accepted but ignored.
//
// Two views:
//
//	reconftw config show      the merged result as TOML (secrets rendered as ***)
//	reconftw config sources   each layer, its path, and whether it was found
//
// `show` reuses config.SnapshotBytes — the same deterministic, redacted rendering the
// checkpoint input-hash consumes — so what is printed is exactly what the run sees.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/config"
)

// newConfigCmd builds the `config` command group.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect the effective configuration and where it came from",
		Long: `Inspect configuration after the 8-source merge chain resolves.

Precedence (later wins):
  1. built-in defaults
  2. /etc/reconftw/config.toml            (system)
  3. ~/.config/reconftw/config.toml       (user)
  4. ./reconftw.toml                      (project)
  5. --config FILE                        (explicit)
  6. secrets.toml / --secrets FILE        (secret material)
  7. RECONFTW_* environment variables
  8. command-line flags`,
	}
	cmd.AddCommand(newConfigShowCmd(), newConfigSourcesCmd())
	return cmd
}

// newConfigShowCmd prints the merged configuration as TOML.
func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the effective merged configuration as TOML (secrets redacted)",
		Long: `Print the configuration this binary would run with, after merging all
sources. Every secret-typed value is rendered as "***" — the output is safe to paste
into a bug report.

Honours --config and --secrets, so you can preview a file before scanning with it.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfigForInspection(cmd)
			if err != nil {
				return err
			}
			data, err := config.SnapshotBytes(cfg)
			if err != nil {
				return fmt.Errorf("config show: render: %w", err)
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

// newConfigSourcesCmd reports each layer of the chain and whether it was found.
func newConfigSourcesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sources",
		Short: "List each config layer, its path, and whether it exists",
		Long: `List the 8-source precedence chain with the concrete path each file layer
resolves to and whether that file is present. Use it to answer "why is my setting being
ignored" — the usual answer is a config sitting somewhere the loader does not look.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			efs := parseEarlyFlags(os.Args[1:])
			opts := config.LoadOptions{
				ExplicitConfigPath: efs.configPath,
				SecretsPath:        efs.secretsPath,
			}
			config.ResolveDefaultPaths(&opts)

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Config sources (later wins):")
			fmt.Fprintf(out, "  %-9s %-6s %s\n", "LAYER", "STATE", "PATH")
			fmt.Fprintf(out, "  %-9s %-6s %s\n", "1 default", "built-in", "(compiled defaults)")

			for _, layer := range []struct{ name, path string }{
				{"2 system", opts.SystemPath},
				{"3 user", opts.UserPath},
				{"4 project", opts.ProjectPath},
				{"5 config", opts.ExplicitConfigPath},
				{"6 secrets", opts.SecretsPath},
			} {
				if layer.path == "" {
					fmt.Fprintf(out, "  %-9s %-6s %s\n", layer.name, "unset", "(not supplied)")
					continue
				}
				abs, err := filepath.Abs(layer.path)
				if err != nil {
					abs = layer.path
				}
				state := "absent"
				if st, statErr := os.Stat(layer.path); statErr == nil && !st.IsDir() {
					state = "LOADED"
				}
				fmt.Fprintf(out, "  %-9s %-6s %s\n", layer.name, state, abs)
			}

			fmt.Fprintf(out, "  %-9s %-6s %s\n", "7 env", "always", "RECONFTW_* environment variables")
			fmt.Fprintf(out, "  %-9s %-6s %s\n", "8 flags", "always", "command-line flags")
			fmt.Fprintln(out, "\nRun 'reconftw config show' to see the merged result.")
			return nil
		},
	}
}

// loadConfigForInspection re-runs the loader with the operator's --config/--secrets
// and the same CLI overrides a scan would apply, so `config show` reflects the real
// invocation rather than a pristine load.
func loadConfigForInspection(cmd *cobra.Command) (*config.Config, error) {
	efs := parseEarlyFlags(os.Args[1:])
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		return nil, fmt.Errorf("config show: load: %w", err)
	}
	// Mirror the overrides BootReconApp applies, so what is printed is what runs.
	if cliLogLevel != "" {
		cfg.Output.LogLevel = cliLogLevel
	}
	if cliOutputDir != "" {
		cfg.Paths.DataDir = cliOutputDir
	}
	if force, _ := cmd.Flags().GetBool("force"); force {
		cfg.Advanced.Diff = true
	}
	return cfg, nil
}
