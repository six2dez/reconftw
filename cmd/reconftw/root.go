// root.go — cobra root command: 15 visible v2 subcommands + v1 aliases.
//
// Source: ADR 0002 §8 (BINDING — CLI Surface):
//   - §8.1 lines 2064-2088: subcommand inventory (15 visible + version + 12 stubbed + 3 working).
//   - §8.2 lines 2089-2112: persistent global flags.
//   - §8.3 lines 2113-2167: cobra deprecation pattern for v1 long + short flag aliases.
//   - §8.4 lines 2168-2186: removal timeline (v2.2.0).
//
// CONTEXT decisions (03-CONTEXT.md):
//   - D-01: All 15 v2 subcommands visible in --help.
//   - D-02: Stubbed subcommands exit 64 with phase-pointer message.
//   - D-03: All v1 deprecated aliases wired with cobra.MarkDeprecated.
//   - D-04: version + health-check ship fully working.
//   - D-05 (W16): Hidden kernel-demo subcommand deleted in Phase 4 plan-01 per
//                 its own header — demo scaffold replaced by subdomains module.

package main

import (
	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
)

// newRootCmd builds the cobra root command tree.
//
// app is the wired *AppContext (when --target was supplied) or nil (version /
// health-check / stubbed subcommands can operate without a target).
//
// cfg is the resolved Config (always non-nil after STEP 5 in main.run).
func newRootCmd(app *appctx.AppContext, cfg *config.Config) *cobra.Command {
	root := &cobra.Command{
		Use:   "reconftw",
		Short: "Comprehensive reconnaissance automation framework",
		Long: `reconFTW v2 — orchestrates 70+ external security tools across subdomain
enumeration, web probing, OSINT, and vulnerability scanning. Single binary;
resumable checkpoints; structured output; optional Axiom distributed execution.

See subcommands below for v2 modes. v1 flags (--recon, -r, --all, -a, ...)
remain functional with deprecation warnings until v2.2.0 per ADR 0002 §8.4.`,
		SilenceUsage:  true, // RunE errors should not dump --help every time
		SilenceErrors: true, // main() handles error printing
	}

	addPersistentGlobalFlags(root)
	addV1DeprecatedAliases(root)

	// 12 stubbed v2 subcommands (per D-01 surface + D-02 exit 64).
	root.AddCommand(newReconCmd())
	root.AddCommand(newAllCmd())
	root.AddCommand(newPassiveCmd())
	root.AddCommand(newSubsCmd())
	root.AddCommand(newWebCmd())
	root.AddCommand(newVulnsCmd())
	root.AddCommand(newOSINTCmd())
	root.AddCommand(newZenCmd())
	root.AddCommand(newDeepCmd())
	root.AddCommand(newMonitorCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newMCPCmd())
	root.AddCommand(newMigrateCmd())
	root.AddCommand(newInstallCmd())

	// 3 stateful utility subcommands (Phase 9 plan 09-04 — MODE-06/07/08).
	root.AddCommand(newGenResolversCmd())
	root.AddCommand(newRefreshCacheCmd())
	root.AddCommand(newQuickRescanCmd())

	// Phase 10 plan 02: notify --test reachability subcommand (NOTIF-04).
	root.AddCommand(newNotifyCmd())

	// 1 working v2 subcommand from the §8.1 visible inventory (per D-04).
	root.AddCommand(newHealthCheckCmd(app, cfg))

	// 1 additional working subcommand per D-04 (version).
	root.AddCommand(newVersionCmd())

	// Phase 4 plan-01: kernel-demo hidden subcommand deleted (along with
	// internal/modules/demo/noop.go and cmd/reconftw/kernel_demo.go).
	// Blank import of subdomains package now wires the 6 passive Tasks.

	return root
}

// addPersistentGlobalFlags wires the persistent global flag set per ADR §8.2.
//
// The pre-cobra parseEarlyFlags (W14) already extracted --config and --secrets;
// declaring them on cobra here lets `reconftw <subcmd> --help` show them and lets
// cobra perform proper validation on the visible call site. Cobra's parse
// is the authoritative one for all flags except the W14 pair (which were
// consumed earlier so the logger + config could initialize).
func addPersistentGlobalFlags(root *cobra.Command) {
	// Standard v2-native global flags per ADR §8.2.
	root.PersistentFlags().String("target", "", "Target domain (single)")
	root.PersistentFlags().String("list", "", "Path to file with one target per line")
	root.PersistentFlags().String("config", "", "Explicit reconftw.toml path (overrides 8-source default chain)")
	root.PersistentFlags().String("secrets", "", "Explicit secrets.toml path")
	root.PersistentFlags().Bool("dry-run", false, "Preview tool invocations without executing")
	root.PersistentFlags().Bool("force", false, "Bypass checkpoint cache; re-run completed tasks")
	root.PersistentFlags().String("log-level", "info", "slog level (debug|info|warn|error)")
	root.PersistentFlags().Bool("axiom", false, "Enable axiom distributed execution")
	root.PersistentFlags().BoolP("quiet", "q", false, "Quiet mode (alias for --log-level=error)")
	root.PersistentFlags().BoolP("verbose", "V", false, "Verbose mode (alias for --log-level=debug)")
	root.PersistentFlags().StringP("output", "o", "workspaces", "Output workspace directory root")
	root.PersistentFlags().Bool("no-color", false, "Disable ANSI color output")
}

// addV1DeprecatedAliases wires every v1 alias per ADR §8.3 + CONTEXT D-03.
//
// The behaviour-preserving contract (ADR §8.4): the alias REMAINS FUNCTIONAL —
// cobra's MarkDeprecated only emits a stderr warning the first time the flag
// is observed in a process; the underlying flag value still propagates. For
// boolean-mode aliases like `--recon` the operator-facing semantic is "dispatch
// to subcommand 'recon'", which Phase 3 implements as: cobra parses the flag,
// MarkDeprecated emits the warning, and the root RunE does nothing — the
// operator still has to invoke the subcommand explicitly. Phase 9 (composite
// modes) wires the dispatch so `reconftw --recon -d X` becomes equivalent to
// `reconftw recon --target X`.
//
// Counts (D-03 spec):
//   - 9 long-flag aliases:  --recon, --all, --passive, --subdomains, --web,
//                           --vulns, --osint, --monitor, --health-check
//   - 8 short-flag aliases: -r, -a, -p, -s, -w, -n, -z, -y
//   - 3 global aliases:     -d (target), -l (list), -v (axiom — "vps")
//
// (No -v/--vulns because cobra reserves -v for --verbose; ADR §8.3 line 2148
// resolves the collision by NOT aliasing vulns to a short flag.)
//
// Total: 9 + 8 + 3 = 20 deprecated alias entries.
func addV1DeprecatedAliases(root *cobra.Command) {
	pf := root.PersistentFlags()

	// Long-flag + short-flag subcommand aliases (combined per cobra flag API).
	// 9 long flags, 8 of which carry a short letter.
	pf.BoolP("recon", "r", false, "DEPRECATED: use `reconftw recon` instead")
	mustMarkDeprecated(pf, "recon", "use subcommand 'recon' instead: `reconftw recon --target example.com`")

	pf.BoolP("all", "a", false, "DEPRECATED: use `reconftw all` instead")
	mustMarkDeprecated(pf, "all", "use subcommand 'all' instead: `reconftw all --target example.com`")

	pf.BoolP("passive", "p", false, "DEPRECATED: use `reconftw passive` instead")
	mustMarkDeprecated(pf, "passive", "use subcommand 'passive' instead: `reconftw passive --target example.com`")

	pf.BoolP("subdomains", "s", false, "DEPRECATED: use `reconftw subs` instead")
	mustMarkDeprecated(pf, "subdomains", "use subcommand 'subs' instead: `reconftw subs --target example.com`")

	pf.BoolP("web", "w", false, "DEPRECATED: use `reconftw web` instead")
	mustMarkDeprecated(pf, "web", "use subcommand 'web' instead: `reconftw web --target example.com`")

	// --vulns has NO short alias (cobra reserves -v for --verbose per ADR §8.3).
	pf.Bool("vulns", false, "DEPRECATED: use `reconftw vulns` instead")
	mustMarkDeprecated(pf, "vulns", "use subcommand 'vulns' instead: `reconftw vulns --target example.com`")

	pf.BoolP("osint", "n", false, "DEPRECATED: use `reconftw osint` instead")
	mustMarkDeprecated(pf, "osint", "use subcommand 'osint' instead: `reconftw osint --target example.com`")

	pf.BoolP("zen", "z", false, "DEPRECATED: use `reconftw zen` instead")
	mustMarkDeprecated(pf, "zen", "use subcommand 'zen' instead: `reconftw zen --target example.com`")

	pf.BoolP("deep", "y", false, "DEPRECATED: use `reconftw deep` instead")
	mustMarkDeprecated(pf, "deep", "use subcommand 'deep' instead: `reconftw deep --target example.com`")

	pf.Bool("monitor", false, "DEPRECATED: use `reconftw monitor` instead")
	mustMarkDeprecated(pf, "monitor", "use subcommand 'monitor' instead: `reconftw monitor --target example.com`")

	pf.Bool("health-check", false, "DEPRECATED: use `reconftw health-check` instead")
	mustMarkDeprecated(pf, "health-check", "use subcommand 'health-check' instead: `reconftw health-check`")

	// Global v1 short-flag aliases per ADR §8.3 lines 2143-2153:
	//   -d → --target,   -l → --list,   -v → --axiom (called "vps" in v1)
	//
	// We register them as distinct named flags (not Shorthand on the v2 flag
	// itself) so MarkDeprecated triggers properly. A small downside is that
	// `-d X` does not auto-populate the --target value — Phase 9 wires the
	// dispatch. Phase 3 satisfies D-03's "emits warning" requirement.
	pf.StringP("target-deprecated", "d", "", "DEPRECATED: use --target instead")
	mustMarkDeprecated(pf, "target-deprecated", "use --target instead: `reconftw <subcommand> --target example.com`")

	pf.StringP("list-deprecated", "l", "", "DEPRECATED: use --list instead")
	mustMarkDeprecated(pf, "list-deprecated", "use --list instead: `reconftw <subcommand> --list targets.txt`")

	pf.BoolP("vps", "v", false, "DEPRECATED: use --axiom instead")
	mustMarkDeprecated(pf, "vps", "use --axiom instead: `reconftw <subcommand> --axiom`")
}

// mustMarkDeprecated wraps cobra's MarkDeprecated so we don't have to ignore
// the error inline at every call site. The only path that errors here is
// "flag not registered", which is a programmer mistake (panic-worthy).
func mustMarkDeprecated(fs interface {
	MarkDeprecated(name, usageMessage string) error
}, name, message string) {
	// Append the removal version (ADR 0002 §8.4) so every deprecation warning
	// states when the alias goes away — MODE-09 criterion 5.
	if err := fs.MarkDeprecated(name, message+" — will be removed in v2.2"); err != nil {
		panic("reconftw: MarkDeprecated " + name + ": " + err.Error())
	}
}
