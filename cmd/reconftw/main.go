// Package main is the reconFTW v2 CLI binary entry point.
//
// Source: ADR 0002 §10.3 lines 2521-2575 (BINDING — CRITICAL initialization order).
//
// CRITICAL init order (numbered STEPs in run()):
//
//	STEP 1: signal.NotifyContext for SIGINT/SIGTERM (cancels root ctx on Ctrl-C)
//	STEP 2: Redactor (Layer 2 substring scrubber)
//	STEP 3: Bootstrap logger BEFORE config load (validation errors must be captured)
//	STEP 4: parseEarlyFlags (W14) — pre-cobra scan extracting --config / --secrets only
//	STEP 5: config.Load(LoadOptions) — 8-source merge chain
//	STEP 6: Rebuild logger from full config (level + format from cfg.Output.{LogLevel,LogFormat})
//	STEP 7: Register every Secret-typed config field with the Redactor BEFORE AppContext.Boot
//	STEP 8: task.Default.Build() — topo sort + cycle detection BEFORE scheduler accepts submissions
//	STEP 9/9b: REMOVED (F18) — no pre-cobra scheduler or AppContext boot. Each
//	           subcommand initialises only what it uses, via handlers.BootReconApp;
//	           booting here too meant two handles on one checkpoints.db, a workspace
//	           created for commands that need none, and an argv scan that could
//	           disagree with cobra about --output. See STEP 9 in run() for detail.
//	STEP 10: cobra.ExecuteContext — dispatches subcommand
//
// W14 — parseEarlyFlags is a pre-cobra os.Args scan that extracts ONLY
// --config FILE and --secrets FILE so logger + config can initialize before
// cobra owns full parsing. All other flags are owned by cobra inside Execute().
//
// W10 — register every log.Secret-typed field per config.go SECRET FIELD
// ENUMERATION comment block (9 fields: Slack/Telegram/Discord webhooks/tokens,
// AI OpenAI/Anthropic keys, MCP API key, APIKeys Shodan/WhoisXML/PDCP).
//
// Blocker 5 — health-check (cmd/reconftw/healthcheck.go) uses backend.Default
// .MissingCritical() per FOUND-08 two-tier semantics (warn on missing-but-required,
// fail on missing-and-critical).
//
// CONTEXT D-01..D-05 (cmd/reconftw/root.go + stub_subcommands.go + kernel_demo.go)
// — 15 visible v2 subcommands + 1 hidden kernel-demo (W16); v1 deprecated aliases
// per ADR §8.3 wired via cobra.MarkDeprecated.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/task"
)

// Version / CommitSHA / BuildDate are populated at link time via XCUT-02 ldflags:
//
//	-ldflags="-s -w -X main.Version=v2.0.0 -X main.CommitSHA=abc1234 -X main.BuildDate=2026-05-28T00:00:00Z"
//
// At go-run / unit-test time they remain the dev/unknown defaults, which is fine —
// `reconftw version` falls back to runtime/debug.ReadBuildInfo for the commit SHA.
var (
	Version   = "dev"
	CommitSHA = "unknown"
	BuildDate = "unknown"
)

func main() {
	if err := run(); err != nil {
		// exitCodeError carries a specific exit code (D-02 stubs use 64);
		// other errors fall through to exit 1.
		var ec *exitCodeError
		if errors.As(err, &ec) {
			if ec.msg != "" {
				fmt.Fprintln(os.Stderr, ec.msg)
			}
			os.Exit(ec.code)
		}
		// Human-readable on stderr, not a JSON log record. This is the message an
		// operator reads after a typo ("unknown flag: --recno", "--target is
		// required"), and rendering it as a slog line made ordinary CLI mistakes
		// look like internal failures. The structured copy stays available at debug.
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if isUsageError(err) {
			fmt.Fprintf(os.Stderr, "Run 'reconftw --help' for usage.\n")
		}
		slog.Debug("reconftw_exit_error", "err", err)
		os.Exit(1)
	}
}

// isUsageError reports whether err is the kind of mistake a usage hint helps with
// (a mistyped flag, a missing required flag, an unknown subcommand) rather than a
// runtime failure. cobra/pflag return these as plain errors, so match on their
// stable message prefixes.
func isUsageError(err error) bool {
	msg := err.Error()
	for _, p := range []string{
		"unknown flag",
		"unknown shorthand flag",
		"unknown command",
		"flag needs an argument",
		"invalid argument",
		"is required",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// run is the testable entry point — wraps the 10-STEP ADR §10.3 init order.
// Returns nil on clean exit, *exitCodeError for D-02 stub semantics, or any
// other error which main() wraps to exit 1.
func run() error {
	// STEP 1: signal.NotifyContext for SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// STEP 2: Create the redactor FIRST — no log lines emitted yet.
	redactor := &log.Redactor{}

	// STEP 3: Bootstrap logger BEFORE config load.
	// A zero-value log.Config means JSON to stderr at info level — enough to
	// surface parse / validation errors from STEP 5 with proper redaction.
	//
	// Bootstrap logger is always a RedactingHandler (D-10 XCUT-07); secrets
	// registered in STEP 7. This means the default logger is always redacting
	// regardless of TTY/piped/quiet/dry-run path — no inert redactor bypass.
	bootstrapLogger := log.New(&log.Config{}, redactor)
	slog.SetDefault(bootstrapLogger)

	// STEP 4: Pre-cobra parseEarlyFlags (W14) — extract --config and --secrets only.
	// All other flags are owned by cobra and parsed inside Execute().
	efs := parseEarlyFlags(os.Args[1:])

	// STEP 5: Load config via the 8-source merge chain. The two paths from
	// parseEarlyFlags slot into ExplicitConfigPath (layer 5) + SecretsPath (layer 6).
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		slog.Error("config_load_failed", "err", err)
		return err
	}

	// STEP 6: Rebuild logger from full config (level + format from cfg.Output).
	logger := log.New(cfg.AsLoggerConfig(), redactor)
	slog.SetDefault(logger)

	// STEP 7: Register every log.Secret-typed config field with the Redactor
	// BEFORE AppContext.Boot. Per W10 explicit enumeration (config.go SECRET
	// FIELD ENUMERATION comment block).
	registerSecrets(cfg, redactor)

	// STEP 8: task.Default.Build() — topo sort + cycle detection BEFORE Scheduler
	// accepts submissions. ConfigError on cycle / missing-dep aborts the run.
	if _, err := task.Default.Build(); err != nil {
		logger.Error("task_dag_invalid", "err", err)
		return err
	}

	// STEP 9 + 9b: DELIBERATELY ABSENT — there is no pre-cobra boot (F18).
	//
	// main.run used to construct a Scheduler and Boot an AppContext here whenever
	// argv contained --target. Every subcommand that runs a pipeline boots again
	// through handlers.BootReconApp, which owns the scheduler/checkpoint wiring,
	// so the early block was a duplicate with three concrete costs:
	//
	//  1. Two handles on one checkpoints.db from a single process. SQLite in WAL
	//     mode with a busy timeout does not make two writers safe; interleaved
	//     task state corrupts resume decisions.
	//  2. A workspace tree created for commands that need none. `--target x
	//     version` or a mistyped subcommand still produced a directory.
	//  3. Two roots that could disagree. This block read a hand-rolled argv scan
	//     that recognised `--output`/`-o`/`--output=` but not every short form
	//     (`-o=path`), while the subcommand read cobra's parse — so a workspace
	//     could appear under the configured root as well as the one the operator
	//     named.
	//
	// Consequently newRootCmd receives a nil *appctx.AppContext. The only consumer
	// is health-check, which is routinely invoked without --target and already
	// treats a nil app as "no target booted" (cmd/reconftw/healthcheck.go).
	//
	// STEP 10: cobra.ExecuteContext — dispatches subcommand.
	// Phase 9 (D-08): rewrite v1 alias forms into v2 invocations before cobra
	// parses. translateV1Args leaves the original flag in the slice so
	// MarkDeprecated still emits its one-time warning (MODE-09).
	translated := translateV1Args(os.Args[1:])
	rootCmd := newRootCmd(nil, cfg)
	rootCmd.SetArgs(translated)
	return rootCmd.ExecuteContext(ctx)
}

// earlyFlagSet is the W14 pre-cobra extraction result.
//
// configPath and secretsPath are the load-bearing pair: config.Load must run
// before cobra owns parsing, so those two paths have to be recovered from raw
// argv. target, outputDir and dryRun are parsed but no longer drive anything in
// run() — the pre-cobra boot they existed to correct is gone (F18), and cobra's
// own parse is now the single source of truth for -o/--output, --target and
// --dry-run. They are retained because this argv scanner is a shared helper
// (config/notify/mcp/composite subcommands all call it) and because dropping
// them would silently narrow a parser whose behaviour is pinned by tests.
type earlyFlagSet struct {
	configPath  string
	secretsPath string
	target      string
	// outputDir mirrors the subcommand's -o/--output. Read by tests only; the
	// early boot that consumed it (and could disagree with cobra about the root)
	// no longer exists.
	outputDir string
	// dryRun mirrors --dry-run. Read by tests only. The dry-run guarantee is now
	// enforced where it belongs — handlers gate on opts.DryRun before any
	// mutation — rather than by teaching a pre-cobra boot to skip itself.
	dryRun bool
}

// parseEarlyFlags scans args for ONLY --config FILE, --secrets FILE, and
// --target FILE per W14. All other flags are owned by cobra and parsed inside
// Execute().
//
// Accepts both `--flag PATH` and `--flag=PATH` forms. Unknown flags are silently
// ignored — cobra will parse them.
func parseEarlyFlags(args []string) earlyFlagSet {
	var efs earlyFlagSet
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" && i+1 < len(args):
			efs.configPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--config="):
			efs.configPath = strings.TrimPrefix(a, "--config=")
		case a == "--secrets" && i+1 < len(args):
			efs.secretsPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--secrets="):
			efs.secretsPath = strings.TrimPrefix(a, "--secrets=")
		case a == "--target" && i+1 < len(args):
			efs.target = args[i+1]
			i++
		case strings.HasPrefix(a, "--target="):
			efs.target = strings.TrimPrefix(a, "--target=")
		case (a == "--output" || a == "-o") && i+1 < len(args):
			efs.outputDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--output="):
			efs.outputDir = strings.TrimPrefix(a, "--output=")
		case a == "--dry-run":
			efs.dryRun = true
		}
	}
	return efs
}

// registerSecrets registers every log.Secret-typed field value with the
// Redactor per W10 explicit enumeration. CRITICAL: this MUST run immediately
// after config.Load and BEFORE the first log line that could reference any
// secret value (AppContext.Boot may log info lines that touch the config).
//
// Per config.go SECRET FIELD ENUMERATION (lines 38-47), the 9 fields are:
//
//	Notifications.Slack.WebhookURL
//	Notifications.Telegram.BotToken
//	Notifications.Discord.WebhookURL
//	AI.OpenAIKey
//	AI.AnthropicKey
//	MCP.APIKey
//	APIKeys.Shodan
//	APIKeys.WhoisXML
//	APIKeys.PDCP
//
// Axiom SSH credentials flow through env vars per ADR §6 Axiom note and are
// registered separately when read from environment (Plan 03-06+ wiring).
func registerSecrets(cfg *config.Config, r *log.Redactor) {
	r.Register(string(cfg.Notifications.Slack.WebhookURL))
	r.Register(string(cfg.Notifications.Telegram.BotToken))
	r.Register(string(cfg.Notifications.Discord.WebhookURL))
	r.Register(string(cfg.AI.OpenAIKey))
	r.Register(string(cfg.AI.AnthropicKey))
	r.Register(string(cfg.MCP.APIKey))
	r.Register(string(cfg.APIKeys.Shodan))
	r.Register(string(cfg.APIKeys.WhoisXML))
	r.Register(string(cfg.APIKeys.PDCP))
}
