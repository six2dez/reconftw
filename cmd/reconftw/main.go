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
//	STEP 9: scheduler.NewScheduler + appctx.Boot if --target supplied
//	STEP 9b: sched.RunTask closure — closes the appctx ↔ scheduler ↔ task triple cycle
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

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/scheduler"
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
		slog.Error("reconftw_exit_error", "err", err)
		os.Exit(1)
	}
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

	// STEP 9 + 9b: Construct the Scheduler and (if --target supplied) the AppContext.
	// The cycle break: scheduler is built first; appctx.Boot takes it as a parameter;
	// sched.RunTask closure is set AFTER Boot returns so the closure can capture *app.
	//
	// Target resolution: parseEarlyFlags does NOT extract --target (cobra owns it).
	// Instead cobra subcommands that need an AppContext build one lazily, or we use
	// the pre-built one when a flag is supplied via os.Args. For Phase 3 the binary
	// boots an AppContext from a target supplied via early flag scan of --target,
	// so kernel-demo and run can use it. Subcommands with no --target (version,
	// health-check, stubs) operate on a nil *AppContext.
	target := efs.target
	var app *appctx.AppContext
	var sched *scheduler.Scheduler
	if target != "" {
		tgt, err := appctx.NewTarget(target, nil, "")
		if err != nil {
			logger.Error("target_invalid", "err", err)
			return err
		}
		// Workspace directory: workspaces/<target>-<timestamp>/ per ADR §3.1.
		workdir, err := output.WorkspaceInit(cfg.Paths.DataDir, tgt.Domain)
		if err != nil {
			// Fallback when DataDir empty — use ./workspaces relative to cwd.
			workdir, err = output.WorkspaceInit("workspaces", tgt.Domain)
			if err != nil {
				return fmt.Errorf("workspace init: %w", err)
			}
		}
		tgt.WorkDir = workdir
		sched = scheduler.NewScheduler(cfg.Concurrency.MaxJobs, cfg.Concurrency.HeartbeatSeconds, nil, logger)
		app, err = appctx.Boot(ctx, logger, cfg, tgt, sched, appctx.BootOptions{})
		if err != nil {
			logger.Error("appctx_boot_failed", "err", err)
			return err
		}
		// Wire the scheduler back to the Boot-constructed Checkpoint.
		sched.Checkpoint = app.Checkpoint
		// STEP 9b: scheduler.RunTask closure — closes the appctx ↔ scheduler ↔ task
		// triple cycle. Per Plan 05 SUMMARY "Cycle-break #2".
		sched.RunTask = func(ctx context.Context, t task.Task) (task.Result, error) {
			return t.Run(ctx, app)
		}
	}

	// STEP 10: cobra.ExecuteContext — dispatches subcommand.
	// Phase 9 (D-08): rewrite v1 alias forms into v2 invocations before cobra
	// parses. translateV1Args leaves the original flag in the slice so
	// MarkDeprecated still emits its one-time warning (MODE-09).
	translated := translateV1Args(os.Args[1:])
	rootCmd := newRootCmd(app, cfg)
	rootCmd.SetArgs(translated)
	return rootCmd.ExecuteContext(ctx)
}

// earlyFlagSet is the W14 pre-cobra extraction result.
type earlyFlagSet struct {
	configPath  string
	secretsPath string
	target      string
}

// parseEarlyFlags scans args for ONLY --config FILE, --secrets FILE, and
// --target FILE per W14. All other flags are owned by cobra and parsed inside
// Execute(). --target is included because Phase 3 main() Boots an AppContext
// before cobra dispatch when a target is supplied (so kernel-demo + run can use it).
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
