// Source: ADR 0002 §5.3 + §10.3 (build order).
//
// Boot is the AppContext factory called from Plan 06 cmd/reconftw/main.go.
// It wires the 9 dependency-kernel fields in the order mandated by ADR
// §10.3:
//
//  1. Logger (already constructed by the caller — passed in)
//  2. Config (already loaded by the caller — passed in)
//  3. Backend + Runner   (LocalBackend vs AxiomBackend per cfg.Axiom.Enabled)
//  4. Checkpoint store   (SQLite at <workDir>/checkpoints.db)
//  5. OutputTree         (with DefaultScopeFilter wrapping target.Scope)
//  6. Scheduler          (cfg.Concurrency.MaxJobs + HeartbeatSeconds)
//  7. Notifier Multi     (LogSink + 3 stubs)
//  8. UI Printer         (stderr, cfg.Output.Verbosity)
//
// Caller responsibilities (Plan 06 main.go owns these):
//   - Construct logger via log.New(cfg, redactor)
//   - Load config via config.Load(cliOverrides)
//   - Register every Secret-typed config value with the Redactor
//   - Build Target via appctx.NewTarget
//   - Call appctx.Boot
//   - **Set sched.RunTask = func(ctx, t) { return t.Run(ctx, app) }**
//     (main.go does this to close the cycle break — appctx itself does NOT
//     import task; the closure lives in main where the import is OK)
//   - On context cancel, close the Checkpoint store
//
// Closing: AppContext does not own teardown — Plan 06 main.go is
// responsible. The Checkpoint store should be closed via a defer in main.

package appctx

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/checkpoint"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/notifier"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/ui"
)

// BootOptions adjusts Boot's wiring at construction time. Tests inject
// alternate backends, output trees, or checkpoint stores via this struct.
// Production Boot callers pass a zero-value options struct (or a small
// subset — Backend may be set to backend.AxiomBackend when Axiom is
// enabled and credentials are present).
type BootOptions struct {
	// Backend overrides the default Backend selection. nil → LocalBackend
	// when cfg.Axiom.Enabled is false; AxiomBackend (stub) otherwise.
	Backend backend.Backend
	// Tree overrides the default *output.OutputTree. nil → constructed
	// from target.WorkDir + DefaultScopeFilter(target.Scope).
	Tree output.Interface
	// Checkpoint overrides the default *checkpoint.Store. nil → opened at
	// filepath.Join(target.WorkDir, "checkpoints.db"). Tests pass a stub.
	Checkpoint checkpoint.Interface
	// NotifySinks overrides the default Notifier sinks. nil → LogSink +
	// 3 stubs (Slack/Telegram/Discord per CONTEXT default option (a)).
	NotifySinks []notifier.Notifier
	// PassiveMode wraps the chosen backend with PassiveBackend, hard-blocking
	// any tool in the active-tool set (D-09: defense-in-depth beyond composition
	// guard). When true, LocalBackend.Exec/Stream for puredns/nmap/etc. return
	// ErrPassiveViolation instead of executing. Ignored when Backend is already
	// a PassiveBackend (idempotent).
	PassiveMode bool
}

// Boot constructs the AppContext. Returns the wired *AppContext or an
// error if any subsystem fails to initialize. ctx is used only for
// Backend.Discover (which is fast; tests may pass context.Background()).
//
// On error, Boot does NOT clean up partially-initialized subsystems —
// the caller is expected to fail-fast at startup and exit.
//
// IMPORTANT — the Scheduler is constructed OUTSIDE appctx and passed in.
// This split is the import-cycle break: appctx must not import
// scheduler (because scheduler imports task, task imports appctx —
// triple cycle). The caller (Plan 06 main.go) constructs the Scheduler,
// passes it as sched, and then sets sched.RunTask = func(ctx, t) {
// return t.Run(ctx, app) } once Boot returns. This wiring lives in main
// where importing task is permitted.
//
// sched must implement appctx.SchedulerRunner (a minimal interface — see
// appctx.go). *scheduler.Scheduler satisfies it.
func Boot(ctx context.Context, logger *slog.Logger, cfg *config.Config, target *Target, sched SchedulerRunner, opt BootOptions) (*AppContext, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil {
		return nil, fmt.Errorf("appctx.Boot: nil *config.Config")
	}
	if target == nil {
		return nil, fmt.Errorf("appctx.Boot: nil *Target")
	}

	// 3. Backend + Runner.
	be := opt.Backend
	if be == nil {
		be = pickBackend(cfg, logger)
	}
	// D-09: Wrap with PassiveBackend when PassiveMode is requested.
	// PassiveBackend hard-blocks active tools (puredns/nmap/etc.) as
	// defense-in-depth beyond the composition-level guard (ModePassive only
	// schedules passive-prefixed tasks).
	if opt.PassiveMode {
		if _, already := be.(*backend.PassiveBackend); !already {
			be = backend.NewPassiveBackend(be)
		}
	}
	// Discover() is tolerant of an empty registry — Plan 04 tests already
	// validate this; Plan 07 seeds the canonical tools.lock.
	if err := backend.Default.Discover(ctx); err != nil {
		// Discover currently returns nil always (Plan 04 SUMMARY); future
		// IOError paths surface here.
		return nil, fmt.Errorf("appctx.Boot: backend discover: %w", err)
	}
	limiter := pickLimiter(cfg)
	runner := backend.NewRunner(be, backend.Default, limiter)

	// 4. Checkpoint.
	cp := opt.Checkpoint
	if cp == nil {
		dbPath := filepath.Join(target.WorkDir, "checkpoints.db")
		// Ensure the workspace dir exists (NewStore won't create parents).
		if err := os.MkdirAll(target.WorkDir, 0o755); err != nil {
			return nil, fmt.Errorf("appctx.Boot: mkdir workspace: %w", err)
		}
		store, err := checkpoint.NewStore(dbPath)
		if err != nil {
			return nil, fmt.Errorf("appctx.Boot: checkpoint store: %w", err)
		}
		cp = store
	}

	// 5. OutputTree.
	tree := opt.Tree
	if tree == nil {
		scope := &output.DefaultScopeFilter{Patterns: target.Scope}
		ot, err := output.NewTree(target.WorkDir, scope)
		if err != nil {
			return nil, fmt.Errorf("appctx.Boot: output tree: %w", err)
		}
		tree = ot
	}

	// 6. Scheduler — provided by the caller (cycle-break, see header).
	if sched == nil {
		return nil, fmt.Errorf("appctx.Boot: nil Scheduler — caller must construct via scheduler.NewScheduler(...)")
	}

	// 7. Notifier Multi (LogSink + 3 stubs per CONTEXT default option (a)).
	sinks := opt.NotifySinks
	if sinks == nil {
		sinks = defaultNotifierSinks(logger, cfg)
	}
	notif := notifier.NewMulti(sinks...)

	// 8. UI Printer.
	printer := ui.NewPrinter(os.Stderr, ui.Verbosity(cfg.Output.Verbosity))
	if cfg.Concurrency.LogMode != "" {
		printer.ParallelMode = ui.ParallelMode(cfg.Concurrency.LogMode)
	}
	if cfg.Concurrency.TailLines > 0 {
		printer.TailLines = cfg.Concurrency.TailLines
	}

	app := &AppContext{
		Log:        logger,
		Cfg:        cfg,
		Scheduler:  sched,
		Tools:      runner,
		Tree:       tree,
		Checkpoint: cp,
		Notify:     notif,
		Target:     target,
		UI:         printer,
	}
	return app, nil
}

// pickBackend chooses LocalBackend (default) or AxiomBackend per cfg.Axiom.Enabled.
// logger is required for AxiomBackend (repairKnownHosts logging).
func pickBackend(cfg *config.Config, logger *slog.Logger) backend.Backend {
	if cfg.Axiom.Enabled {
		return backend.NewAxiomBackend(cfg, backend.Default, logger)
	}
	killGrace := time.Duration(cfg.Concurrency.KillGraceSeconds) * time.Second
	return backend.NewLocalBackend(killGrace)
}

// pickLimiter constructs the central RateLimiter from per-tool + global
// rate-limit configuration (INTEG-05).
//
// Previously this returned backend.NewRateLimiter(map[string]int{}, 0) — an
// empty per-tool map and zero global RPS — so RateLimiter.Wait returned
// immediately for every tool and the configured *_RATELIMIT / adaptive-rate
// settings were never enforced centrally. The enforcement path itself already
// exists: backend.Runner.Run/Stream call Limiter.Wait(ctx, toolName) before
// every dispatch (runner.go), so feeding a populated map is all that is needed
// to make the central throttle take effect — no Runner or RateLimiter change.
//
// The per-tool map is keyed by the registered tool binary name the Runner
// passes to Limiter.Wait ("httpx", "nuclei", "ffuf", "favirecon", "dnsx").
func pickLimiter(cfg *config.Config) *backend.RateLimiter {
	perToolRPS, globalRPS := buildLimiterConfig(cfg)
	return backend.NewRateLimiter(perToolRPS, globalRPS)
}

// buildLimiterConfig derives the per-tool RPS map and the optional global RPS
// cap from config. It is split out from pickLimiter so tests can assert the
// derived values deterministically (map contents + global int) instead of
// relying on wall-clock timing.
//
// Only tool classes with a configured RateLimit > 0 are inserted: a 0 means
// "no per-tool cap", so the key is left out and NewRateLimiter treats that tool
// as unlimited (Wait returns immediately). This keeps unlisted / zero-rate
// tools from being accidentally throttled.
//
// A global cap is applied only when adaptive_rate.enabled is true (using
// adaptive_rate.max_rate); when disabled there is no aggregate cap. A nil cfg
// yields an empty map + 0 global, preserving the prior nil-safe contract.
func buildLimiterConfig(cfg *config.Config) (map[string]int, int) {
	perToolRPS := map[string]int{}
	if cfg == nil {
		return perToolRPS, 0
	}

	// Rate-limited tool classes, keyed by the binary name the Runner passes to
	// Limiter.Wait. Insert only positive caps (0 == unlimited → omit the key).
	candidates := map[string]int{
		"httpx":     cfg.Web.Probe.RateLimit,
		"nuclei":    cfg.Web.Nuclei.RateLimit,
		"ffuf":      cfg.Web.Fuzz.RateLimit,
		"favirecon": cfg.Web.Favirecon.RateLimit,
		"dnsx":      cfg.Subdomains.DNSResolve.DNSXRateLimit,
	}
	for name, rps := range candidates {
		if rps > 0 {
			perToolRPS[name] = rps
		}
	}

	// Global aggregate cap only when adaptive rate is enabled.
	globalRPS := 0
	if cfg.AdaptiveRate.Enabled {
		globalRPS = cfg.AdaptiveRate.MaxRate
	}
	return perToolRPS, globalRPS
}

// defaultNotifierSinks builds the Phase 10 real-webhook sink set.
//
// When Notifications.Enabled is false, returns only LogSink (same as
// Phase 3 behaviour — backward-compatible).
//
// When enabled, real HTTP dispatchers replace the stubs and are wrapped
// in a DigestCoalescer (D-06) to prevent channel flooding on critical-
// finding bursts. The outer Multi (constructed by Boot's caller) wraps
// the single DigestCoalescer element — so app.Notify.(notifier.Flusher)
// succeeds via Multi.FlushNow delegating to DigestCoalescer.FlushNow.
//
// target is passed as "" because Boot is process-scoped; per-scan target
// context is set by the monitor loop via its own DigestCoalescer instance.
//
// Pitfall 6 fix: wraps REAL HTTP dispatchers, not stubs, when enabled.
func defaultNotifierSinks(logger *slog.Logger, cfg *config.Config) []notifier.Notifier {
	sinks := []notifier.Notifier{notifier.NewLogSink(logger)}
	if !cfg.Notifications.Enabled {
		return sinks // Phase 3 behaviour preserved when not enabled
	}
	// Phase 10: real HTTP dispatchers (Pitfall 6: real, not stubs).
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if wh := string(cfg.Notifications.Slack.WebhookURL); wh != "" {
		sinks = append(sinks, notifier.NewSlack(logger, httpClient, wh))
	}
	if tok := string(cfg.Notifications.Telegram.BotToken); tok != "" {
		chatID := cfg.Notifications.Telegram.ChatID
		sinks = append(sinks, notifier.NewTelegram(logger, httpClient, tok, chatID))
	}
	if wh := string(cfg.Notifications.Discord.WebhookURL); wh != "" {
		sinks = append(sinks, notifier.NewDiscord(logger, httpClient, wh))
	}
	multi := notifier.NewMulti(sinks...)
	// Wrap Multi in DigestCoalescer (D-06: burst coalescing, nothing dropped).
	// target is "" at Boot time; the monitor loop sets its own per-scan target.
	return []notifier.Notifier{notifier.NewDigestCoalescer(multi, cfg.Notifications, "")}
}
