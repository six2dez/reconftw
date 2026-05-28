// Package appctx defines reconFTW v2's dependency kernel.
//
// AppContext is wired ONCE at startup (Plan 06 cmd/reconftw/main.go) via
// appctx.Boot(...) and passed by pointer into every Task.Run. NO
// package-level globals — every dependency is explicit at the call site.
//
// Source: ADR 0002 §5.3 lines 1693-1746 (BINDING — 9 fields).
//
// Adding fields is non-breaking per ADR §0 D-07; removing or renaming
// requires an ADR amendment (D-06).
//
// Phase 3 Plan 5 split:
//   - Plan 05 Task 1 ships the AppContext struct shape + Target type so the
//     Task interface signature `Run(ctx, *appctx.AppContext)` resolves.
//   - Plan 05 Task 2 ships target.go (NewTarget validator) + boot.go
//     (Boot factory) + notifier + UI dependencies.
//   - Plan 06 wires `cmd/reconftw/main.go` calling Boot at startup.
//
// IMPORT-CYCLE BREAK NOTE:
//
// The AppContext.Scheduler field is typed as the SchedulerRunner interface
// (declared below), NOT the concrete *scheduler.Scheduler. Reason — the
// natural import graph forms a 3-cycle:
//
//	appctx → scheduler  (AppContext.Scheduler field)
//	scheduler → task    ([]task.Task in RunStage)
//	task → appctx       (Task.Run signature takes *appctx.AppContext per ADR §5.1)
//
// Go does not permit cyclic imports. The standard inversion is to invert
// ONE edge using a small interface defined at the consumer site. Here we
// invert appctx → scheduler: appctx declares SchedulerRunner (minimal —
// the operator-visible contract Plan 06 needs), and scheduler.Scheduler
// satisfies it via its exported methods. ADR §5.3 BINDING is preserved:
// field NAMES match verbatim (Scheduler is still named "Scheduler"); only
// the type changes from concrete to interface. Per ADR §0 D-07,
// non-breaking field-shape additions are explicitly allowed; this is a
// type widening (concrete → interface that the concrete satisfies), which
// is the cleanest form of non-breaking change. Callers that need the
// concrete type can type-assert: `s := app.Scheduler.(*scheduler.Scheduler)`.
package appctx

import (
	"log/slog"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/checkpoint"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/notifier"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/ui"
)

// SchedulerRunner is the cycle-breaking interface AppContext.Scheduler is
// typed against. The concrete *scheduler.Scheduler satisfies it via its
// exported methods (see internal/core/scheduler/scheduler.go).
//
// Kept deliberately minimal so this interface evolves only when truly
// operator-visible Scheduler methods change. Plan 06 main.go performs the
// type assertion to access the full *scheduler.Scheduler API.
type SchedulerRunner interface {
	// MaxConcurrency returns the bounded-parallel limit (cfg.Concurrency.MaxJobs).
	// Lets the UI display the active concurrency, and lets Plan 09 composite
	// modes adjust dispatch behaviour without a hard import of scheduler.
	MaxConcurrency() int
}

// AppContext is the dependency kernel. Wired ONCE at startup; passed by
// pointer into every Task.Run().
//
// 9 fields verbatim per ADR §5.3 lines 1723-1733:
//
//	Log        *slog.Logger          structured logger (RedactingHandler chain)
//	Cfg        *config.Config        resolved + validated config (all keys)
//	Scheduler  SchedulerRunner       bounded concurrency + failure_policy (interface — see header)
//	Tools      *backend.Runner       wraps Backend + ToolRegistry + RateLimiter
//	Tree       output.Interface      atomic JSONL writer + scope filter (W15 interface)
//	Checkpoint checkpoint.Interface  SQLite-backed task idempotency store (W15 interface)
//	Notify     notifier.Notifier     multi-channel notification dispatcher
//	Target     *Target               immutable scan target description
//	UI         *ui.Printer           terminal UI printer (dot-fill format)
//
// W15 NOTE (Tree/Checkpoint): typed on the interface (not the concrete
// *output.OutputTree / *checkpoint.Store) so Plan 07's MockOutputTree /
// MockCheckpoint can substitute without disk/SQLite I/O. The concrete types
// satisfy the interfaces via the var _ Interface = (*Store)(nil) gates in
// the respective packages.
type AppContext struct {
	Log        *slog.Logger
	Cfg        *config.Config
	Scheduler  SchedulerRunner
	Tools      *backend.Runner
	Tree       output.Interface
	Checkpoint checkpoint.Interface
	Notify     notifier.Notifier
	Target     *Target
	UI         *ui.Printer
}

// Target describes the scan target. Immutable after construction in
// Boot (Plan 05 Task 2).
//
// Source: ADR §5.3 lines 1736-1742 (5 fields verbatim).
type Target struct {
	Domain  string   // sanitized domain, IP, or CIDR (validated by NewTarget)
	IsCIDR  bool     // true when Domain is CIDR notation (e.g. "10.0.0.0/24")
	IsIP    bool     // true when Domain is a bare IPv4 / IPv6 literal
	Scope   []string // wildcard patterns from scope file (e.g. "*.example.com")
	WorkDir string   // absolute path to workspaces/<target-id>/
}
