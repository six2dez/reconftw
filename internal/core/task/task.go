// Package task defines reconFTW v2's smallest schedulable unit.
//
// Every module function in v1 (sub_passive, nuclei_check, xss, etc.)
// becomes a Task implementation in v2. Tasks self-register via init() in
// their owning package (internal/modules/<module>/), and are scheduled by
// the Scheduler (internal/core/scheduler) after dependency resolution
// (Registry.Build topological sort) and config-based enablement filtering
// (Task.Enabled returns false → SKIP, no checkpoint written).
//
// Source: ADR 0002 §5.1 lines 1525-1614 (BINDING — verbatim interface).
//
// BLOCKER 4 RESOLUTION: Plan 05 colocates Task + Scheduler in one wave so
// the Task interface is BORN FINAL. No placeholder `any` parameters ever
// existed. Scheduler.runStage consumes `*appctx.AppContext` and `task.Task`
// directly because all three packages ship together.
//
// Adding methods is non-breaking per ADR §0 D-07; renaming, removing, or
// changing method signatures requires an ADR amendment (D-06).
package task

import (
	"context"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
)

// Task is the smallest schedulable unit of recon work. Implementors live
// in internal/modules/<domain>/ and self-register via init().
//
// 6 methods verbatim per ADR §5.1 lines 1542-1568:
//
//	Name() string                                                  unique dot-namespaced id
//	Module() string                                                module group ("subdomains"...)
//	Description() string                                           one-line description for UI
//	Enabled (cfg *config.Config) bool                              config-based enable filter
//	DependsOn() []string                                           prereq task names (DAG edges)
//	Run(ctx, app *appctx.AppContext) (Result, error)               execution entry point
type Task interface {
	// Name returns the globally unique dot-namespaced task identifier.
	// Convention: "<module>.<action>" e.g. "subdomains.passive", "web.fuzz".
	Name() string

	// Module returns the owning module group for grouping and failure_policy lookup.
	// One of: "subdomains", "web", "vulns", "osint", "axiom", "demo".
	Module() string

	// Description returns a human-readable one-line description for UI badges.
	Description() string

	// Enabled reports whether this task should run given the resolved config.
	// Called by Scheduler before Run; return false → SKIP badge, no checkpoint written.
	Enabled(cfg *config.Config) bool

	// DependsOn returns names of tasks that must complete (status=done) before
	// this task may be scheduled. Empty slice = no dependencies (runs in parallel
	// with peers). Registry.Build() performs topological sort cycle detection;
	// circular DependsOn is a *errors.ConfigError, not a runtime error (see ADR
	// §6 PITFALL NOTE).
	DependsOn() []string

	// Run executes the task. ctx is cancellable; cancel = SIGINT or task timeout.
	// MUST respect ctx.Done() promptly; MUST NOT call os.Exit.
	// Returns (Result, nil) on success; (Result, error) on partial or full failure.
	// Non-nil error → Scheduler records status=errored or status=cancelled per policy.
	Run(ctx context.Context, app *appctx.AppContext) (Result, error)
}

// Result carries the outcome of a single task execution.
//
// Source: ADR §5.1 lines 1572-1577.
type Result struct {
	Status   Status         // done | errored | cancelled | skipped
	Duration time.Duration  // populated by Scheduler.runOne (time.Since(start))
	Outputs  []string       // paths written (for checkpoint.output_paths)
	Stats    map[string]int // optional counters (e.g. "subdomains_found": 42)

	// Reason explains a non-Done status in one operator-readable sentence.
	//
	// THE RULE: a non-Done Status with an empty Reason is a bug. The whole point
	// is that an operator reading a SKIP can tell WHY without opening the source.
	// "[SKIP] web.nuclei 0s" answers nothing; "templates path not configured"
	// answers it.
	//
	// Additive field, non-breaking per ADR §0 D-07 — the ADR §5.1 provenance note
	// above fixes the other four fields, not the struct's size.
	Reason string
}

// Produced reports a task that genuinely produced n things.
//
// Reason stays empty because a Done status needs no explanation.
func Produced(statKey string, n int, outputs ...string) Result {
	return Result{
		Status:  StatusDone,
		Outputs: outputs,
		Stats:   map[string]int{statKey: n},
	}
}

// NothingProduced reports rule B2: the tool RAN SUCCESSFULLY and yielded nothing
// from a non-empty input.
//
// This is the shape that cost the most in the first live v2 run. web.httpx
// reported "[OK] web.httpx 31s" having written zero records, because a parser
// contract had drifted; every downstream web task then skipped correctly and the
// run produced 0 live hosts against v1's 12. A task that consumed input and
// produced nothing is not Done — it is a question that needs an answer.
func NothingProduced(reason string, outputs ...string) Result {
	return Result{Status: StatusSkipped, Outputs: outputs, Reason: reason}
}

// ToolDegraded reports rule B1: the tool FAILED and the task continues by design
// (bash CONTINUE_ON_TOOL_ERROR parity).
//
// Distinct from NothingProduced because the two facts are different and were
// conflated for months: dnstake's bad arg vector was swallowed as "run failed or
// tool not registered" and takeover detection silently produced zero. "The tool
// broke" and "the tool worked and found nothing" must never share a message.
func ToolDegraded(tool string, cause error, outputs ...string) Result {
	reason := tool + ": tool failed, continuing"
	if cause != nil {
		reason = tool + ": " + cause.Error()
	}
	return Result{Status: StatusSkipped, Outputs: outputs, Reason: reason}
}

// Status enumerates the terminal states a task may reach.
//
// Source: ADR §5.1 lines 1579-1587.
type Status string

const (
	StatusDone      Status = "done"
	StatusErrored   Status = "errored"
	StatusCancelled Status = "cancelled"
	StatusSkipped   Status = "skipped"
)

// LifecycleAware is an optional lifecycle extension Tasks may implement.
// The Scheduler checks for this interface via type assertion before each
// Run. OnStart is called immediately before Run; OnEnd is called after Run
// completes (including on error or cancellation).
//
// Source: ADR §5.1 lines 1606-1613.
type LifecycleAware interface {
	OnStart(ctx context.Context, app *appctx.AppContext) error
	OnEnd(ctx context.Context, app *appctx.AppContext, r Result) error
}
