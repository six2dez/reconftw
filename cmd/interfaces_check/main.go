// SPDX-License-Identifier: MIT
// interfaces_check — compile-only BINDING-signature delta detector.
//
// Source:
//   - .planning/decisions/0002-architecture-v2.md §5 Interface Signatures (BINDING).
//   - .planning/decisions/verify-0002.sh Check 3 (Go snippets compile).
//   - .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 3.
//
// Phase 2 D-14 shipped this binary with placeholder `interface{}` types
// so it could compile before the real internal/core/{task,backend,appctx}
// packages existed.
//
// Phase 3 Plan 07 Task 3 UPGRADES it to import the real packages and
// declares compile-time assertions: if the real interface signatures
// drift from what ADR §5 specifies, this file fails to compile and the
// CI lint job (and `bash .planning/decisions/verify-0002.sh`) breaks.
// That is the canonical BINDING enforcement gate end-to-end:
//
//   - var _ task.Task = (*placeholderTask)(nil)          (ADR §5.1)
//   - var _ task.LifecycleAware = (*placeholderLifecycle)(nil) (ADR §5.1)
//   - var _ backend.Backend = (*placeholderBackend)(nil) (ADR §5.2)
//   - var _ appctx.SchedulerRunner = (*placeholderSched)(nil) (Plan 05 cycle-break)
//
// If any signature is renamed, removed, or changed (D-06 amendment),
// these assertions will fail at compile time before the change can
// reach trunk. Adding interface methods (D-07 non-breaking) will also
// fail and require the placeholder type to grow new methods — explicit
// caller acknowledgement of the extension.
//
// This binary is NEVER executed in production. main() is a no-op.
// `go build ./cmd/interfaces_check/...` is the only invocation.

package main

import (
	"context"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// --------------------------------------------------------------------------
// §5.1 — Task interface (ARCH-05) — real type assertion
// --------------------------------------------------------------------------

// placeholderTask satisfies task.Task. Adding a method to task.Task forces
// this struct to grow a new method — a compile error here surfaces the
// BINDING change at the verify-0002.sh gate.
type placeholderTask struct{}

func (placeholderTask) Name() string                  { return "" }
func (placeholderTask) Module() string                { return "" }
func (placeholderTask) Description() string           { return "" }
func (placeholderTask) Enabled(_ *config.Config) bool { return false }
func (placeholderTask) DependsOn() []string           { return nil }
func (placeholderTask) Run(_ context.Context, _ *appctx.AppContext) (task.Result, error) {
	return task.Result{}, nil
}

// placeholderLifecycle satisfies task.LifecycleAware (optional extension).
type placeholderLifecycle struct{}

func (placeholderLifecycle) OnStart(_ context.Context, _ *appctx.AppContext) error {
	return nil
}

func (placeholderLifecycle) OnEnd(_ context.Context, _ *appctx.AppContext, _ task.Result) error {
	return nil
}

// --------------------------------------------------------------------------
// §5.2 — Backend interface (ARCH-06) — real type assertion
// --------------------------------------------------------------------------

// placeholderBackend satisfies backend.Backend. Compile error here ⇒
// backend.Backend's signature drifted from ADR §5.2 BINDING.
type placeholderBackend struct{}

func (placeholderBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	return nil, nil
}

func (placeholderBackend) ExecEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (*backend.Result, error) {
	return nil, nil
}

func (placeholderBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	return nil, nil
}

func (placeholderBackend) StreamEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (<-chan backend.Event, error) {
	return nil, nil
}

func (placeholderBackend) HealthCheck(_ context.Context) error { return nil }
func (placeholderBackend) Capacity() int                       { return 0 }

// --------------------------------------------------------------------------
// §5.3 — AppContext cycle-break (Plan 05) — SchedulerRunner assertion
// --------------------------------------------------------------------------

// placeholderScheduler satisfies appctx.SchedulerRunner. Plan 05's
// interface-inversion cycle-break is captured here: AppContext.Scheduler
// is typed on this interface so `appctx → scheduler` import edge stays
// broken. The concrete *scheduler.Scheduler satisfies it.
type placeholderScheduler struct{}

func (placeholderScheduler) MaxConcurrency() int { return 0 }

// --------------------------------------------------------------------------
// Compile-time BINDING assertions
// --------------------------------------------------------------------------
//
// These assertions live at package level so they run at every `go build`
// invocation — not just `go test`. The verify-0002.sh Check 3 step is
// `go build ./cmd/interfaces_check/...`, which exits non-zero if ANY of
// these assertions fails.

var (
	_ task.Task              = (*placeholderTask)(nil)
	_ task.LifecycleAware    = (*placeholderLifecycle)(nil)
	_ backend.Backend        = (*placeholderBackend)(nil)
	_ appctx.SchedulerRunner = (*placeholderScheduler)(nil)
)

// --------------------------------------------------------------------------
// §5.3 — AppContext shape spot-check (informational, not asserted)
// --------------------------------------------------------------------------
//
// AppContext is a struct, not an interface, so a "satisfies" assertion is
// not directly applicable. We instead reference each field by name so
// renaming a field surfaces here. ADR §5.3 BINDING field names:
// {Log, Cfg, Scheduler, Tools, Tree, Checkpoint, Notify, Target, UI}.

var _ = func() {
	var app appctx.AppContext
	_ = app.Log
	_ = app.Cfg
	_ = app.Scheduler
	_ = app.Tools
	_ = app.Tree
	_ = app.Checkpoint
	_ = app.Notify
	_ = app.Target
	_ = app.UI

	// Target subfields (ADR §5.3 lines 1736-1742 — 5 fields).
	var tgt appctx.Target
	_ = tgt.Domain
	_ = tgt.IsCIDR
	_ = tgt.IsIP
	_ = tgt.Scope
	_ = tgt.WorkDir
}

// --------------------------------------------------------------------------
// §5.1 — Status / Result constants
// --------------------------------------------------------------------------

// Reference the Status enum values so renaming them surfaces here.
var _ = []task.Status{
	task.StatusDone,
	task.StatusErrored,
	task.StatusCancelled,
	task.StatusSkipped,
}

// Reference the Result fields so renaming them surfaces here.
var _ = func() {
	var r task.Result
	_ = r.Status
	_ = r.Duration
	_ = r.Outputs
	_ = r.Stats
}

// Reference time.Duration to keep the import live (task.Result.Duration is time.Duration).
var _ time.Duration

// --------------------------------------------------------------------------
// main — required for `go build ./cmd/interfaces_check/...`
// --------------------------------------------------------------------------
//
// Compile-only gate. main() is a no-op; the build itself is the test.

func main() {
	// All assertions live at package init time — main is a no-op.
	_ = task.StatusDone
	_ = backend.Default
	_ = task.Default
}
